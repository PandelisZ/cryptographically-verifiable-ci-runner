// Worker-side dependency collector.
//
// Installed as early as possible in every Vitest worker (by the `--import` preload, and again,
// idempotently, by the setup file). It patches node:fs (sync, callback and promise APIs), proxies
// process.env, wraps network/process APIs to mark the file tainted, registers module resolution
// hooks, and follows the Vite module runner's evaluated modules.
//
// Records are appended synchronously to a per-(test file, worker) part file under
// `<VCI_OUT>/.vci-parts/`. The main-process reporter merges them at the end of the run.
//
// Fail-open rules: anything we cannot attribute confidently to Vitest internals is recorded.
//
// The same collector also runs in the Vitest main process (mode "main", installed by the
// `--import` of src/main/preload.js). There it records only what user code does: the config
// file (bundled by Vite into a `*.timestamp-*` module), inline plugins, globalSetup files and
// anything else outside node_modules. Those records are kept in memory and attributed to every
// test file of the run by the reporter.
//
// Mode "node-test" (installed by src/node-test/preload.js in the child process `node --test`
// starts for one test file): every record belongs to that one file (VCI_TEST_FILE). It also
// reports writes (`write` records), `module.register` calls, `process.exit` calls, and resolves
// modules reached through a linked workspace package (node_modules symlink into the repository)
// to their real path, so in-repository code is never identified by a package version.

import fs from "node:fs";
import module from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";
import childProcess from "node:child_process";
import net from "node:net";
import http from "node:http";
import https from "node:https";
import http2 from "node:http2";
import tls from "node:tls";
import dgram from "node:dgram";
import dns from "node:dns";
import workerThreads from "node:worker_threads";

import {
  OWN_ENV_KEYS,
  candidateKind,
  PACKAGE_DIR,
  WORKER_ENV,
  idToFsPath,
  isInNodeModules,
  isInternalPath,
  isUnder,
  linkedPackagePath,
  localCopyPackage,
  nodeOptionsProblems,
  packageOf,
  resolutionCandidates,
  sha256,
  toSlash,
} from "../util.js";

const KEY = Symbol.for("vci.vitest.worker-collector");
const MAIN_KEY = Symbol.for("vci.vitest.main-collector");
/** Basename of the temp module Vite bundles a config file into. */
const CONFIG_BUNDLE_RE = /\.timestamp-\d+(?:-[0-9a-f]+)?\.[cm]?js$/;
/** Largest directory tree recorded for one `fs.cp` source. */
const MAX_TREE_ENTRIES = 10000;
const PKG_DIR = toSlash(PACKAGE_DIR);
const STACK_LIMIT = 400;

// Originals captured before any patching.
const orig = {
  appendFileSync: fs.appendFileSync,
  mkdirSync: fs.mkdirSync,
};

/** @typedef {"read" | "stat" | "readdir" | "exists" | "open"} FsKind */

/**
 * @typedef {object} WorkerConfig
 * @property {string} partsDir
 * @property {string[]} ignoreDirs
 * @property {string} root
 * @property {string} [file] node-test mode: the absolute path of the one test file
 */

class Collector {
  /** @param {WorkerConfig} cfg @param {{preload: boolean, mode?: "worker" | "main" | "node-test"}} opts */
  constructor(cfg, opts) {
    this.cfg = cfg;
    this.mode = opts.mode || "worker";
    this.partsDir = cfg.partsDir;
    this.ignoreDirs = (cfg.ignoreDirs || []).map((d) => toSlash(d).replace(/\/$/, ""));
    this.preload = opts.preload;
    /** Main mode: records (JSON line -> record) attributed to every test file. */
    /** @type {Map<string, object>} */
    this.mainRecords = new Map();
    this.busy = false;
    /** @type {Map<string, Set<string>>} */
    this.seen = new Map();
    /** @type {string[]} */
    this.pending = [];
    this.pendingSet = new Set();
    /** Files the test itself fully (re)wrote, and dirs it created with mkdtemp. */
    this.selfFiles = new Set();
    /** @type {string[]} */
    this.selfDirs = [];
    this.runnerAttached = false;
    this.hooks = false;
    /** node-test: the `node --test` process (main mode, every non-node: frame is user code). */
    this.nodeTestParent = false;
    /** @type {any} */
    this.rpcWrapped = null;
    if (this.mode !== "main") {
      try {
        orig.mkdirSync(this.partsDir, { recursive: true });
      } catch {
        // appendFileSync below will fail loudly enough if this is really broken
      }
    }
  }

  currentFile() {
    if (this.mode === "node-test") return this.cfg.file || null;
    const st = /** @type {any} */ (globalThis).__vitest_worker__;
    const f = st && st.filepath;
    return typeof f === "string" && f ? f : null;
  }

  /** @param {object} rec */
  emit(rec) {
    const line = JSON.stringify(rec);
    if (this.mode === "main") {
      if (!this.mainRecords.has(line)) this.mainRecords.set(line, rec);
      return;
    }
    const file = this.currentFile();
    if (!file) {
      if (!this.pendingSet.has(line)) {
        this.pendingSet.add(line);
        this.pending.push(line);
      }
      return;
    }
    if (this.pending.length) {
      // Activity before the worker knew its test file (worker startup) is attributed to the
      // first file the worker runs. With isolate: true that is the only file.
      const lines = this.pending;
      this.pending = [];
      this.pendingSet.clear();
      for (const l of lines) this.writeLine(file, l);
    }
    this.writeLine(file, line);
  }

  /** @param {string} file @param {string} line */
  writeLine(file, line) {
    let set = this.seen.get(file);
    if (!set) {
      set = new Set();
      this.seen.set(file, set);
    }
    if (set.has(line)) return;
    set.add(line);
    const part = path.join(
      this.partsDir,
      `${sha256(file)}.${process.pid}-${workerThreads.threadId}.jsonl`,
    );
    const wasBusy = this.busy;
    this.busy = true;
    try {
      orig.appendFileSync(part, line + "\n");
    } finally {
      this.busy = wasBusy;
    }
  }

  /**
   * Classify the current call stack.
   *  - syncUser / asyncUser: a user frame (sync or async continuation) is on the stack,
   *  - internal: a Vitest/Vite (worker) or node_modules (main) frame is on the stack,
   *  - snapshot: inside a SnapshotEnvironment's `readSnapshotFile` (Vitest reads the test's
   *    snapshot files, including `toMatchFileSnapshot` targets and custom snapshot paths),
   *  - cp: inside Node's own `fs.cp` implementation (the source tree is recorded up front),
   *  - loader: the access is made by Node's module loader itself (the nearest frame that is
   *    not ours is loader code), as opposed to user code the loader is evaluating.
   * @returns {{syncUser: boolean, asyncUser: boolean, internal: boolean, snapshot: boolean, cp: boolean, loader: boolean}}
   */
  stack() {
    const E = /** @type {any} */ (Error);
    const prevLimit = E.stackTraceLimit;
    const prevPrep = E.prepareStackTrace;
    /** @type {any[]} */
    let sites = [];
    try {
      E.stackTraceLimit = STACK_LIMIT;
      E.prepareStackTrace = (/** @type {any} */ _e, /** @type {any[]} */ s) => s;
      const holder = /** @type {any} */ ({});
      E.captureStackTrace(holder);
      sites = holder.stack;
    } catch {
      sites = [];
    } finally {
      E.stackTraceLimit = prevLimit;
      E.prepareStackTrace = prevPrep;
    }
    let syncUser = false;
    let asyncUser = false;
    let internal = false;
    let snapshot = false;
    let cp = false;
    let loader = false;
    if (!Array.isArray(sites)) {
      return { syncUser: true, asyncUser: false, internal: false, snapshot: false, cp: false, loader: false };
    }
    let nearest = true;
    for (const cs of sites) {
      let f;
      try {
        f = cs.getFileName() || cs.getScriptNameOrSourceURL?.();
        const fn = cs.getFunctionName?.() || cs.getMethodName?.();
        if (fn === "readSnapshotFile") snapshot = true;
      } catch {
        f = undefined;
      }
      if (!f) continue;
      if (f.startsWith("node:")) {
        if (f.startsWith("node:internal/fs/cp/")) cp = true;
        if (nearest && f.startsWith("node:internal/modules/")) loader = true;
        nearest = false;
        continue;
      }
      if (f.startsWith("file://")) {
        try {
          f = fileURLToPath(f);
        } catch {
          // keep the URL string
        }
      }
      f = toSlash(f);
      if (f.startsWith(PKG_DIR + "/")) continue; // our own frames
      nearest = false;
      if (this.isInternalFrame(f)) {
        internal = true;
        continue;
      }
      let isAsync = false;
      try {
        isAsync = !!(cs.isAsync?.() || cs.isPromiseAll?.());
      } catch {
        isAsync = false;
      }
      if (isAsync) asyncUser = true;
      else syncUser = true;
    }
    // Truncated stack without a user frame: we cannot tell, so treat it as user activity.
    if (sites.length >= STACK_LIMIT && !syncUser && !asyncUser) syncUser = true;
    return { syncUser, asyncUser, internal, snapshot, cp, loader };
  }

  /**
   * Worker: Vitest/Vite internals. Main process: everything in node_modules (Vite, Vitest,
   * rolldown, third-party plugins) except the module Vite bundled the config file into.
   * @param {string} f '/'-normalised file of a stack frame
   */
  isInternalFrame(f) {
    // node:test runs entirely in node: internals; every other frame is user code (test files,
    // their imports, --import hooks, packages).
    if (this.mode === "node-test" || this.nodeTestParent) return false;
    if (this.mode === "main") {
      if (CONFIG_BUNDLE_RE.test(f)) return false;
      return isInNodeModules(f);
    }
    return isInternalPath(f);
  }

  /**
   * True for strict ancestors of a directory the test created with mkdtemp: stat'ing them
   * (as `fs.cp` and `mkdir -p` style code does) says nothing about the repository.
   * @param {string} abs
   */
  isSelfDirAncestor(abs) {
    const s = toSlash(abs).replace(/\/$/, "");
    for (const d of this.selfDirs) {
      if (d.startsWith(s === "" ? "/" : s + "/")) return true;
    }
    return false;
  }

  /** @param {string} abs */
  isSelfProduced(abs) {
    return this.selfFiles.has(abs) || (this.selfDirs.length > 0 && isUnder(abs, this.selfDirs));
  }

  /**
   * Decide at call time whether an fs call on `abs` should be recorded.
   * @param {string} abs
   * @param {FsKind} [kind]
   */
  shouldRecordFs(abs, kind) {
    if (this.isSelfProduced(abs)) return false;
    // node-test: Node's loader reading vci's own preloads.
    if (this.mode === "node-test" && toSlash(abs).startsWith(PKG_DIR + "/")) return false;
    if (kind !== "readdir" && this.isSelfDirAncestor(abs)) return false;
    const s = this.stack();
    // Node's fs.cp stats and reads while copying; the patched cp records the source tree.
    if (s.cp) return false;
    if (this.mode === "main") {
      if (s.loader) return false;
      if (toSlash(abs).startsWith(PKG_DIR + "/")) return false;
      return s.syncUser || s.asyncUser;
    }
    if (s.snapshot) return true;
    if (s.syncUser) return true;
    const sp = toSlash(abs);
    if (s.asyncUser) return !(isUnder(sp, this.ignoreDirs) || isInternalPath(sp));
    if (s.internal) return false;
    // Only Node-internal frames (e.g. the ESM loader resolving Vitest's own deps).
    return !(isInNodeModules(sp) || isUnder(sp, this.ignoreDirs));
  }

  /**
   * An installed package: `name@version`, unless it is a copy of a repository directory (its
   * version does not change with that directory's content).
   * @param {string} abs a file of the package
   * @param {{name: string, version: string}} pkg
   */
  emitExternal(abs, pkg) {
    let local = null;
    try {
      local = localCopyPackage(abs);
    } catch {
      local = null;
    }
    if (local) {
      this.emit({ kind: "taint", reason: `external-local-directory:${local} (a copy of a repository directory, identified only by its version)` });
    } else {
      this.emit({ kind: "external", name: pkg.name, version: pkg.version });
    }
  }

  /**
   * @param {"read" | "probe" | "readdir"} kind
   * @param {string} abs
   */
  recordPath(kind, abs) {
    abs = this.unlinked(abs);
    const pkg = packageOf(abs);
    if (pkg === undefined) {
      this.emit({ kind, path: abs });
    } else if (pkg) {
      this.emitExternal(abs, pkg);
    } else if (kind === "probe") {
      this.emit({ kind, path: abs });
    } else {
      this.emit({ kind: "taint", reason: `external-without-version:${abs}` });
    }
  }

  /**
   * node-test: a path below a linked workspace package's `node_modules` entry, as the real path
   * (repository content, not an external). Other modes: unchanged.
   * @param {string} abs
   */
  unlinked(abs) {
    if (this.mode !== "node-test") return abs;
    const wasBusy = this.busy;
    this.busy = true;
    try {
      return linkedPackagePath(abs) || abs;
    } catch {
      return abs;
    } finally {
      this.busy = wasBusy;
    }
  }

  /**
   * node-test: a path the test created, changed or removed (`write` record). The Rust side
   * refuses a file that wrote inside the repository.
   * @param {any} p
   */
  onWrite(p) {
    if (this.mode !== "node-test" || this.busy) return;
    const abs = argPath(p);
    if (!abs) return;
    this.busy = true;
    try {
      this.emit({ kind: "write", path: linkedPackagePath(abs) || abs });
    } catch {
      // never break the test because of the collector
    } finally {
      this.busy = false;
    }
  }

  /**
   * The file of the nearest stack frame that is neither Node-internal nor ours.
   * @returns {string | null}
   */
  nearestFrameFile() {
    const E = /** @type {any} */ (Error);
    const prevLimit = E.stackTraceLimit;
    const prevPrep = E.prepareStackTrace;
    try {
      E.stackTraceLimit = STACK_LIMIT;
      E.prepareStackTrace = (/** @type {any} */ _e, /** @type {any[]} */ s) => s;
      const holder = /** @type {any} */ ({});
      E.captureStackTrace(holder);
      for (const cs of holder.stack || []) {
        let f = cs.getFileName() || cs.getScriptNameOrSourceURL?.();
        if (!f || f.startsWith("node:")) continue;
        if (f.startsWith("file://")) {
          try {
            f = fileURLToPath(f);
          } catch {
            // keep the URL
          }
        }
        f = toSlash(f);
        if (f.startsWith(PKG_DIR + "/")) continue;
        return f;
      }
      return null;
    } catch {
      return null;
    } finally {
      E.stackTraceLimit = prevLimit;
      E.prepareStackTrace = prevPrep;
    }
  }

  /** @param {string} reason */
  taint(reason) {
    if (this.busy) return;
    this.busy = true;
    try {
      const s = this.stack();
      const user = s.syncUser || s.asyncUser;
      if (user || (this.mode !== "main" && !s.internal)) this.emit({ kind: "taint", reason });
    } finally {
      this.busy = false;
    }
  }

  /** @param {string} key */
  onEnv(key) {
    if (this.busy || OWN_ENV_KEYS.has(key)) return;
    this.busy = true;
    try {
      const s = this.stack();
      // Main process: Node's module loader reads its own settings while loading user code.
      if (this.mode === "main" && s.loader) return;
      if (s.syncUser || s.asyncUser) this.emit({ kind: "env", key });
    } finally {
      this.busy = false;
    }
  }

  onEnvEnumerate() {
    if (this.busy) return;
    this.busy = true;
    try {
      const s = this.stack();
      if (s.syncUser || s.asyncUser) this.emit({ kind: "taint", reason: "process.env.enumerate" });
    } finally {
      this.busy = false;
    }
  }

  /**
   * Called when the fs call starts. Returns a context for `post`, or null if not recorded.
   * @param {FsKind} kind
   * @param {any} arg first argument of the fs call
   * @param {any} [flags]
   */
  pre(kind, arg, flags) {
    if (this.busy) return null;
    if (kind === "readdir" && flags && typeof flags === "object" && flags.recursive) {
      this.taint("fs.readdir.recursive");
      return null;
    }
    const abs = argPath(arg);
    if (!abs) return null;
    if (kind === "open" && isWriteFlag(flags)) return null;
    this.busy = true;
    try {
      if (!this.shouldRecordFs(abs, kind)) return null;
      return { kind, abs };
    } catch {
      return { kind, abs };
    } finally {
      this.busy = false;
    }
  }

  /**
   * @param {{kind: FsKind, abs: string} | null} ctx
   * @param {boolean} ok
   * @param {any} value result (ok) or error (!ok)
   */
  post(ctx, ok, value) {
    if (!ctx) return;
    const wasBusy = this.busy;
    this.busy = true;
    try {
      let out;
      if (ctx.kind === "exists") {
        out = ok && value === true ? "read" : "probe";
        if (!ok) out = "read";
      } else if (ok) {
        // statSync(p, { throwIfNoEntry: false }) returns undefined for a missing path.
        if (ctx.kind === "stat" && value == null) out = "probe";
        else out = ctx.kind === "readdir" ? "readdir" : "read";
      } else {
        const code = value && value.code;
        out = code === "ENOENT" || code === "ENOTDIR" ? "probe" : ctx.kind === "readdir" ? "readdir" : "read";
      }
      this.recordPath(/** @type {any} */ (out), ctx.abs);
    } catch {
      // never break the test because of the collector
    } finally {
      this.busy = wasBusy;
    }
  }

  /** @param {any} p */
  markWritten(p) {
    const abs = argPath(p);
    if (abs) this.selfFiles.add(abs);
  }

  /** @param {any} dir */
  markTempDir(dir) {
    if (typeof dir !== "string" || !dir) return;
    this.onWrite(dir);
    const abs = toSlash(path.resolve(dir));
    this.selfDirs.push(abs);
    // Also the canonical form (os.tmpdir() is /var/... -> /private/var/... on macOS).
    const wasBusy = this.busy;
    this.busy = true;
    try {
      const real = toSlash(fs.realpathSync(abs));
      if (real !== abs) this.selfDirs.push(real);
    } catch {
      // gone already
    } finally {
      this.busy = wasBusy;
    }
  }

  /**
   * Record the current state of `abs` now: a read if something exists there (following
   * symlinks), a probe otherwise.
   * @param {string} abs
   */
  observeNow(abs) {
    const wasBusy = this.busy;
    this.busy = true;
    try {
      const st = fs.statSync(abs, { throwIfNoEntry: false });
      this.recordPath(st ? "read" : "probe", abs);
    } catch {
      this.recordPath("read", abs);
    } finally {
      this.busy = wasBusy;
    }
  }

  /**
   * Record a whole tree (the source of `fs.cp`): directories as listings, everything else as
   * reads. Symlinks are recorded as themselves (the Rust side follows them).
   * @param {string} root
   */
  recordTree(root) {
    const wasBusy = this.busy;
    this.busy = true;
    try {
      /** @type {string[]} */
      const stack = [root];
      let n = 0;
      while (stack.length) {
        const p = /** @type {string} */ (stack.pop());
        if (++n > MAX_TREE_ENTRIES) {
          this.emit({ kind: "taint", reason: `fs.cp:tree-too-large:${root}` });
          return;
        }
        if (this.isSelfProduced(p)) continue;
        const st = fs.lstatSync(p, { throwIfNoEntry: false });
        if (!st) {
          this.recordPath("probe", p);
          continue;
        }
        if (st.isDirectory()) {
          this.recordPath("readdir", p);
          if (packageOf(p) !== undefined) continue; // node_modules: the package version covers it
          for (const name of fs.readdirSync(p)) stack.push(path.join(p, name));
        } else {
          this.recordPath("read", p);
        }
      }
    } catch (e) {
      this.emit({ kind: "taint", reason: `fs.cp:unreadable-source:${String(/** @type {any} */ (e)?.code || e)}` });
    } finally {
      this.busy = wasBusy;
    }
  }

  /**
   * `fs.cp*` / `fs.link*` / `fs.symlink*`: the destination is a copy (or alias) of a source the
   * test depends on. Records the source if user code made the call.
   * @param {any} src
   * @param {"tree" | "path"} how
   */
  onCopySource(src, how) {
    if (this.busy) return;
    const abs = argPath(src);
    if (!abs) return;
    this.busy = true;
    let record = false;
    try {
      record = this.shouldRecordFs(abs, "read");
    } catch {
      record = true;
    } finally {
      this.busy = false;
    }
    if (!record) return;
    if (how === "tree") this.recordTree(abs);
    else this.observeNow(abs);
  }

  /**
   * Candidate files of a successful relative/absolute resolution: every candidate that does
   * not exist is a probe (creating it could change what resolves), every file or symlink that
   * does is a read (a symlinked module is recorded by its link path, not only its target).
   * @param {string} base absolute path of the specifier
   */
  recordCandidates(base) {
    const wasBusy = this.busy;
    this.busy = true;
    try {
      for (const cand of resolutionCandidates(base)) {
        const sp = toSlash(cand);
        if (isInNodeModules(sp) || sp.startsWith(PKG_DIR + "/") || this.isSelfProduced(cand)) continue;
        const kind = candidateKind(cand);
        if (kind) this.emit({ kind, path: cand });
      }
    } finally {
      this.busy = wasBusy;
    }
  }

  /** @param {string | null | undefined} idOrFile */
  onRunnerModule(idOrFile) {
    const p = idToFsPath(idOrFile);
    if (!p) return;
    const sp = toSlash(p);
    if (sp.startsWith(PKG_DIR + "/") || isInternalPath(sp)) return;
    const wasBusy = this.busy;
    this.busy = true;
    try {
      const pkg = packageOf(p);
      if (pkg === undefined) this.emit({ kind: "module", path: p, via: "runner" });
      else if (pkg) this.emitExternal(p, pkg);
      else this.emit({ kind: "taint", reason: `external-without-version:${p}` });
    } finally {
      this.busy = wasBusy;
    }
  }

  /**
   * @param {string | undefined} parentURL
   */
  parentIsInternal(parentURL) {
    if (!parentURL) return false;
    let p = parentURL;
    if (p.startsWith("file://")) {
      try {
        p = fileURLToPath(p);
      } catch {
        return false;
      }
    }
    p = toSlash(p);
    return p.startsWith(PKG_DIR + "/") || isInternalPath(p);
  }

  /** @param {string} url @param {string | undefined} parentURL @param {string} [spec] */
  onResolved(url, parentURL, spec) {
    if (this.busy || !url || !url.startsWith("file:")) return;
    if (this.parentIsInternal(parentURL)) return;
    if (typeof spec === "string" && parentURL && parentURL.startsWith("file:") && !isInNodeModules(toSlash(parentURL))) {
      let base = null;
      try {
        if (spec.startsWith("./") || spec.startsWith("../")) base = path.resolve(parentDir(parentURL), spec);
        else if (spec.startsWith("file:")) base = fileURLToPath(spec);
        else if (path.isAbsolute(spec)) base = spec;
      } catch {
        base = null;
      }
      if (base) this.recordCandidates(base);
    }
    let p;
    try {
      p = this.unlinked(fileURLToPath(url));
    } catch {
      return;
    }
    if (this.isSelfProduced(p)) return;
    const sp = toSlash(p);
    if (sp.startsWith(PKG_DIR + "/") || isInternalPath(sp)) return;
    this.busy = true;
    try {
      const pkg = packageOf(p);
      if (pkg === undefined) {
        this.emit({ kind: "module", path: p, via: "node-hooks" });
        if (typeof spec === "string" && isBareSpecifier(spec)) this.recordProbedBy(p);
      } else if (pkg) this.emitExternal(p, pkg);
      else this.emit({ kind: "taint", reason: `external-without-version:${p}` });
    } finally {
      this.busy = false;
    }
  }

  /**
   * A bare or aliased specifier (a workspace package without `exports`, a legacy `main`, an alias
   * resolver calling Node's own resolution) that resolved to `file` in the repository: Node may
   * have probed other files first (`X`, `X.js`, ... before `X/index.js`; the other extensions of an
   * extensionless request). Record those candidates, so that creating one is noticed.
   * @param {string} file
   */
  recordProbedBy(file) {
    const ext = path.extname(file);
    const stem = ext ? file.slice(0, -ext.length) : file;
    this.recordCandidates(stem);
    if (path.basename(stem) === "index") this.recordCandidates(path.dirname(stem));
  }

  /** @param {string} spec @param {string | undefined} parentURL */
  onResolveFail(spec, parentURL) {
    if (this.busy || typeof spec !== "string") return;
    if (this.parentIsInternal(parentURL)) return;
    let base = null;
    try {
      if (spec.startsWith("file:")) base = fileURLToPath(spec);
      else if (path.isAbsolute(spec)) base = spec;
      else if (spec.startsWith("./") || spec.startsWith("../") || spec === "." || spec === "..") {
        base = path.resolve(parentURL && parentURL.startsWith("file:") ? parentDir(parentURL) : process.cwd(), spec);
      }
    } catch {
      base = null;
    }
    if (!base) return; // bare specifiers: covered by the lockfile / package.json global inputs
    this.busy = true;
    try {
      // A candidate that exists although this resolution failed (a hook retrying with a suffix,
      // Node not trying extensions) is recorded as a read, not a probe.
      for (const c of resolutionCandidates(base)) {
        if (this.isSelfProduced(c)) continue;
        const kind = candidateKind(c);
        if (kind) this.emit({ kind, path: this.unlinked(c) });
      }
    } finally {
      this.busy = false;
    }
  }

  /** Follow the Vite module runner (called from the setup file once worker state exists). */
  attachRunner() {
    if (this.runnerAttached) return;
    const st = /** @type {any} */ (globalThis).__vitest_worker__;
    const em = st && st.evaluatedModules;
    if (!em || !em.idToModuleMap) {
      this.emit({ kind: "taint", reason: "vci:runner-modules-unavailable" });
      return;
    }
    this.runnerAttached = true;
    this.snapshotRunner();
    const self = this;
    const ensure = em.ensureModule;
    if (typeof ensure === "function") {
      em.ensureModule = function (/** @type {any[]} */ ...args) {
        const node = Reflect.apply(ensure, this, args);
        try {
          self.onRunnerModule((node && node.file) || args[0]);
        } catch {
          // ignore
        }
        return node;
      };
    } else {
      this.emit({ kind: "taint", reason: "vci:runner-hook-unavailable" });
    }
  }

  /**
   * Wrap the worker's RPC so module-runner resolution failures (e.g. a caught
   * `await import('./optional')`) become probe records. Vitest reads `state().rpc` on every call.
   */
  attachRpc() {
    const st = /** @type {any} */ (globalThis).__vitest_worker__;
    // birpc proxies answer every property with a function, so track wrapping ourselves.
    if (!st || !st.rpc || this.rpcWrapped === st.rpc) return;
    const target = st.rpc;
    const self = this;
    /** @type {Array<[string, string | undefined]>} */
    const unresolved = [];
    const root = (st.config && st.config.root) || this.cfg.root || process.cwd();
    const wrapped = new Proxy(target, {
      get(t, prop) {
        const v = Reflect.get(t, prop);
        if (prop === "resolve" && typeof v === "function") {
          return async (/** @type {any[]} */ ...args) => {
            const res = await Reflect.apply(v, t, args);
            if (!res && typeof args[0] === "string") unresolved.push([args[0], args[1]]);
            return res;
          };
        }
        if (prop === "fetch" && typeof v === "function") {
          return async (/** @type {any[]} */ ...args) => {
            try {
              return await Reflect.apply(v, t, args);
            } catch (e) {
              try {
                const misses = unresolved.splice(0, unresolved.length);
                misses.push([args[0], args[1]]);
                for (const [id, importer] of misses) self.onRunnerMiss(id, importer, root);
              } catch {
                // ignore
              }
              throw e;
            }
          };
        }
        return v;
      },
    });
    try {
      st.rpc = wrapped;
      this.rpcWrapped = wrapped;
    } catch {
      this.emit({ kind: "taint", reason: "vci:rpc-hook-unavailable" });
    }
  }

  /**
   * @param {string} id
   * @param {string | undefined | null} importer
   * @param {string} root
   */
  onRunnerMiss(id, importer, root) {
    if (typeof id !== "string") return;
    let spec = id.replace(/[?#].*$/, "");
    /** @type {string[]} */
    const bases = [];
    if (spec.startsWith("/@fs/")) spec = spec.slice(4);
    if (spec.startsWith("/@id/")) spec = spec.slice(5);
    if (spec.startsWith("file://")) {
      const p = idToFsPath(spec);
      if (p) bases.push(p);
    } else if (spec.startsWith("./") || spec.startsWith("../")) {
      const imp = idToFsPath(importer || "");
      if (imp) bases.push(path.resolve(path.dirname(imp), spec));
    } else if (spec.startsWith("/")) {
      // Vite ids starting with '/' are either already absolute under the root or root-relative.
      bases.push(toSlash(spec).startsWith(toSlash(root) + "/") ? spec : path.join(root, spec));
    }
    const wasBusy = this.busy;
    this.busy = true;
    try {
      for (const b of bases) {
        const sp = toSlash(b);
        if (isInNodeModules(sp) || sp.startsWith(PKG_DIR + "/")) continue;
        for (const c of resolutionCandidates(b)) this.emit({ kind: "probe", path: c });
      }
    } finally {
      this.busy = wasBusy;
    }
  }

  snapshotRunner() {
    const st = /** @type {any} */ (globalThis).__vitest_worker__;
    const em = st && st.evaluatedModules;
    if (!em || !em.idToModuleMap) return;
    for (const [id, node] of em.idToModuleMap) {
      if (node && (node.evaluated || node.promise || node.exports)) this.onRunnerModule(node.file || id);
    }
  }
}

/**
 * The directory a relative specifier is resolved against: the importing module's directory, or
 * the URL itself when it names a directory (`--import ./x.mjs` is resolved against
 * `file:///<cwd>/`).
 * @param {string} parentURL a file: URL
 */
function parentDir(parentURL) {
  const p = fileURLToPath(parentURL);
  return parentURL.endsWith("/") ? p : path.dirname(p);
}

/**
 * A specifier Node resolves through packages, `imports` or a custom resolver (not a path, a URL
 * or a builtin).
 * @param {string} spec
 */
function isBareSpecifier(spec) {
  return !(
    spec.startsWith("./") ||
    spec.startsWith("../") ||
    spec === "." ||
    spec === ".." ||
    path.isAbsolute(spec) ||
    /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(spec)
  );
}

/** @param {any} p */
function argPath(p) {
  try {
    if (typeof p === "string") {
      if (p.startsWith("file:")) return fileURLToPath(p);
      return path.resolve(p);
    }
    if (p instanceof URL) return p.protocol === "file:" ? fileURLToPath(p) : null;
    if (Buffer.isBuffer(p)) return path.resolve(p.toString());
  } catch {
    return null;
  }
  return null;
}

/** @param {any} flags */
function isWriteFlag(flags) {
  if (flags == null) return false;
  if (typeof flags === "number") {
    const c = fs.constants;
    return (flags & (c.O_WRONLY | c.O_RDWR | c.O_CREAT | c.O_TRUNC | c.O_APPEND)) !== 0;
  }
  return /[wa+x]/.test(String(flags));
}

/** @param {any} options writeFile options */
function isFullOverwrite(options) {
  if (options == null || typeof options === "string") return true;
  const flag = options.flag;
  return flag == null || flag === "w" || flag === "w+";
}

/**
 * @param {any} obj
 * @param {string} name
 * @param {(orig: Function) => Function} make
 */
function patch(obj, name, make) {
  if (!obj) return;
  const o = obj[name];
  if (typeof o !== "function" || o.__vci) return;
  const w = make(o);
  try {
    Object.defineProperty(w, "name", { value: o.name });
    Object.defineProperty(w, "length", { value: o.length });
  } catch {
    // ignore
  }
  for (const k of Object.keys(o)) {
    if (!(k in w)) /** @type {any} */ (w)[k] = o[k];
  }
  /** @type {any} */ (w).__vci = true;
  /** @type {any} */ (w).__vciOrig = o;
  try {
    obj[name] = w;
  } catch {
    // non-writable property: leave it
  }
}

/** @param {Collector} c */
function patchFs(c) {
  /** @type {Array<[string, FsKind]>} */
  const syncReads = [
    ["readFileSync", "read"],
    ["statSync", "stat"],
    ["lstatSync", "stat"],
    ["statfsSync", "read"],
    ["accessSync", "read"],
    ["realpathSync", "read"],
    ["readlinkSync", "read"],
    ["readdirSync", "readdir"],
    ["opendirSync", "readdir"],
  ];
  for (const [name, kind] of syncReads) {
    patch(fs, name, (o) =>
      function (/** @type {any[]} */ ...args) {
        const ctx = c.pre(kind, args[0], kind === "readdir" ? args[1] : undefined);
        let res;
        try {
          res = Reflect.apply(o, this, args);
        } catch (e) {
          c.post(ctx, false, e);
          throw e;
        }
        c.post(ctx, true, res);
        return res;
      },
    );
  }
  // realpathSync.native
  if (fs.realpathSync && typeof fs.realpathSync.native === "function") {
    patch(fs.realpathSync, "native", (o) =>
      function (/** @type {any[]} */ ...args) {
        const ctx = c.pre("read", args[0]);
        let res;
        try {
          res = Reflect.apply(o, this, args);
        } catch (e) {
          c.post(ctx, false, e);
          throw e;
        }
        c.post(ctx, true, res);
        return res;
      },
    );
  }
  patch(fs, "existsSync", (o) =>
    function (/** @type {any[]} */ ...args) {
      const ctx = c.pre("exists", args[0]);
      const res = Reflect.apply(o, this, args);
      c.post(ctx, true, res);
      return res;
    },
  );
  patch(fs, "openSync", (o) =>
    function (/** @type {any[]} */ ...args) {
      const ctx = c.pre("open", args[0], args[1]);
      let res;
      try {
        res = Reflect.apply(o, this, args);
      } catch (e) {
        c.post(ctx, false, e);
        throw e;
      }
      c.post(ctx, true, res);
      return res;
    },
  );
  patch(fs, "copyFileSync", (o) =>
    function (/** @type {any[]} */ ...args) {
      const ctx = c.pre("read", args[0]);
      let res;
      try {
        res = Reflect.apply(o, this, args);
      } catch (e) {
        c.post(ctx, false, e);
        throw e;
      }
      c.post(ctx, true, res);
      return res;
    },
  );
  patch(fs, "createReadStream", (o) =>
    function (/** @type {any[]} */ ...args) {
      const ctx = c.pre("read", args[0]);
      c.post(ctx, true, undefined);
      return Reflect.apply(o, this, args);
    },
  );

  // Callback APIs. The decision is made at call time (user frames are on the stack then).
  /** @type {Array<[string, FsKind]>} */
  const cbReads = [
    ["readFile", "read"],
    ["stat", "stat"],
    ["lstat", "stat"],
    ["statfs", "read"],
    ["access", "read"],
    ["realpath", "read"],
    ["readlink", "read"],
    ["readdir", "readdir"],
    ["opendir", "readdir"],
    ["copyFile", "read"],
    ["open", "open"],
  ];
  for (const [name, kind] of cbReads) {
    patch(fs, name, (o) =>
      function (/** @type {any[]} */ ...args) {
        const second = typeof args[1] !== "function" ? args[1] : undefined;
        const ctx = c.pre(kind, args[0], kind === "open" || kind === "readdir" ? second : undefined);
        const cbIndex = findLastFn(args);
        if (ctx && cbIndex >= 0) {
          const cb = args[cbIndex];
          args[cbIndex] = function (/** @type {any} */ err, /** @type {any[]} */ ...rest) {
            c.post(ctx, !err, err || rest[0]);
            return Reflect.apply(cb, this, [err, ...rest]);
          };
        }
        return Reflect.apply(o, this, args);
      },
    );
  }
  patch(fs, "exists", (o) =>
    function (/** @type {any[]} */ ...args) {
      const ctx = c.pre("exists", args[0]);
      const cbIndex = findLastFn(args);
      if (ctx && cbIndex >= 0) {
        const cb = args[cbIndex];
        args[cbIndex] = function (/** @type {any} */ exists) {
          c.post(ctx, true, exists === true);
          return Reflect.apply(cb, this, [exists]);
        };
      }
      return Reflect.apply(o, this, args);
    },
  );

  // Promise APIs (fs.promises === require('node:fs/promises')).
  const fsp = fs.promises;
  /** @type {Array<[string, FsKind]>} */
  const pReads = [
    ["readFile", "read"],
    ["stat", "stat"],
    ["lstat", "stat"],
    ["statfs", "read"],
    ["access", "read"],
    ["realpath", "read"],
    ["readlink", "read"],
    ["readdir", "readdir"],
    ["opendir", "readdir"],
    ["copyFile", "read"],
    ["open", "open"],
  ];
  for (const [name, kind] of pReads) {
    patch(fsp, name, (o) =>
      function (/** @type {any[]} */ ...args) {
        const ctx = c.pre(kind, args[0], kind === "open" || kind === "readdir" ? args[1] : undefined);
        const p = Reflect.apply(o, this, args);
        if (!ctx || !p || typeof p.then !== "function") return p;
        return p.then(
          (/** @type {any} */ r) => {
            c.post(ctx, true, r);
            return r;
          },
          (/** @type {any} */ e) => {
            c.post(ctx, false, e);
            throw e;
          },
        );
      },
    );
  }

  // Writes: remember files the test fully overwrote and dirs it created, so reading them back
  // is not treated as an input.
  patch(fs, "writeFileSync", (o) =>
    function (/** @type {any[]} */ ...args) {
      const res = Reflect.apply(o, this, args);
      if (isFullOverwrite(args[2])) c.markWritten(args[0]);
      return res;
    },
  );
  patch(fs, "writeFile", (o) =>
    function (/** @type {any[]} */ ...args) {
      if (isFullOverwrite(typeof args[2] === "function" ? undefined : args[2])) c.markWritten(args[0]);
      return Reflect.apply(o, this, args);
    },
  );
  patch(fsp, "writeFile", (o) =>
    function (/** @type {any[]} */ ...args) {
      if (isFullOverwrite(args[2])) c.markWritten(args[0]);
      return Reflect.apply(o, this, args);
    },
  );
  patch(fs, "mkdtempSync", (o) =>
    function (/** @type {any[]} */ ...args) {
      const res = Reflect.apply(o, this, args);
      c.markTempDir(res);
      return res;
    },
  );
  patch(fs, "mkdtemp", (o) =>
    function (/** @type {any[]} */ ...args) {
      const cbIndex = findLastFn(args);
      if (cbIndex >= 0) {
        const cb = args[cbIndex];
        args[cbIndex] = function (/** @type {any} */ err, /** @type {any} */ dir) {
          if (!err) c.markTempDir(dir);
          return Reflect.apply(cb, this, [err, dir]);
        };
      }
      return Reflect.apply(o, this, args);
    },
  );
  patch(fsp, "mkdtemp", (o) =>
    function (/** @type {any[]} */ ...args) {
      return Reflect.apply(o, this, args).then((/** @type {any} */ dir) => {
        c.markTempDir(dir);
        return dir;
      });
    },
  );

  // Reads that return a promise from the fs module itself.
  patch(fs, "openAsBlob", (o) =>
    function (/** @type {any[]} */ ...args) {
      const ctx = c.pre("read", args[0]);
      const p = Reflect.apply(o, this, args);
      if (!ctx || !p || typeof p.then !== "function") return p;
      return p.then(
        (/** @type {any} */ r) => {
          c.post(ctx, true, r);
          return r;
        },
        (/** @type {any} */ e) => {
          c.post(ctx, false, e);
          throw e;
        },
      );
    },
  );
  // Watchers react to the watched path: record it like a stat.
  for (const [obj, name] of /** @type {Array<[any, string]>} */ ([
    [fs, "watch"],
    [fs, "watchFile"],
    [fsp, "watch"],
  ])) {
    patch(obj, name, (o) =>
      function (/** @type {any[]} */ ...args) {
        const ctx = c.pre("read", args[0]);
        let res;
        try {
          res = Reflect.apply(o, this, args);
        } catch (e) {
          c.post(ctx, false, e);
          throw e;
        }
        c.post(ctx, true, res);
        return res;
      },
    );
  }

  // Copies and links into (usually temp) destinations: the destination is test-owned, so its
  // reads are not recorded; record the source instead.
  for (const [obj, name] of /** @type {Array<[any, string]>} */ ([
    [fs, "cpSync"],
    [fs, "cp"],
    [fsp, "cp"],
  ])) {
    patch(obj, name, (o) =>
      function (/** @type {any[]} */ ...args) {
        c.onCopySource(args[0], "tree");
        if (name !== "cpSync") return Reflect.apply(o, this, args);
        const wasBusy = c.busy;
        c.busy = true;
        try {
          return Reflect.apply(o, this, args);
        } finally {
          c.busy = wasBusy;
        }
      },
    );
  }
  for (const [obj, name] of /** @type {Array<[any, string]>} */ ([
    [fs, "linkSync"],
    [fs, "link"],
    [fsp, "link"],
    [fs, "renameSync"],
    [fs, "rename"],
    [fsp, "rename"],
  ])) {
    patch(obj, name, (o) =>
      function (/** @type {any[]} */ ...args) {
        c.onCopySource(args[0], "path");
        return Reflect.apply(o, this, args);
      },
    );
  }
  for (const [obj, name] of /** @type {Array<[any, string]>} */ ([
    [fs, "symlinkSync"],
    [fs, "symlink"],
    [fsp, "symlink"],
  ])) {
    patch(obj, name, (o) =>
      function (/** @type {any[]} */ ...args) {
        try {
          // A relative target is resolved against the link's directory when it is followed.
          const link = argPath(args[1]);
          const t = args[0] instanceof URL ? args[0] : Buffer.isBuffer(args[0]) ? args[0].toString() : args[0];
          if (typeof t === "string" && link && !t.startsWith("file:") && !path.isAbsolute(t)) {
            c.onCopySource(path.resolve(path.dirname(link), t), "path");
          } else {
            c.onCopySource(t, "path");
          }
        } catch {
          // never break the test because of the collector
        }
        return Reflect.apply(o, this, args);
      },
    );
  }

  // Globbing reads many directories we cannot express precisely: taint.
  for (const name of ["glob", "globSync"]) {
    patch(fs, name, (o) =>
      function (/** @type {any[]} */ ...args) {
        c.taint(`fs.${name}`);
        return Reflect.apply(o, this, args);
      },
    );
  }
  patch(fsp, "glob", (o) =>
    function (/** @type {any[]} */ ...args) {
      c.taint("fs.promises.glob");
      return Reflect.apply(o, this, args);
    },
  );
}

/**
 * Built-ins that open files in native code, bypassing the fs module.
 * @param {Collector} c
 */
function patchNativeReaders(c) {
  patch(process, "loadEnvFile", (o) =>
    function (/** @type {any[]} */ ...args) {
      const ctx = c.pre("read", args[0] === undefined ? ".env" : args[0]);
      let res;
      try {
        res = Reflect.apply(o, this, args);
      } catch (e) {
        c.post(ctx, false, e);
        throw e;
      }
      c.post(ctx, true, res);
      return res;
    },
  );
  patch(module, "findPackageJSON", (o) =>
    function (/** @type {any[]} */ ...args) {
      const res = Reflect.apply(o, this, args);
      if (typeof res === "string") c.post(c.pre("read", res), true, true);
      else c.taint("module.findPackageJSON:not-found");
      return res;
    },
  );
  // process.binding('fs') (deprecated) reads files natively, beside every fs patch.
  for (const n of ["binding", "_linkedBinding"]) {
    patch(process, n, (o) =>
      function (/** @type {any[]} */ ...args) {
        c.taint(`process.${n}:${String(args[0])}`);
        return Reflect.apply(o, this, args);
      },
    );
  }
  // node:sqlite is patched when it is first loaded (loading it early would print its
  // experimental warning on older Node versions): see registerResolveHooks and getBuiltinModule.
  patch(process, "getBuiltinModule", (o) =>
    function (/** @type {any[]} */ ...args) {
      if (typeof args[0] === "string" && /^(node:)?sqlite$/.test(args[0])) patchSqlite(c);
      return Reflect.apply(o, this, args);
    },
  );
}

/** @param {Collector} c */
function patchSqlite(c) {
  const g = /** @type {any} */ (globalThis);
  const key = Symbol.for("vci.vitest.sqlite-patched");
  if (g[key]) return;
  g[key] = true;
  const wasBusy = c.busy;
  c.busy = true;
  try {
    const getBuiltin = /** @type {any} */ (process).getBuiltinModule;
    const sqlite = getBuiltin && (getBuiltin.__vciOrig || getBuiltin)("node:sqlite");
    if (!sqlite) return;
    for (const name of ["DatabaseSync", "Database"]) {
      patchSqlStatements(c, sqlite[name] && sqlite[name].prototype);
      patch(sqlite, name, (o) => {
        const w = function (/** @type {any[]} */ ...args) {
          const p = sqliteFile(args[0]);
          if (p != null) {
            const ctx = c.pre("read", p);
            c.post(ctx, true, true);
          }
          return new.target ? Reflect.construct(o, args, new.target) : Reflect.apply(o, this, args);
        };
        Object.setPrototypeOf(w, o);
        w.prototype = o.prototype;
        return w;
      });
    }
    patch(sqlite, "backup", (o) =>
      function (/** @type {any[]} */ ...args) {
        c.taint("sqlite.backup");
        return Reflect.apply(o, this, args);
      },
    );
    module.syncBuiltinESMExports();
  } catch {
    c.emit({ kind: "taint", reason: "vci:sqlite-patch-failed" });
  } finally {
    c.busy = wasBusy;
  }
}

/** SQL that makes SQLite open another file natively (or load code). */
const SQL_FILE_RE = /\b(attach|load_extension)\b|\bvacuum\b[\s\S]*\binto\b/i;

/**
 * The file a node:sqlite database name opens, or null for an in-memory database. SQLite reads a
 * `file:` name as a URI relative to the working directory (`file:data/db.sqlite?mode=ro`).
 * @param {any} name
 * @returns {any}
 */
function sqliteFile(name) {
  if (name == null || name === "" || name === ":memory:") return null;
  if (typeof name !== "string" || !name.startsWith("file:")) return name;
  const q = name.indexOf("?");
  const query = q < 0 ? "" : name.slice(q + 1).replace(/#.*$/, "");
  if (/(^|&)mode=memory(&|$)/.test(query)) return null;
  let rest = name.slice(5).replace(/[?#].*$/, "");
  if (rest.startsWith("//")) {
    const i = rest.indexOf("/", 2);
    const host = rest.slice(2, i < 0 ? undefined : i);
    // Another host: never a file of the repository (recorded as given, outside it).
    if (host && host !== "localhost") return `//${host}/`;
    rest = i < 0 ? "/" : rest.slice(i);
  }
  try {
    rest = decodeURIComponent(rest);
  } catch {
    // keep it as written
  }
  if (rest === "" || rest === ":memory:") return null;
  return path.resolve(rest);
}

/**
 * node:sqlite statements: SQL that attaches another database (`ATTACH`), writes one (`VACUUM
 * INTO`) or loads an extension is read natively, where vci sees nothing: taint.
 * @param {Collector} c
 * @param {any} proto DatabaseSync.prototype (or Database.prototype)
 */
function patchSqlStatements(c, proto) {
  if (!proto) return;
  /** @param {any} sql */
  const check = (sql) => {
    const text = Array.isArray(sql) ? sql.join(" ") : typeof sql === "string" ? sql : "";
    const m = SQL_FILE_RE.exec(text);
    if (m) c.taint(`sqlite:${m[1] ? m[1].toLowerCase() : "vacuum-into"} (SQLite opens files the SQL names natively)`);
  };
  for (const n of ["exec", "prepare"]) {
    patch(proto, n, (o) =>
      function (/** @type {any[]} */ ...args) {
        check(args[0]);
        return Reflect.apply(o, this, args);
      },
    );
  }
  patch(proto, "loadExtension", (o) =>
    function (/** @type {any[]} */ ...args) {
      c.taint("sqlite.loadExtension");
      return Reflect.apply(o, this, args);
    },
  );
  patch(proto, "enableLoadExtension", (o) =>
    function (/** @type {any[]} */ ...args) {
      if (args[0]) c.taint("sqlite.enableLoadExtension");
      return Reflect.apply(o, this, args);
    },
  );
  patch(proto, "createTagStore", (o) =>
    function (/** @type {any[]} */ ...args) {
      const store = Reflect.apply(o, this, args);
      try {
        const sp = store && Object.getPrototypeOf(store);
        for (const n of ["get", "all", "iterate", "run"]) {
          patch(sp, n, (f) =>
            function (/** @type {any[]} */ ...a) {
              check(a[0]);
              return Reflect.apply(f, this, a);
            },
          );
        }
      } catch {
        c.taint("vci:sqlite-tag-store-unpatched");
      }
      return store;
    },
  );
}

/** @param {any[]} args */
function findLastFn(args) {
  for (let i = args.length - 1; i >= 0; i--) if (typeof args[i] === "function") return i;
  return -1;
}

/**
 * Wrap a function or class so any call marks the current test file tainted.
 * @param {Collector} c
 * @param {any} obj
 * @param {string} name
 * @param {string} reason
 */
function taintOn(c, obj, name, reason) {
  patch(obj, name, (o) => {
    const w = function (/** @type {any[]} */ ...args) {
      c.taint(reason);
      return new.target ? Reflect.construct(o, args, new.target) : Reflect.apply(o, this, args);
    };
    Object.setPrototypeOf(w, o);
    w.prototype = o.prototype;
    return w;
  });
}

/** @param {Collector} c */
function patchTaints(c) {
  for (const n of ["spawn", "spawnSync", "exec", "execSync", "execFile", "execFileSync", "fork"]) {
    taintOn(c, childProcess, n, `child_process.${n}`);
  }
  for (const n of ["connect", "createConnection", "createServer"]) taintOn(c, net, n, `net.${n}`);
  // `new net.Socket().connect()` (and net.Stream, its alias; database drivers do this) never
  // goes through net.connect.
  for (const n of ["connect"]) taintOn(c, net.Socket && net.Socket.prototype, n, `net.Socket.${n}`);
  for (const n of ["bind", "send", "connect"]) taintOn(c, dgram.Socket && dgram.Socket.prototype, n, `dgram.Socket.${n}`);
  for (const n of ["request", "get", "createServer"]) {
    taintOn(c, http, n, `http.${n}`);
    taintOn(c, https, n, `https.${n}`);
  }
  for (const n of ["connect", "createServer", "createSecureServer"]) taintOn(c, http2, n, `http2.${n}`);
  for (const n of ["connect", "createServer"]) taintOn(c, tls, n, `tls.${n}`);
  taintOn(c, dgram, "createSocket", "dgram.createSocket");
  const dnsFns = [
    "lookup", "lookupService", "resolve", "resolve4", "resolve6", "resolveAny", "resolveCname",
    "resolveMx", "resolveNs", "resolveTxt", "resolveSrv", "resolvePtr", "resolveNaptr", "resolveSoa", "reverse",
  ];
  for (const n of dnsFns) {
    taintOn(c, dns, n, `dns.${n}`);
    taintOn(c, dns.promises, n, `dns.promises.${n}`);
  }
  taintOn(c, workerThreads, "Worker", "worker_threads.Worker");
  const g = /** @type {any} */ (globalThis);
  for (const n of ["fetch", "WebSocket", "EventSource"]) {
    if (typeof g[n] === "function") taintOn(c, g, n, n);
  }
}

/** @param {Collector} c */
function proxyEnv(c) {
  if (/** @type {any} */ (process.env)[KEY]) return;
  const target = process.env;
  const handler = {
    get(/** @type {any} */ t, /** @type {string | symbol} */ k) {
      if (k === KEY) return true;
      if (typeof k === "string") c.onEnv(k);
      return t[k];
    },
    has(/** @type {any} */ t, /** @type {string | symbol} */ k) {
      if (typeof k === "string") c.onEnv(k);
      return k in t;
    },
    getOwnPropertyDescriptor(/** @type {any} */ t, /** @type {string | symbol} */ k) {
      if (typeof k === "string") c.onEnv(k);
      return Reflect.getOwnPropertyDescriptor(t, k);
    },
    ownKeys(/** @type {any} */ t) {
      c.onEnvEnumerate();
      return Reflect.ownKeys(t);
    },
    // Node's process.env rejects defineProperty with the proxy as receiver: assign directly.
    set(/** @type {any} */ t, /** @type {string | symbol} */ k, /** @type {any} */ v) {
      t[k] = v;
      return true;
    },
    defineProperty(/** @type {any} */ t, /** @type {string | symbol} */ k, /** @type {PropertyDescriptor} */ d) {
      if ("value" in d) t[k] = d.value;
      return true;
    },
    deleteProperty(/** @type {any} */ t, /** @type {string | symbol} */ k) {
      delete t[k];
      return true;
    },
  };
  try {
    process.env = new Proxy(target, handler);
  } catch {
    c.emit({ kind: "taint", reason: "vci:env-proxy-failed" });
  }
}

/**
 * @param {Collector} c
 * @param {{load?: boolean}} [opts] also follow `load` (node-test: every URL a module is loaded from)
 */
function registerResolveHooks(c, opts = {}) {
  const reg = /** @type {any} */ (module).registerHooks;
  if (typeof reg !== "function") return false;
  /** @type {any} */
  const extra = {};
  if (opts.load) {
    extra.load = function (/** @type {string} */ url, /** @type {any} */ ctx, /** @type {Function} */ next) {
      try {
        c.onResolved(url, undefined);
      } catch {
        // ignore
      }
      return next(url, ctx);
    };
  }
  try {
    reg({
      ...extra,
      resolve(/** @type {string} */ spec, /** @type {any} */ ctx, /** @type {Function} */ next) {
        if (spec === "node:sqlite" || spec === "sqlite") patchSqlite(c);
        let r;
        try {
          r = next(spec, ctx);
        } catch (e) {
          try {
            c.onResolveFail(spec, ctx && ctx.parentURL);
          } catch {
            // ignore
          }
          throw e;
        }
        try {
          c.onResolved(r && r.url, ctx && ctx.parentURL, spec);
        } catch {
          // ignore
        }
        return r;
      },
    });
    return true;
  } catch {
    return false;
  }
}

/**
 * Install the collector in this worker (idempotent across module instances).
 * @param {{preload?: boolean}} [opts]
 * @returns {Collector | null}
 */
export function install(opts = {}) {
  const g = /** @type {any} */ (globalThis);
  if (g[KEY] !== undefined) return g[KEY];
  const raw = process.env[WORKER_ENV];
  if (!raw) {
    g[KEY] = null;
    return null;
  }
  /** @type {WorkerConfig} */
  let cfg;
  try {
    cfg = JSON.parse(raw);
  } catch {
    g[KEY] = null;
    return null;
  }
  const c = new Collector(cfg, { preload: !!opts.preload });
  g[KEY] = c;
  c.busy = true;
  try {
    patchFs(c);
    patchNativeReaders(c);
    patchTaints(c);
    c.hooks = registerResolveHooks(c);
    module.syncBuiltinESMExports();
    proxyEnv(c);
  } finally {
    c.busy = false;
  }
  return c;
}

/**
 * Install the collector in the Vitest main process (from src/main/preload.js, loaded with
 * `--import` before Vitest). Inert unless VCI_OUT is set, and in Vitest workers (they inherit
 * VCI_WORKER from the main process and use the worker collector instead).
 * @returns {Collector | null}
 */
export function installMain() {
  const g = /** @type {any} */ (globalThis);
  if (g[MAIN_KEY] !== undefined) return g[MAIN_KEY];
  if (!process.env.VCI_OUT || process.env[WORKER_ENV] || !workerThreads.isMainThread) {
    g[MAIN_KEY] = null;
    return null;
  }
  const c = new Collector({ partsDir: "", ignoreDirs: [], root: process.cwd() }, { preload: true, mode: "main" });
  g[MAIN_KEY] = c;
  c.busy = true;
  try {
    patchFs(c);
    patchNativeReaders(c);
    patchTaints(c);
    module.syncBuiltinESMExports();
    proxyEnv(c);
  } finally {
    c.busy = false;
  }
  c.emit({ kind: "vci-main" });
  return c;
}

/**
 * node-test: every call that creates, changes or removes a path records a `write` (the paths at
 * the given argument indexes; for `open`, only with a write flag).
 * @param {Collector} c
 */
function patchWrites(c) {
  const fsp = fs.promises;
  /** @type {Array<[any, string, number[], number?]>} */
  const specs = [];
  /** @param {string} name @param {number[]} idx @param {number} [flagIdx] */
  const all = (name, idx, flagIdx) => {
    specs.push([fs, `${name}Sync`, idx, flagIdx], [fs, name, idx, flagIdx], [fsp, name, idx, flagIdx]);
  };
  all("appendFile", [0]);
  all("writeFile", [0]);
  all("mkdir", [0]);
  all("rm", [0]);
  all("rmdir", [0]);
  all("unlink", [0]);
  all("rename", [0, 1]);
  all("copyFile", [1]);
  all("cp", [1]);
  all("link", [1]);
  all("symlink", [1]);
  all("truncate", [0]);
  all("chmod", [0]);
  all("lchmod", [0]);
  all("chown", [0]);
  all("lchown", [0]);
  all("utimes", [0]);
  all("lutimes", [0]);
  all("open", [0], 1);
  specs.push([fs, "createWriteStream", [0]]);
  for (const [obj, name, idx, flagIdx] of specs) {
    if (!obj) continue;
    const o = obj[name];
    if (typeof o !== "function" || o.__vciW) continue;
    const w = function (/** @type {any[]} */ ...args) {
      try {
        if (flagIdx === undefined || (typeof args[flagIdx] !== "function" && isWriteFlag(args[flagIdx]))) {
          for (const i of idx) c.onWrite(args[i]);
        }
      } catch {
        // never break the test because of the collector
      }
      return Reflect.apply(o, this, args);
    };
    try {
      Object.defineProperty(w, "name", { value: o.name });
      Object.defineProperty(w, "length", { value: o.length });
    } catch {
      // ignore
    }
    for (const k of Object.keys(o)) {
      if (!(k in w)) /** @type {any} */ (w)[k] = o[k];
    }
    /** @type {any} */ (w).__vciW = true;
    try {
      obj[name] = w;
    } catch {
      // non-writable: leave it
    }
  }
}

/**
 * Packages whose `module.register` hooks are accepted (their configuration is a global input):
 * those that only strip types or map extensions. tsx, @swc-node/register and
 * @esbuild-kit/esm-loader resolve tsconfig `paths` on the hooks thread, trying targets in order
 * where vci sees no probe, so their `module.register` is refused.
 */
const LOADER_PACKAGES = new Set(["ts-node", "amaro"]);

/**
 * node-test specifics: `process.exit` from user code (the rest of the file never runs, and node:test
 * reports the file as one passing test), and `module.register` hooks, which run on another thread
 * where nothing is observed (accepted only from known TypeScript loaders).
 * @param {Collector} c
 */
function patchNodeTest(c) {
  patch(process, "exit", (o) =>
    function (/** @type {any[]} */ ...args) {
      try {
        if (!c.busy) {
          c.busy = true;
          try {
            const s = c.stack();
            if (s.syncUser || s.asyncUser) c.emit({ kind: "taint", reason: "process.exit" });
          } finally {
            c.busy = false;
          }
        }
      } catch {
        // ignore
      }
      return Reflect.apply(o, this, args);
    },
  );
  patch(module, "register", (o) =>
    function (/** @type {any[]} */ ...args) {
      try {
        const wasBusy = c.busy;
        c.busy = true;
        try {
          const from = c.nearestFrameFile();
          const pkg = from ? packageOf(from) : undefined;
          if (pkg && LOADER_PACKAGES.has(pkg.name)) {
            c.emit({ kind: "external", name: pkg.name, version: pkg.version });
          } else {
            const spec = args[0] instanceof URL ? args[0].href : String(args[0]);
            c.emit({ kind: "taint", reason: `module.register:${spec}` });
          }
        } finally {
          c.busy = wasBusy;
        }
      } catch {
        c.emit({ kind: "taint", reason: "module.register" });
      }
      return Reflect.apply(o, this, args);
    },
  );
}

/**
 * Install the collector in the process `node --test` starts for one test file (from
 * src/node-test/preload.js, loaded with `--require` before the user's preloads). Inert unless
 * VCI_OUT and VCI_TEST_FILE are set and this is a node:test child process.
 * @returns {Collector | null}
 */
export function installNodeTest() {
  const g = /** @type {any} */ (globalThis);
  if (g[KEY] !== undefined) return g[KEY];
  const out = process.env.VCI_OUT;
  const file = process.env.VCI_TEST_FILE;
  if (!out || !file || process.env.NODE_TEST_CONTEXT === undefined || !workerThreads.isMainThread) {
    g[KEY] = null;
    return null;
  }
  const c = new Collector(
    {
      partsDir: path.join(out, ".vci-parts"),
      ignoreDirs: [toSlash(out)],
      root: process.env.VCI_ROOT || process.cwd(),
      file: path.resolve(file),
    },
    { preload: true, mode: "node-test" },
  );
  g[KEY] = c;
  c.busy = true;
  try {
    patchFs(c);
    patchWrites(c);
    patchNativeReaders(c);
    patchTaints(c);
    patchNodeTest(c);
    c.hooks = registerResolveHooks(c);
    module.syncBuiltinESMExports();
    proxyEnv(c);
  } finally {
    c.busy = false;
  }
  c.emit({ kind: "vci-node-test", hooks: c.hooks, pid: process.pid });
  checkNodeTestEnv(c, true);
  return c;
}

/**
 * node-test: what reached this process through the environment rather than the command line.
 *  - NODE_OPTIONS as it is here (from vci's environment, an `--env-file`, or set by a `--require`
 *    preload of the `node --test` process): it applies before the collector, so only memory,
 *    warning and stack-trace options are accepted;
 *  - (test process) TZ: unset, ICU takes the machine's zone, which is not an input; LANG, LC_ALL
 *    and LC_MESSAGES (ICU's default locale) are recorded as read.
 * @param {Collector} c
 * @param {boolean} child
 */
function checkNodeTestEnv(c, child) {
  const env = process.env; // read while busy: not recorded as the test's reads
  const wasBusy = c.busy;
  c.busy = true;
  try {
    for (const tok of nodeOptionsProblems(env.NODE_OPTIONS)) {
      c.emit({
        kind: "taint",
        reason: `node-test:NODE_OPTIONS:${tok} (NODE_OPTIONS, from the environment, an --env-file or a preload, reaches every process before vci's collector; only memory, warning and stack-trace options are accepted there)`,
      });
    }
    if (!child) return;
    const tz = env.TZ;
    if (tz === undefined || tz === "") {
      c.emit({ kind: "taint", reason: "node-test:TZ-unset (the local time zone comes from the machine, which is not an input: set TZ, e.g. TZ=UTC, where vci runs and in CI)" });
    } else if (tz.startsWith(":") || tz.startsWith("/")) {
      c.emit({ kind: "taint", reason: `node-test:TZ-file:${tz} (a zoneinfo file is not an input)` });
    }
    for (const k of ["TZ", "LANG", "LC_ALL", "LC_MESSAGES"]) c.emit({ kind: "env", key: k });
  } finally {
    c.busy = wasBusy;
  }
}

/**
 * node-test: the `node --test` process itself also loads `--require` preloads (not `--import`
 * ones), so the user's `--require` modules run there too, before it starts the child process
 * for the test file (which inherits its environment). This records what user code does there,
 * like the Vitest main-process collector; the node:test reporter adds the records to the file.
 * @returns {Collector | null}
 */
export function installNodeTestParent() {
  const g = /** @type {any} */ (globalThis);
  if (g[MAIN_KEY] !== undefined) return g[MAIN_KEY];
  if (
    !process.env.VCI_OUT ||
    !process.env.VCI_TEST_FILE ||
    process.env.NODE_TEST_CONTEXT !== undefined ||
    !workerThreads.isMainThread
  ) {
    g[MAIN_KEY] = null;
    return null;
  }
  const c = new Collector({ partsDir: "", ignoreDirs: [], root: process.cwd() }, { preload: true, mode: "main" });
  c.nodeTestParent = true;
  g[MAIN_KEY] = c;
  c.busy = true;
  try {
    patchFs(c);
    patchNativeReaders(c);
    patchTaints(c);
    // Every module the user's preloads load here (a computed `require(path.join(...))` too).
    c.hooks = registerResolveHooks(c, { load: true });
    module.syncBuiltinESMExports();
    proxyEnv(c);
  } finally {
    c.busy = false;
  }
  c.emit({ kind: "vci-main" });
  if (!c.hooks) c.emit({ kind: "taint", reason: "vci:module-hooks-unavailable (Node 22.15 or later is needed)" });
  checkNodeTestEnv(c, false);
  return c;
}

/**
 * node-test: register a second set of hooks after the user's preloads (src/node-test/late.js).
 * Hooks registered last run first, so these see every specifier and the final result of the
 * whole chain, including resolutions and loads the user's hooks answer themselves.
 * @returns {boolean}
 */
export function installLateHooks() {
  const c = /** @type {Collector | null | undefined} */ (/** @type {any} */ (globalThis)[KEY]);
  if (!c || c.mode !== "node-test") return false;
  const ok = registerResolveHooks(c, { load: true });
  c.emit({ kind: "vci-late-hooks", ok });
  return ok;
}

/** @returns {Collector | null | undefined} the main-process collector */
export function currentMain() {
  return /** @type {any} */ (globalThis)[MAIN_KEY];
}

/** @returns {Collector | null | undefined} */
export function current() {
  return /** @type {any} */ (globalThis)[KEY];
}
