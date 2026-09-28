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
 */

class Collector {
  /** @param {WorkerConfig} cfg @param {{preload: boolean, mode?: "worker" | "main"}} opts */
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
    /** @type {any} */
    this.rpcWrapped = null;
    if (this.mode === "worker") {
      try {
        orig.mkdirSync(this.partsDir, { recursive: true });
      } catch {
        // appendFileSync below will fail loudly enough if this is really broken
      }
    }
  }

  currentFile() {
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
   * @param {"read" | "probe" | "readdir"} kind
   * @param {string} abs
   */
  recordPath(kind, abs) {
    const pkg = packageOf(abs);
    if (pkg === undefined) {
      this.emit({ kind, path: abs });
    } else if (pkg) {
      this.emit({ kind: "external", name: pkg.name, version: pkg.version });
    } else if (kind === "probe") {
      this.emit({ kind, path: abs });
    } else {
      this.emit({ kind: "taint", reason: `external-without-version:${abs}` });
    }
  }

  /** @param {string} reason */
  taint(reason) {
    if (this.busy) return;
    this.busy = true;
    try {
      const s = this.stack();
      const user = s.syncUser || s.asyncUser;
      if (user || (this.mode === "worker" && !s.internal)) this.emit({ kind: "taint", reason });
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
      else if (pkg) this.emit({ kind: "external", name: pkg.name, version: pkg.version });
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
        if (spec.startsWith("./") || spec.startsWith("../")) base = path.resolve(path.dirname(fileURLToPath(parentURL)), spec);
        else if (spec.startsWith("file:")) base = fileURLToPath(spec);
        else if (path.isAbsolute(spec)) base = spec;
      } catch {
        base = null;
      }
      if (base) this.recordCandidates(base);
    }
    let p;
    try {
      p = fileURLToPath(url);
    } catch {
      return;
    }
    if (this.isSelfProduced(p)) return;
    const sp = toSlash(p);
    if (sp.startsWith(PKG_DIR + "/") || isInternalPath(sp)) return;
    this.busy = true;
    try {
      const pkg = packageOf(p);
      if (pkg === undefined) this.emit({ kind: "module", path: p, via: "node-hooks" });
      else if (pkg) this.emit({ kind: "external", name: pkg.name, version: pkg.version });
      else this.emit({ kind: "taint", reason: `external-without-version:${p}` });
    } finally {
      this.busy = false;
    }
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
        const parent = parentURL && parentURL.startsWith("file:") ? fileURLToPath(parentURL) : path.join(process.cwd(), "x");
        base = path.resolve(path.dirname(parent), spec);
      }
    } catch {
      base = null;
    }
    if (!base) return; // bare specifiers: covered by the lockfile / package.json global inputs
    this.busy = true;
    try {
      for (const c of resolutionCandidates(base)) this.emit({ kind: "probe", path: c });
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
      patch(sqlite, name, (o) => {
        const w = function (/** @type {any[]} */ ...args) {
          const p = args[0];
          if (p != null && p !== ":memory:" && p !== "") {
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

/** @param {Collector} c */
function registerResolveHooks(c) {
  const reg = /** @type {any} */ (module).registerHooks;
  if (typeof reg !== "function") return false;
  try {
    reg({
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

/** @returns {Collector | null | undefined} the main-process collector */
export function currentMain() {
  return /** @type {any} */ (globalThis)[MAIN_KEY];
}

/** @returns {Collector | null | undefined} */
export function current() {
  return /** @type {any} */ (globalThis)[KEY];
}
