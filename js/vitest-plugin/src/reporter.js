// Main-process side: project setup (setup file, preload, attestability checks), module-graph
// collection at onTestModuleEnd, and merging of worker parts into one JSONL file per test file.

import * as fs from "node:fs";
import { createRequire } from "node:module";
import * as path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { getState } from "./state.js";
import { PACKAGE_DIR, WORKER_ENV, candidateKind, idToFsPath, packageOf, sha256, toSlash } from "./util.js";
import { currentMain } from "./worker/collector.js";

export const SETUP_FILE = fileURLToPath(new URL("./worker/setup.js", import.meta.url));
export const PRELOAD_URL = pathToFileURL(fileURLToPath(new URL("./worker/preload.js", import.meta.url))).href;
/** `--import` this in the Vitest main process (node --import <url> vitest.mjs run ...). */
export const MAIN_PRELOAD_URL = pathToFileURL(fileURLToPath(new URL("./main/preload.js", import.meta.url))).href;
export const SCAN_PLUGIN_NAME = "vci:scan";

const PKG_VERSION = (() => {
  try {
    return JSON.parse(fs.readFileSync(path.join(PACKAGE_DIR, "package.json"), "utf8")).version;
  } catch {
    return "unknown";
  }
})();

const KIND_ORDER = /** @type {Record<string, number>} */ ({
  module: 1,
  external: 2,
  read: 3,
  probe: 4,
  readdir: 5,
  env: 6,
  taint: 7,
});

/**
 * Configure one Vitest project for collection. Idempotent.
 * @param {any} project TestProject
 * @param {any} vitest Vitest
 * @param {import("./state.js").MainState} state
 */
export function setupProject(project, vitest, state) {
  if (!state.outDir || !project || state.projects.has(project)) return;
  /** Records added to every test file of this project: taints, and paths it depends on. */
  /** @type {Array<{kind: "taint", reason: string} | {kind: "path", path: string}>} */
  const recs = [];
  const taint = (/** @type {string} */ reason) => recs.push({ kind: "taint", reason });
  const cfg = project.config || {};
  if (cfg.isolate === false) taint("isolate:false");
  const pool = cfg.pool;
  if (typeof pool !== "string") taint("pool:custom");
  else if (pool !== "forks" && pool !== "threads") taint(`pool:${pool}`);
  if (cfg.browser && cfg.browser.enabled) taint("pool:browser");
  if (cfg.experimental && cfg.experimental.viteModuleRunner === false) taint("native-runner");
  if (cfg.fsModuleCache || (cfg.experimental && cfg.experimental.fsModuleCache)) taint("fs-module-cache");
  if (cfg.typecheck && cfg.typecheck.enabled) taint("typecheck");
  if (cfg.snapshotOptions && cfg.snapshotOptions.updateSnapshot === "all") taint("snapshot:update-all");
  try {
    const plugins = (project.vite && project.vite.config && project.vite.config.plugins) || [];
    if (!plugins.some((/** @type {any} */ p) => p && p.name === SCAN_PLUGIN_NAME)) {
      taint("vci:plugin-not-in-project");
    }
  } catch {
    taint("vci:plugin-not-in-project");
  }

  try {
    if (!Array.isArray(cfg.setupFiles)) cfg.setupFiles = cfg.setupFiles ? [cfg.setupFiles] : [];
    if (!cfg.setupFiles.includes(SETUP_FILE)) cfg.setupFiles.unshift(SETUP_FILE);
  } catch {
    taint("vci:setup-file-injection-failed");
  }
  try {
    if (!Array.isArray(cfg.execArgv)) cfg.execArgv = [];
    if (!cfg.execArgv.includes(PRELOAD_URL)) cfg.execArgv.push("--import", PRELOAD_URL);
  } catch {
    // setup file still installs the collector; missing preload is checked per file
  }

  for (const d of [
    project.tmpDir,
    vitest && vitest._tmpDir,
    project.vite && project.vite.config && project.vite.config.cacheDir,
    state.outDir,
  ]) {
    if (typeof d === "string" && d) {
      state.ignoreDirs.add(toSlash(d));
      try {
        state.ignoreDirs.add(toSlash(fs.realpathSync(d)));
      } catch {
        // may not exist yet
      }
    }
  }
  // Vite loads .env files in the main process and exposes them through import.meta.env.
  try {
    const vc = project.vite && project.vite.config;
    if (vc && vc.envDir !== false) {
      const envDir = vc.envDir || vc.root || cfg.root;
      const mode = vc.mode || "test";
      if (typeof envDir === "string") {
        for (const n of [".env", ".env.local", `.env.${mode}`, `.env.${mode}.local`]) recs.push({ kind: "path", path: path.join(envDir, n) });
      }
    }
  } catch {
    taint("vci:env-files-unknown");
  }
  process.env[WORKER_ENV] = JSON.stringify({
    partsDir: state.partsDir,
    ignoreDirs: [...state.ignoreDirs],
    root: vitest && vitest.config ? vitest.config.root : cfg.root,
  });
  state.projects.set(project, recs);
}

/**
 * Walk a directory tree for recursive glob dependencies.
 * @param {string} dir
 * @param {(kind: string, p: string) => void} add
 */
function listDirs(dir, add) {
  /** @type {string[]} */
  const stack = [dir];
  let count = 0;
  while (stack.length) {
    const d = /** @type {string} */ (stack.pop());
    let entries;
    try {
      entries = fs.readdirSync(d, { withFileTypes: true });
    } catch (e) {
      const code = /** @type {any} */ (e).code;
      add(code === "ENOENT" || code === "ENOTDIR" ? "probe" : "readdir", d);
      continue;
    }
    add("readdir", d);
    if (++count > 10000) {
      add("taint", `vci:directory-tree-too-large:${dir}`);
      return;
    }
    for (const e of entries) {
      if (e.isDirectory() && e.name !== "node_modules" && e.name !== ".git") stack.push(path.join(d, e.name));
    }
  }
}

/**
 * @typedef {object} FileEntry
 * @property {string} moduleId
 * @property {string} projectName
 * @property {any} project
 * @property {Map<string, object>} records  JSON line -> record
 * @property {object | null} result
 * @property {Set<string>} modulePaths  source module paths seen (for scan/miss derivation)
 */

export class VciReporter {
  /** @param {{outDir?: string}} [options] */
  constructor(options = {}) {
    this.state = getState(options);
    /** @type {any} */
    this.vitest = null;
    /** @type {Map<string, FileEntry>} */
    this.files = new Map();
    this.meta = { vitest: "unknown", vite: "unknown" };
    this.snapshotUnobservable = false;
  }

  /** @param {any} vitest */
  onInit(vitest) {
    this.vitest = vitest;
    const st = this.state;
    if (!st.outDir) return;
    try {
      fs.rmSync(/** @type {string} */ (st.partsDir), { recursive: true, force: true });
      fs.mkdirSync(/** @type {string} */ (st.partsDir), { recursive: true });
    } catch {
      // the reporter taints files that end up without worker data
    }
    for (const project of vitest.projects || []) setupProject(project, vitest, st);
    this.meta.vitest = vitest.version || "unknown";
    this.meta.vite = viteVersion(vitest.config && vitest.config.root);
    // Snapshot writes make a file non-attestable.
    try {
      const snap = vitest.snapshot;
      if (snap && typeof snap.add === "function" && !snap.add.__vci) {
        const origAdd = snap.add;
        const wrapped = function (/** @type {any} */ result) {
          try {
            if (result && (result.added || result.updated || result.fileDeleted)) {
              if (typeof result.filepath === "string") st.snapshotWrites.add(result.filepath);
              else st.snapshotWriteUnattributed = true;
            }
          } catch {
            st.snapshotWriteUnattributed = true;
          }
          return origAdd.call(this, result);
        };
        wrapped.__vci = true;
        snap.add = wrapped;
      }
    } catch {
      // cannot observe snapshot writes: be conservative
      this.snapshotUnobservable = true;
    }
  }

  onTestRunStart() {
    this.files.clear();
    this.state.snapshotWrites.clear();
    this.state.snapshotWriteUnattributed = false;
  }

  /** @param {any} testModule */
  fileEntry(testModule) {
    const moduleId = testModule.moduleId;
    const projectName = (testModule.project && testModule.project.name) || "";
    let entry = this.files.get(moduleId);
    if (!entry) {
      entry = {
        moduleId,
        projectName,
        project: testModule.project,
        records: new Map(),
        result: null,
        modulePaths: new Set(),
      };
      this.files.set(moduleId, entry);
    } else if (entry.projectName !== projectName) {
      addRecord(entry, { kind: "taint", reason: "vci:test-file-in-multiple-projects" });
    }
    return entry;
  }

  /** @param {any} testModule */
  onTestModuleEnd(testModule) {
    if (!this.state.outDir) return;
    const entry = this.fileEntry(testModule);
    try {
      this.collectGraph(entry, testModule);
    } catch (e) {
      addRecord(entry, { kind: "taint", reason: `vci:graph-error:${String(/** @type {any} */ (e)?.message || e)}` });
    }
    try {
      entry.result = resultOf(testModule);
    } catch {
      entry.result = { kind: "result", state: "failed", tests: 0, failed: 0, skipped: 0, durationMs: 0 };
      addRecord(entry, { kind: "taint", reason: "vci:result-unavailable" });
    }
    const projectRecs = this.state.projects.get(testModule.project) || [{ kind: "taint", reason: "vci:project-not-set-up" }];
    for (const r of projectRecs) addRecord(entry, r.kind === "path" ? dirRecord(r.path) : r);
    try {
      const pool = testModule.task && testModule.task.pool;
      if (typeof pool === "string" && pool !== "forks" && pool !== "threads") {
        addRecord(entry, { kind: "taint", reason: `pool:${pool}` });
      }
    } catch {
      // ignore
    }
  }

  /**
   * @param {FileEntry} entry
   * @param {any} testModule
   */
  collectGraph(entry, testModule) {
    const project = testModule.project;
    const envs = (project && project.vite && project.vite.environments) || {};
    const roots = [testModule.moduleId];
    for (const f of (project && project.config && project.config.setupFiles) || []) {
      if (f !== SETUP_FILE) roots.push(f);
    }
    let found = false;
    const seen = new Set();
    for (const name of Object.keys(envs)) {
      const graph = envs[name] && envs[name].moduleGraph;
      if (!graph) continue;
      /** @type {any[]} */
      const queue = [];
      for (const r of roots) {
        const byId = graph.getModuleById && graph.getModuleById(r);
        if (byId) queue.push(byId);
        const byFile = graph.getModulesByFile && graph.getModulesByFile(r);
        if (byFile) queue.push(...byFile);
      }
      if (queue.some((n) => n && (n.id === testModule.moduleId || n.file === testModule.moduleId))) found = true;
      while (queue.length) {
        const node = queue.pop();
        if (!node || seen.has(node)) continue;
        seen.add(node);
        this.addModule(entry, node.file || node.id, "vite-graph");
        if (node.importedModules) for (const child of node.importedModules) queue.push(child);
      }
    }
    if (!found) addRecord(entry, { kind: "taint", reason: "vci:test-module-not-in-graph" });
    this.collectMainRunner(entry, project);
  }

  /**
   * Modules evaluated in the main process by the project's module runner: globalSetup files and
   * everything they import (Vitest loads them with `project.runner.import`). They run before any
   * test file, so they are dependencies of every test file of the project. The root project's
   * globalSetup runs for every project.
   * @param {FileEntry} entry
   * @param {any} project
   */
  collectMainRunner(entry, project) {
    const projects = [project];
    try {
      const rootProject = this.vitest && typeof this.vitest.getRootProject === "function" ? this.vitest.getRootProject() : null;
      if (rootProject && rootProject !== project) projects.push(rootProject);
    } catch {
      // no root project API: the project's own runner is still walked
    }
    for (const p of projects) {
      const files = toArray(p && p.config && p.config.globalSetup);
      for (const f of files) if (typeof f === "string") this.addModule(entry, f, "runner");
      let map = null;
      try {
        const em = p && p.runner && p.runner.evaluatedModules;
        map = em && em.idToModuleMap;
      } catch {
        map = null;
      }
      if (!map || typeof map.entries !== "function") {
        if (files.length) addRecord(entry, { kind: "taint", reason: "vci:global-setup-modules-unavailable" });
        continue;
      }
      for (const [id, node] of map) this.addModule(entry, (node && node.file) || id, "runner");
    }
  }

  /**
   * @param {FileEntry} entry
   * @param {string} idOrFile
   * @param {string} via
   */
  addModule(entry, idOrFile, via) {
    const p = idToFsPath(idOrFile);
    if (!p) return;
    const sp = toSlash(p);
    if (sp.startsWith(toSlash(PACKAGE_DIR) + "/")) return;
    const pkg = packageOf(p);
    if (pkg === undefined) {
      addRecord(entry, { kind: "module", path: p, via });
      entry.modulePaths.add(p);
    } else if (pkg) {
      addRecord(entry, { kind: "external", name: pkg.name, version: pkg.version });
    } else {
      addRecord(entry, { kind: "taint", reason: `external-without-version:${p}` });
    }
  }

  /**
   * @param {ReadonlyArray<any>} _testModules
   * @param {ReadonlyArray<any>} unhandledErrors
   * @param {string} reason
   */
  async onTestRunEnd(_testModules, unhandledErrors, reason) {
    const st = this.state;
    if (!st.outDir) return;
    const parts = readParts(/** @type {string} */ (st.partsDir));
    fs.mkdirSync(st.outDir, { recursive: true });
    const root = (this.vitest && this.vitest.config && this.vitest.config.root) || process.cwd();
    for (const entry of this.files.values()) {
      const fileParts = parts.get(sha256(entry.moduleId)) || [];
      let sawWorker = false;
      for (const rec of fileParts) {
        if (rec.kind === "vci-worker") {
          sawWorker = true;
          if (!rec.preload) {
            const userSetup = ((entry.project && entry.project.config && entry.project.config.setupFiles) || []).filter(
              (/** @type {string} */ f) => f !== SETUP_FILE,
            );
            if (userSetup.length) addRecord(entry, { kind: "taint", reason: "vci:preload-inactive-with-setup-files" });
          }
          continue;
        }
        if (rec.kind === "module" && typeof rec.path === "string") entry.modulePaths.add(rec.path);
        if (rec.kind === "result" || rec.kind === "meta") continue;
        addRecord(entry, rec);
      }
      if (!sawWorker) addRecord(entry, { kind: "taint", reason: "vci:worker-collector-missing" });
      // Main-process activity (config, plugins, globalSetup) belongs to every test file.
      const main = currentMain();
      if (!main) addRecord(entry, { kind: "taint", reason: "vci:main-collector-missing" });
      else {
        for (const rec of main.mainRecords.values()) {
          if (/** @type {any} */ (rec).kind !== "vci-main") addRecord(entry, rec);
        }
      }
      // Directory listings behind glob / computed imports, and failed resolutions.
      for (const mp of [...entry.modulePaths]) {
        const scan = st.scans.get(mp);
        if (scan) {
          for (const d of scan.dirs) {
            if (d.recursive) listDirs(d.dir, (kind, p) => addRecord(entry, kind === "taint" ? { kind, reason: p } : { kind, path: p }));
            else addRecord(entry, dirRecord(d.dir));
          }
          for (const t of scan.taints) addRecord(entry, { kind: "taint", reason: t });
        }
        const miss = st.misses.get(mp);
        if (miss) for (const c of miss) addRecord(entry, { kind: "probe", path: c });
        const cands = st.resolves.get(mp);
        if (cands) {
          for (const c of cands) {
            const kind = candidateKind(c);
            if (kind) addRecord(entry, { kind, path: c });
          }
        }
      }
      if (st.snapshotWrites.has(entry.moduleId)) addRecord(entry, { kind: "taint", reason: "snapshot:written" });
      if (st.snapshotWriteUnattributed || this.snapshotUnobservable) {
        addRecord(entry, { kind: "taint", reason: "snapshot:write-unattributed" });
      }
      if (unhandledErrors && unhandledErrors.length) addRecord(entry, { kind: "taint", reason: "run:unhandled-errors" });
      if (reason === "interrupted") addRecord(entry, { kind: "taint", reason: "run:interrupted" });
      writeEntry(st.outDir, root, entry, this.meta);
    }
    // Unattributed snapshot writes (path we could not map) taint every file above; clean up parts.
    try {
      fs.rmSync(/** @type {string} */ (st.partsDir), { recursive: true, force: true });
    } catch {
      // ignore
    }
  }
}

/** @param {any} v */
function toArray(v) {
  return v == null ? [] : Array.isArray(v) ? v : [v];
}

/**
 * Record for a path the run depends on: listing for directories, content for files, absence otherwise.
 * @param {string} dir
 */
function dirRecord(dir) {
  try {
    const s = fs.statSync(dir);
    return s.isDirectory() ? { kind: "readdir", path: dir } : { kind: "read", path: dir };
  } catch {
    return { kind: "probe", path: dir };
  }
}

/**
 * @param {FileEntry} entry
 * @param {any} rec
 */
function addRecord(entry, rec) {
  const line = JSON.stringify(rec);
  if (!entry.records.has(line)) entry.records.set(line, rec);
}

/** @param {any} testModule */
function resultOf(testModule) {
  let tests = 0;
  let failed = 0;
  let skipped = 0;
  for (const t of testModule.children.allTests()) {
    tests++;
    const s = t.result().state;
    if (s === "failed") failed++;
    else if (s === "skipped") skipped++;
  }
  let state = testModule.state();
  const errors = typeof testModule.errors === "function" ? testModule.errors() : [];
  if (errors && errors.length) state = "failed";
  if (state !== "passed" && state !== "failed" && state !== "skipped") state = "failed";
  const d = typeof testModule.diagnostic === "function" ? testModule.diagnostic() : null;
  return {
    kind: "result",
    state,
    tests,
    failed,
    skipped,
    durationMs: Math.max(0, Math.round((d && d.duration) || 0)),
  };
}

/**
 * @param {string} partsDir
 * @returns {Map<string, any[]>} sha256(abs test path) -> records
 */
function readParts(partsDir) {
  /** @type {Map<string, any[]>} */
  const out = new Map();
  let names = [];
  try {
    names = fs.readdirSync(partsDir);
  } catch {
    return out;
  }
  for (const name of names) {
    const m = /^([0-9a-f]{64})\..*\.jsonl$/.exec(name);
    if (!m) continue;
    let text = "";
    try {
      text = fs.readFileSync(path.join(partsDir, name), "utf8");
    } catch {
      continue;
    }
    let list = out.get(m[1]);
    if (!list) {
      list = [];
      out.set(m[1], list);
    }
    for (const line of text.split("\n")) {
      if (!line.trim()) continue;
      try {
        list.push(JSON.parse(line));
      } catch {
        list.push({ kind: "taint", reason: "vci:corrupt-worker-record" });
      }
    }
  }
  return out;
}

/**
 * @param {string} outDir
 * @param {string} root
 * @param {FileEntry} entry
 * @param {{vitest: string, vite: string}} meta
 */
function writeEntry(outDir, root, entry, meta) {
  const testId = toSlash(path.relative(root, entry.moduleId));
  const lines = [
    JSON.stringify({
      v: 1,
      kind: "meta",
      testId,
      project: entry.projectName,
      vitest: meta.vitest,
      vite: meta.vite,
      node: process.versions.node,
      root,
      collector: `@vci/vitest@${PKG_VERSION}`,
    }),
  ];
  const recs = [...entry.records.entries()].sort((a, b) => {
    const ka = KIND_ORDER[/** @type {any} */ (a[1]).kind] || 99;
    const kb = KIND_ORDER[/** @type {any} */ (b[1]).kind] || 99;
    return ka - kb || (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0);
  });
  // One module record per path; prefer the Vite graph as `via`, then the runner, then Node hooks.
  const VIA_ORDER = ["vite-graph", "runner", "node-hooks"];
  /** @type {Map<string, any>} */
  const modules = new Map();
  for (const [line, rec] of recs) {
    const r = /** @type {any} */ (rec);
    if (r.kind !== "module") {
      lines.push(line);
      continue;
    }
    const prev = modules.get(r.path);
    if (!prev || VIA_ORDER.indexOf(r.via) < VIA_ORDER.indexOf(prev.via)) modules.set(r.path, r);
  }
  const moduleLines = [...modules.values()]
    .sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0))
    .map((r) => JSON.stringify({ kind: "module", path: r.path, via: r.via }));
  lines.splice(1, 0, ...moduleLines);
  lines.push(
    JSON.stringify(entry.result || { kind: "result", state: "failed", tests: 0, failed: 0, skipped: 0, durationMs: 0 }),
  );
  const file = path.join(outDir, `${sha256(testId)}.jsonl`);
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, lines.join("\n") + "\n");
  fs.renameSync(tmp, file);
}

/** @param {string | undefined} root */
function viteVersion(root) {
  const tries = [];
  if (root) tries.push(path.join(root, "package.json"));
  try {
    const r = createRequire(path.join(root || process.cwd(), "package.json"));
    tries.push(r.resolve("vitest/package.json"));
  } catch {
    // ignore
  }
  for (const from of tries) {
    try {
      const req = createRequire(from);
      const pj = req.resolve("vite/package.json");
      return JSON.parse(fs.readFileSync(pj, "utf8")).version;
    } catch {
      // try next
    }
  }
  return "unknown";
}
