// node:test reporter for vci (`--test-reporter=<this file>`), running in the `node --test` process
// that vci starts for one test file. It counts the file's tests from the runner's events, merges
// the records the collector wrote in the child process, and writes
// `$VCI_OUT/<sha256(testId)>.jsonl` (meta first, result last; see docs/CONTRACTS.md).
//
// Result rules (anything unexpected is a taint or a non-passing state, never a pass):
//  - `passed` needs the per-file `test:summary` (node:test emits none when the file has no test, or
//    when the child exited before the runner finished, e.g. `process.exit()` inside a test), at
//    least one test, no failure anywhere (a test, a suite, or the file itself: load errors,
//    `process.exitCode`, asynchronous activity after a test ended), nothing cancelled, and counts
//    that agree with the summary;
//  - a skipped or todo test or suite (`{ skip }`, `t.skip()`, `describe.skip`, `test.todo`) is
//    counted in `skipped`, which makes the result non-attestable on the Rust side;
//  - a test that uses `only` taints the file (node:test reports it in a diagnostic).

import * as fs from "node:fs";
import * as path from "node:path";

import { PACKAGE_DIR, nodeOptionsProblems, sha256, toSlash } from "../util.js";
import { currentMain } from "../worker/collector.js";

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
  write: 6,
  env: 7,
  taint: 8,
});

/** @param {string} p */
function canonical(p) {
  try {
    return toSlash(fs.realpathSync(p));
  } catch {
    return toSlash(path.resolve(p));
  }
}

/**
 * @param {string} partsDir
 * @param {string} key sha256 of the test file path
 * @returns {any[]}
 */
function readParts(partsDir, key) {
  /** @type {any[]} */
  const out = [];
  let names = [];
  try {
    names = fs.readdirSync(partsDir);
  } catch {
    return out;
  }
  for (const name of names) {
    if (!name.startsWith(`${key}.`) || !name.endsWith(".jsonl")) continue;
    let text = "";
    try {
      text = fs.readFileSync(path.join(partsDir, name), "utf8");
    } catch {
      out.push({ kind: "taint", reason: "vci:unreadable-collector-record" });
      continue;
    }
    for (const line of text.split("\n")) {
      if (!line.trim()) continue;
      try {
        out.push(JSON.parse(line));
      } catch {
        out.push({ kind: "taint", reason: "vci:corrupt-collector-record" });
      }
    }
  }
  return out;
}

/**
 * The reporter. Yields nothing (vci sends its destination to a scratch file; the human-readable
 * `spec` reporter runs beside it).
 * @param {AsyncIterable<any>} source
 */
export default async function* vciNodeTestReporter(source) {
  const outDir = process.env.VCI_OUT;
  const fileEnv = process.env.VCI_TEST_FILE;
  const root = process.env.VCI_ROOT || process.cwd();
  const file = fileEnv ? path.resolve(fileEnv) : "";
  const fileCanon = file ? canonical(file) : "";
  const cwd = process.cwd();

  /** @type {Set<string>} */
  const taints = new Set();
  let tests = 0;
  let passed = 0;
  let failed = 0;
  let skipped = 0;
  let todo = 0;
  let fileFailed = false;
  let fileLevelEvents = 0;
  /** @type {any} */
  let summary = null;
  let durationMs = 0;

  /** @param {any} d */
  const isOurFile = (d) => {
    if (!d || typeof d.file !== "string") return true;
    return d.file === file || canonical(d.file) === fileCanon;
  };
  /** @param {any} d */
  const isFileLevel = (d) =>
    d.nesting === 0 &&
    typeof d.name === "string" &&
    (d.name === file || path.resolve(cwd, d.name) === file || canonical(path.resolve(cwd, d.name)) === fileCanon);

  for await (const ev of source) {
    const d = ev && ev.data;
    try {
      switch (ev.type) {
        case "test:pass":
        case "test:fail": {
          if (!isOurFile(d)) {
            taints.add(`vci:unexpected-test-file:${d.file}`);
            break;
          }
          const fail = ev.type === "test:fail";
          if (isFileLevel(d) && (!d.details || d.details.type !== "suite")) {
            fileLevelEvents++;
            if (fail) fileFailed = true;
            break;
          }
          const isSuite = d.details && d.details.type === "suite";
          if (d.skip !== undefined && d.skip !== false) skipped++;
          if (d.todo !== undefined && d.todo !== false) todo++;
          if (fail) failed++;
          if (!isSuite) {
            tests++;
            if (!fail && !(d.skip !== undefined && d.skip !== false) && !(d.todo !== undefined && d.todo !== false)) passed++;
          }
          break;
        }
        case "test:diagnostic": {
          // node:test says so when a test uses `only` without --test-only (vci refuses that
          // option): every test still runs in Node 22 to 26, but the file asks for a filtered
          // run, which a later Node or a plain `--test-only` run would honour.
          const msg = d && typeof d.message === "string" ? d.message : "";
          if (isOurFile(d) && msg.includes("'only'") && msg.includes("--test-only")) {
            taints.add("node-test:only (a test uses `only`: the file asks for a filtered run)");
          }
          break;
        }
        case "test:summary": {
          if (d && typeof d.file === "string") {
            if (!isOurFile(d)) taints.add(`vci:unexpected-test-file:${d.file}`);
            else if (summary) taints.add("vci:duplicate-file-summary");
            else summary = d;
          } else if (d && typeof d.duration_ms === "number") {
            durationMs = Math.max(durationMs, Math.round(d.duration_ms));
          }
          break;
        }
        default:
          break;
      }
    } catch (e) {
      taints.add(`vci:reporter-error:${String(/** @type {any} */ (e)?.message || e)}`);
    }
  }

  if (!outDir || !file) return;
  /** @type {Map<string, any>} */
  const records = new Map();
  /** @param {any} r */
  const add = (r) => {
    const line = JSON.stringify(r);
    if (!records.has(line)) records.set(line, r);
  };
  let sawCollector = false;
  let sawLate = false;
  for (const rec of readParts(path.join(outDir, ".vci-parts"), sha256(file))) {
    if (rec.kind === "vci-node-test") {
      sawCollector = true;
      if (!rec.hooks) add({ kind: "taint", reason: "vci:module-hooks-unavailable (Node 22.15 or later is needed)" });
      continue;
    }
    if (rec.kind === "vci-late-hooks") {
      sawLate = true;
      if (!rec.ok) add({ kind: "taint", reason: "vci:module-hooks-unavailable" });
      continue;
    }
    add(rec);
  }
  if (!sawCollector) add({ kind: "taint", reason: "vci:collector-missing" });
  // What user code (`--require` preloads) did in this process before the child started.
  const main = currentMain();
  if (!main) add({ kind: "taint", reason: "vci:parent-collector-missing" });
  else {
    for (const rec of main.mainRecords.values()) {
      if (/** @type {any} */ (rec).kind !== "vci-main") add(rec);
    }
  }
  if (!sawLate) add({ kind: "taint", reason: "vci:late-hooks-missing" });
  // NODE_OPTIONS as this process handed it to the file's process (a preload may have set it after
  // the collector looked, and the file's process may have removed it before its collector did).
  for (const tok of nodeOptionsProblems(process.env.NODE_OPTIONS)) {
    add({
      kind: "taint",
      reason: `node-test:NODE_OPTIONS:${tok} (NODE_OPTIONS, from the environment, an --env-file or a preload, reaches every process before vci's collector; only memory, warning and stack-trace options are accepted there)`,
    });
  }
  for (const t of taints) add({ kind: "taint", reason: t });
  // The test file itself (its resolution also records it; this keeps it even if hooks missed it).
  add({ kind: "module", path: file });

  const counts = summary && summary.counts ? summary.counts : null;
  let state = "passed";
  if (fileFailed || failed > 0 || (counts && (counts.failed > 0 || counts.cancelled > 0))) {
    state = "failed";
  } else if (!counts) {
    // No per-file summary: the file declared no test, or its process ended before the runner
    // finished (process.exit in a test): what it reported cannot be trusted.
    state = tests === 0 && fileLevelEvents > 0 ? "no-tests" : "failed";
    if (tests > 0) add({ kind: "taint", reason: "node-test:no-file-summary (the test process ended before node:test finished)" });
  } else if (tests === 0) {
    state = "no-tests";
  }
  if (counts) {
    const cSkipped = (counts.skipped || 0) + (counts.todo || 0);
    if (counts.passed !== passed || counts.tests !== tests) {
      add({ kind: "taint", reason: `node-test:count-mismatch (events: ${tests} tests, ${passed} passed; summary: ${counts.tests} tests, ${counts.passed} passed)` });
    }
    skipped = Math.max(skipped + todo, cSkipped);
  } else {
    skipped += todo;
  }
  if (summary && typeof summary.duration_ms === "number") durationMs = Math.round(summary.duration_ms);

  const testId = toSlash(path.relative(root, file));
  const meta = {
    v: 1,
    kind: "meta",
    adapter: "node-test",
    testId,
    project: "",
    node: process.versions.node,
    root,
    collector: `@vci/vitest@${PKG_VERSION}`,
  };
  const sorted = [...records.entries()].sort((a, b) => {
    const ka = KIND_ORDER[a[1].kind] || 99;
    const kb = KIND_ORDER[b[1].kind] || 99;
    return ka - kb || (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0);
  });
  const lines = [JSON.stringify(meta)];
  /** @type {Set<string>} */
  const modules = new Set();
  for (const [line, rec] of sorted) {
    if (rec.kind !== "module") {
      lines.push(line);
    } else if (typeof rec.path === "string" && !modules.has(rec.path)) {
      modules.add(rec.path);
      lines.push(JSON.stringify({ kind: "module", path: rec.path, via: "node-hooks" }));
    }
  }
  lines.push(
    JSON.stringify({
      kind: "result",
      state,
      tests,
      failed: Math.max(failed, counts ? counts.failed + counts.cancelled : 0) + (fileFailed ? 1 : 0),
      skipped,
      durationMs: Math.max(0, durationMs),
      todo,
    }),
  );
  fs.mkdirSync(outDir, { recursive: true });
  const out = path.join(outDir, `${sha256(testId)}.jsonl`);
  const tmp = `${out}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, lines.join("\n") + "\n");
  fs.renameSync(tmp, out);
}
