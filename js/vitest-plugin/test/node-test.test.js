// The node:test collector (src/node-test/): runs throwaway copies of fixtures/node-test-abcd
// the way the vci adapter does, one `node --test` process per file:
//   node --require <preload> <flags> --import <late> --test-reporter=<reporter> --test <file>

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";
import { test } from "node:test";
import { pathToFileURL } from "node:url";

import { PKG_DIR, readOut, tmpDir } from "./helpers.js";

const NT = path.join(PKG_DIR, "src/node-test");
const FIXTURE = path.resolve(PKG_DIR, "../../fixtures/node-test-abcd");
const MS = path.resolve(PKG_DIR, "../../fixtures/vitest-abcd/node_modules/ms");
const FLAGS = ["--experimental-strip-types", "--import=./test/register-hooks.mjs"];

/**
 * A copy of the fixture with node_modules/ms, plus extra files.
 * @param {Record<string, string>} [files]
 */
function makeProject(files = {}) {
  const dir = tmpDir("vci-nt-");
  for (const name of ["src", "fixtures", "test", "package.json", "package-lock.json"]) {
    fs.cpSync(path.join(FIXTURE, name), path.join(dir, name), { recursive: true });
  }
  fs.mkdirSync(path.join(dir, "node_modules"));
  fs.cpSync(MS, path.join(dir, "node_modules/ms"), { recursive: true });
  for (const [rel, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), content);
  }
  return dir;
}

/** @param {string} p */
function escapeGlob(p) {
  return p.replace(/[*?[\]()]/g, (c) => `[${c}]`);
}

/**
 * Run one test file with the collectors, like the adapter (TZ=UTC unless `unset` names it).
 * @param {string} project
 * @param {string} rel
 * @param {{flags?: string[], env?: Record<string, string>, unset?: string[]}} [opts]
 */
function runFile(project, rel, opts = {}) {
  const outDir = tmpDir("vci-nt-out-");
  const abs = path.join(project, rel);
  const env = { ...process.env, NODE_ENV: "test", NO_COLOR: "1", TZ: "UTC", ...(opts.env ?? {}) };
  delete env.NODE_TEST_CONTEXT;
  delete env.NODE_OPTIONS;
  for (const k of opts.unset ?? []) delete env[k];
  env.VCI_OUT = outDir;
  env.VCI_TEST_FILE = abs;
  env.VCI_ROOT = project;
  const r = spawnSync(
    process.execPath,
    [
      "--require",
      path.join(NT, "preload.cjs"),
      ...(opts.flags ?? FLAGS),
      "--import",
      pathToFileURL(path.join(NT, "late.js")).href,
      `--test-reporter=${pathToFileURL(path.join(NT, "reporter.js")).href}`,
      `--test-reporter-destination=${path.join(outDir, "reporter.out")}`,
      "--test-reporter=spec",
      "--test-reporter-destination=stderr",
      "--test",
      escapeGlob(abs),
    ],
    { cwd: project, env, encoding: "utf8", timeout: 60_000 },
  );
  const byTest = readOut(outDir);
  const recs = byTest.get(rel);
  return { status: r.status, output: `${r.stdout}\n${r.stderr}`, recs: recs ?? [], outDir };
}

/** @param {any[]} recs @param {string} kind */
const paths = (recs, kind) => new Set(recs.filter((r) => r.kind === kind).map((r) => r.path));
/** @param {any[]} recs */
const taints = (recs) => recs.filter((r) => r.kind === "taint").map((r) => r.reason);
/** @param {any[]} recs */
const result = (recs) => recs.find((r) => r.kind === "result");

test("fixture: modules, reads, probes and externals per file", () => {
  const p = makeProject();
  const a = runFile(p, "src/a.test.ts");
  assert.equal(a.status, 0, a.output);
  assert.equal(a.recs[0].adapter, "node-test");
  assert.equal(a.recs[0].node, process.versions.node);
  assert.deepEqual(result(a.recs), { kind: "result", state: "passed", tests: 1, failed: 0, skipped: 0, durationMs: result(a.recs).durationMs, todo: 0 });
  assert.deepEqual(taints(a.recs), []);
  const am = paths(a.recs, "module");
  assert.ok(am.has(path.join(p, "src/a.ts")), [...am].join("\n"));
  assert.ok(am.has(path.join(p, "test/register-hooks.mjs")));
  assert.ok(!am.has(path.join(p, "src/b.mjs")));
  for (const r of a.recs) {
    if (typeof r.path === "string") assert.ok(r.path.startsWith(p + "/"), `outside the project: ${JSON.stringify(r)}`);
  }

  const b = runFile(p, "src/b.test.mjs");
  assert.equal(result(b.recs).state, "passed");
  assert.ok(paths(b.recs, "read").has(path.join(p, "fixtures/b.json")));
  assert.ok(paths(b.recs, "probe").has(path.join(p, "fixtures/b.local.json")));

  // C: an extensionless import resolved by the user's hook (it tries .ts first), and a computed
  // dynamic import.
  const c = runFile(p, "src/c.test.mjs");
  assert.equal(result(c.recs).state, "passed", c.output);
  assert.ok(paths(c.recs, "module").has(path.join(p, "src/impl-x.mjs")));
  assert.ok(paths(c.recs, "module").has(path.join(p, "src/c.mjs")));
  assert.ok(paths(c.recs, "probe").has(path.join(p, "src/c.ts")), "the hook's first candidate");
  assert.ok(!paths(c.recs, "probe").has(path.join(p, "src/c.mjs")), "an existing file is never a probe");

  const d = runFile(p, "src/d.test.mjs");
  assert.ok(d.recs.some((r) => r.kind === "external" && r.name === "ms" && r.version === "2.1.3"));
  assert.ok(![...paths(d.recs, "read")].some((x) => x.includes("node_modules")));
});

test("skip, todo, only, failures, process.exit and no tests are not passes", () => {
  const p = makeProject({
    "src/skip.test.mjs": "import { test } from 'node:test';\ntest('a', () => {});\ntest('b', { skip: true }, () => {});\n",
    "src/rtskip.test.mjs": "import { test } from 'node:test';\ntest('a', (t) => { t.skip('later'); });\n",
    "src/todo.test.mjs": "import { test } from 'node:test';\ntest('a', () => {});\ntest.todo('b');\n",
    "src/suite.test.mjs": "import { describe, it } from 'node:test';\ndescribe.skip('s', () => { it('x', () => {}); });\nit('y', () => {});\n",
    "src/only.test.mjs": "import { test } from 'node:test';\ntest.only('a', () => {});\ntest('b', () => {});\n",
    "src/fail.test.mjs": "import assert from 'node:assert';\nimport { test } from 'node:test';\ntest('a', () => { assert.equal(1, 2); });\n",
    "src/exit.test.mjs": "import { test } from 'node:test';\ntest('a', () => {});\ntest('b', () => { process.exit(0); });\ntest('c', () => {});\n",
    "src/exitcode.test.mjs": "import { test } from 'node:test';\ntest('a', () => { process.exitCode = 3; });\n",
    "src/late.test.mjs": "import { test } from 'node:test';\ntest('a', () => { setTimeout(() => { throw new Error('late'); }, 5); });\ntest('b', async () => { await new Promise((r) => setTimeout(r, 30)); });\n",
    "src/none.test.mjs": "export const x = 1;\n",
    "src/loaderr.test.mjs": "import { test } from 'node:test';\nimport './missing.mjs';\ntest('a', () => {});\n",
  });
  const skipped = (/** @type {string} */ f) => {
    const r = result(runFile(p, f).recs);
    assert.ok(r.skipped > 0, `${f}: ${JSON.stringify(r)}`);
  };
  skipped("src/skip.test.mjs");
  skipped("src/rtskip.test.mjs");
  skipped("src/todo.test.mjs");
  skipped("src/suite.test.mjs");
  // `.only` without --test-only (vci refuses that flag) filters nothing in Node 22 to 26, but the
  // file asks for a filtered run: tainted.
  const onlyRun = runFile(p, "src/only.test.mjs");
  const only = result(onlyRun.recs);
  assert.deepEqual([only.state, only.tests, only.skipped], ["passed", 2, 0]);
  assert.ok(taints(onlyRun.recs).some((t) => t.startsWith("node-test:only")), JSON.stringify(taints(onlyRun.recs)));
  for (const f of ["src/fail.test.mjs", "src/exitcode.test.mjs", "src/late.test.mjs", "src/loaderr.test.mjs"]) {
    const r = runFile(p, f);
    assert.equal(result(r.recs).state, "failed", `${f}: ${JSON.stringify(result(r.recs))}`);
    assert.notEqual(r.status, 0);
  }
  const ex = runFile(p, "src/exit.test.mjs");
  assert.notEqual(result(ex.recs).state, "passed", JSON.stringify(ex.recs));
  assert.ok(taints(ex.recs).includes("process.exit"), JSON.stringify(taints(ex.recs)));
  assert.equal(result(runFile(p, "src/none.test.mjs").recs).state, "no-tests");
});

test("taints: child processes, network, workers, module.register, env enumeration", () => {
  const p = makeProject({
    "src/spawn.test.mjs": "import { test } from 'node:test';\nimport { execFileSync } from 'node:child_process';\ntest('a', () => { execFileSync(process.execPath, ['-e', '1']); });\n",
    "src/fetch.test.mjs": "import { test } from 'node:test';\ntest('a', async () => { await fetch('http://127.0.0.1:9').catch(() => {}); });\n",
    "src/worker.test.mjs": "import { test } from 'node:test';\nimport { Worker } from 'node:worker_threads';\ntest('a', async () => { const w = new Worker('1', { eval: true }); await new Promise((r) => w.on('exit', r)); });\n",
    "src/register.test.mjs": "import { test } from 'node:test';\nimport { register } from 'node:module';\nregister('data:text/javascript,export async function resolve(s, c, n) { return n(s, c); }');\ntest('a', () => {});\n",
    "src/envall.test.mjs": "import { test } from 'node:test';\ntest('a', () => { Object.keys(process.env); });\n",
  });
  const expect = (/** @type {string} */ f, /** @type {string} */ prefix) => {
    const t = taints(runFile(p, f).recs);
    assert.ok(t.some((x) => x.startsWith(prefix)), `${f}: ${JSON.stringify(t)}`);
  };
  expect("src/spawn.test.mjs", "child_process.");
  expect("src/fetch.test.mjs", "fetch");
  expect("src/worker.test.mjs", "worker_threads.Worker");
  expect("src/register.test.mjs", "module.register:");
  expect("src/envall.test.mjs", "process.env.enumerate");
});

test("writes, env reads, env files and snapshot files are recorded", () => {
  const p = makeProject({
    "src/write.test.mjs":
      "import { test } from 'node:test';\nimport fs from 'node:fs';\nimport os from 'node:os';\nimport path from 'node:path';\n" +
      "test('a', () => {\n  fs.writeFileSync(new URL('../out.txt', import.meta.url), 'x');\n  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'nt-'));\n  fs.writeFileSync(path.join(d, 'f'), 'y');\n  fs.readFileSync(path.join(d, 'f'));\n  fs.rmSync(d, { recursive: true });\n});\n",
    "src/env.test.mjs": "import assert from 'node:assert';\nimport { test } from 'node:test';\ntest('a', () => { assert.equal(process.env.GREETING_VAR ?? 'unset', 'unset'); });\n",
    "src/envfile.test.mjs": "import assert from 'node:assert';\nimport { test } from 'node:test';\ntest('a', () => { assert.equal(process.env.FROM_ENV_FILE, 'yes'); });\n",
    "src/snap.test.mjs": "import { test } from 'node:test';\ntest('a', (t) => { t.assert.snapshot({ a: 1 }); });\n",
    "src/snap.test.mjs.snapshot": "exports[`a 1`] = `\n{\n  \"a\": 1\n}\n`;\n",
    ".env.test": "FROM_ENV_FILE=yes\n",
  });
  const w = runFile(p, "src/write.test.mjs");
  const writes = paths(w.recs, "write");
  assert.ok(writes.has(path.join(p, "out.txt")), JSON.stringify([...writes]));
  assert.ok(![...paths(w.recs, "read")].some((x) => x.includes("/nt-")), "files the test made itself are not inputs");
  const e = runFile(p, "src/env.test.mjs");
  assert.ok(e.recs.some((r) => r.kind === "env" && r.key === "GREETING_VAR"));
  const ef = runFile(p, "src/envfile.test.mjs", { flags: [...FLAGS, "--env-file=.env.test"] });
  assert.equal(result(ef.recs).state, "passed", ef.output);
  assert.ok(ef.recs.some((r) => r.kind === "env" && r.key === "FROM_ENV_FILE"));
  const s = runFile(p, "src/snap.test.mjs");
  assert.equal(result(s.recs).state, "passed", s.output);
  assert.ok(paths(s.recs, "read").has(path.join(p, "src/snap.test.mjs.snapshot")), JSON.stringify(s.recs));
});

test("mock.module and t.mock work under the collector", () => {
  const p = makeProject({
    "src/mock.test.mjs":
      "import assert from 'node:assert/strict';\nimport { mock, test } from 'node:test';\n" +
      "mock.module('./b.mjs', { namedExports: { loadGreeting: () => 'mocked' } });\n" +
      "test('a', async (t) => {\n  const { loadGreeting } = await import('./b.mjs');\n  assert.equal(loadGreeting(), 'mocked');\n" +
      "  const f = t.mock.fn(() => 1);\n  assert.equal(f(), 1);\n  const { minute } = await import('./d.mjs');\n  assert.equal(minute(), 60000);\n});\n",
  });
  const r = runFile(p, "src/mock.test.mjs", { flags: [...FLAGS, "--experimental-test-module-mocks"] });
  assert.equal(result(r.recs).state, "passed", r.output);
  assert.deepEqual(taints(r.recs), []);
  // The mocked module's file is still an input (over-approximation), the real one too.
  assert.ok(paths(r.recs, "module").has(path.join(p, "src/b.mjs")), JSON.stringify(r.recs));
  assert.ok(paths(r.recs, "module").has(path.join(p, "src/d.mjs")));
});

test("a linked workspace package is repository content, not an external", () => {
  const p = makeProject({
    "packages/lib/package.json": JSON.stringify({ name: "@fx/lib", version: "0.0.0", type: "module", exports: "./index.mjs" }),
    "packages/lib/index.mjs": "export const shout = (s) => s.toUpperCase();\n",
    "src/ws.test.mjs": "import assert from 'node:assert';\nimport { test } from 'node:test';\nimport { shout } from '@fx/lib';\ntest('a', () => { assert.equal(shout('x'), 'X'); });\n",
  });
  fs.mkdirSync(path.join(p, "node_modules/@fx"), { recursive: true });
  fs.symlinkSync("../../packages/lib", path.join(p, "node_modules/@fx/lib"), "dir");
  // --preserve-symlinks keeps the node_modules path: still recorded at the real path.
  for (const flags of [FLAGS, [...FLAGS, "--preserve-symlinks"]]) {
    const r = runFile(p, "src/ws.test.mjs", { flags });
    assert.equal(result(r.recs).state, "passed", r.output);
    assert.ok(paths(r.recs, "module").has(path.join(p, "packages/lib/index.mjs")), JSON.stringify(r.recs));
    assert.ok(!r.recs.some((x) => x.kind === "external" && x.name === "@fx/lib"), JSON.stringify(r.recs));
  }
});

test("what a --require preload does in the node --test process is recorded", () => {
  const p = makeProject({
    "test/setup.cjs": "const fs = require('node:fs');\nif (!process.env.NODE_TEST_CONTEXT) process.env.FROM_PARENT = fs.readFileSync(require('node:path').join(__dirname, 'parent.txt'), 'utf8');\n",
    "test/parent.txt": "p",
    "src/parent.test.mjs": "import assert from 'node:assert';\nimport { test } from 'node:test';\ntest('a', () => { assert.equal(process.env.FROM_PARENT, 'p'); });\n",
  });
  const r = runFile(p, "src/parent.test.mjs", { flags: [...FLAGS, "--require", "./test/setup.cjs"] });
  assert.equal(result(r.recs).state, "passed", r.output);
  assert.ok(paths(r.recs, "read").has(path.join(p, "test/parent.txt")), JSON.stringify(r.recs));
  assert.deepEqual(taints(r.recs), []);
});

test("list.js lists what node --test would run", () => {
  const p = makeProject({ "src/test/helper.js": "", "node_modules/x/a.test.js": "" });
  /** @param {string[]} args @param {string[]} [flags] */
  const list = (args, flags = []) =>
    spawnSync(process.execPath, [...flags, "--no-warnings", path.join(NT, "list.js"), p, ...args], { encoding: "utf8" });
  const r = list(["src/**/*.test.ts", "src/**/*.test.mjs"]);
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(
    JSON.parse(r.stdout).files.map((/** @type {string} */ f) => path.relative(p, f)),
    ["src/a.test.ts", "src/b.test.mjs", "src/c.test.mjs", "src/d.test.mjs"],
  );
  // Default patterns: test/**/* files too, node_modules never; .ts only with type stripping.
  const d = list([]);
  const files = JSON.parse(d.stdout).files.map((/** @type {string} */ f) => path.relative(p, f));
  assert.ok(files.includes("src/test/helper.js") && files.includes("src/a.test.ts"), files.join(" "));
  assert.ok(!files.some((/** @type {string} */ f) => f.startsWith("node_modules")));
  const noTs = list([], ["--no-experimental-strip-types"]);
  assert.ok(!JSON.parse(noTs.stdout).files.some((/** @type {string} */ f) => f.endsWith(".ts")));
  assert.equal(list(["src"]).status, 2, "a directory pattern is refused");
  assert.equal(list(["src/missing.test.mjs"]).status, 1, "node:test's 'Could not find'");
});

// ---------------------------------------------------------------------------------------------
// Regressions from the node:test adapter review (each failed before its fix).

const GOOD_BAD =
  "import assert from 'node:assert';\nimport { test } from 'node:test';\ntest('good', () => {});\ntest('bad', () => { assert.fail('bad'); });\n";

test("NODE_OPTIONS from an --env-file is checked like the environment variable", () => {
  const p = makeProject({
    ".env.filter": "NODE_OPTIONS=--test-name-pattern=good\n",
    ".env.early": "NODE_OPTIONS=--require=./early.cjs\n",
    ".env.mem": "NODE_OPTIONS=--max-old-space-size=4096\n",
    "early.cjs": "globalThis.V = 1;\n",
    "src/x.test.mjs": GOOD_BAD,
    "src/v.test.mjs": "import assert from 'node:assert';\nimport { test } from 'node:test';\ntest('v', () => { assert.equal(globalThis.V, 1); });\n",
    "src/ok.test.mjs": "import { test } from 'node:test';\ntest('ok', () => {});\n",
  });
  // The filter hides the failing test: whatever the result says, the file is tainted.
  const f = runFile(p, "src/x.test.mjs", { flags: [...FLAGS, "--env-file=.env.filter"] });
  assert.ok(taints(f.recs).some((t) => t.startsWith("node-test:NODE_OPTIONS:--test-name-pattern=good")), JSON.stringify(f.recs));
  const e = runFile(p, "src/v.test.mjs", { flags: [...FLAGS, "--env-file=.env.early"] });
  assert.equal(result(e.recs).state, "passed", e.output);
  assert.ok(taints(e.recs).some((t) => t.startsWith("node-test:NODE_OPTIONS:--require=./early.cjs")), JSON.stringify(e.recs));
  // Memory options are fine there, as in the environment.
  const m = runFile(p, "src/ok.test.mjs", { flags: [...FLAGS, "--env-file=.env.mem"] });
  assert.equal(result(m.recs).state, "passed", m.output);
  assert.deepEqual(taints(m.recs), []);
});

test("the node --test process: computed requires are modules, NODE_OPTIONS it sets is checked", () => {
  const p = makeProject({
    "test/setup.cjs":
      "const path = require('node:path');\nif (!process.env.NODE_TEST_CONTEXT) process.env.APP_SEED = String(require(path.join(__dirname, 'seed.cjs')).seed);\n",
    "test/seed.cjs": "module.exports = { seed: 1 };\n",
    "test/setopts.cjs":
      "const path = require('node:path');\nif (!process.env.NODE_TEST_CONTEXT) process.env.NODE_OPTIONS = `--require=${path.join(__dirname, 'lib', 'early.cjs')}`;\n",
    "test/lib/early.cjs": "globalThis.V = 1;\n",
    "src/seed.test.mjs": "import assert from 'node:assert';\nimport { test } from 'node:test';\ntest('a', () => { assert.equal(process.env.APP_SEED, '1'); });\n",
    "src/v.test.mjs": "import assert from 'node:assert';\nimport { test } from 'node:test';\ntest('v', () => { assert.equal(globalThis.V, 1); });\n",
  });
  const s = runFile(p, "src/seed.test.mjs", { flags: [...FLAGS, "--require", "./test/setup.cjs"] });
  assert.equal(result(s.recs).state, "passed", s.output);
  assert.ok(paths(s.recs, "module").has(path.join(p, "test/seed.cjs")), JSON.stringify(s.recs));
  const o = runFile(p, "src/v.test.mjs", { flags: [...FLAGS, "--require", "./test/setopts.cjs"] });
  assert.equal(result(o.recs).state, "passed", o.output);
  assert.ok(taints(o.recs).some((t) => t.startsWith("node-test:NODE_OPTIONS:--require=")), JSON.stringify(o.recs));
});

test("bare and aliased specifiers that Node resolves into the repository record what it probed", () => {
  const p = makeProject({
    // A workspace package without `exports`: `@fx/lib/util` probes util, util.js, ... util/index.js.
    "packages/lib/package.json": JSON.stringify({ name: "@fx/lib", version: "0.0.0" }),
    "packages/lib/util/index.js": "module.exports = { v: 1 };\n",
    "src/ws.test.cjs": "const assert = require('node:assert');\nconst { test } = require('node:test');\ntest('a', () => { assert.equal(require('@fx/lib/util').v, 1); });\n",
    // A linked package with a legacy `main` naming a directory, imported from ESM.
    "vendor/pkg/package.json": JSON.stringify({ name: "pkg", version: "1.0.0", main: "lib" }),
    "vendor/pkg/lib/index.js": "module.exports = { v: 1 };\n",
    "src/main.test.mjs": "import assert from 'node:assert';\nimport { test } from 'node:test';\nimport pkg from 'pkg';\ntest('a', () => { assert.equal(pkg.v, 1); });\n",
    // A module-alias style resolver: `@lib/*` -> src/lib/* through Module._resolveFilename.
    "test/alias.cjs":
      "const Module = require('node:module');\nconst path = require('node:path');\nconst orig = Module._resolveFilename;\n" +
      "Module._resolveFilename = function (req, ...rest) {\n  if (req.startsWith('@lib/')) req = path.join(__dirname, '../src/lib', req.slice(5));\n  return orig.call(this, req, ...rest);\n};\n",
    "src/lib/package.json": JSON.stringify({ type: "commonjs" }),
    "src/lib/thing/index.js": "module.exports = { v: 1 };\n",
    "src/alias.test.cjs": "const assert = require('node:assert');\nconst { test } = require('node:test');\ntest('a', () => { assert.equal(require('@lib/thing').v, 1); });\n",
  });
  fs.mkdirSync(path.join(p, "node_modules/@fx"), { recursive: true });
  fs.symlinkSync("../../packages/lib", path.join(p, "node_modules/@fx/lib"), "dir");
  fs.symlinkSync("../vendor/pkg", path.join(p, "node_modules/pkg"), "dir");
  const ws = runFile(p, "src/ws.test.cjs");
  assert.equal(result(ws.recs).state, "passed", ws.output);
  assert.ok(paths(ws.recs, "probe").has(path.join(p, "packages/lib/util.js")), JSON.stringify(ws.recs));
  const m = runFile(p, "src/main.test.mjs");
  assert.equal(result(m.recs).state, "passed", m.output);
  assert.ok(paths(m.recs, "probe").has(path.join(p, "vendor/pkg/lib.js")), JSON.stringify(m.recs));
  const a = runFile(p, "src/alias.test.cjs", { flags: [...FLAGS, "--require", "./test/alias.cjs"] });
  assert.equal(result(a.recs).state, "passed", a.output);
  assert.ok(paths(a.recs, "probe").has(path.join(p, "src/lib/thing.js")), JSON.stringify(a.recs));
});

test("packages copied from a directory of the repository (pnpm file:, npm install-links) are refused", () => {
  const lib = { "package.json": JSON.stringify({ name: "lib", version: "1.0.0" }), "index.js": "module.exports = { v: 1 };\n" };
  const p = makeProject({
    "lib/package.json": lib["package.json"],
    "lib/index.js": lib["index.js"],
    "src/pf.test.cjs": "const assert = require('node:assert');\nconst { test } = require('node:test');\ntest('a', () => { assert.equal(require('lib').v, 1); });\n",
  });
  // pnpm: node_modules/lib -> .pnpm/lib@file+lib/node_modules/lib, a copy.
  const store = path.join(p, "node_modules/.pnpm/lib@file+lib/node_modules/lib");
  fs.mkdirSync(store, { recursive: true });
  for (const [n, c] of Object.entries(lib)) fs.writeFileSync(path.join(store, n), c);
  fs.symlinkSync(".pnpm/lib@file+lib/node_modules/lib", path.join(p, "node_modules/lib"), "dir");
  const r = runFile(p, "src/pf.test.cjs");
  assert.equal(result(r.recs).state, "passed", r.output);
  assert.ok(taints(r.recs).some((t) => t.startsWith("external-local-directory:lib")), JSON.stringify(r.recs));
  // npm with install-links (or yarn 1): a plain copy, declared `file:` in package.json.
  const q = makeProject({ "src/pf.test.cjs": "const assert = require('node:assert');\nconst { test } = require('node:test');\ntest('a', () => { assert.equal(require('lib').v, 1); });\n" });
  const pj = JSON.parse(fs.readFileSync(path.join(q, "package.json"), "utf8"));
  pj.dependencies.lib = "file:./lib";
  fs.writeFileSync(path.join(q, "package.json"), JSON.stringify(pj));
  fs.mkdirSync(path.join(q, "node_modules/lib"));
  for (const [n, c] of Object.entries(lib)) fs.writeFileSync(path.join(q, "node_modules/lib", n), c);
  const s = runFile(q, "src/pf.test.cjs");
  assert.ok(taints(s.recs).some((t) => t.startsWith("external-local-directory:lib")), JSON.stringify(s.recs));
});

test("sqlite: ATTACH, VACUUM INTO and extensions are refused; file: URIs are read relative to the cwd", () => {
  const pre = "import assert from 'node:assert';\nimport { test } from 'node:test';\nimport { DatabaseSync } from 'node:sqlite';\n";
  const p = makeProject({
    "src/q1.test.mjs": pre + "test('a', () => { const db = new DatabaseSync(':memory:'); db.exec(\"ATTACH 'data/db.sqlite' AS o\"); });\n",
    "src/q3.test.mjs": pre + "test('a', () => { const db = new DatabaseSync(':memory:'); db.prepare('attach ? as o').run('data/db.sqlite'); });\n",
    "src/tag.test.mjs": pre + "test('a', () => { const db = new DatabaseSync(':memory:'); const sql = db.createTagStore(); sql.run`ATTACH ${'data/db.sqlite'} AS o`; });\n",
    "src/ext.test.mjs": pre + "test('a', () => { const db = new DatabaseSync(':memory:', { allowExtension: true }); try { db.loadExtension('./nope'); } catch {} });\n",
    "src/q4.test.mjs": pre + "test('a', () => { const db = new DatabaseSync('file:data/db.sqlite?mode=ro'); db.close(); });\n",
    "src/plain.test.mjs": pre + "test('a', () => { const db = new DatabaseSync(':memory:'); db.exec('create table t(v)'); db.prepare('insert into t values (1)').run(); });\n",
  });
  fs.mkdirSync(path.join(p, "data"));
  const mk = spawnSync(process.execPath, ["-e", "const {DatabaseSync}=require('node:sqlite');const d=new DatabaseSync('data/db.sqlite');d.exec('create table t(v)');d.close();"], { cwd: p });
  assert.equal(mk.status, 0, String(mk.stderr));
  for (const [f, prefix] of [["src/q1.test.mjs", "sqlite:"], ["src/q3.test.mjs", "sqlite:"], ["src/tag.test.mjs", "sqlite:"], ["src/ext.test.mjs", "sqlite."]]) {
    const r = runFile(p, f);
    assert.ok(taints(r.recs).some((t) => t.startsWith(prefix)), `${f}: ${JSON.stringify(taints(r.recs))}\n${r.output}`);
  }
  const u = runFile(p, "src/q4.test.mjs");
  assert.equal(result(u.recs).state, "passed", u.output);
  assert.ok(paths(u.recs, "read").has(path.join(p, "data/db.sqlite")), JSON.stringify(u.recs));
  assert.deepEqual(taints(u.recs), []);
  const plain = runFile(p, "src/plain.test.mjs");
  assert.deepEqual(taints(plain.recs), []);
});

test("process.binding is refused", () => {
  const p = makeProject({
    "d2/bind.txt": "one",
    "src/binding.test.mjs":
      "import assert from 'node:assert';\nimport { test } from 'node:test';\nimport path from 'node:path';\n" +
      "test('a', () => { const b = process.binding('fs'); assert.ok(b); });\n",
  });
  const r = runFile(p, "src/binding.test.mjs");
  assert.ok(taints(r.recs).some((t) => t.startsWith("process.binding:fs")), JSON.stringify(r.recs) + r.output);
});

test("an unset TZ (the machine's zone) is refused; locale variables are inputs", () => {
  const p = makeProject({ "src/ok.test.mjs": "import { test } from 'node:test';\ntest('ok', () => {});\n" });
  const r = runFile(p, "src/ok.test.mjs", { unset: ["TZ"] });
  assert.equal(result(r.recs).state, "passed", r.output);
  assert.ok(taints(r.recs).some((t) => t.startsWith("node-test:TZ")), JSON.stringify(r.recs));
  const s = runFile(p, "src/ok.test.mjs", { env: { TZ: "UTC" } });
  assert.deepEqual(taints(s.recs), []);
  for (const k of ["LANG", "LC_ALL", "LC_MESSAGES"]) assert.ok(s.recs.some((x) => x.kind === "env" && x.key === k), k);
});

test("module.register from TypeScript loaders that resolve off-thread (tsx) is refused", () => {
  const p = makeProject({
    "node_modules/tsx/package.json": JSON.stringify({ name: "tsx", version: "4.23.0", type: "module", exports: { ".": "./index.mjs" } }),
    "node_modules/tsx/index.mjs": "import { register } from 'node:module';\nregister('data:text/javascript,export async function resolve(s, c, n) { return n(s, c); }');\n",
    "src/ok.test.mjs": "import { test } from 'node:test';\ntest('ok', () => {});\n",
  });
  const r = runFile(p, "src/ok.test.mjs", { flags: [...FLAGS, "--import", "tsx"] });
  assert.equal(result(r.recs).state, "passed", r.output);
  assert.ok(taints(r.recs).some((t) => t.startsWith("module.register:")), JSON.stringify(r.recs));
});
