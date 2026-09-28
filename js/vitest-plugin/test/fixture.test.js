// End-to-end tests: run the real fixture (and throwaway variants of it) through the wrapper
// config and check the JSONL records written per test file.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import { describe, test } from "node:test";

import { FIXTURE, makeProject, ofKind, runVitest } from "./helpers.js";

/** @param {any[]} recs @param {string} p */
const hasModule = (recs, p) => ofKind(recs, "module").some((r) => r.path === p);
/** @param {any[]} recs @param {string} p */
const hasRead = (recs, p) => ofKind(recs, "read").some((r) => r.path === p);
/** @param {any[]} recs @param {string} p */
const hasProbe = (recs, p) => ofKind(recs, "probe").some((r) => r.path === p);
/** @param {any[]} recs @param {string} p */
const mentions = (recs, p) => recs.some((r) => r.path === p || (typeof r.path === "string" && r.path.endsWith(p)));
/** @param {any[]} recs */
const taints = (recs) => ofKind(recs, "taint").map((r) => r.reason);

/**
 * @param {import("./helpers.js").RunResult} run
 * @param {string} id
 */
function recordsOf(run, id) {
  const recs = run.byTest.get(id);
  assert.ok(recs, `no records for ${id}; got ${[...run.byTest.keys()].join(", ")}\n${run.output}`);
  return recs;
}

describe("fixture vitest-abcd (in place, wrapper in a temp dir)", () => {
  const root = FIXTURE;
  const run = runVitest(root);

  test("vitest succeeds and writes one file per test file named sha256(testId).jsonl", () => {
    assert.equal(run.status, 0, run.output);
    for (const id of ["src/a.test.ts", "src/b.test.ts", "src/c.test.ts", "src/d.test.ts"]) {
      const name = /** @type {any} */ (run.byTest.get(`file:${id}`));
      assert.equal(name, `${createHash("sha256").update(id).digest("hex")}.jsonl`);
      const recs = recordsOf(run, id);
      const meta = recs[0];
      assert.equal(meta.v, 1);
      assert.equal(meta.testId, id);
      assert.equal(meta.vitest, "5.0.2");
      assert.equal(meta.root, root);
      assert.match(meta.vite, /^\d+\.\d+\.\d+/);
      assert.equal(meta.node, process.versions.node);
      const result = recs.at(-1);
      assert.deepEqual(
        { kind: result.kind, state: result.state, tests: result.tests, failed: result.failed, skipped: result.skipped },
        { kind: "result", state: "passed", tests: 1, failed: 0, skipped: 0 },
      );
      assert.equal(typeof result.durationMs, "number");
      assert.deepEqual(taints(recs), [], `unexpected taint for ${id}`);
      // No leftover worker parts in VCI_OUT
      assert.ok(!fs.existsSync(path.join(run.outDir, ".vci-parts")));
    }
  });

  test("B: read of fixtures/b.json and module src/b.ts", () => {
    const b = recordsOf(run, "src/b.test.ts");
    assert.ok(hasRead(b, path.join(root, "fixtures/b.json")), JSON.stringify(b, null, 1));
    assert.ok(hasModule(b, path.join(root, "src/b.ts")));
    assert.ok(hasModule(b, path.join(root, "src/b.test.ts")));
  });

  test("C: computed dynamic import records module src/impl-x.ts and the listing of src/", () => {
    const c = recordsOf(run, "src/c.test.ts");
    assert.ok(hasModule(c, path.join(root, "src/impl-x.ts")), JSON.stringify(c, null, 1));
    assert.ok(hasModule(c, path.join(root, "src/c.ts")));
    // import(`./impl-${name}.ts`) is a glob over src/: adding src/impl-y.ts must invalidate C.
    assert.ok(ofKind(c, "readdir").some((r) => r.path === path.join(root, "src")));
  });

  test("D: external ms@2.1.3", () => {
    const d = recordsOf(run, "src/d.test.ts");
    assert.ok(
      ofKind(d, "external").some((r) => r.name === "ms" && r.version === "2.1.3"),
      JSON.stringify(d, null, 1),
    );
    assert.ok(hasModule(d, path.join(root, "src/d.ts")));
    // node_modules files are never reported as module/read paths
    assert.ok(!d.some((r) => typeof r.path === "string" && r.path.includes("/node_modules/")));
  });

  test("A: no cross-contamination from B, C or D", () => {
    const a = recordsOf(run, "src/a.test.ts");
    assert.ok(hasModule(a, path.join(root, "src/a.ts")));
    assert.ok(!mentions(a, "fixtures/b.json"), JSON.stringify(a, null, 1));
    assert.ok(!mentions(a, "src/impl-x.ts"));
    assert.ok(!mentions(a, "src/b.ts"));
    assert.ok(!mentions(a, "src/c.ts"));
    assert.ok(!ofKind(a, "external").some((r) => r.name === "ms"));
    assert.deepEqual(ofKind(a, "readdir"), []);
    // and B/D do not see C's dynamic import
    assert.ok(!mentions(recordsOf(run, "src/b.test.ts"), "src/impl-x.ts"));
    assert.ok(!mentions(recordsOf(run, "src/d.test.ts"), "fixtures/b.json"));
  });
});

const EXTRA_FILES = {
  "src/spawn.test.ts": `import { expect, test } from "vitest";
import { execFileSync } from "node:child_process";
test("spawns", () => {
  expect(execFileSync(process.execPath, ["-e", "process.stdout.write('ok')"]).toString()).toBe("ok");
});
`,
  "src/probe.test.ts": `import { expect, test } from "vitest";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
test("missing file", () => {
  expect(existsSync(fileURLToPath(new URL("../fixtures/missing.json", import.meta.url)))).toBe(false);
});
`,
  "src/env.test.ts": `import { expect, test } from "vitest";
test("env", () => {
  expect(process.env.VCI_FIXTURE_FLAG).toBe("on");
  expect("VCI_FIXTURE_MISSING" in process.env).toBe(false);
});
`,
  "src/opaque.ts": `export const loadOpaque = async (name: string) => {
  const spec = ["./impl", name].join("-") + ".ts";
  return import(/* @vite-ignore */ spec);
};
`,
  "src/opaque.test.ts": `import { expect, test } from "vitest";
import { loadOpaque } from "./opaque";
test("opaque import", async () => {
  expect((await loadOpaque("x")).name).toBe("x");
});
`,
  "src/fetch.test.ts": `import { expect, test } from "vitest";
test("fetch", async () => {
  const r = await fetch("data:text/plain,hi");
  expect(await r.text()).toBe("hi");
});
`,
  "src/fsasync.test.ts": `import { expect, test } from "vitest";
import fs from "node:fs";
import { readFile, stat } from "node:fs/promises";
import { fileURLToPath } from "node:url";
const p = (rel: string) => fileURLToPath(new URL(rel, import.meta.url));
test("async fs", async () => {
  expect(JSON.parse(await readFile(p("../fixtures/b.json"), "utf8")).greeting).toBe("hello");
  await expect(stat(p("../fixtures/nope-promises.json"))).rejects.toThrow();
  const listing: string[] = await new Promise((res, rej) => fs.readdir(p("../fixtures"), (e, l) => (e ? rej(e) : res(l))));
  expect(listing).toContain("b.json");
  const text: string = await new Promise((res, rej) => fs.readFile(p("../fixtures/b.json"), "utf8", (e, t) => (e ? rej(e) : res(t))));
  expect(text).toContain("hello");
});
`,
  "src/globbed/one.ts": `export default 1;\n`,
  "src/glob.test.ts": `import { expect, test } from "vitest";
const mods = import.meta.glob("./globbed/*.ts", { eager: true });
test("glob", () => {
  expect(Object.keys(mods)).toEqual(["./globbed/one.ts"]);
});
`,
  "src/optional.test.ts": `import { expect, test } from "vitest";
test("optional import", async () => {
  const name = ["maybe", "there"].join("-");
  let ok = true;
  try {
    await import(/* @vite-ignore */ "./" + name + ".ts");
  } catch {
    ok = false;
  }
  expect(ok).toBe(false);
});
`,
  "src/tmp.test.ts": `import { expect, test } from "vitest";
import { mkdtempSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
test("tmp roundtrip", () => {
  const d = mkdtempSync(join(tmpdir(), "vci-selftest-"));
  writeFileSync(join(d, "x.txt"), "x");
  expect(readFileSync(join(d, "x.txt"), "utf8")).toBe("x");
});
`,
  "src/cjs.test.ts": `import { expect, test } from "vitest";
import { createRequire } from "node:module";
test("require", () => {
  const req = createRequire(import.meta.url);
  expect(req("ms")("1s")).toBe(1000);
  expect(() => req("./not-here.cjs")).toThrow();
});
`,
};

describe("extra cases (temp copy of the fixture)", () => {
  const root = makeProject({ files: EXTRA_FILES });
  const run = runVitest(root, { env: { VCI_FIXTURE_FLAG: "on" } });

  test("run succeeds", () => {
    assert.equal(run.status, 0, run.output);
    assert.equal(run.byTest.size / 2, 4 + 10);
  });

  test("a test that spawns a child process gets a taint record", () => {
    const s = recordsOf(run, "src/spawn.test.ts");
    assert.ok(taints(s).includes("child_process.execFileSync"), JSON.stringify(s, null, 1));
    // and only that file is tainted by it
    assert.deepEqual(taints(recordsOf(run, "src/b.test.ts")), []);
  });

  test("checking existence of a missing file gets a probe record", () => {
    const p = recordsOf(run, "src/probe.test.ts");
    assert.ok(hasProbe(p, path.join(root, "fixtures/missing.json")), JSON.stringify(p, null, 1));
    assert.deepEqual(taints(p), []);
  });

  test("env reads are recorded by key", () => {
    const e = recordsOf(run, "src/env.test.ts");
    const keys = ofKind(e, "env").map((r) => r.key);
    assert.ok(keys.includes("VCI_FIXTURE_FLAG"), JSON.stringify(e, null, 1));
    assert.ok(keys.includes("VCI_FIXTURE_MISSING"));
    assert.ok(!keys.includes("VCI_OUT") && !keys.includes("VCI_WORKER"));
    assert.ok(!ofKind(recordsOf(run, "src/a.test.ts"), "env").some((r) => r.key === "VCI_FIXTURE_FLAG"));
  });

  test("fully opaque import() is recorded by the runner fallback, not the graph", () => {
    const o = recordsOf(run, "src/opaque.test.ts");
    const m = ofKind(o, "module").find((r) => r.path === path.join(root, "src/impl-x.ts"));
    assert.ok(m, JSON.stringify(o, null, 1));
    assert.equal(m.via, "runner");
  });

  test("global fetch taints", () => {
    assert.ok(taints(recordsOf(run, "src/fetch.test.ts")).includes("fetch"));
  });

  test("promise and callback fs APIs: reads, probes and readdir", () => {
    const f = recordsOf(run, "src/fsasync.test.ts");
    assert.ok(hasRead(f, path.join(root, "fixtures/b.json")), JSON.stringify(f, null, 1));
    assert.ok(hasProbe(f, path.join(root, "fixtures/nope-promises.json")));
    assert.ok(ofKind(f, "readdir").some((r) => r.path === path.join(root, "fixtures")));
  });

  test("import.meta.glob records the globbed directory", () => {
    const g = recordsOf(run, "src/glob.test.ts");
    assert.ok(ofKind(g, "readdir").some((r) => r.path === path.join(root, "src/globbed")), JSON.stringify(g, null, 1));
    assert.ok(hasModule(g, path.join(root, "src/globbed/one.ts")));
  });

  test("failed runtime import resolution becomes probes", () => {
    const o = recordsOf(run, "src/optional.test.ts");
    assert.ok(hasProbe(o, path.join(root, "src/maybe-there.ts")), JSON.stringify(o, null, 1));
  });

  test("files inside a mkdtemp dir created by the test are not inputs", () => {
    const t = recordsOf(run, "src/tmp.test.ts");
    assert.ok(!t.some((r) => typeof r.path === "string" && r.path.includes("vci-selftest-")), JSON.stringify(t, null, 1));
    assert.deepEqual(taints(t), []);
  });

  test("CommonJS require: external via Node hooks, failed relative require becomes probes", () => {
    const c = recordsOf(run, "src/cjs.test.ts");
    assert.ok(ofKind(c, "external").some((r) => r.name === "ms" && r.version === "2.1.3"), JSON.stringify(c, null, 1));
    assert.ok(hasProbe(c, path.join(root, "src/not-here.cjs")));
  });

  test("still no cross-contamination with many files", () => {
    const a = recordsOf(run, "src/a.test.ts");
    for (const bad of ["fixtures/b.json", "src/impl-x.ts", "fixtures/missing.json", "src/globbed", "src/maybe-there.ts"]) {
      assert.ok(!mentions(a, bad), `${bad} leaked into A`);
    }
    assert.deepEqual(taints(a), []);
  });
});

describe("threads pool", () => {
  const root = makeProject();
  const run = runVitest(root, { args: ["--pool", "threads"] });
  test("same records as forks for B and C", () => {
    assert.equal(run.status, 0, run.output);
    const b = recordsOf(run, "src/b.test.ts");
    assert.ok(hasRead(b, path.join(root, "fixtures/b.json")));
    assert.ok(hasModule(recordsOf(run, "src/c.test.ts"), path.join(root, "src/impl-x.ts")));
    assert.ok(!mentions(recordsOf(run, "src/a.test.ts"), "fixtures/b.json"));
    assert.deepEqual(taints(b), []);
  });
});

describe("non-attestable modes are tainted", () => {
  test("isolate: false", () => {
    const run = runVitest(makeProject(), { args: ["--no-isolate"] });
    assert.equal(run.status, 0, run.output);
    for (const id of ["src/a.test.ts", "src/b.test.ts"]) assert.ok(taints(recordsOf(run, id)).includes("isolate:false"));
  });
  test("vmThreads pool", () => {
    const run = runVitest(makeProject(), { args: ["--pool", "vmThreads"] });
    assert.equal(run.status, 0, run.output);
    assert.ok(taints(recordsOf(run, "src/a.test.ts")).includes("pool:vmThreads"));
  });
  test("native runner (experimental.viteModuleRunner: false)", () => {
    const config = `import { defineConfig } from "vitest/config";
export default defineConfig({ test: { include: ["src/native.test.ts"], experimental: { viteModuleRunner: false } } });
`;
    // Native Node ESM needs explicit extensions.
    const files = {
      "src/native.test.ts": `import { expect, test } from "vitest";\nimport { add } from "./a.ts";\ntest("n", () => { expect(add(1, 1)).toBe(2); });\n`,
    };
    const run = runVitest(makeProject({ config, files }));
    assert.equal(run.status, 0, run.output);
    const recs = recordsOf(run, "src/native.test.ts");
    assert.ok(taints(recs).includes("native-runner"), JSON.stringify(recs));
  });
  test("fs module cache", () => {
    const config = `import { defineConfig } from "vitest/config";
export default defineConfig({ test: { include: ["src/a.test.ts"], fsModuleCache: true, fsModuleCachePath: "./.fs-cache", experimental: { fsModuleCache: true } } as any });
`;
    const run = runVitest(makeProject({ config }));
    assert.equal(run.status, 0, run.output);
    assert.ok(taints(recordsOf(run, "src/a.test.ts")).includes("fs-module-cache"));
  });
  test("failing test is reported as failed", () => {
    const run = runVitest(
      makeProject({
        files: { "src/fail.test.ts": `import { test, expect } from "vitest";\ntest("x", () => { expect(1).toBe(2); });\n` },
      }),
    );
    assert.notEqual(run.status, 0);
    const r = recordsOf(run, "src/fail.test.ts").at(-1);
    assert.equal(r.state, "failed");
    assert.equal(r.failed, 1);
  });
  test("snapshot written during the run taints the file", () => {
    const run = runVitest(
      makeProject({
        files: { "src/snap.test.ts": `import { test, expect } from "vitest";\ntest("s", () => { expect({ a: 1 }).toMatchSnapshot(); });\n` },
      }),
      { env: { CI: "" }, args: ["--update=new"] },
    );
    assert.equal(run.status, 0, run.output);
    assert.ok(taints(recordsOf(run, "src/snap.test.ts")).includes("snapshot:written"), JSON.stringify(recordsOf(run, "src/snap.test.ts")));
    assert.ok(!taints(recordsOf(run, "src/a.test.ts")).includes("snapshot:written"));
  });
});

describe("vi.mock and __mocks__", () => {
  const root = makeProject({
    files: {
      "src/mock1.test.ts": `import { expect, test, vi } from "vitest";\nimport { add } from "./a";\nvi.mock("./a");\ntest("m", () => { expect(vi.isMockFunction(add)).toBe(true); });\n`,
      "src/mock2.test.ts": `import { expect, test, vi } from "vitest";\nimport { minute } from "./d";\nvi.mock("./d");\ntest("m", () => { expect(minute()).toBe(1); });\n`,
      "src/__mocks__/d.ts": `export const minute = () => 1;\n`,
    },
  });
  const run = runVitest(root);
  test("automock probes the missing __mocks__ file; manual mock is a module", () => {
    assert.equal(run.status, 0, run.output);
    assert.ok(hasProbe(recordsOf(run, "src/mock1.test.ts"), path.join(root, "src/__mocks__/a.ts")));
    assert.ok(hasModule(recordsOf(run, "src/mock2.test.ts"), path.join(root, "src/__mocks__/d.ts")));
  });
});

describe("wrapper config", () => {
  test("file filters on the command line limit output to those files", () => {
    const run = runVitest(makeProject(), { args: ["src/b.test.ts"] });
    assert.equal(run.status, 0, run.output);
    assert.deepEqual([...run.byTest.keys()].filter((k) => !k.startsWith("file:")), ["src/b.test.ts"]);
  });

  test("function-form user config with import.meta.url and a user setup file", () => {
    const config = `import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";
export default defineConfig(({ mode }) => ({
  test: {
    include: ["src/**/*.test.ts"],
    setupFiles: [fileURLToPath(new URL("./setup-user.ts", import.meta.url))],
    env: { VCI_CONFIG_MODE: mode },
  },
}));
`;
    const root = makeProject({
      config,
      files: {
        "setup-user.ts": `import { readFileSync } from "node:fs";
readFileSync(new URL("./fixtures/b.json", import.meta.url));
`,
      },
    });
    const run = runVitest(root);
    assert.equal(run.status, 0, run.output);
    const a = recordsOf(run, "src/a.test.ts");
    // user setup files run for every test file, so their dependencies belong to every file
    assert.ok(hasModule(a, path.join(root, "setup-user.ts")), JSON.stringify(a, null, 1));
    assert.ok(hasRead(a, path.join(root, "fixtures/b.json")));
    assert.deepEqual(taints(a), []);
  });

  test("wrapper placed inside the project (default location) also works", async () => {
    const { writeWrapperConfig } = await import("../src/wrapper.js");
    const root = makeProject();
    const w = writeWrapperConfig({ root, outFile: path.join(root, ".vci", "vitest.config.vci.mjs") });
    assert.ok(fs.readFileSync(w, "utf8").includes(path.join(root, "vitest.config.ts")));
    const run = runVitest(root, { wrapperDir: path.join(root, ".vci2") });
    assert.equal(run.status, 0, run.output);
    assert.ok(hasRead(recordsOf(run, "src/b.test.ts"), path.join(root, "fixtures/b.json")));
  });
});

describe("plugin is inert without VCI_OUT", () => {
  test("no output, tests still pass", async () => {
    const { spawnSync } = await import("node:child_process");
    const root = makeProject();
    const { writeWrapperConfig } = await import("../src/wrapper.js");
    const w = writeWrapperConfig({ root, outFile: path.join(root, ".vci", "w.mjs") });
    const env = { ...process.env };
    delete env.VCI_OUT;
    const r = spawnSync(process.execPath, [path.join(root, "node_modules/vitest/vitest.mjs"), "run", "--config", w], {
      cwd: root,
      env,
      encoding: "utf8",
    });
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.ok(!fs.existsSync(path.join(root, ".vci-parts")));
  });
});
