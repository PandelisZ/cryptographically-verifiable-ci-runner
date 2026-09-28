// Regression tests for false skips found by adversarial verification. Each case runs a real test
// file through the wrapper and checks that the dependency (or a taint) is recorded, so that the
// Rust side re-hashes it (or refuses to attest).

import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";
import { describe, test } from "node:test";

import { makeProject, ofKind, runVitest } from "./helpers.js";

/** @param {any[]} recs @param {string} kind @param {string} p */
const has = (recs, kind, p) => ofKind(recs, kind).some((r) => r.path === p);
/** @param {any[]} recs */
const taints = (recs) => ofKind(recs, "taint").map((r) => r.reason);
/** @param {any[]} recs */
const dump = (recs) => JSON.stringify(recs, null, 1);

/**
 * @param {import("./helpers.js").RunResult} run
 * @param {string} id
 */
function recordsOf(run, id) {
  const recs = run.byTest.get(id);
  assert.ok(recs, `no records for ${id}; got ${[...run.byTest.keys()].join(", ")}\n${run.output}`);
  return recs;
}

const FILES = {
  // Symlinked source module (retargeting the link must invalidate).
  "shared/real-a.ts": `export const v = "A";\n`,
  "shared/real-b.ts": `export const v = "B";\n`,
  "src/atk/symlink.test.ts": `import { expect, test } from "vitest";
import { v } from "./link";
test("symlink", () => { expect(v).toBe("A"); });
`,
  // Higher-priority resolution candidates (ext.js beside ext.ts, dirmod.ts beside dirmod/index.ts).
  "src/atk/ext.ts": `export const kind = "ts";\n`,
  "src/atk/dirmod/index.ts": `export const kind = "index";\n`,
  "src/atk/resolve.test.ts": `import { expect, test } from "vitest";
import { kind as e } from "./ext";
import { kind as d } from "./dirmod";
test("resolve", () => { expect(e).toBe("ts"); expect(d).toBe("index"); });
`,
  // toMatchFileSnapshot target file.
  "src/atk/__file_snapshots__/out.txt": "hello\n",
  "src/atk/filesnap.test.ts": `import { expect, test } from "vitest";
test("file snapshot", async () => { await expect("hello\\n").toMatchFileSnapshot("./__file_snapshots__/out.txt"); });
`,
  // Fixtures copied, symlinked or hard-linked into a mkdtemp dir, and openAsBlob.
  "data/proj/cfg.txt": "c1",
  "data/sl.txt": "sl",
  "data/hl.txt": "hl",
  "data/blob.txt": "b1",
  "data/p3.txt": "p3",
  "src/atk/tmpcopy.test.ts": `import { expect, test } from "vitest";
import fs from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
const data = (p: string) => path.join(process.cwd(), "data", p);
test("cpSync", () => {
  const tmp = fs.mkdtempSync(path.join(tmpdir(), "vci-atk-"));
  fs.cpSync(data("proj"), path.join(tmp, "proj"), { recursive: true });
  expect(fs.readFileSync(path.join(tmp, "proj", "cfg.txt"), "utf8")).toBe("c1");
});
test("symlinkSync", () => {
  const tmp = fs.mkdtempSync(path.join(tmpdir(), "vci-atk-"));
  fs.symlinkSync(data("sl.txt"), path.join(tmp, "x"));
  expect(fs.readFileSync(path.join(tmp, "x"), "utf8")).toBe("sl");
});
test("linkSync", () => {
  const tmp = fs.mkdtempSync(path.join(tmpdir(), "vci-atk-"));
  fs.linkSync(data("hl.txt"), path.join(tmp, "x"));
  expect(fs.readFileSync(path.join(tmp, "x"), "utf8")).toBe("hl");
});
test("openAsBlob", async () => {
  const blob = await fs.openAsBlob(data("blob.txt"));
  expect(await blob.text()).toBe("b1");
});
`,
  "src/atk/promcp.test.ts": `import { expect, test } from "vitest";
import { cp, mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
test("promises cp into a promises mkdtemp dir", async () => {
  const d = await mkdtemp(path.join(tmpdir(), "vci-t3-"));
  await cp(path.join(process.cwd(), "data", "p3.txt"), path.join(d, "x.txt"));
  expect(await readFile(path.join(d, "x.txt"), "utf8")).toBe("p3");
});
`,
  // Sockets created with the constructor.
  "src/atk/sock.test.ts": `import { expect, test } from "vitest";
import net from "node:net";
const attempt = (s: net.Socket) => new Promise<string>((res) => {
  s.once("connect", () => { s.destroy(); res("connect"); });
  s.once("error", () => res("error"));
  s.connect(1, "127.0.0.1");
});
test("new net.Socket().connect", async () => { expect(await attempt(new net.Socket())).toMatch(/connect|error/); });
test("new net.Stream().connect", async () => { expect(await attempt(new (net as any).Stream())).toMatch(/connect|error/); });
`,
  // Native reads: process.loadEnvFile and node:sqlite.
  "data/app.env": "APP_MODE=alpha\n",
  "src/atk/native.test.ts": `import { expect, test } from "vitest";
import path from "node:path";
import { createRequire } from "node:module";
test("loadEnvFile", () => {
  process.loadEnvFile(path.join(process.cwd(), "data", "app.env"));
  expect(process.env.APP_MODE).toBe("alpha");
});
test("sqlite", () => {
  const { DatabaseSync } = createRequire(import.meta.url)("node:sqlite");
  const db = new DatabaseSync(path.join(process.cwd(), "data", "t.db"), { readOnly: true });
  expect(db.prepare("select v from t").get().v).toBe("one");
  db.close();
});
`,
  // statSync(p, { throwIfNoEntry: false }) on a missing file is a probe, not a read.
  "src/atk/exists.test.ts": `import { expect, test } from "vitest";
import fs from "node:fs";
import path from "node:path";
test("stat without throwing", () => {
  expect(fs.statSync(path.join(process.cwd(), "data", "maybe3.txt"), { throwIfNoEntry: false })).toBeUndefined();
  expect(fs.lstatSync(path.join(process.cwd(), "data", "maybe4.txt"), { throwIfNoEntry: false })).toBeUndefined();
});
`,
};

/** Create data/t.db with one row ('one') using node:sqlite in this process. */
async function makeDb(/** @type {string} */ file) {
  const { DatabaseSync } = await import("node:sqlite");
  const db = new DatabaseSync(file);
  db.exec("create table t (v text); insert into t values ('one');");
  db.close();
}

describe("false-skip regressions (collector records)", async () => {
  const root = makeProject({ files: FILES });
  fs.symlinkSync("../../shared/real-a.ts", path.join(root, "src/atk/link.ts"));
  await makeDb(path.join(root, "data/t.db"));
  const run = runVitest(root, { args: ["src/atk"] });
  const at = (/** @type {string} */ rel) => path.join(root, rel);

  test("run succeeds", () => {
    assert.equal(run.status, 0, run.output);
  });

  test("a symlinked module's link path is an input (retargeting it is noticed)", () => {
    const r = recordsOf(run, "src/atk/symlink.test.ts");
    assert.ok(has(r, "read", at("src/atk/link.ts")) || has(r, "module", at("src/atk/link.ts")), dump(r));
  });

  test("higher-priority resolution candidates of successful imports are probed", () => {
    const r = recordsOf(run, "src/atk/resolve.test.ts");
    for (const p of ["src/atk/ext.js", "src/atk/ext.mjs", "src/atk/dirmod.ts", "src/atk/dirmod.js"]) {
      assert.ok(has(r, "probe", at(p)), `${p} not probed\n${dump(r)}`);
    }
    assert.deepEqual(taints(r), []);
  });

  test("toMatchFileSnapshot target file is read", () => {
    const r = recordsOf(run, "src/atk/filesnap.test.ts");
    assert.ok(has(r, "read", at("src/atk/__file_snapshots__/out.txt")), dump(r));
  });

  test("cpSync source tree, symlinkSync target, linkSync source and openAsBlob are reads", () => {
    const r = recordsOf(run, "src/atk/tmpcopy.test.ts");
    for (const p of ["data/proj/cfg.txt", "data/sl.txt", "data/hl.txt", "data/blob.txt"]) {
      assert.ok(has(r, "read", at(p)), `${p} not read\n${dump(r)}`);
    }
    assert.ok(has(r, "readdir", at("data/proj")), dump(r));
    assert.deepEqual(taints(r), []);
  });

  test("promises cp into a promises mkdtemp dir: source read, nothing outside the project", () => {
    const r = recordsOf(run, "src/atk/promcp.test.ts");
    assert.ok(has(r, "read", at("data/p3.txt")), dump(r));
    const outside = r.filter((x) => typeof x.path === "string" && !x.path.startsWith(root + "/") && x.path !== root);
    assert.deepEqual(outside, [], dump(r));
    assert.deepEqual(taints(r), []);
  });

  test("new net.Socket() / new net.Stream() connect taints", () => {
    const r = recordsOf(run, "src/atk/sock.test.ts");
    assert.ok(taints(r).some((t) => t.startsWith("net.Socket")), dump(r));
  });

  test("process.loadEnvFile and node:sqlite paths are reads", () => {
    const r = recordsOf(run, "src/atk/native.test.ts");
    assert.ok(has(r, "read", at("data/app.env")), dump(r));
    assert.ok(has(r, "read", at("data/t.db")), dump(r));
  });

  test("statSync/lstatSync with throwIfNoEntry: false on a missing file are probes", () => {
    const r = recordsOf(run, "src/atk/exists.test.ts");
    for (const p of ["data/maybe3.txt", "data/maybe4.txt"]) {
      assert.ok(has(r, "probe", at(p)), `${p} not probed\n${dump(r)}`);
      assert.ok(!has(r, "read", at(p)), `${p} recorded as read\n${dump(r)}`);
    }
  });
});

describe("main-process inputs (config, plugins, globalSetup)", () => {
  const config = `import { defineConfig } from "vitest/config";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
const here = path.dirname(fileURLToPath(import.meta.url));
const top = readFileSync(path.join(here, "data", "top.txt"), "utf8");
export default defineConfig({
  define: { __FLAG__: JSON.stringify(process.env.ATK_FLAG || "off"), __TOP__: JSON.stringify(top) },
  plugins: [{
    name: "virtual-data",
    resolveId(id) { return id === "virtual:data" ? "\\0virtual:data" : null; },
    load(id) {
      if (id !== "\\0virtual:data") return null;
      return "export default " + JSON.stringify(readFileSync(path.join(here, "data", "virt.txt"), "utf8"));
    },
  }],
  test: {
    include: ["src/main/**/*.test.ts"],
    globalSetup: [path.join(process.cwd(), "tools", "gsetup.ts")],
  },
});
`;
  const root = makeProject({
    config,
    files: {
      "data/g.txt": "g1",
      "data/virt.txt": "v1",
      "data/top.txt": "t1",
      "tools/gsetup.ts": `import { readFileSync } from "node:fs";
import path from "node:path";
import { helper } from "./gsetup-helper";
export default function ({ provide }: any) {
  provide("g", helper(readFileSync(path.join(process.cwd(), "data", "g.txt"), "utf8")));
}
`,
      "tools/gsetup-helper.ts": `export const helper = (s: string) => s;\n`,
      "src/main/m.test.ts": `import { expect, inject, test } from "vitest";
import virt from "virtual:data";
declare const __FLAG__: string;
declare const __TOP__: string;
test("main-process inputs", () => {
  expect(inject("g" as never)).toBe("g1");
  expect(virt).toBe("v1");
  expect(__FLAG__).toBe("off");
  expect(__TOP__).toBe("t1");
});
`,
    },
  });
  const run = runVitest(root, { env: { ATK_FLAG: "" } });
  const at = (/** @type {string} */ rel) => path.join(root, rel);

  test("globalSetup files (and their imports), config-plugin reads and config env reads are recorded", () => {
    assert.equal(run.status, 0, run.output);
    const r = recordsOf(run, "src/main/m.test.ts");
    assert.ok(has(r, "module", at("tools/gsetup.ts")), `globalSetup module\n${dump(r)}`);
    assert.ok(has(r, "module", at("tools/gsetup-helper.ts")), `globalSetup import\n${dump(r)}`);
    assert.ok(has(r, "read", at("data/g.txt")), `globalSetup read\n${dump(r)}`);
    assert.ok(has(r, "read", at("data/virt.txt")), `plugin read\n${dump(r)}`);
    assert.ok(has(r, "read", at("data/top.txt")), `config top-level read\n${dump(r)}`);
    assert.ok(ofKind(r, "env").some((e) => e.key === "ATK_FLAG"), `config env read\n${dump(r)}`);
    // Node's module loader reading its own settings is not a dependency.
    assert.ok(!ofKind(r, "env").some((e) => e.key === "WATCH_REPORT_DEPENDENCIES"), dump(r));
    assert.deepEqual(taints(r), []);
  });
});

describe("custom snapshot paths and aliased template imports", () => {
  const config = `import { defineConfig } from "vitest/config";
import path from "node:path";
export default defineConfig({
  resolve: { alias: { "@p": path.join(process.cwd(), "src", "w", "plug") } },
  test: {
    include: ["src/w/**/*.test.ts"],
    resolveSnapshotPath: (testPath, ext) => path.join(process.cwd(), "snaps", path.basename(testPath) + ext),
  },
});
`;
  const root = makeProject({
    config,
    files: {
      "src/w/plug/one.ts": `export default "one";\n`,
      "src/w/alias.test.ts": `import { expect, test } from "vitest";
test("aliased template import", async () => {
  const n = ["la", "te"].join("");
  let got = "none";
  try { got = (await import(\`@p/\${n}.ts\`)).default; } catch {}
  expect(got).toBe("none");
});
`,
      "src/w/snapr.test.ts": `import { expect, test } from "vitest";
test("custom snapshot path", () => { expect({ a: 1 }).toMatchSnapshot(); });
`,
      "snaps/snapr.test.ts.snap": `// Vitest Snapshot v1, https://vitest.dev/guide/snapshot.html

exports[\`custom snapshot path 1\`] = \`
{
  "a": 1,
}
\`;
`,
    },
  });
  const run = runVitest(root);
  const at = (/** @type {string} */ rel) => path.join(root, rel);

  test("an aliased template import() lists the aliased directory", () => {
    assert.equal(run.status, 0, run.output);
    const r = recordsOf(run, "src/w/alias.test.ts");
    assert.ok(has(r, "readdir", at("src/w/plug")), dump(r));
  });

  test("a snapshot file at a custom resolveSnapshotPath location is read", () => {
    const r = recordsOf(run, "src/w/snapr.test.ts");
    assert.ok(has(r, "read", at("snaps/snapr.test.ts.snap")), dump(r));
    assert.deepEqual(taints(r), []);
  });
});
