// Compatibility run against Vitest 4.1.11. Opt-in because it needs an npm install:
//   VCI_TEST_VITEST4=1 node --test test/vitest4.test.js
// Set VCI_VITEST4_NODE_MODULES=<dir>/node_modules to reuse an existing install.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";
import { describe, test } from "node:test";

import { FIXTURE, makeProject, ofKind, runVitest, tmpDir } from "./helpers.js";

const enabled = !!process.env.VCI_TEST_VITEST4;

function vitest4NodeModules() {
  if (process.env.VCI_VITEST4_NODE_MODULES) return path.resolve(process.env.VCI_VITEST4_NODE_MODULES);
  const dir = tmpDir("vci-vitest4-");
  const pkg = JSON.parse(fs.readFileSync(path.join(FIXTURE, "package.json"), "utf8"));
  pkg.devDependencies = { vitest: "4.1.11" };
  fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify(pkg, null, 2));
  execFileSync("npm", ["install", "--no-audit", "--no-fund", "--silent"], { cwd: dir, stdio: "inherit" });
  return path.join(dir, "node_modules");
}

describe("vitest 4.1.11", { skip: !enabled && "set VCI_TEST_VITEST4=1 to run" }, () => {
  const nm = enabled ? vitest4NodeModules() : "";
  const files = {
    "src/spawn.test.ts": `import { expect, test } from "vitest";
import { execFileSync } from "node:child_process";
test("spawns", () => { expect(execFileSync(process.execPath, ["-e", "1"]).length).toBe(0); });
`,
    "src/probe.test.ts": `import { expect, test } from "vitest";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
test("missing", () => { expect(existsSync(fileURLToPath(new URL("../fixtures/missing.json", import.meta.url)))).toBe(false); });
`,
  };
  const root = enabled ? makeProject({ nodeModules: nm, files }) : "";
  const run = enabled ? runVitest(root) : /** @type {any} */ (null);

  test("installed version is 4.1.11", () => {
    const v = JSON.parse(fs.readFileSync(path.join(nm, "vitest", "package.json"), "utf8")).version;
    assert.equal(v, "4.1.11");
  });

  test("records match the Vitest 5 expectations", () => {
    assert.equal(run.status, 0, run.output);
    const get = (/** @type {string} */ id) => {
      const r = run.byTest.get(id);
      assert.ok(r, `${id} missing\n${run.output}`);
      return r;
    };
    const a = get("src/a.test.ts");
    const b = get("src/b.test.ts");
    const c = get("src/c.test.ts");
    const d = get("src/d.test.ts");
    assert.equal(a[0].vitest, "4.1.11");
    assert.ok(ofKind(b, "read").some((r) => r.path === path.join(root, "fixtures/b.json")));
    assert.ok(ofKind(b, "module").some((r) => r.path === path.join(root, "src/b.ts")));
    assert.ok(ofKind(c, "module").some((r) => r.path === path.join(root, "src/impl-x.ts")));
    assert.ok(ofKind(d, "external").some((r) => r.name === "ms" && r.version === "2.1.3"));
    assert.ok(!a.some((r) => typeof r.path === "string" && (r.path.endsWith("b.json") || r.path.endsWith("impl-x.ts"))));
    for (const recs of [a, b, c, d]) assert.deepEqual(ofKind(recs, "taint"), []);
    assert.ok(ofKind(get("src/spawn.test.ts"), "taint").some((r) => r.reason === "child_process.execFileSync"));
    assert.ok(ofKind(get("src/probe.test.ts"), "probe").some((r) => r.path === path.join(root, "fixtures/missing.json")));
  });
});
