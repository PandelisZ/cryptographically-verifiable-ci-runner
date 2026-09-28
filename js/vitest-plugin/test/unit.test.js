import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";
import { test } from "node:test";

import { scanSource, staticDirOf } from "../src/scan.js";
import { idToFsPath, packageOf } from "../src/util.js";
import { FIXTURE, tmpDir } from "./helpers.js";

test("staticDirOf", () => {
  assert.deepEqual(staticDirOf("./impl-*.ts", "/r/src", "/r"), { dir: "/r/src", recursive: false });
  assert.deepEqual(staticDirOf("./locales/*/index.ts", "/r/src", "/r"), { dir: "/r/src/locales", recursive: true });
  assert.deepEqual(staticDirOf("../data/**/*.json", "/r/src", "/r"), { dir: "/r/data", recursive: true });
  assert.deepEqual(staticDirOf("/pages/*.ts", "/r/src", "/r"), { dir: "/r/pages", recursive: false });
  assert.equal(staticDirOf("@/x/*.ts", "/r/src", "/r"), null);
});

test("scanSource finds globs and computed imports", () => {
  const code = [
    "const a = import.meta.glob('./globbed/*.ts', { eager: true });",
    "const b = import.meta.glob(['./x/**/*.json', '!./x/skip/*.json']);",
    "const c = (n) => import(`./impl-${n}.ts`);",
    "const d = (n) => import(/* @vite-ignore */ './plugins/' + n);",
    "const e = import('./static.ts');",
  ].join("\n");
  const r = scanSource(code, "/r/src/mod.ts", "/r");
  assert.ok(r);
  assert.deepEqual(r.taints, []);
  assert.deepEqual(
    r.dirs.map((d) => `${d.dir}:${d.recursive}`).sort(),
    ["/r/src/globbed:false", "/r/src/x:true", "/r/src:false", "/r/src/plugins:true"].sort(),
  );
  assert.equal(scanSource("import x from './y'", "/r/a.ts", "/r"), null);
  const bad = scanSource("import.meta.glob(pattern)", "/r/a.ts", "/r");
  assert.ok(bad && bad.taints.length === 1);
});

test("packageOf uses the nearest package.json with name and version", () => {
  assert.deepEqual(packageOf(path.join(FIXTURE, "node_modules/ms/index.js")), { name: "ms", version: "2.1.3" });
  assert.equal(packageOf(path.join(FIXTURE, "src/a.ts")), undefined);
  const d = tmpDir("vci-pkg-");
  fs.mkdirSync(path.join(d, "node_modules/@s/p/dist"), { recursive: true });
  fs.writeFileSync(path.join(d, "node_modules/@s/p/package.json"), JSON.stringify({ name: "@s/p", version: "1.2.3" }));
  fs.writeFileSync(path.join(d, "node_modules/@s/p/dist/package.json"), JSON.stringify({ type: "module" }));
  assert.deepEqual(packageOf(path.join(d, "node_modules/@s/p/dist/x.js")), { name: "@s/p", version: "1.2.3" });
  fs.mkdirSync(path.join(d, "node_modules/nover"), { recursive: true });
  assert.equal(packageOf(path.join(d, "node_modules/nover/x.js")), null);
});

test("idToFsPath", () => {
  assert.equal(idToFsPath("\0virtual"), null);
  assert.equal(idToFsPath("/a/b.ts?raw"), "/a/b.ts");
  assert.equal(idToFsPath("file:///a/b.ts"), "/a/b.ts");
  assert.equal(idToFsPath("/@fs/a/b.ts"), "/a/b.ts");
  assert.equal(idToFsPath("fs"), null);
});
