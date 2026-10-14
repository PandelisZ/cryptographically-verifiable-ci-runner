// Lists the test files `node --test [patterns...]` would run, with node:test's own rules: the
// patterns are globs relative to the working directory (Node's glob, `node_modules` directories
// excluded), and without a pattern node:test's default pattern, which includes TypeScript
// extensions when type stripping is on. vci runs it with the project's node and its type
// stripping flags, as `node [flags] --input-type=module -e <this source> -- <cwd> [patterns...]`.
// Prints `{"files": [<absolute path>...], "typescript": ...}`; exits 2 on anything node:test
// itself would not run (a pattern naming a directory, a match that is not a file) and 1 when no
// pattern without wildcards matches (node:test's "Could not find").
import fs from "node:fs";
import path from "node:path";

// As a file (`node list.js <cwd> ...`) the arguments start at argv[2]; with `-e`, at argv[1].
const asFile = import.meta.url.endsWith("/list.js");
const [cwd, ...patterns] = process.argv.slice(asFile ? 2 : 1);
if (!cwd) {
  console.error("usage: list.js <cwd> [patterns...]");
  process.exit(2);
}
const typescript = /** @type {any} */ (process.features).typescript || false;
const exts = ["js", "mjs", "cjs", ...(typescript ? ["ts", "mts", "cts"] : [])];
const DEFAULT = `**/{test,test/**/*,test-*,*[._-]test}.{${exts.join(",")}}`;
const user = patterns.length > 0;
const pats = user ? patterns : [DEFAULT];
for (const p of user ? pats : []) {
  const abs = path.isAbsolute(p) ? p : path.resolve(cwd, p);
  let dir = false;
  try {
    dir = fs.statSync(abs).isDirectory();
  } catch {
    dir = false;
  }
  if (dir) {
    // Node 26 searches a directory argument with the default pattern; older versions do not.
    console.error(`test pattern ${JSON.stringify(p)} is a directory; name the files with a glob (e.g. '${p.replace(/\/+$/, "")}/**/*.test.js')`);
    process.exit(2);
  }
}
if (typeof (/** @type {any} */ (fs).globSync) !== "function") {
  console.error(`fs.globSync is not available in Node ${process.version} (Node 22 or later is needed)`);
  process.exit(2);
}
const results = /** @type {string[]} */ (
  /** @type {any} */ (fs).globSync(pats, { cwd, exclude: (/** @type {any} */ name) => name === "node_modules" })
).sort();
const MAGIC = /[*?[\]{}()!+@]/;
if (user && results.length === 0 && pats.every((p) => !MAGIC.test(p))) {
  console.error(`Could not find '${pats.join(", ")}'`);
  process.exit(1);
}
const files = [];
for (const r of results) {
  const abs = path.resolve(cwd, r);
  let st;
  try {
    st = fs.statSync(abs);
  } catch {
    st = null;
  }
  if (!st || !st.isFile()) {
    console.error(`test pattern match ${JSON.stringify(r)} is not a file`);
    process.exit(2);
  }
  files.push(abs);
}
process.stdout.write(JSON.stringify({ files, typescript }) + "\n");
