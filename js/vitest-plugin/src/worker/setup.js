// Vitest setup file injected by the plugin (first in `setupFiles`). Runs inside the worker for
// every test file, once Vitest's worker state exists.
//
// - installs the collector if the preload did not (idempotent),
// - writes a marker so the reporter can tell the worker collectors ran for this file,
// - follows the Vite module runner (records every module it fetches/evaluates),
// - re-snapshots the runner's modules in a final afterAll hook.

import fs from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { install } from "./collector.js";

const collector = install({ preload: false });

if (collector) {
  const st = /** @type {any} */ (globalThis).__vitest_worker__;
  collector.emit({
    kind: "vci-worker",
    preload: collector.preload,
    hooks: collector.hooks,
    isolate: st && st.config ? st.config.isolate !== false : null,
    pool: st && st.ctx ? st.ctx.pool ?? null : null,
  });
  if (st && st.config && st.config.isolate === false) {
    collector.emit({ kind: "taint", reason: "isolate:false" });
  }
  collector.attachRunner();
  collector.attachRpc();

  // Final snapshot of the runner's modules after all tests of the file (best effort).
  try {
    const root = (st && st.config && st.config.root) || process.cwd();
    let pkgJsonPath;
    let pkg;
    collector.busy = true;
    try {
      const req = createRequire(path.join(root, "package.json"));
      pkgJsonPath = req.resolve("vitest/package.json");
      pkg = JSON.parse(fs.readFileSync(pkgJsonPath, "utf8"));
    } finally {
      collector.busy = false;
    }
    const dot = pkg.exports && pkg.exports["."];
    const entry =
      (dot && dot.import && (typeof dot.import === "string" ? dot.import : dot.import.default)) ||
      pkg.module ||
      "./dist/index.js";
    const vitest = await import(pathToFileURL(path.join(path.dirname(pkgJsonPath), entry)).href);
    if (typeof vitest.afterAll === "function") {
      vitest.afterAll(() => {
        collector.snapshotRunner();
      });
    }
  } catch {
    // The live ensureModule hook already covers the runner; nothing else to do.
  }
}
