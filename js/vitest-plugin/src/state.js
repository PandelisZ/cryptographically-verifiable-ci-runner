// Main-process state shared by every instance of the plugin and the reporter in this process.

import * as path from "node:path";

const KEY = Symbol.for("vci.vitest.main-state");

/**
 * @typedef {object} MainState
 * @property {string | null} outDir
 * @property {string | null} partsDir
 * @property {Map<string, import("./scan.js").ScanResult>} scans  module file -> scan result
 * @property {Map<string, Set<string>>} misses  importer file -> candidate paths of failed resolutions
 * @property {Map<string, Set<string>>} resolves  importer file -> candidate paths of relative/absolute
 *   specifiers it resolved (classified as probe/read when the run ends)
 * @property {WeakSet<object>} vitests  Vitest instances we registered a reporter for
 * @property {WeakMap<object, Array<{kind: "taint", reason: string} | {kind: "path", path: string}>>} projects
 *   project -> records added to each of its test files
 * @property {Set<string>} ignoreDirs
 * @property {Set<string>} snapshotWrites  test files whose snapshots were written this run
 * @property {boolean} snapshotWriteUnattributed
 */

/**
 * @param {{outDir?: string}} [options]
 * @returns {MainState}
 */
export function getState(options = {}) {
  const g = /** @type {any} */ (globalThis);
  /** @type {MainState} */
  let st = g[KEY];
  if (!st) {
    st = {
      outDir: null,
      partsDir: null,
      scans: new Map(),
      misses: new Map(),
      resolves: new Map(),
      vitests: new WeakSet(),
      projects: new WeakMap(),
      ignoreDirs: new Set(),
      snapshotWrites: new Set(),
      snapshotWriteUnattributed: false,
    };
    g[KEY] = st;
  }
  const out = options.outDir || process.env.VCI_OUT || null;
  if (out && !st.outDir) {
    st.outDir = path.resolve(out);
    st.partsDir = path.join(st.outDir, ".vci-parts");
  }
  return st;
}
