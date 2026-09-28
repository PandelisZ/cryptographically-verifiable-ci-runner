// Shared helpers used by both the main process (plugin/reporter) and the worker collectors.
// Keep this module dependency-free: it is loaded by the worker preload before anything else.

import { createHash } from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

// Captured at module load, before the worker collector patches `fs`.
const readFileSync = fs.readFileSync;
const lstatSync = fs.lstatSync;

/** Directory of this package (…/vitest-plugin), used to recognise our own stack frames. */
export const PACKAGE_DIR = path.dirname(path.dirname(fileURLToPath(import.meta.url)));

/** Name of the env var the main process uses to hand configuration to workers. */
export const WORKER_ENV = "VCI_WORKER";

/** Env keys that belong to vci itself and are never reported as dependencies. */
export const OWN_ENV_KEYS = new Set([WORKER_ENV, "VCI_OUT"]);

/**
 * @param {string} s
 * @returns {string} lowercase sha256 hex
 */
export function sha256(s) {
  return createHash("sha256").update(s).digest("hex");
}

/**
 * Convert slashes to '/'. Paths stay absolute.
 * @param {string} p
 */
export function toSlash(p) {
  return p.replace(/\\/g, "/");
}

/**
 * Packages whose own activity is not a dependency of the test (Vitest/Vite internals).
 * Matched against '/'-normalised absolute paths.
 */
export const INTERNAL_PKG_RE =
  /\/node_modules\/(?:vitest|vite|vite-node|tinypool|tinyspy|@vitest\/[^/]+)\//;

/**
 * @param {string} p '/'-normalised absolute path
 */
export function isInternalPath(p) {
  return INTERNAL_PKG_RE.test(p);
}

/**
 * @param {string} p '/'-normalised absolute path
 */
export function isInNodeModules(p) {
  return p.includes("/node_modules/");
}

/**
 * Turn a Vite module id / file / URL into an absolute filesystem path, or null for virtual ids.
 * @param {string | null | undefined} id
 * @returns {string | null}
 */
export function idToFsPath(id) {
  if (!id || typeof id !== "string") return null;
  if (id.startsWith("\0") || id.startsWith("virtual:")) return null;
  let p = id;
  if (p.startsWith("file://")) {
    try {
      p = fileURLToPath(p.replace(/[?#].*$/, ""));
    } catch {
      return null;
    }
  }
  if (p.startsWith("/@fs/")) p = p.slice(4);
  p = p.replace(/[?#].*$/, "");
  if (!path.isAbsolute(p)) return null;
  return p;
}

/** @type {Map<string, {name: string, version: string} | null>} */
const pkgCache = new Map();

/**
 * Resolve the package owning a file inside node_modules: nearest package.json with both
 * `name` and `version`, walking up but not beyond the package root that follows the last
 * `node_modules` segment.
 * @param {string} file absolute path
 * @returns {{name: string, version: string} | null | undefined} undefined if not in node_modules,
 *   null if in node_modules but no usable package.json
 */
export function packageOf(file) {
  const p = toSlash(file);
  const marker = "/node_modules/";
  const idx = p.lastIndexOf(marker);
  if (idx < 0) return undefined;
  const rest = p.slice(idx + marker.length).split("/");
  if (!rest[0]) return null;
  const nameParts = rest[0].startsWith("@") ? rest.slice(0, 2) : rest.slice(0, 1);
  const pkgRoot = p.slice(0, idx + marker.length) + nameParts.join("/");
  const cached = pkgCache.get(pkgRoot + "|" + path.dirname(p));
  if (cached !== undefined) return cached;
  let dir = path.dirname(p);
  let result = null;
  // Walk from the file's directory up to pkgRoot (inclusive).
  while (dir.length >= pkgRoot.length) {
    try {
      const json = JSON.parse(readFileSync(path.join(dir, "package.json"), "utf8"));
      if (json && typeof json.name === "string" && typeof json.version === "string") {
        result = { name: json.name, version: json.version };
        break;
      }
    } catch {
      // no package.json here, keep walking
    }
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  pkgCache.set(pkgRoot + "|" + path.dirname(p), result);
  return result;
}

/**
 * Candidate files Node/Vite might look at for a relative/absolute specifier (a superset of
 * Node's and Vite's default `resolve.extensions` order, plus `extraExts`).
 * @param {string} base absolute path of the specifier
 * @param {string[]} [extraExts] additional extensions (Vite `resolve.extensions`)
 * @returns {string[]}
 */
export function resolutionCandidates(base, extraExts = []) {
  const exts = [".js", ".mjs", ".cjs", ".json", ".node", ".ts", ".mts", ".cts", ".tsx", ".jsx"];
  for (const e of extraExts) if (typeof e === "string" && e.startsWith(".") && !exts.includes(e)) exts.push(e);
  const out = [base];
  for (const e of exts) out.push(base + e);
  for (const e of [".js", ".json", ".node", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".mts", ".cts"]) out.push(path.join(base, "index" + e));
  for (const e of extraExts) if (typeof e === "string" && e.startsWith(".")) out.push(path.join(base, "index" + e));
  out.push(path.join(base, "package.json"));
  return out;
}

/**
 * How a resolution candidate is recorded: `probe` if nothing is there (creating it later may
 * change what the specifier resolves to), `read` for a file or symlink (so a symlinked module is
 * an input by its link path, not only by the realpath Vite reports), nothing for a directory
 * (its `index.*` / `package.json` candidates are recorded on their own).
 * @param {string} p absolute path
 * @returns {"probe" | "read" | null}
 */
export function candidateKind(p) {
  try {
    const st = lstatSync(p);
    return st.isDirectory() ? null : "read";
  } catch (e) {
    const code = /** @type {any} */ (e).code;
    return code === "ENOENT" || code === "ENOTDIR" ? "probe" : "read";
  }
}

/**
 * @param {string} p absolute path
 * @param {string[]} dirs absolute directories ('/'-normalised, no trailing slash)
 */
export function isUnder(p, dirs) {
  const s = toSlash(p);
  for (const d of dirs) {
    if (!d) continue;
    if (s === d || s.startsWith(d.endsWith("/") ? d : d + "/")) return true;
  }
  return false;
}
