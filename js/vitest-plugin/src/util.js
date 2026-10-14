// Shared helpers used by both the main process (plugin/reporter) and the worker collectors.
// Keep this module dependency-free: it is loaded by the worker preload before anything else.

import { createHash } from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

// Captured at module load, before the worker collector patches `fs`.
const readFileSync = fs.readFileSync;
const lstatSync = fs.lstatSync;
const realpathSync = fs.realpathSync;

/** Directory of this package (…/vitest-plugin), used to recognise our own stack frames. */
export const PACKAGE_DIR = path.dirname(path.dirname(fileURLToPath(import.meta.url)));

/** Name of the env var the main process uses to hand configuration to workers. */
export const WORKER_ENV = "VCI_WORKER";

/** Env keys that belong to vci itself and are never reported as dependencies. */
export const OWN_ENV_KEYS = new Set([WORKER_ENV, "VCI_OUT", "VCI_TEST_FILE", "VCI_ROOT"]);

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
 * For a path below `node_modules/<pkg>` where `<pkg>` is a link to a directory outside every
 * `node_modules` (a linked workspace package: pnpm, npm and yarn workspaces link them), the same
 * path below the link's real target. That code is repository content: it must be hashed, never
 * identified by the package's version. Otherwise null.
 * @param {string} file absolute path
 * @returns {string | null}
 */
export function linkedPackagePath(file) {
  const p = toSlash(file);
  const marker = "/node_modules/";
  const idx = p.lastIndexOf(marker);
  if (idx < 0) return null;
  const rest = p.slice(idx + marker.length).split("/");
  if (!rest[0] || rest[0].startsWith(".")) return null;
  const n = rest[0].startsWith("@") ? 2 : 1;
  if (rest.length < n) return null;
  const pkgRoot = p.slice(0, idx + marker.length) + rest.slice(0, n).join("/");
  let real;
  try {
    real = toSlash(realpathSync(pkgRoot));
  } catch {
    return null;
  }
  if (real === pkgRoot || real.includes(marker)) return null;
  const tail = rest.slice(n).join("/");
  return tail ? `${real}/${tail}` : real;
}

/** @type {Map<string, string | null>} */
const localCopyCache = new Map();

/**
 * For a file of an installed package that is a copy of a directory of the repository, the
 * package's name; otherwise null. Such a package is identified by the version in its
 * package.json, which does not change when its source in the repository does, so it must never be
 * accepted as an external:
 *  - pnpm's virtual store entry of a `file:` dependency (`node_modules/.pnpm/lib@file+lib/...`),
 *    also used for injected workspace packages;
 *  - a real directory `node_modules/<name>` (npm with install-links, yarn 1) that the
 *    package.json beside that `node_modules` declares as `file:<directory>`.
 * @param {string} file absolute path
 * @returns {string | null}
 */
export function localCopyPackage(file) {
  const p = toSlash(file);
  const marker = "/node_modules/";
  const idx = p.lastIndexOf(marker);
  if (idx < 0) return null;
  const rest = p.slice(idx + marker.length).split("/");
  if (!rest[0] || rest[0].startsWith(".")) return null;
  const n = rest[0].startsWith("@") ? 2 : 1;
  const name = rest.slice(0, n).join("/");
  const pkgRoot = p.slice(0, idx + marker.length) + name;
  const cached = localCopyCache.get(pkgRoot);
  if (cached !== undefined) return cached;
  let out = null;
  const store = /\/node_modules\/\.pnpm\/([^/]+)\/node_modules\/$/.exec(p.slice(0, idx + marker.length));
  if (store && /@file\+/.test(store[1])) {
    out = name;
  } else if (!store) {
    try {
      if (!lstatSync(pkgRoot).isSymbolicLink()) {
        const owner = JSON.parse(readFileSync(path.join(p.slice(0, idx), "package.json"), "utf8"));
        for (const k of ["dependencies", "devDependencies", "optionalDependencies"]) {
          const spec = owner && owner[k] && owner[k][name];
          if (typeof spec === "string" && spec.startsWith("file:") && !/\.(tgz|tar\.gz|tar)$/.test(spec)) out = name;
        }
      }
    } catch {
      // no owner package.json: an ordinary install
    }
  }
  localCopyCache.set(pkgRoot, out);
  return out;
}

/** Node options accepted in NODE_OPTIONS (as in the Rust adapter): memory, warning, stack-trace. */
const NODE_OPTIONS_OK = new Set([
  "--max-old-space-size",
  "--max-semi-space-size",
  "--stack-trace-limit",
  "--stack-size",
  "--test-concurrency",
  "--test-reporter",
  "--test-reporter-destination",
  "--enable-source-maps",
  "--no-warnings",
  "--trace-warnings",
  "--no-deprecation",
  "--trace-deprecation",
  "--disable-warning",
  "--unhandled-rejections",
  "--trace-uncaught",
]);

/**
 * The NODE_OPTIONS tokens vci does not accept (anything but memory, warning and stack-trace
 * options; a quoted value is never accepted).
 * @param {string | undefined} value
 * @returns {string[]}
 */
export function nodeOptionsProblems(value) {
  if (!value) return [];
  /** @type {string[]} */
  const out = [];
  for (const tok of value.split(/\s+/)) {
    if (!tok) continue;
    const raw = tok.includes("=") ? tok.slice(0, tok.indexOf("=")) : tok;
    const name = raw.startsWith("--") ? `--${raw.slice(2).replace(/_/g, "-")}` : raw;
    if (!NODE_OPTIONS_OK.has(name) || /["'\\]/.test(tok)) out.push(tok);
  }
  return out;
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
