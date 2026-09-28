// Source scan for imports whose target set depends on a directory listing:
//   import.meta.glob(...)                    (Vite glob import)
//   import(`./dir/${x}.ts`)                  (Vite dynamic-import-vars rewrites this to a glob)
//   import('./dir/' + x)                     (concatenation, same treatment)
// For each we compute the static directory prefix. The reporter turns these into `readdir`
// records (recursively when the wildcard can span directories) for every test file that
// reached the scanned module. Anything we cannot parse becomes a taint (fail open).

import * as path from "node:path";

/**
 * @typedef {object} ScanResult
 * @property {Array<{dir: string, recursive: boolean}>} dirs
 * @property {string[]} taints
 */

/**
 * A Vite alias entry (`config.resolve.alias` after config resolution).
 * @typedef {{find: string | RegExp, replacement: string}} Alias
 */

/**
 * Apply the first matching alias to `spec`, the way @rollup/plugin-alias does.
 * @param {string} spec
 * @param {Alias[]} aliases
 * @returns {string | null} the rewritten specifier, or null if no alias matches
 */
export function applyAlias(spec, aliases) {
  for (const a of aliases || []) {
    if (!a || typeof a.replacement !== "string") continue;
    const f = a.find;
    if (typeof f === "string") {
      if (spec === f || spec.startsWith(f.endsWith("/") ? f : f + "/")) return a.replacement + spec.slice(f.length);
    } else if (f instanceof RegExp) {
      f.lastIndex = 0;
      if (f.test(spec)) {
        f.lastIndex = 0;
        return spec.replace(f, a.replacement);
      }
    }
  }
  return null;
}

/**
 * Static directory of a glob/template pattern that may start with an alias: the alias is
 * applied first, and an absolute result is used as a filesystem path.
 * @param {string} pattern
 * @param {string} baseDir
 * @param {string} root
 * @param {Alias[]} aliases
 * @param {boolean} [forceRecursive]
 * @returns {{dir: string, recursive: boolean} | null}
 */
export function staticDirWithAlias(pattern, baseDir, root, aliases, forceRecursive = false) {
  const direct = staticDirOf(pattern, baseDir, root, forceRecursive);
  if (direct) return direct;
  const aliased = applyAlias(pattern, aliases);
  if (aliased == null || aliased === pattern) return null;
  if (path.isAbsolute(aliased)) {
    // Aliases resolve to filesystem paths (not root-relative ones): express it relative to the
    // importer so staticDirOf treats it as a path.
    const rel = path.relative(baseDir, aliased).split(path.sep).join("/");
    return staticDirOf(rel.startsWith("../") ? rel : "./" + rel, baseDir, root, forceRecursive);
  }
  return staticDirOf(aliased, baseDir, root, forceRecursive);
}

const GLOB_CHARS = /[*?{}[\]()!]/;

/**
 * @param {string} pattern glob or template prefix (relative to `baseDir`, or root-absolute)
 * @param {string} baseDir absolute directory of the importing module
 * @param {string} root project root (for patterns starting with '/')
 * @param {boolean} [forceRecursive]
 * @returns {{dir: string, recursive: boolean} | null}
 */
export function staticDirOf(pattern, baseDir, root, forceRecursive = false) {
  let p = pattern;
  if (p.startsWith("!")) return null; // negations never add files
  let absBase;
  if (p.startsWith("./") || p.startsWith("../")) absBase = baseDir;
  else if (p.startsWith("/")) {
    absBase = root;
    p = "." + p;
  } else return null; // aliases / bare: cannot resolve here
  const m = GLOB_CHARS.exec(p);
  const staticPart = m ? p.slice(0, m.index) : p;
  const dynamicPart = m ? p.slice(m.index) : "";
  // Directory containing the first wildcard.
  const staticDir = staticPart.endsWith("/") ? staticPart : path.posix.dirname(staticPart);
  const recursive = forceRecursive || dynamicPart.includes("/") || dynamicPart.includes("**");
  return { dir: path.resolve(absBase, staticDir), recursive };
}

/**
 * Parse the string literals of the first argument of `import.meta.glob(` starting at `start`
 * (index just after the opening parenthesis).
 * @param {string} code
 * @param {number} start
 * @returns {{patterns: string[], base: string | null, ok: boolean}}
 */
function parseGlobArgs(code, start) {
  let i = start;
  const skipWs = () => {
    while (i < code.length && /\s/.test(code[i])) i++;
  };
  /** @returns {string | null} */
  const readString = () => {
    const q = code[i];
    if (q !== "'" && q !== '"' && q !== "`") return null;
    let j = i + 1;
    let out = "";
    while (j < code.length && code[j] !== q) {
      if (code[j] === "\\") {
        out += code[j + 1];
        j += 2;
        continue;
      }
      if (q === "`" && code[j] === "$" && code[j + 1] === "{") return null;
      out += code[j];
      j++;
    }
    if (j >= code.length) return null;
    i = j + 1;
    return out;
  };
  skipWs();
  /** @type {string[]} */
  const patterns = [];
  if (code[i] === "[") {
    i++;
    for (;;) {
      skipWs();
      if (code[i] === "]") {
        i++;
        break;
      }
      const s = readString();
      if (s == null) return { patterns, base: null, ok: false };
      patterns.push(s);
      skipWs();
      if (code[i] === ",") i++;
    }
  } else {
    const s = readString();
    if (s == null) return { patterns, base: null, ok: false };
    patterns.push(s);
  }
  // Optional options object: look for `base: '...'` up to the matching close paren.
  let base = null;
  let depth = 1;
  let j = i;
  for (; j < code.length && depth > 0; j++) {
    if (code[j] === "(") depth++;
    else if (code[j] === ")") depth--;
  }
  const rest = code.slice(i, j);
  const bm = /\bbase\s*:\s*(['"])([^'"]*)\1/.exec(rest);
  if (bm) base = bm[2];
  else if (/\bbase\s*:/.test(rest)) return { patterns, base: null, ok: false };
  return { patterns, base, ok: true };
}

/**
 * @param {string} code source code (pre-transform)
 * @param {string} file absolute path of the module
 * @param {string} root project root
 * @param {Alias[]} [aliases] resolved Vite aliases
 * @returns {ScanResult | null} null when nothing relevant was found
 */
export function scanSource(code, file, root, aliases = []) {
  if (!code.includes("import")) return null;
  const hasGlob = code.includes("import.meta.glob");
  const hasDyn = /\bimport\s*\(/.test(code);
  if (!hasGlob && !hasDyn) return null;
  const baseDir = path.dirname(file);
  /** @type {ScanResult} */
  const res = { dirs: [], taints: [] };

  if (hasGlob) {
    const re = /import\.meta\.glob(?:Eager)?\s*(?:<[^>]*>)?\s*\(/g;
    let m;
    while ((m = re.exec(code))) {
      const { patterns, base, ok } = parseGlobArgs(code, m.index + m[0].length);
      if (!ok) {
        res.taints.push(`vci:unparsed-import.meta.glob:${file}`);
        continue;
      }
      let dirForBase = baseDir;
      if (base) {
        if (base.startsWith("/")) dirForBase = path.resolve(root, "." + base);
        else if (base.startsWith("./") || base.startsWith("../")) dirForBase = path.resolve(baseDir, base);
        else if (applyAlias(base, aliases) != null && path.isAbsolute(/** @type {string} */ (applyAlias(base, aliases)))) {
          dirForBase = /** @type {string} */ (applyAlias(base, aliases));
        } else {
          res.taints.push(`vci:unresolved-glob-base:${file}`);
          continue;
        }
      }
      for (const pat of patterns) {
        if (pat.startsWith("!")) continue;
        const d = staticDirWithAlias(pat, dirForBase, root, aliases);
        if (d) res.dirs.push(d);
        else res.taints.push(`vci:unresolved-glob:${pat}:${file}`);
      }
    }
  }

  if (hasDyn) {
    // Template literal with interpolation: import(`./x/${a}.ts`)
    const tre = /\bimport\s*\(\s*(?:\/\*[\s\S]*?\*\/\s*)*`([^`]*)`/g;
    let m;
    while ((m = tre.exec(code))) {
      const tpl = m[1];
      const idx = tpl.indexOf("${");
      if (idx < 0) continue; // plain literal: a normal static edge in the module graph
      const prefix = tpl.slice(0, idx);
      if (!prefix) continue; // fully dynamic: a runtime import, recorded by the worker runner hook
      // Relative, root-absolute or aliased prefixes (Vite's dynamic-import-vars turns these into
      // a glob, so a missing target never reaches the runner). Bare package prefixes stay
      // externals, covered by the package version.
      const d = staticDirWithAlias(tpl.replace(/\$\{[^}]*\}/g, "*"), baseDir, root, aliases);
      if (d) res.dirs.push(d);
    }
    // Concatenation: import('./dir/' + x ...), also with an aliased prefix.
    const cre = /\bimport\s*\(\s*(?:\/\*[\s\S]*?\*\/\s*)*(['"])([^'"]*)\1\s*\+/g;
    while ((m = cre.exec(code))) {
      const d = staticDirWithAlias(m[2] + "*", baseDir, root, aliases, true);
      if (d) res.dirs.push(d);
    }
  }
  if (!res.dirs.length && !res.taints.length) return null;
  return res;
}
