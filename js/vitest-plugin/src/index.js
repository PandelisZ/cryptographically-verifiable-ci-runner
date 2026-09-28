// @vci/vitest: Vite/Vitest plugin that records per-test-file runtime dependencies.
//
// Inert unless an output directory is configured (`options.outDir` or `VCI_OUT`).

import * as path from "node:path";

import { SCAN_PLUGIN_NAME, VciReporter, setupProject } from "./reporter.js";
import { scanSource } from "./scan.js";
import { getState } from "./state.js";
import { PACKAGE_DIR, idToFsPath, isInNodeModules, resolutionCandidates, toSlash } from "./util.js";

export { VciReporter, setupProject, MAIN_PRELOAD_URL } from "./reporter.js";
export { writeWrapperConfig, findUserConfig } from "./wrapper.js";

/**
 * @typedef {object} VciOptions
 * @property {string} [outDir] directory for the JSONL output (default: `process.env.VCI_OUT`)
 */

/**
 * Absolute base path of a relative, root-absolute or file: specifier, or null (bare, virtual).
 * @param {string} source
 * @param {string} importerFile
 * @param {string} root
 */
function specBase(source, importerFile, root) {
  const spec = source.replace(/[?#].*$/, "");
  if (spec.startsWith("./") || spec.startsWith("../")) return path.resolve(path.dirname(importerFile), spec);
  if (spec.startsWith("/")) return spec.startsWith(root + "/") ? spec : path.join(root, spec);
  if (spec.startsWith("file://")) return idToFsPath(spec);
  return null;
}

/**
 * The Vitest plugin. Returns an array of Vite plugins:
 *  - `vci:scan` (pre): records directories behind `import.meta.glob` / computed imports, and the
 *    resolution candidates of every relative/absolute import (a higher-priority candidate that
 *    appears later, or a retargeted symlink, changes what the import resolves to),
 *  - `vci:resolve-miss` (post): records failed relative resolutions as probes,
 *  - `vci`: `configureVitest` registers the reporter, the worker setup file and the preload.
 * @param {VciOptions} [options]
 * @returns {any[]}
 */
export default function vci(options = {}) {
  const state = getState(options);
  let root = process.cwd();
  /** @type {import("./scan.js").Alias[]} */
  let aliases = [];
  /** @type {string[]} */
  let extensions = [];

  return [
    {
      name: SCAN_PLUGIN_NAME,
      enforce: "pre",
      /** @param {any} config */
      configResolved(config) {
        if (config && config.root) root = config.root;
        const a = config && config.resolve && config.resolve.alias;
        if (Array.isArray(a)) aliases = a;
        else if (a && typeof a === "object") aliases = Object.entries(a).map(([find, replacement]) => ({ find, replacement }));
        const ex = config && config.resolve && config.resolve.extensions;
        if (Array.isArray(ex)) extensions = ex;
      },
      /** @param {string} source @param {string | undefined} importer */
      resolveId(source, importer) {
        // Observes only; resolution continues with the other plugins.
        if (!state.outDir || !importer || typeof source !== "string") return null;
        if (source.includes("\0") || source.startsWith("virtual:")) return null;
        const importerFile = idToFsPath(importer);
        if (!importerFile) return null;
        const imp = toSlash(importerFile);
        if (isInNodeModules(imp) || imp.startsWith(toSlash(PACKAGE_DIR) + "/")) return null;
        const base = specBase(source, importerFile, root);
        if (!base) return null;
        let set = state.resolves.get(importerFile);
        if (!set) {
          set = new Set();
          state.resolves.set(importerFile, set);
        }
        for (const c of resolutionCandidates(base, extensions)) {
          if (!isInNodeModules(toSlash(c))) set.add(c);
        }
        return null;
      },
      /** @param {string} code @param {string} id */
      transform(code, id) {
        if (!state.outDir || typeof code !== "string") return null;
        const file = idToFsPath(id);
        if (!file || file.includes("/node_modules/")) return null;
        try {
          const res = scanSource(code, file, root, aliases);
          if (res) state.scans.set(file, res);
        } catch {
          state.scans.set(file, { dirs: [], taints: [`vci:scan-error:${file}`] });
        }
        return null;
      },
    },
    {
      name: "vci:resolve-miss",
      enforce: "post",
      /** @param {string} source @param {string | undefined} importer */
      resolveId(source, importer) {
        // Only reached when every other resolver returned null.
        if (!state.outDir || !importer || typeof source !== "string") return null;
        if (source.includes("\0") || source.startsWith("virtual:")) return null;
        const importerFile = idToFsPath(importer);
        if (!importerFile) return null;
        const base = specBase(source, importerFile, root);
        const bases = base ? [base] : [];
        if (!bases.length) return null;
        let set = state.misses.get(importerFile);
        if (!set) {
          set = new Set();
          state.misses.set(importerFile, set);
        }
        for (const b of bases) for (const c of resolutionCandidates(b)) set.add(c);
        return null;
      },
    },
    {
      name: "vci",
      /** @param {{project: any, vitest: any}} ctx */
      configureVitest(ctx) {
        if (!state.outDir) return;
        const { vitest, project } = ctx;
        if (vitest && !state.vitests.has(vitest)) {
          state.vitests.add(vitest);
          // `vitest.reporters` is rebuilt from `vitest.config.reporters` after this hook.
          vitest.config.reporters.push(new VciReporter(options));
        }
        setupProject(project, vitest, state);
      },
    },
  ];
}

export { vci };
