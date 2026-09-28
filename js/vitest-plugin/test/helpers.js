// Test helpers: build throwaway copies of the fixture and run Vitest through the wrapper config.

import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

import { MAIN_PRELOAD_URL } from "../src/reporter.js";
import { writeWrapperConfig } from "../src/wrapper.js";

export const PKG_DIR = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
export const FIXTURE = path.resolve(PKG_DIR, "../../fixtures/vitest-abcd");

/** @param {string} prefix */
export function tmpDir(prefix) {
  return fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
}

/**
 * Copy the fixture (sources only) into a temp dir and link its node_modules.
 * @param {{nodeModules?: string, files?: Record<string, string>, config?: string}} [opts]
 * @returns {string} project dir
 */
export function makeProject(opts = {}) {
  const dir = tmpDir("vci-fixture-");
  for (const name of ["src", "fixtures"]) fs.cpSync(path.join(FIXTURE, name), path.join(dir, name), { recursive: true });
  fs.copyFileSync(path.join(FIXTURE, "package.json"), path.join(dir, "package.json"));
  fs.writeFileSync(path.join(dir, "vitest.config.ts"), opts.config ?? fs.readFileSync(path.join(FIXTURE, "vitest.config.ts"), "utf8"));
  fs.symlinkSync(opts.nodeModules ?? path.join(FIXTURE, "node_modules"), path.join(dir, "node_modules"), "dir");
  for (const [rel, content] of Object.entries(opts.files ?? {})) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), content);
  }
  return dir;
}

/**
 * @typedef {object} RunResult
 * @property {number | null} status
 * @property {string} output
 * @property {string} outDir
 * @property {string} wrapper
 * @property {Map<string, any[]>} byTest testId -> records (meta first, result last)
 */

/**
 * Run `vitest run --config <wrapper>` in `project` with VCI_OUT set.
 * @param {string} project
 * @param {{args?: string[], wrapperDir?: string, env?: Record<string, string>}} [opts]
 * @returns {RunResult}
 */
export function runVitest(project, opts = {}) {
  const outDir = tmpDir("vci-out-");
  const wrapper = writeWrapperConfig({
    root: project,
    outFile: path.join(opts.wrapperDir ?? tmpDir("vci-wrapper-"), "vitest.config.vci.mjs"),
  });
  const vitestBin = path.join(project, "node_modules", "vitest", "vitest.mjs");
  // Same command line as the vci adapter: the main-process collector is loaded with --import.
  const r = spawnSync(process.execPath, ["--import", MAIN_PRELOAD_URL, vitestBin, "run", "--config", wrapper, ...(opts.args ?? [])], {
    cwd: project,
    env: { ...process.env, VCI_OUT: outDir, CI: "1", NO_COLOR: "1", ...(opts.env ?? {}) },
    encoding: "utf8",
    timeout: 120_000,
  });
  const output = `${r.stdout ?? ""}\n${r.stderr ?? ""}`;
  return { status: r.status, output, outDir, wrapper, byTest: readOut(outDir) };
}

/**
 * @param {string} outDir
 * @returns {Map<string, any[]>}
 */
export function readOut(outDir) {
  /** @type {Map<string, any[]>} */
  const map = new Map();
  for (const name of fs.readdirSync(outDir)) {
    if (!name.endsWith(".jsonl")) continue;
    const recs = fs
      .readFileSync(path.join(outDir, name), "utf8")
      .split("\n")
      .filter(Boolean)
      .map((l) => JSON.parse(l));
    const meta = recs[0];
    if (!meta || meta.kind !== "meta") throw new Error(`${name}: first record is not meta`);
    map.set(meta.testId, recs);
    map.set(`file:${meta.testId}`, /** @type {any} */ (name));
  }
  return map;
}

/**
 * @param {any[]} recs
 * @param {string} kind
 */
export function ofKind(recs, kind) {
  return recs.filter((r) => r.kind === kind);
}
