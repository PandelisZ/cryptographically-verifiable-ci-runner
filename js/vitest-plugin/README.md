# @vci/vitest

This package records the runtime dependencies of each Vitest test file for `vci`. It is plain ESM JavaScript
with JSDoc and has no build step and no runtime dependencies. It supports Vitest `>=3.2 <6` and is tested on
5.0.2 and 4.1.11.

The plugin does nothing unless an output directory is set, either with `VCI_OUT` or with `vci({ outDir })`.

## How the vci CLI uses it

```js
import { writeWrapperConfig } from "@vci/vitest/wrapper";
const wrapper = writeWrapperConfig({ root: projectDir /*, configFile, outFile, outDir */ });
// then: VCI_OUT=<dir> node --import <@vci/vitest/main-preload URL> node_modules/vitest/vitest.mjs \
//         run --config <wrapper> <files…>                          (cwd = projectDir)
```

The `--import` installs the main-process collector before Vitest loads the config. Without it every file is
tainted `vci:main-collector-missing`.

The wrapper imports the user's config (auto-detecting `vitest.config.*` and then `vite.config.*`). Vite's config
loader bundles it, so TypeScript configs, `import.meta.url` and function-form configs all keep working. The
wrapper then appends the plugin. The plugin itself is loaded with a non-analysable dynamic `import()`, so its
file paths stay valid. The wrapper can live in a temp dir or inside the project (default:
`<root>/node_modules/.vci/vitest.config.vci.mjs`).

## Public API

| Entry | Export | Purpose |
|---|---|---|
| `@vci/vitest` | `default vci(options?)` (also named `vci`) | Array of Vite plugins: `vci:scan` (pre transform), `vci:resolve-miss` (post resolveId), `vci` (`configureVitest`) |
| `@vci/vitest` | `VciReporter`, `setupProject`, `writeWrapperConfig`, `findUserConfig` | re-exports |
| `@vci/vitest/wrapper` | `writeWrapperConfig(opts) -> string`, `findUserConfig(root)` | wrapper config generation |
| `@vci/vitest/reporter` | `VciReporter`, `setupProject`, `SETUP_FILE`, `PRELOAD_URL`, `MAIN_PRELOAD_URL` | reporter (merges records) |
| `@vci/vitest/setup` | (setup file) | injected into `setupFiles` (first) |
| `@vci/vitest/preload` | (preload) | injected into the workers' `execArgv` as `--import` |
| `@vci/vitest/main-preload` | (preload) | `node --import` for the Vitest main process (config, plugins, globalSetup) |

`options.outDir` defaults to `process.env.VCI_OUT`.

## Output

For each test file the plugin writes `$VCI_OUT/<sha256(testId)>.jsonl`, where `testId` is relative to the
Vitest root and uses `/` separators. The first line is `meta` and the last line is `result`. The records in
between are sorted by kind and deduplicated. See `docs/CONTRACTS.md`.

```
{"v":1,"kind":"meta","testId":"src/b.test.ts","project":"","vitest":"5.0.2","vite":"8.3.1","node":"26.9.0","root":"/abs/project","collector":"@vci/vitest@0.1.0"}
{"kind":"module","path":"/abs/project/src/b.test.ts","via":"vite-graph"}
{"kind":"module","path":"/abs/project/src/b.ts","via":"vite-graph"}
{"kind":"external","name":"vitest","version":"5.0.2"}
{"kind":"read","path":"/abs/project/fixtures/b.json"}
{"kind":"probe","path":"/abs/project/.env"}
{"kind":"result","state":"passed","tests":1,"failed":0,"skipped":0,"durationMs":2}
```

Additions to CONTRACTS.md, all backwards compatible:
- `meta.collector`: package name and version.
- `module.via` takes one of `"vite-graph"` (main-process module graph), `"runner"` (the worker's Vite module
  runner) or `"node-hooks"` (a native `import`/`require` seen by `module.registerHooks`). There is one record per
  path, and the first source in that order wins.
- `result.state` can also be `"skipped"`. Anything that is not `"passed"` must be treated as not attestable.
- `taint.reason` is free text. Examples: `child_process.spawn`, `fetch`, `net.connect`, `net.Socket.connect`,
  `dgram.Socket.send`, `worker_threads.Worker`, `vci:main-collector-missing`, `vci:global-setup-modules-unavailable`,
  `fs.cp:tree-too-large:<path>`, `sqlite.backup`, `module.findPackageJSON:not-found`,
  `process.env.enumerate`, `fs.glob`, `fs.readdir.recursive`, `isolate:false`, `pool:vmThreads`, `pool:browser`,
  `native-runner`, `fs-module-cache`, `typecheck`, `snapshot:written`, `snapshot:update-all`,
  `vci:worker-collector-missing`, `vci:plugin-not-in-project`, `external-without-version:<path>`,
  `run:unhandled-errors`, `run:interrupted`.

Semantics that matter to the Rust side:
- A `read` is a successful read, stat, exists, access, realpath, readlink or open of a file **or directory**.
- A `probe` is the same kind of access failing with `ENOENT`/`ENOTDIR` (also `statSync(p, { throwIfNoEntry: false })`
  returning `undefined`). It also covers the candidate paths of relative/absolute module resolutions (extensions,
  `index.*`, `package.json`; for successful resolutions too, so a higher-priority candidate created later is
  noticed), and the Vite `.env` files (`.env`, `.env.local`, `.env.<mode>`, `.env.<mode>.local`) when they do not
  exist. Existing resolution candidates that are files or symlinks are `read`s, so a symlinked module is recorded by
  its link path as well as by the realpath Vite reports.
- A `readdir` is a directory listing, including the static directory prefix of `import.meta.glob` and of template
  or concatenated relative `import()`. The prefix is walked recursively when the pattern can span directories.
- Any path under `node_modules/<pkg>` is reported as `external` (name and version from the nearest `package.json`
  that has both), never as a path.
- Paths can lie outside the repo, for example `os.tmpdir()` reads. The Rust side decides whether that is attestable.
- Files the test itself created (`mkdtemp` dirs, full `writeFile` overwrites) are not reported when read back, and
  stats of the ancestors of a `mkdtemp` dir are ignored. What was copied or linked into them is reported at the
  source: `fs.cp`/`cpSync` (the whole source tree), `link`, `symlink` (the target), `rename` (the old path).
- Native readers are reported as reads: `fs.openAsBlob`, `fs.watch`/`watchFile`, `statfs`, `process.loadEnvFile`,
  `node:sqlite` `DatabaseSync` paths (patched when `node:sqlite` is first loaded), `module.findPackageJSON` results.
- Snapshot files Vitest reads for the test (inside a `readSnapshotFile` frame) are reported, which covers
  `toMatchFileSnapshot` targets and custom `resolveSnapshotPath` locations.
- Snapshot files, config files, setup-file graphs from global configuration, and the lockfile are **global inputs**
  for the Rust side.
- Main-process records (reads, probes, env, taints made by the config file, inline plugins and globalSetup code,
  plus the globalSetup module graph from `project.runner`) are added to every test file of the run.

## Collectors

1. **Main process** (`onTestModuleEnd`): walks `importedModules` from the test module and from the user's setup
   files, in every Vite environment of the project, plus the modules the project's (and root project's) module
   runner evaluated for globalSetup. The `vci:scan` plugin records resolution candidates and aliased glob/template
   prefixes.
   **Main-process collector** (`--import` of `main-preload`): the same fs/env/network patches as the workers, but
   only activity with a user frame on the stack is recorded. User frames are files outside `node_modules`, plus the
   `*.timestamp-*` module Vite bundles the config into; Node's module loader reading on its own behalf is ignored.
2. **Worker preload** (`--import`): patches `node:fs` for sync, callback and promise APIs, followed by
   `syncBuiltinESMExports()`. It also proxies `process.env`, wraps `child_process`, `net`, `http`, `https`,
   `http2`, `tls`, `dgram`, `dns`, `worker_threads.Worker`, global `fetch`/`WebSocket`/`EventSource` to taint,
   and registers `module.registerHooks({ resolve })` for externals and failed resolutions.
3. **Worker setup file**: follows the Vite module runner by wrapping `evaluatedModules.ensureModule` and taking
   snapshots, which is the fallback for computed `import()` that the graph misses. It also wraps the worker RPC
   `resolve`/`fetch` to turn failed runtime imports into probes, and writes a marker so the reporter can taint a
   file whose worker collectors never ran.

Worker activity is attributed using structured V8 stacks, sync and async. The rules are in `docs/spike.md`.

## Tests

```
npm test                   # node --test --test-concurrency=1 test/
npm run test:vitest4       # also runs against Vitest 4.1.11 (npm install into a temp dir)
```

The suite runs `fixtures/vitest-abcd` in place through a wrapper written to a temp dir. It also runs throwaway
copies of the fixture with extra test files for spawn, probe, env, opaque import, fetch, promise and callback
fs, glob, optional import, tmp files, CJS require, `vi.mock` with and without `__mocks__` (the missing
`__mocks__/a.ts` is recorded as a probe), the threads pool and the non-attestable modes.

## Vitest 4.1.11

`VCI_TEST_VITEST4=1 node --test test/vitest4.test.js` runs `npm install vitest@4.1.11` into a temp copy of the
fixture and then runs the same core assertions: B reads `b.json` and imports `b.ts`, C imports `impl-x.ts`,
D uses `ms@2.1.3`, A does not pick up B's or C's dependencies, and the spawn and probe cases behave as on 5.0.2.
It passes. `--no-isolate`, `--pool vmForks`, `--pool threads` and `experimental.fsModuleCache` were also
checked by hand on 4.1.11 and produce the expected taints.

## Known gaps

- Native addons, time, locale, and other state that is not read through fs/env are not seen, as the plan says.
- Third-party Vite plugins (code under `node_modules`) reading files in the main process are not recorded; only
  their package version is an input.
- A file-system call made from a callback that Node invokes with **no** user frame on the stack is ignored when
  Vitest frames are present. An example is `setTimeout(fs.readFile, 0, p, cb)` handing a bare fs function to Node.
- `fs` bindings that user code captured before the preload ran cannot be patched. Because the preload runs
  first, this only affects code loaded by `--require`/`--import` flags placed before it.
- `vitest list` through the wrapper with `VCI_OUT` set is not meant to be used. Run `list` without `VCI_OUT`.
