# M0 spike: Vitest dependency collection

Date: 2026-09-27. Node v26.9.0, macOS arm64.
Versions checked: **Vitest 5.0.2 + Vite 8.3.1** (the fixture's install) and **Vitest 4.1.11 + Vite 8.3.1**
(installed with `npm i -D vitest@4.1.11` into a scratch copy of `fixtures/vitest-abcd`).

The spike harness is kept in `js/vitest-plugin/spike/`:

- `graph-plugin.mjs`: a plugin whose `configureVitest` pushes a reporter into `vitest.config.reporters` and a
  setup file into `project.config.setupFiles`; the reporter walks `importedModules` from the test module in
  every Vite environment at `onTestModuleEnd`.
- `graph-setup.mjs`: a setup file that, in `afterAll`, dumps the worker's `__vitest_worker__.evaluatedModules`
  entries that were evaluated, with `process.pid` and `threadId`.
- `fs-preload.mjs`: an `--import` preload that patches `node:fs` and proxies `process.env`, and logs every call
  with a structured stack classification.
- `e.test.ts.txt` / `e.ts.txt`: an extra test whose import target is fully opaque
  (`const spec = "./impl-" + name + ".ts"; import(/* @vite-ignore */ spec)`).

Sources read: `node_modules/vitest/dist/chunks/index.C-uw7tH9.js` (5.0.2: `_attachProjectServers`, `ModuleFetcher`,
`getModuleGraph`, `fetchWarmModules`, `createReporters`, `SnapshotManager`), `chunks/base.5tQXSzMP.js`
(worker `run()`, `startModuleRunner`, `runBaseTests`), `chunks/index.hTNFpC24.js` (`VitestModuleRunner`,
`VitestTransport`), `chunks/utils.DYj33du9.js` (`resetModules`), `chunks/plugin.d.My_z-jmU.d.ts` (config types),
plus the 4.1.11 `reporters.d.*.d.ts`. Docs: vitest.dev/api/advanced/plugin and /api/advanced/reporters.

## Q1. Do computed dynamic `import()` targets appear in the Vite module graph at `onTestModuleEnd`?

**It depends on the form of the import. The answer is "yes" for C and "no" for fully opaque imports, so the
fallback is needed.**

Output of the graph reporter (Vitest 5.0.2; 4.1.11 prints the same sets), ids made relative to the root:

```
[spike] graph a.test.ts env=ssr: [ '/src/a.test.ts', '/src/a.ts' ]
[spike] graph b.test.ts env=ssr: [ '/src/b.test.ts', '/src/b.ts' ]
[spike] graph c.test.ts env=ssr: [ '/src/c.test.ts', '/src/c.ts', '/src/impl-x.ts', '\x00vite/dynamic-import-helper.js' ]
[spike] graph d.test.ts env=ssr: [ '/src/d.test.ts', '/src/d.ts', '/node_modules/ms/index.js' ]
[spike] graph e.test.ts env=ssr: [ '/src/e.test.ts', '/src/e.ts' ]          <-- impl-x.ts missing
```

- C (`` import(`./impl-${name}.ts`) ``) is rewritten by Vite's dynamic-import-vars into a glob over `./impl-*.ts`
  plus `\0vite/dynamic-import-helper.js`, so **every** file matching the glob becomes a graph edge of `c.ts`. That
  is why `impl-x.ts` shows up. The glob depends on a directory listing, which the graph does not record: adding
  `impl-y.ts` changes what the rewritten code can load. The plugin therefore scans sources for `import.meta.glob`
  and template-literal or concatenated relative `import()` and records `readdir` of the static directory prefix
  (recursively when a wildcard is followed by more path segments).
- E (fully opaque specifier) is resolved at runtime through `ModuleFetcher.fetch` ("handle unresolved id of dynamic
  import skipped by Vite import analysis") -> `ensureEntryFromUrl`. That creates a node but **no importer
  edge**, so it is not reachable from the test module.
- Graph nodes are shared across all test files in the run, but edges are static imports, so reachability from
  one test module does not pick up another file's modules. No cross-contamination was seen.

Worker-side `evaluatedModules` (setup file `afterAll`) lists what actually ran, including the opaque target:

```
[spike-worker] pid=92522 file=b.test.ts evaluated: ["/spike/setup.mjs","worker_threads","fs","/src/b.test.ts","url","/src/b.ts"]
[spike-worker] pid=92525 file=a.test.ts evaluated: ["/spike/setup.mjs","worker_threads","fs","/src/a.test.ts","/src/a.ts"]
[spike-worker] pid=92521 file=e.test.ts evaluated: [...,"/src/e.test.ts","/src/e.ts","/src/impl-x.ts"]
[spike-worker] pid=92523 file=d.test.ts evaluated: [...,"/src/d.test.ts","/src/d.ts","/node_modules/ms/index.js"]
[spike-worker] pid=92524 file=c.test.ts evaluated: [...,"/src/c.test.ts","/src/c.ts","\u0000vite/dynamic-import-helper.js","/src/impl-x.ts"]
```

**Fallback chosen:** in the worker, the setup file wraps `__vitest_worker__.evaluatedModules.ensureModule` on the
live instance, which the module runner calls for every module it fetches, and snapshots `idToModuleMap` at setup
time and again in `afterAll`. Each entry becomes a `module` record with `via:"runner"`, or an `external` record
when it is under `node_modules`. This is what records `impl-x.ts` for the opaque case, and it also records it
for C.
Also: with `isolate: true` (the default) both `forks` and `threads` start a **fresh worker per test file**
(distinct pid, or distinct threadId for threads, per file above), so worker-side records cannot leak between files.
The collector still keys every record by `__vitest_worker__.filepath`.

Runtime resolution failures (`try { await import('./optional') } catch {}`) do not reach the worker as fs calls,
because resolution happens in the main process. A `resolveId` hook with `enforce: 'post'` does see the miss,
but in practice it arrives as a root-relative id (`/src/maybe-there.ts`) with importer `<root>/index.html`, so it
cannot be attributed to a test file. The worker side is used instead. Vitest reads
`__vitest_worker__.rpc` on every call (`const rpc = () => state().rpc`), so the setup file replaces it with a
Proxy. The Proxy remembers `resolve` calls that return null, and when `fetch` rejects it emits `probe` records
for the candidate paths (the exact path, common extensions, `index.*` and `package.json`). birpc answers every
property with a function, so a marker property on the RPC object cannot be used to detect an existing wrap.
The post `resolveId` hook is kept as a secondary source, keyed by importer.

## Q2. How to get externals (node_modules packages) per test file

Three sources, all per test file, merged:

1. Main process graph: externalized deps appear as nodes such as `/node_modules/ms/index.js` (see D above).
2. Worker `evaluatedModules`: externalized imports appear with their resolved file path (D above).
3. Worker preload `module.registerHooks({ resolve })` (Node >= 22.15; present on Node 26). It sees every native
   `import`/`require` in the worker, including `createRequire(...)("ms")` from test code and transitive requires
   inside externals, as well as **failed** resolutions:
   ```
   pid=94660 file=f.test.ts resolve ms -> /node_modules/ms/index.js
   pid=94660 file=f.test.ts resolve-fail does-not-exist-pkg MODULE_NOT_FOUND
   pid=94658 file=undefined resolve chai -> /node_modules/chai/index.js      (vitest's own deps, parentURL in vitest/dist)
   ```
   Resolutions whose `parentURL` is inside vitest/vite internals are ignored. Sources 1 and 2 already cover
   user-level externals loaded by the runner.

Any path under `.../node_modules/<pkg>/` is turned into `{kind:"external",name,version}` using the nearest
`package.json` that has both `name` and `version`, walking up to the package root (`node_modules/<pkg>` or
`node_modules/@scope/pkg`; pnpm's `.pnpm/.../node_modules/<pkg>` works because the last `node_modules` segment
wins). If no version can be found, the file gets a taint record (fail open).

## Q3. Injecting a worker preload / setup file from `configureVitest` (Vitest 5 and 4.1)

`configureVitest(ctx)` runs in `Vitest._attachProjectServers` after config resolution and **before** reporters are
created. `ctx` has `{ project, vitest, injectTestProjects, defineCacheKeyGenerator (5.x), experimental_defineCacheKeyGenerator }`.

- **Setup file:** `project.config.setupFiles.push(absPath)` works in both versions (the spike setup file ran for all
  files in 5.0.2 and 4.1.11). `setupFiles` is already resolved to absolute paths at this point, and the docs warn
  it is not re-resolved, so the pushed path must be absolute. `project.serializedConfig` is recomputed on every
  run (`_serializeOverriddenConfig`), so the mutation reaches the workers.
- **Preload:** `project.config.execArgv.push("--import", fileUrl)` works for `forks` (child process) and `threads`
  (worker_threads accept `--import`). Vitest 5 already passes
  `--experimental-import-meta-resolve --require .../suppress-warnings.cjs --conditions node --conditions development`,
  and our `--import` is appended:
  ```
  pid=94658 tid=0 preload start execArgv=[..., "--import", "file:///.../preload.mjs"]
  pid=94783 tid=1 preload start ...   (threads pool, one threadId per test file)
  ```
- **Reporter:** pushing into `vitest.reporters` has no effect because it is overwritten, as the docs also say.
  Push an instance into `vitest.config.reporters` instead; `createReporters` passes instances through unchanged.
  Verified in both versions.
- The reporter's `onInit(vitest)` runs before any pool is created. The plugin uses it as a second chance to set up
  projects whose Vite config does not contain the plugin (for example `projects` without `extends: true`). Those
  projects are also marked tainted, because the transform-time glob scan cannot run there.

## Q4. Public APIs used, and internals touched

Public or documented:
- Plugin hook `configureVitest` (3.1+), `project.config` mutation, `vitest.config.reporters`.
- Reporter API: `onInit`, `onTestModuleEnd`, `onTestRunEnd`, `TestModule.moduleId/project/state()/diagnostic()/children.allTests()/errors()`,
  `TestCase.result()`, `TestProject.name/config/vite`, `vitest.version`, `vitest.config.root`.
- Vite: `environment.moduleGraph.getModuleById`, `EnvironmentModuleNode.importedModules/file/id`, plugin
  `transform` / `resolveId` hooks.
- Node: `module.registerHooks`, `module.syncBuiltinESMExports`, `Error.captureStackTrace` with a structured
  `prepareStackTrace`.

Internal (guarded with try/catch; a failure leads to a taint record or to fewer ignored reads, never to fewer
recorded dependencies):
- `globalThis.__vitest_worker__` (`filepath`, `evaluatedModules`, `config.root`). Present in 4.1 and 5.0.
- `vitest.snapshot.add` (wrapped to detect snapshot writes per file), `project.tmpDir`, `vitest._tmpDir`
  (used only to ignore Vitest's own transformed-code cache reads).

## Attribution of worker fs/env activity (evidence)

With the fs/env preload installed, every call was classified by frames from a structured stack
(sync frames and V8 async frames):

```
readFileSync /fixtures/b.json                 syncUser=2 asyncUser=0 top=src/b.ts                       <- user
readFileSync /var/folders/.../T/<nanoid>/ssr/<sha1>  syncUser=0 asyncUser=1 top=vitest/dist/chunks/index.hTNFpC24.js  <- vitest tmp transform cache
existsSync  /src/__snapshots__/b.test.ts.snap  syncUser=0 asyncUser=0 top=vitest/dist/chunks/node.*.js  <- vitest snapshot state
realpathSync /node_modules/ms/index.js         syncUser=0 asyncUser=2 top=vitest/dist/module-evaluator.js
env WATCH_REPORT_DEPENDENCIES                  syncUser=0 asyncUser=0 (node ESM loader, ~40x per file)
```

Rules used by the collector, all fail-open:
- If there is a synchronous user frame (any frame outside `node:`, vitest/vite/@vitest packages, and this
  package), record the call.
- If the only user frames are async (a user `await` further up the chain), record it, unless the path is in
  Vitest's tmp or cache dirs or inside vitest/vite's own package dirs.
  This removes the transformed-code reads, which happen under the user's `await import()`.
- If there are no user frames and at least one vitest/vite frame, ignore it as Vitest's own activity
  (snapshot existence checks, module loading).
- If only Node-internal frames are present, ignore paths under `node_modules` (loader realpath/read of vitest's own
  deps). Record everything else.
- `process.env` reads are recorded only when a user frame (sync or async) is on the stack. Enumerating
  `process.env` (`ownKeys`) from user code is recorded as a taint, because the dependency cannot be expressed per key.
- `process.env` cannot be replaced by a naive `Proxy`: Node 26 throws `ERR_INVALID_OBJECT_DEFINE_PROPERTY` when a
  `set` is forwarded with the proxy as receiver. The proxy needs explicit `set` and `defineProperty` traps that
  assign on the real object.

## Non-attestable modes (emit taint for every file of the project)

`isolate: false`; `pool` = `vmThreads` / `vmForks` / anything other than `forks` or `threads` (including custom
pool objects); `browser.enabled`; `experimental.viteModuleRunner === false` (native runner, both versions);
file-system module cache (`fsModuleCache` top-level in 5.x, `experimental.fsModuleCache` in 4.1);
`typecheck.enabled`; `snapshotOptions.updateSnapshot === "all"`; plugin not present in a project's Vite
config. Per file: snapshot files added, updated or deleted during the run; taint from the worker collectors;
unhandled errors or an interrupted run (all files).

## Results on Vitest 4.1.11 (final plugin)

`VCI_TEST_VITEST4=1 node --test test/vitest4.test.js` (in `js/vitest-plugin`) runs `npm install vitest@4.1.11`
into a temp copy of the fixture and runs the plugin through the wrapper config. It passes:

- B: `read fixtures/b.json` and `module src/b.ts`.
- C: `module src/impl-x.ts`.
- D: `external ms@2.1.3`.
- A: none of B's or C's paths.
- No taints on A-D. The spawn test gets `child_process.execFileSync`, and the missing-file test gets a `probe`.

Checked by hand on 4.1.11: `--no-isolate` gives `isolate:false`. `--pool vmForks` gives `pool:vmForks` (plus
`isolate:false`, which the worker reports). `--pool threads` gives the same records as forks.
`experimental.fsModuleCache: true` gives `fs-module-cache`.

The only API difference that matters between the two versions is where the fs module cache option lives
(`experimental.fsModuleCache` in 4.1, top-level `fsModuleCache` in 5.0). The plugin checks both.
`defineCacheKeyGenerator` exists only in 5.x and is not used. Everything else the plugin touches behaves the
same in both versions: `configureVitest` context, `project.config.setupFiles`/`execArgv` mutation,
`vitest.config.reporters`, `__vitest_worker__.evaluatedModules`/`rpc`/`filepath`, and the reporter API.
