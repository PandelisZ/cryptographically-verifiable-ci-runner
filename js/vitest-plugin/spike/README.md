Spike harness for docs/spike.md (M0). Not part of the published package.

Run against a scratch copy of fixtures/vitest-abcd (copy e.test.ts.txt / e.ts.txt into src/ as .ts):

    # graph vs. worker-evaluated modules
    echo 'import p from "/abs/path/to/spike/graph-plugin.mjs"; export default { plugins: [p()], test: { include: ["src/**/*.test.ts"] } }' > spike.config.mjs
    npx vitest run --config spike.config.mjs   # reporter output on stdout, worker output in spike/worker.log

    # fs/env attribution: add ["--import", "file:///abs/path/to/spike/fs-preload.mjs"] to project.config.execArgv
