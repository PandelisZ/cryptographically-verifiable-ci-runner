import { afterAll } from "vitest";
import { threadId } from "node:worker_threads";
import { appendFileSync } from "node:fs";
const log = (m) => appendFileSync(new URL("./worker.log", import.meta.url), m + "\n");
log(`[setup-loaded] pid=${process.pid} tid=${threadId} file=${globalThis.__vitest_worker__?.filepath}`);
afterAll(() => {
  const st = globalThis.__vitest_worker__;
  const mods = [...st.evaluatedModules.idToModuleMap.entries()].filter(([id, n]) => (n.evaluated || n.promise) && !id.includes('/vitest/dist') && !id.includes('@vitest')).map(([id]) => id.replace(st.config.root, ''));
  log(`[spike-worker] pid=${process.pid} tid=${threadId} file=${st.filepath.split('/').pop()} evaluated: ${JSON.stringify(mods)}`);
});
