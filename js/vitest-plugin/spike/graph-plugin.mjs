import { fileURLToPath } from "node:url";
const setup = fileURLToPath(new URL("./graph-setup.mjs", import.meta.url));
export default function spike() {
  return {
    name: "spike",
    configureVitest(ctx) {
      const { vitest, project } = ctx;
      console.log("[spike] configureVitest keys", Object.keys(ctx), "setupFiles", project.config.setupFiles, "isolate", project.config.isolate, "pool", project.config.pool, "execArgv", project.config.execArgv);
      project.config.setupFiles.push(setup);
            vitest.onAfterSetServer?.(()=>{});
      const rep = {
        onTestModuleEnd(tm) {
          const envs = tm.project.vite.environments;
          for (const name of Object.keys(envs)) {
            const g = envs[name].moduleGraph;
            const root = g.getModuleById(tm.moduleId);
            if (!root) continue;
            const seen = new Set(); const q = [root];
            while (q.length) { const n = q.pop(); if (seen.has(n)) continue; seen.add(n); q.push(...n.importedModules); }
            console.log(`[spike] graph ${tm.moduleId.split('/').pop()} env=${name}:`, [...seen].map(n => n.id?.replace(tm.project.config.root, '') ).filter(id => !id.includes('/vitest/dist')));
          }
        },
      };
      vitest.config.reporters.push(rep);
      console.log("[spike] reporters now", vitest.reporters?.length, typeof vitest.config.reporters);
    },
  };
}
