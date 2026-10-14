// Resolver hooks for `npm test` (node --test), the shape of a real project's: map the `@/`
// alias to src/, and try TypeScript and .mjs suffixes for extensionless relative imports.
import { registerHooks } from "node:module";
import path from "node:path";
import { pathToFileURL } from "node:url";

const srcRoot = path.resolve(import.meta.dirname, "../src");

registerHooks({
  resolve(specifier, context, nextResolve) {
    const mapped = specifier.startsWith("@/") ? pathToFileURL(path.join(srcRoot, specifier.slice(2))).href : specifier;
    try {
      return nextResolve(mapped, context);
    } catch (error) {
      const relative = mapped.startsWith("./") || mapped.startsWith("../") || mapped.startsWith("file:");
      if (error?.code === "ERR_MODULE_NOT_FOUND" && relative) {
        for (const suffix of [".ts", ".mjs", "/index.ts"]) {
          try {
            return nextResolve(mapped + suffix, context);
          } catch {
            // try the next suffix
          }
        }
      }
      throw error;
    }
  },
});
