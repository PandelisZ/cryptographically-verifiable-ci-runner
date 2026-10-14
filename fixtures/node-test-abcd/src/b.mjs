import { existsSync, readFileSync } from "node:fs";

// A local override wins when it exists (so its absence is an input too).
export const loadGreeting = () => {
  const local = new URL("../fixtures/b.local.json", import.meta.url);
  const p = existsSync(local) ? local : new URL("../fixtures/b.json", import.meta.url);
  return JSON.parse(readFileSync(p, "utf8")).greeting;
};
