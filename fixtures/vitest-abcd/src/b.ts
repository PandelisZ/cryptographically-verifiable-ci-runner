import { readFileSync } from "node:fs";

export const loadGreeting = (path: string): string =>
  JSON.parse(readFileSync(path, "utf8")).greeting;
