import { expect, test } from "vitest";
import { fileURLToPath } from "node:url";
import { loadGreeting } from "./b";

test("reads fixture", () => {
  const path = fileURLToPath(new URL("../fixtures/b.json", import.meta.url));
  expect(loadGreeting(path)).toBe("hello");
});
