import { expect, test } from "vitest";
import { loadImpl } from "./c";

test("computed dynamic import", async () => {
  const impl = await loadImpl("x");
  expect(impl.name).toBe("x");
});
