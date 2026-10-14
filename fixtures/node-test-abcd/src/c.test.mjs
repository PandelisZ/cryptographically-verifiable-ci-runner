import assert from "node:assert/strict";
import { test } from "node:test";
import { loadImpl } from "./c";

test("computed dynamic import", async () => {
  const impl = await loadImpl("x");
  assert.equal(impl.name, "x");
});
