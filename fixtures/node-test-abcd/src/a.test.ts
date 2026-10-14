import assert from "node:assert/strict";
import { test } from "node:test";
import { add } from "@/a.ts";

test("add", () => {
  const sum: number = add(1, 2);
  assert.equal(sum, 3);
});
