import assert from "node:assert/strict";
import { test } from "node:test";
import { minute } from "./d.mjs";

test("uses an external package", () => {
  assert.equal(minute(), 60000);
});
