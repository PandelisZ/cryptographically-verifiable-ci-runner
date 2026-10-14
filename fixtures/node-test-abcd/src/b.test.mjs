import assert from "node:assert/strict";
import { test } from "node:test";
import { loadGreeting } from "./b.mjs";

test("reads fixture", () => {
  assert.equal(loadGreeting(), "hello");
});
