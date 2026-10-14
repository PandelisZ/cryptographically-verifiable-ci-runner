import assert from "node:assert/strict";
import { test } from "node:test";
import { shout } from "@fx/lib";

test("uses a workspace package", () => {
  assert.equal(shout("hi"), "HI!");
});
