import assert from "node:assert/strict";
import { test } from "node:test";
import ms from "ms";

test("uses a package from the pnpm store", () => {
  const n: number = ms("1s");
  assert.equal(n, 1000);
});
