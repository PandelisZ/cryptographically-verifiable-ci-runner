import { expect, test } from "vitest";
import { minute } from "./d";

test("uses an external package", () => {
  expect(minute()).toBe(60000);
});
