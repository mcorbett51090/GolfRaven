import { describe, expect, it } from "vitest";
import { MATCHER_VERSION } from "../src/index.js";

describe("@golfraven/matching (P0 placeholder)", () => {
  it("exports MATCHER_VERSION = 0 until P1/§7.4 defines real matching", () => {
    expect(MATCHER_VERSION).toBe(0);
  });
});
