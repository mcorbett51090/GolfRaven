import { describe, expect, it } from "vitest";
import { POLICY_VERSION } from "../src/index.js";

describe("@golfraven/rules (P0 placeholder)", () => {
  it("exports POLICY_VERSION = 0 until P1/§8 defines real rules", () => {
    expect(POLICY_VERSION).toBe(0);
  });
});
