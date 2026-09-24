import { describe, expect, it } from "vitest";
import { CONTRACT_VERSION, ContractVersionSchema } from "../src/index.js";

describe("@golfraven/catalog", () => {
  it("exports CONTRACT_VERSION = 0 until the M-freeze (build plan §10 P1)", () => {
    expect(CONTRACT_VERSION).toBe(0);
  });

  it("validates a minimal payload against ContractVersionSchema", () => {
    const result = ContractVersionSchema.safeParse({ contractVersion: 0 });
    expect(result.success).toBe(true);
  });

  it("rejects a payload with the wrong contract version", () => {
    const result = ContractVersionSchema.safeParse({ contractVersion: 1 });
    expect(result.success).toBe(false);
  });
});
