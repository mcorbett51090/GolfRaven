import { describe, expect, it } from "vitest";
import { CONTRACT_VERSION, PlaceholderCatalogSchema } from "../src/index.js";

describe("@golfraven/catalog (P0 placeholder)", () => {
  it("exports CONTRACT_VERSION = 0 until P1 defines the real schema", () => {
    expect(CONTRACT_VERSION).toBe(0);
  });

  it("validates a minimal payload with the placeholder zod schema", () => {
    const result = PlaceholderCatalogSchema.safeParse({ contractVersion: 0 });
    expect(result.success).toBe(true);
  });

  it("rejects a payload with the wrong contract version", () => {
    const result = PlaceholderCatalogSchema.safeParse({ contractVersion: 1 });
    expect(result.success).toBe(false);
  });
});
