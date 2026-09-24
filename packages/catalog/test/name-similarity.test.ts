import { describe, expect, it } from "vitest";
import { diceCoefficient, normalizeName } from "../src/name-similarity.js";

describe("normalizeName", () => {
  it("lowercases, strips punctuation and collapses whitespace", () => {
    expect(normalizeName("  Pebble  Hills, Golf Club!  ")).toBe(
      "pebble hills golf club",
    );
  });
});

describe("diceCoefficient", () => {
  it("is 1 for identical names", () => {
    expect(
      diceCoefficient("Pebble Hills Golf Club", "Pebble Hills Golf Club"),
    ).toBe(1);
  });

  it("is >= 0.8 for a minor rewording (G-P1-12 threshold)", () => {
    expect(
      diceCoefficient("Pebble Hills Golf Club", "Pebble Hills Golf Course"),
    ).toBeGreaterThanOrEqual(0.8);
  });

  it("is low for unrelated names", () => {
    expect(
      diceCoefficient("Pebble Hills Golf Club", "Riverside Municipal"),
    ).toBeLessThan(0.3);
  });
});
