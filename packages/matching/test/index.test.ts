import { describe, expect, it } from "vitest";
import {
  MATCHER_VERSION,
  matchCheckIn,
  matchRoute,
  resolveAskUser,
} from "../src/index.js";

describe("@golfraven/matching", () => {
  it("exports MATCHER_VERSION = 1 (build plan §7.4 v1)", () => {
    expect(MATCHER_VERSION).toBe(1);
  });

  it("exports the core entry points", () => {
    expect(typeof matchRoute).toBe("function");
    expect(typeof matchCheckIn).toBe("function");
    expect(typeof resolveAskUser).toBe("function");
  });

  it("matchRoute rejects an empty fix list rather than guessing", () => {
    expect(() => matchRoute({ fixes: [], candidates: [] })).toThrow(RangeError);
  });

  it("matchRoute returns typeahead when no candidates are given", () => {
    const outcome = matchRoute({
      fixes: [{ point: { lat: 35.9, lon: -84.3 }, timestamp: 0 }],
      candidates: [],
    });
    expect(outcome.kind).toBe("typeahead");
  });
});
