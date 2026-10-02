import { describe, expect, it } from "vitest";
import { compareSemver, isBelowMinAppVersion, parseSemver } from "../src/catalog/semver";

describe("compareSemver", () => {
  it.each([
    ["1.0.0", "1.0.0", 0],
    ["1.2.3", "1.2.4", -1],
    ["1.10.0", "1.9.0", 1],
    ["2.0.0", "10.0.0", -1],
    ["1.0.0-alpha", "1.0.0", -1],
    ["1.0.0", "1.0.0-rc.1", 1],
    ["1.0.0-alpha", "1.0.0-alpha.1", -1],
    ["1.0.0-alpha.1", "1.0.0-alpha.beta", -1],
    ["1.0.0-beta.2", "1.0.0-beta.11", -1],
    ["1.0.0+build.5", "1.0.0+build.9", 0],
  ] as const)("%s vs %s", (a, b, want) => {
    expect(compareSemver(a, b)).toBe(want);
  });

  it("returns null for non-semver input", () => {
    expect(compareSemver("1.0", "1.0.0")).toBeNull();
    expect(compareSemver("v1.0.0", "1.0.0")).toBeNull();
    expect(parseSemver("")).toBeNull();
  });
});

describe("isBelowMinAppVersion", () => {
  it("is true only when the app is older", () => {
    expect(isBelowMinAppVersion("1.0.0", "1.0.1")).toBe(true);
    expect(isBelowMinAppVersion("1.0.1", "1.0.1")).toBe(false);
    expect(isBelowMinAppVersion("2.0.0", "1.9.9")).toBe(false);
  });
  it("fails closed on an unparseable app version", () => {
    expect(isBelowMinAppVersion("garbage", "0.0.0")).toBe(true);
  });
});
