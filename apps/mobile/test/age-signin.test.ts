import { describe, expect, it } from "vitest";
import { AgeGate, DEFAULT_MIN_AGE, MemoryDeviceFlagStore, SqliteDeviceFlagStore, evaluateBirthYear } from "../src/age";
import { openNodeSqlite } from "./support/node-sqlite";

const NOW = () => new Date("2026-10-02T12:00:00.000Z");

describe("evaluateBirthYear (year-only, conservative boundary)", () => {
  it.each([
    [2000, "eligible"],
    [2009, "eligible"], // 2026-2009-1 = 16
    [2010, "ineligible"], // 15 or 16: cannot be sure => not admitted
    [2011, "ineligible"],
    [2026, "ineligible"],
    [2027, "invalid"],
    [1899, "invalid"],
    [1900, "eligible"],
    [Number.NaN, "invalid"],
    [2000.5, "invalid"],
  ] as const)("born %s => %s", (year, want) => {
    expect(evaluateBirthYear(year, 2026, DEFAULT_MIN_AGE)).toBe(want);
  });

  it("a higher server minAge (counsel can raise it without a release) moves the boundary", () => {
    expect(evaluateBirthYear(2009, 2026, 16)).toBe("eligible");
    expect(evaluateBirthYear(2009, 2026, 18)).toBe("ineligible");
    expect(evaluateBirthYear(2007, 2026, 18)).toBe("eligible");
  });
});

describe("AgeGate (O18 / P4 AT 20)", () => {
  it("under the minimum: refused, and the retry with another year is refused on that install", async () => {
    const gate = new AgeGate(new MemoryDeviceFlagStore(), NOW);
    expect(await gate.state()).toBe("unknown");
    expect(await gate.submitBirthYear(2012, 16)).toEqual({ status: "ineligible" });
    expect(await gate.state()).toBe("ineligible");
    // "changing the year on the same install is refused"
    expect(await gate.submitBirthYear(1990, 16)).toEqual({ status: "blocked" });
    expect(await gate.state()).toBe("ineligible");
  });

  it("the SQLite flag store (still used for preferences) keeps the not-eligible flag across a restart and stores no birth year", async () => {
    const db = await openNodeSqlite();
    await new AgeGate(new SqliteDeviceFlagStore(db), NOW).submitBirthYear(2015, 16);
    const reopened = new AgeGate(new SqliteDeviceFlagStore(db), NOW);
    expect(await reopened.state()).toBe("ineligible");
    expect(await reopened.submitBirthYear(1980, 16)).toEqual({ status: "blocked" });
    const rows = await db.all<{ key: string; value: string }>("SELECT key, value FROM device_flags");
    expect(rows).toEqual([{ key: "age_gate", value: "ineligible" }]); // no birth year anywhere
  });

  it("eligible: remembered as a fact, never the birth year", async () => {
    const db = await openNodeSqlite();
    const gate = new AgeGate(new SqliteDeviceFlagStore(db), NOW);
    expect(await gate.submitBirthYear(1985, 16)).toEqual({ status: "eligible" });
    expect(await gate.state()).toBe("eligible");
    const dump = JSON.stringify(await db.all("SELECT * FROM device_flags"));
    expect(dump).not.toContain("1985");
  });

  it("an implausible year is invalid and records nothing (it is a typo, not an answer)", async () => {
    const flags = new MemoryDeviceFlagStore();
    const gate = new AgeGate(flags, NOW);
    expect(await gate.submitBirthYear(3000, 16)).toEqual({ status: "invalid" });
    expect(await gate.submitBirthYear(12, 16)).toEqual({ status: "invalid" });
    expect(await flags.get("age_gate")).toBeNull();
    expect(await gate.submitBirthYear(1990, 16)).toEqual({ status: "eligible" });
  });
});
