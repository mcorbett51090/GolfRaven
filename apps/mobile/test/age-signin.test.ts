import { describe, expect, it, vi } from "vitest";
import { AgeGate, DEFAULT_MIN_AGE, MemoryDeviceFlagStore, SqliteDeviceFlagStore, evaluateBirthYear } from "../src/age";
import { offeredProviders, startSignIn, stubProviders, type SignInProvider, type SignInProviderId } from "../src/signin";
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

  it("the not-eligible flag survives a restart (same SQLite file) and is the only thing stored", async () => {
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

function spyProviders(): { providers: Record<SignInProviderId, SignInProvider>; calls: SignInProviderId[] } {
  const calls: SignInProviderId[] = [];
  const mk = (id: SignInProviderId): SignInProvider => ({
    id,
    signIn: vi.fn(() => {
      calls.push(id);
      return Promise.resolve({ ok: true as const, provider: id, stub: true });
    }),
  });
  return { providers: { apple: mk("apple"), google: mk("google"), email: mk("email") }, calls };
}

describe("startSignIn — no provider before the age gate (O18, AT 20)", () => {
  it.each(["apple", "google", "email"] as const)("%s is NOT called while the gate is unknown", async (id) => {
    const { providers, calls } = spyProviders();
    const r = await startSignIn(id, { gate: new AgeGate(new MemoryDeviceFlagStore(), NOW), providers });
    expect(r).toEqual({ status: "age_required" });
    expect(calls).toEqual([]);
  });

  it.each(["apple", "google", "email"] as const)("%s is NOT called after an under-age answer, on any retry", async (id) => {
    const { providers, calls } = spyProviders();
    const gate = new AgeGate(new MemoryDeviceFlagStore(), NOW);
    await gate.submitBirthYear(2014, 16);
    expect(await startSignIn(id, { gate, providers })).toEqual({ status: "blocked" });
    await gate.submitBirthYear(1980, 16); // refused
    expect(await startSignIn(id, { gate, providers })).toEqual({ status: "blocked" });
    expect(calls).toEqual([]);
  });

  it("is called exactly once after an eligible answer", async () => {
    const { providers, calls } = spyProviders();
    const gate = new AgeGate(new MemoryDeviceFlagStore(), NOW);
    await gate.submitBirthYear(1990, 16);
    const r = await startSignIn("google", { gate, providers });
    expect(r).toMatchObject({ status: "signed_in", result: { provider: "google", stub: true } });
    expect(calls).toEqual(["google"]);
  });

  it("the stub providers sign in to nothing real", async () => {
    const r = await stubProviders().apple.signIn();
    expect(r).toEqual({ ok: true, provider: "apple", stub: true });
  });
});

describe("offered providers (Apple 4.8, AT 17)", () => {
  it("Apple is present, and listed first, in every list that offers Google", () => {
    const list = offeredProviders();
    expect(list).toContain("google");
    expect(list).toContain("apple");
    expect(list.indexOf("apple")).toBeLessThan(list.indexOf("google"));
    expect(list).toContain("email");
  });
});
