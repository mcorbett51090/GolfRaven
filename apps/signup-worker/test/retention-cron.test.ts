import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { runRetentionCron } from "../src/index";
import { makeTestEnv } from "./env";
import type { TestEnv } from "./env";

// N2: "the retention cron can delete rows the K2 verdict is read from" —
// the reverify report's repro showed `"2026"` and `"1"` enabling deletion
// IMMEDIATELY, and a day-0-typed-by-mistake value enabling it inside the
// K2 window. These tests reproduce that repro and assert the fixed
// behavior: no deletion of a confirmed-then-unsubscribed row unless
// K2_GATE_CLOSES_AT is strictly valid AND the grace period has elapsed.

function seedUnsubscribedRow(
  env: TestEnv,
  id: string,
  unsubscribedAt: string,
): void {
  env.DB.rows.push({
    id,
    email_lc: `${id}@example.com`,
    consent_version: "2026-09-23",
    age_confirmed: 1,
    source: null,
    created_at: "2026-01-01T00:00:00.000Z",
    confirmed_at: "2026-01-05T00:00:00.000Z",
    unsubscribed_at: unsubscribedAt,
    confirm_token_hash: null,
    confirm_expires_at: null,
    unsubscribe_token_hash: `hash-${id}`,
    unsubscribe_token_hash_prev: null,
  });
}

describe("runRetentionCron — confirmed-row deletion gate (N2)", () => {
  const FIXED_NOW = "2026-12-20T00:00:00.000Z"; // well after floor (2026-11-16) + 30d grace (2026-12-16)
  const OLD_UNSUB = "2026-01-10T00:00:00.000Z"; // long past UNSUBSCRIBED_RETENTION_DAYS

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(FIXED_NOW));
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it.each([
    ["unset", undefined],
    ["empty string", ""],
    ["garbage", "garbage"],
    [
      'bare year "2026" (used to parse to 2026-01-01 and delete immediately)',
      "2026",
    ],
    ['bare "1" (V8 parses to 2001-01-01)', "1"],
    ["date-only, no time component", "2026-11-20"],
    ["day 0 typed into this var by mistake", "2026-10-10T00:00:00Z"],
    ["one second before the floor", "2026-11-15T23:59:59Z"],
  ])(
    "deletes NO confirmed-then-unsubscribed row when K2_GATE_CLOSES_AT is %s",
    async (_label, value) => {
      const env = makeTestEnv(
        value === undefined ? {} : { K2_GATE_CLOSES_AT: value },
      );
      seedUnsubscribedRow(env, "old", OLD_UNSUB);
      const consoleWarnSpy = vi
        .spyOn(console, "warn")
        .mockImplementation(() => {});

      const result = await runRetentionCron(env);

      expect(result.deletedUnsubscribed).toBe(0);
      expect(env.DB.rows).toHaveLength(1);
      expect(consoleWarnSpy).toHaveBeenCalledTimes(1);
      // No PII (no address) in the warning payload.
      const [, payload] = consoleWarnSpy.mock.calls[0]!;
      expect(JSON.stringify(payload)).not.toContain("@example.com");
      consoleWarnSpy.mockRestore();
    },
  );

  it("deletes NO row when the gate is valid but the 30-day grace period has NOT yet elapsed", async () => {
    // Gate closes 5 days before "now" — well short of the 30-day grace.
    const env = makeTestEnv({ K2_GATE_CLOSES_AT: "2026-12-15T00:00:00Z" });
    seedUnsubscribedRow(env, "old", OLD_UNSUB);

    const result = await runRetentionCron(env);
    expect(result.deletedUnsubscribed).toBe(0);
    expect(env.DB.rows).toHaveLength(1);
  });

  it("deletes stale unsubscribed rows once the gate is valid AND the grace period has elapsed", async () => {
    // Gate closed well over 30 days before "now". K2_GATE_CLOSES_AT here is
    // the floor (2026-11-16), which is exactly day0 (2026-10-05, the plan's
    // P0 start) + 42 days — matching K2_DAY0 below (A-3: both vars required).
    const env = makeTestEnv({
      K2_GATE_CLOSES_AT: "2026-11-16T00:00:00Z",
      K2_DAY0: "2026-10-05",
    });
    seedUnsubscribedRow(env, "old", OLD_UNSUB);
    seedUnsubscribedRow(env, "recent", "2026-12-10T00:00:00.000Z"); // within 30d of FIXED_NOW

    const result = await runRetentionCron(env);
    expect(result.deletedUnsubscribed).toBe(1);
    expect(env.DB.rows.map((r) => r.id)).toEqual(["recent"]);
  });

  it("deletes exactly at the grace boundary (now == gateCloses + 30 days)", async () => {
    // FIXED_NOW is 2026-12-20T00:00:00.000Z; gateCloses + 30d must equal that exactly.
    const env = makeTestEnv({
      K2_GATE_CLOSES_AT: "2026-11-20T00:00:00Z",
      K2_DAY0: "2026-10-09",
    });
    seedUnsubscribedRow(env, "old", OLD_UNSUB);

    const result = await runRetentionCron(env);
    expect(result.deletedUnsubscribed).toBe(1);
  });
});

// A-3: K2_GATE_CLOSES_AT's own floor check only catches "day 0 typed into
// this var by mistake" while day 0 itself is before the floor
// (2026-11-16). Once day 0 slips past that date, the identical mistake
// passes the floor — so deletion additionally requires K2_GATE_CLOSES_AT to
// equal EXACTLY K2_DAY0 + 42 days.
describe("runRetentionCron — K2_DAY0 / K2_GATE_CLOSES_AT consistency gate (A-3)", () => {
  const FIXED_NOW = "2026-12-20T00:00:00.000Z";
  const OLD_UNSUB = "2026-01-10T00:00:00.000Z";

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(FIXED_NOW));
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it('reproduces "day 0 typed into K2_GATE_CLOSES_AT by mistake" at a LATE day 0 (past the floor) — deletes NOTHING', async () => {
    // Day 0 is 2026-11-20 (already past the 2026-11-16 floor on its own).
    // The mistake: K2_GATE_CLOSES_AT was set to day 0 itself instead of
    // day 0 + 42 days. K2_GATE_CLOSES_AT's floor check alone would ACCEPT
    // this (2026-11-20 > floor) — only the K2_DAY0 cross-check catches it.
    const env = makeTestEnv({
      K2_DAY0: "2026-11-20",
      K2_GATE_CLOSES_AT: "2026-11-20T00:00:00Z",
    });
    seedUnsubscribedRow(env, "old", OLD_UNSUB);
    const consoleWarnSpy = vi
      .spyOn(console, "warn")
      .mockImplementation(() => {});

    const result = await runRetentionCron(env);

    expect(result.deletedUnsubscribed).toBe(0);
    expect(env.DB.rows).toHaveLength(1);
    expect(consoleWarnSpy).toHaveBeenCalledTimes(1);
    const [, payload] = consoleWarnSpy.mock.calls[0]!;
    expect(JSON.stringify(payload)).not.toContain("@example.com");
    consoleWarnSpy.mockRestore();
  });

  it("deletes NOTHING when K2_GATE_CLOSES_AT is individually valid but K2_DAY0 is unset", async () => {
    const env = makeTestEnv({ K2_GATE_CLOSES_AT: "2026-11-16T00:00:00Z" });
    seedUnsubscribedRow(env, "old", OLD_UNSUB);
    const result = await runRetentionCron(env);
    expect(result.deletedUnsubscribed).toBe(0);
  });

  it("deletes NOTHING when K2_DAY0 is set but does not match K2_GATE_CLOSES_AT - 42 days at all", async () => {
    const env = makeTestEnv({
      K2_DAY0: "2026-09-01",
      K2_GATE_CLOSES_AT: "2026-11-16T00:00:00Z",
    });
    seedUnsubscribedRow(env, "old", OLD_UNSUB);
    const result = await runRetentionCron(env);
    expect(result.deletedUnsubscribed).toBe(0);
  });

  it("deletes correctly once K2_DAY0 and K2_GATE_CLOSES_AT (= day0 + 42d) are BOTH set and consistent", async () => {
    const env = makeTestEnv({
      K2_DAY0: "2026-10-05",
      K2_GATE_CLOSES_AT: "2026-11-16T00:00:00Z",
    });
    seedUnsubscribedRow(env, "old", OLD_UNSUB);
    const result = await runRetentionCron(env);
    expect(result.deletedUnsubscribed).toBe(1);
  });
});
