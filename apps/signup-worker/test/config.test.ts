import { describe, expect, it } from "vitest";
import { K2_GATE_CLOSES_AT_FLOOR, checkK2Day0, checkK2GateClosesAt, checkK2GateMatchesDay0 } from "../src/config";

// N2: the retention cron must never be able to delete a confirmed row the
// K2 verdict still needs. Every invalid form from the reverify report's
// repro (§2 "N2 / N8: retention cron and K2_GATE_CLOSES_AT") gets its own
// case here, plus the exact floor boundary.
describe("checkK2GateClosesAt (N2)", () => {
  it("rejects unset", () => {
    expect(checkK2GateClosesAt(undefined).ok).toBe(false);
  });

  it("rejects an empty string", () => {
    expect(checkK2GateClosesAt("").ok).toBe(false);
  });

  it("rejects garbage", () => {
    expect(checkK2GateClosesAt("garbage").ok).toBe(false);
  });

  it('rejects a bare year ("2026") — used to parse to 2026-01-01 and enable deletion immediately', () => {
    const result = checkK2GateClosesAt("2026");
    expect(result.ok).toBe(false);
  });

  it('rejects a bare "1" — V8 parses this to 2001-01-01', () => {
    const result = checkK2GateClosesAt("1");
    expect(result.ok).toBe(false);
  });

  it("rejects a date-only string (no time component) even if it's otherwise plausible", () => {
    const result = checkK2GateClosesAt("2026-11-20");
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toMatch(/malformed/);
  });

  it("rejects day 0 typed into this var by mistake (a plausible-looking but too-early timestamp)", () => {
    const result = checkK2GateClosesAt("2026-10-10T00:00:00Z");
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toMatch(/earlier than/);
  });

  it("rejects a timestamp one second before the floor", () => {
    const oneSecondBefore = "2026-11-15T23:59:59Z";
    expect(checkK2GateClosesAt(oneSecondBefore).ok).toBe(false);
  });

  it("accepts the floor timestamp exactly (2026-10-05 P0 start + 42 days)", () => {
    const result = checkK2GateClosesAt(K2_GATE_CLOSES_AT_FLOOR);
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.gateCloses.toISOString()).toBe("2026-11-16T00:00:00.000Z");
  });

  it("accepts a well-formed, sufficiently-late timestamp", () => {
    expect(checkK2GateClosesAt("2026-12-01T09:00:00Z").ok).toBe(true);
  });

  it("rejects a timestamp with a non-Z offset even if otherwise well-formed (strict format)", () => {
    expect(checkK2GateClosesAt("2026-12-01T09:00:00+00:00").ok).toBe(false);
  });

  it("rejects trailing milliseconds (must match the exact strict pattern)", () => {
    expect(checkK2GateClosesAt("2026-12-01T09:00:00.000Z").ok).toBe(false);
  });

  // A-4: a calendar day-of-month rollover (e.g. Nov has 30 days) passes the
  // regex + NaN checks, and V8 silently rolls it FORWARD a day — harmless
  // direction, but not the strict calendar check the format implies.
  it("A-4: rejects a nonexistent calendar date that V8 would silently roll forward", () => {
    const result = checkK2GateClosesAt("2026-11-31T00:00:00Z");
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toMatch(/round-trip/);
  });

  it("A-4: rejects a 24:00:00 rollover the same way", () => {
    expect(checkK2GateClosesAt("2026-11-16T24:00:00Z").ok).toBe(false);
  });
});

// A-3: K2_DAY0 is the bare-date companion Matt copies verbatim from
// docs/p0/K2.md, cross-checked against K2_GATE_CLOSES_AT below.
describe("checkK2Day0 (A-3)", () => {
  it("rejects unset", () => {
    expect(checkK2Day0(undefined).ok).toBe(false);
  });

  it("rejects an empty string", () => {
    expect(checkK2Day0("").ok).toBe(false);
  });

  it("rejects a date-time (must be a bare date)", () => {
    expect(checkK2Day0("2026-10-05T00:00:00Z").ok).toBe(false);
  });

  it("rejects a nonexistent calendar date", () => {
    expect(checkK2Day0("2026-02-30").ok).toBe(false);
  });

  it("accepts a well-formed bare date", () => {
    const result = checkK2Day0("2026-10-05");
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.day0.toISOString()).toBe("2026-10-05T00:00:00.000Z");
  });
});

// A-3: the cross-check that closes the gap checkK2GateClosesAt's floor
// alone leaves open once day 0 itself lands after the floor date.
describe("checkK2GateMatchesDay0 (A-3)", () => {
  it("accepts when K2_GATE_CLOSES_AT is exactly K2_DAY0 + 42 days", () => {
    const day0 = new Date("2026-10-05T00:00:00Z");
    const gateCloses = new Date("2026-11-16T00:00:00Z"); // +42 days exactly
    expect(checkK2GateMatchesDay0(gateCloses, day0).ok).toBe(true);
  });

  it('rejects "day 0 typed into the gate var" — gateCloses == day0, not day0+42', () => {
    const day0 = new Date("2026-11-20T00:00:00Z");
    const gateCloses = new Date("2026-11-20T00:00:00Z"); // the mistake
    const result = checkK2GateMatchesDay0(gateCloses, day0);
    expect(result.ok).toBe(false);
  });

  it("rejects an off-by-one-day mismatch", () => {
    const day0 = new Date("2026-10-05T00:00:00Z");
    const gateCloses = new Date("2026-11-17T00:00:00Z"); // +43 days
    expect(checkK2GateMatchesDay0(gateCloses, day0).ok).toBe(false);
  });
});
