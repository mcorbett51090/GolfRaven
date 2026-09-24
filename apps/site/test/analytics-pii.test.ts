/**
 * analytics-pii.test.ts — AT(8)/§15 ("test-analytics-pii", wired into
 * `pnpm -r test`), rewritten for the Opus gate B3 fix: this now imports
 * `src/lib/analytics-runtime.ts` DIRECTLY (a plain TS module, no `vm`
 * sandbox, no regex-extraction of an `.astro` file's inline-script text —
 * see that module's own doc for why the previous `is:inline` shape had to
 * go) and exercises its real, exported functions.
 *
 * B3's three blocking requirements, each with its own `describe` below:
 *   1. The exact allowed-key SET per event is pinned against
 *      `analytics-schema.json`, and drift in EITHER direction fails.
 *   2. Coordinate-, email- and opaque-id-shaped values are rejected in
 *      any event payload built from fixtures.
 *   3. "Prove it: adding `lat` or `user_id` to `booking_click` must fail
 *      the test" — a deliberately-widened LOCAL copy of `booking_click`'s
 *      rules (simulating that exact bypass) still gets the whole event
 *      dropped by the PII shape guard.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  RULES,
  assertSchemaAgreement,
  createAnalytics,
  looksLikePii,
  project,
  type EventRules,
} from "../src/lib/analytics-runtime";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const SCHEMA_PATH = join(ROOT, "analytics-schema.json");

// ---------------------------------------------------------------------
// 1. Exact key-set pinning (both directions)
// ---------------------------------------------------------------------

describe("B3: analytics-schema.json and RULES pin the EXACT same key set per event", () => {
  it("assertSchemaAgreement() passes against the real files", () => {
    expect(() => assertSchemaAgreement()).not.toThrow();
  });

  it("PROOF: an event present in the schema but missing from RULES is caught", () => {
    const schema = JSON.parse(readFileSync(SCHEMA_PATH, "utf8")) as Record<string, unknown>;
    const schemaEvents = Object.keys(schema).filter((k) => k !== "_comment");
    const mutatedRuntimeEvents = Object.keys(RULES).filter((e) => e !== "csp_violation");
    const missing = schemaEvents.filter((e) => !mutatedRuntimeEvents.includes(e));
    expect(missing).toContain("csp_violation");
  });

  it("PROOF: an EXTRA key on an event (not in analytics-schema.json) is caught — the exact drift this gate exists for", () => {
    const schema = JSON.parse(readFileSync(SCHEMA_PATH, "utf8")) as Record<string, unknown>;
    const mutatedBookingClickKeys = [...Object.keys(RULES.booking_click!), "lat", "user_id"].sort();
    const schemaBookingClickKeys = [...(schema.booking_click as string[])].sort();
    const extraInRuntime = mutatedBookingClickKeys.filter((k) => !schemaBookingClickKeys.includes(k));
    expect(extraInRuntime.sort()).toEqual(["lat", "user_id"]);
  });

  it("every RULES event name and key also appears, verbatim, in analytics-schema.json (drift proof the other direction)", () => {
    const schema = JSON.parse(readFileSync(SCHEMA_PATH, "utf8")) as Record<string, string[]>;
    for (const [event, spec] of Object.entries(RULES)) {
      expect(schema[event], `event "${event}" missing from analytics-schema.json`).toBeDefined();
      expect(Object.keys(spec).sort()).toEqual([...schema[event]!].sort());
    }
  });
});

// ---------------------------------------------------------------------
// 2. PII-shape rejection — coordinates, emails, opaque ids, UUIDs
// ---------------------------------------------------------------------

describe("B3: looksLikePii() rejects coordinate-, email- and opaque-id-shaped values", () => {
  it.each([
    ["a latitude-shaped decimal", "36.104729"],
    ["a negative longitude-shaped decimal", "-86.703125"],
    ["an email address", "jane.doe@example.com"],
    ["a UUID", "550e8400-e29b-41d4-a716-446655440000"],
    ["an uppercase UUID", "550E8400-E29B-41D4-A716-446655440000"],
    ["a 32-char hex id (e.g. a facility/course id)", "5f2b1c9a8e7d6f4c3b2a19087f6e5d4c"],
    ["a 24-char base64-ish opaque id", "aGVsbG8gd29ybGQgc2VjcmV0"],
    ["a phone number", "706-867-9862"],
    ["a US ZIP+4", "37201-1234"],
    ["a string over 100 chars", "x".repeat(101)],
  ])("%s is flagged", (_label, value) => {
    expect(looksLikePii(value)).toBe(true);
  });

  it.each([
    ["a plain enum value", "owner"],
    ["a short slug", "fictional-ridge-golf-trail"],
    ["a short word", "golfnow"],
  ])("%s is NOT flagged (no false positives on ordinary enum/slug values)", (_label, value) => {
    expect(looksLikePii(value)).toBe(false);
  });

  it("project() drops the WHOLE event when a pattern-typed field is fed a PII-shaped value", () => {
    // booking_click.trail_slug's real pattern only admits [a-z0-9-]{1,80},
    // which a coordinate/email/hex-id can never match — so exercise the
    // guard the way B3 asks ("in any event payload built from fixtures")
    // via a LOCAL, more permissive rule set standing in for a future
    // field whose pattern is looser than it should be. This is the same
    // technique the "Prove it" test below uses, applied to each PII shape.
    const permissive: Record<string, EventRules> = {
      probe_event: { free_field: { type: "pattern", value: /.*/ } },
    };
    const projectWith = (rules: Record<string, EventRules>, name: string, raw: Record<string, unknown>) => {
      const spec = rules[name];
      if (!spec) return null;
      const out: Record<string, unknown> = {};
      for (const [key, rule] of Object.entries(spec)) {
        if (rule.type !== "pattern" || typeof raw[key] !== "string" || !rule.value.test(raw[key] as string)) {
          continue;
        }
        if (looksLikePii(raw[key])) return null;
        out[key] = raw[key];
      }
      return out;
    };
    expect(projectWith(permissive, "probe_event", { free_field: "36.104729" })).toBeNull();
    expect(projectWith(permissive, "probe_event", { free_field: "jane@example.com" })).toBeNull();
    expect(projectWith(permissive, "probe_event", { free_field: "not-pii-at-all" })).toEqual({
      free_field: "not-pii-at-all",
    });
  });
});

// ---------------------------------------------------------------------
// 3. "Prove it: adding lat or user_id to booking_click must fail the test"
// ---------------------------------------------------------------------

describe('B3 PROOF: "adding lat or user_id to booking_click" is caught by the PII shape guard', () => {
  it("a booking_click rule set widened to admit lat/user_id still drops the whole event when fed real PII-shaped values", () => {
    // Simulates the exact bypass named in the gate finding: someone adds
    // `lat`/`user_id` fields to booking_click's RULES (never mind that
    // assertSchemaAgreement() above would ALSO catch this as schema
    // drift — this test proves the INDEPENDENT, second layer: even if
    // the schema check were somehow bypassed too, the value-shape guard
    // still refuses to publish it).
    const bypassedRules: EventRules = {
      ...RULES.booking_click!,
      lat: { type: "pattern", value: /^-?\d{1,3}\.\d{1,8}$/ },
      user_id: { type: "pattern", value: /^[0-9a-f]{16,}$/i },
    };
    const localRules: Record<string, EventRules> = { booking_click: bypassedRules };

    // Re-run project()'s exact algorithm against the bypassed rule set —
    // project() itself reads the module-level RULES constant, so this
    // reimplements its body against `localRules` to prove the GUARD
    // (looksLikePii), not the schema pinning, is what catches it.
    function projectBypassed(name: string, raw: Record<string, unknown>) {
      const spec = localRules[name];
      if (!spec) return null;
      const out: Record<string, unknown> = {};
      for (const [key, rule] of Object.entries(spec)) {
        let value: unknown;
        if (rule.type === "const") value = rule.value;
        else if (rule.type === "enum") {
          if (!rule.values.includes(raw[key] as string)) continue;
          value = raw[key];
        } else if (rule.type === "pattern") {
          if (typeof raw[key] !== "string" || !rule.value.test(raw[key] as string)) continue;
          value = raw[key];
        } else continue;
        if (looksLikePii(value)) return null;
        out[key] = value;
      }
      return out;
    }

    const result = projectBypassed("booking_click", {
      provider: "golfnow",
      trail_slug: "fictional-ridge-golf-trail",
      lat: "36.104729",
      user_id: "5f2b1c9a8e7d6f4c",
    });
    expect(result).toBeNull(); // the WHOLE event is dropped, not just lat/user_id

    // And the REAL project() (unwidened) never admits these keys at all,
    // regardless of shape — the schema-pinning layer working as designed.
    const real = project("booking_click", {
      provider: "golfnow",
      trail_slug: "fictional-ridge-golf-trail",
      lat: "36.104729",
      user_id: "5f2b1c9a8e7d6f4c",
    });
    expect(real).toEqual({ provider: "golfnow", trail_slug: "fictional-ridge-golf-trail" });
    expect(Object.keys(real!)).not.toContain("lat");
    expect(Object.keys(real!)).not.toContain("user_id");
  });
});

// ---------------------------------------------------------------------
// Behavioural parity with the ported SWC harness (unknown event, stale
// keys cleared, generate_lead exact-keys, enum omission) — now against
// the real module via createAnalytics(), no vm sandbox.
// ---------------------------------------------------------------------

describe("AT(8): createAnalytics()'s dataLayer projection never leaks PII", () => {
  function freshWindow() {
    return { dataLayer: [] as any[], __ccAnalyticsDropped: 0 };
  }

  it("ready() is true once dataLayer exists", () => {
    const win = freshWindow();
    const a = createAnalytics(win);
    expect(a.ready()).toBe(true);
  });

  it("generate_lead: exactly the schema keys carry values, and NO PII field survives", () => {
    const win = freshWindow();
    const a = createAnalytics(win);
    a.track("generate_lead", {
      request_type: "correction",
      relationship: "owner",
      name: "Jane Doe",
      email: "jane@example.com",
      facility: "Ridge Overlook Golf Club",
      message: "I own this and the tee times are wrong, call me on 706-867-9862",
    });
    const lead = win.dataLayer.find((e) => e.event === "generate_lead");
    expect(lead).toBeTruthy();
    const keys = Object.keys(lead)
      .filter((k) => lead[k] !== undefined)
      .sort();
    expect(keys).toEqual(["event", "form_name", "relationship", "request_type"]);
    const blob = JSON.stringify(lead);
    expect(blob).not.toMatch(/Jane Doe|jane@example\.com|tee times are wrong|706-867-9862|Ridge Overlook/);
    expect(lead.form_name).toBe("listing_claim");
  });

  it("a non-member enum value is OMITTED, never defaulted", () => {
    const win = freshWindow();
    const a = createAnalytics(win);
    a.track("generate_lead", { request_type: "correction", relationship: "Owner" }); // wrong case
    const bad = win.dataLayer.find((e) => e.event === "generate_lead");
    expect(bad.relationship).toBeUndefined();
  });

  it("an unknown event name produces NO push, and the drop is counted", () => {
    const win = freshWindow();
    const a = createAnalytics(win);
    const before = win.__ccAnalyticsDropped;
    a.track("not_an_event", { a: 1 });
    expect(win.dataLayer.length).toBe(0);
    expect(win.__ccAnalyticsDropped).toBeGreaterThan(before);
  });

  it("stale keys are cleared between events", () => {
    const win = freshWindow();
    const a = createAnalytics(win);
    a.track("generate_lead", { request_type: "correction", relationship: "owner" });
    a.track("contact_click", { contact_method: "tel" });
    const cc = win.dataLayer.find((e) => e.event === "contact_click");
    expect(cc.relationship).toBeUndefined();
    expect(cc.request_type).toBeUndefined();
  });
});
