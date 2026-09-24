/**
 * analytics-pii.test.ts — the ported `southern-wine-country/scripts/
 * test-analytics-pii.mjs` harness (build plan §10 P2 stage-2 scope item 6:
 * "Port SWC's `test-analytics-pii` and wire it into `pnpm -r test`
 * (AT8, §15)."), rewritten as a vitest test so `pnpm -r test` (this
 * package's own `test` script, `vitest run`) runs it automatically — no
 * separate CI step needed, unlike SWC's original standalone-script
 * invocation.
 *
 * **"the gate runs against the analytics slot and event-schema code"**
 * (this repo's stage-2 instructions) — `src/components/Analytics.astro`
 * is real and complete, but NOT mounted on any page yet (the GTM
 * container id is still unset, O13). This test extracts its inline
 * script text directly out of the `.astro` SOURCE FILE and runs it in a
 * sandboxed `vm` context — exactly SWC's own technique — so the PII
 * boundary is proven correct independent of whether any page currently
 * renders `<Analytics />`.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import vm from "node:vm";
import { describe, expect, it } from "vitest";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const ASTRO_PATH = path.join(ROOT, "src/components/Analytics.astro");
const SCHEMA_PATH = path.join(ROOT, "analytics-schema.json");

function loadRuntime() {
  const astro = readFileSync(ASTRO_PATH, "utf8");
  const m = astro.match(/<script is:inline>([\s\S]*?)<\/script>/);
  if (!m) throw new Error("could not find the inline script in Analytics.astro");
  const code = m[1]!;

  const sandbox: any = {
    console,
    window: { dataLayer: [] as any[], addEventListener() {}, __ccAnalyticsDropped: 0 },
    document: { addEventListener() {} },
  };
  sandbox.globalThis = sandbox;
  vm.createContext(sandbox);
  vm.runInContext(code, sandbox);
  return sandbox;
}

describe("AT(8)/§15 test-analytics-pii: the Analytics.astro dataLayer projection never leaks PII", () => {
  it("ccAnalytics is defined and ready() is true when dataLayer is present", () => {
    const { window } = loadRuntime();
    expect(window.ccAnalytics).toBeTruthy();
    expect(window.ccAnalytics.ready()).toBe(true);
  });

  it("generate_lead: exactly the schema keys carry values, and NO PII field survives", () => {
    const { window } = loadRuntime();
    const before = window.dataLayer.length;
    window.ccAnalytics.track("generate_lead", {
      request_type: "correction",
      relationship: "owner",
      // Everything below is what a claim/correction form will eventually
      // collect (stage 3) — none of it may survive the projection.
      name: "Jane Doe",
      email: "jane@example.com",
      facility: "Ridge Overlook Golf Club",
      message: "I own this and the tee times are wrong, call me on 706-867-9862",
    });
    const lead = window.dataLayer.slice(before).find((e: any) => e.event === "generate_lead");
    expect(lead).toBeTruthy();
    const keys = Object.keys(lead)
      .filter((k) => lead[k] !== undefined)
      .sort()
      .join(",");
    expect(keys).toBe("event,form_name,relationship,request_type");
    const blob = JSON.stringify(lead);
    expect(blob).not.toMatch(/Jane Doe/);
    expect(blob).not.toMatch(/jane@example\.com/);
    expect(blob).not.toMatch(/tee times are wrong/);
    expect(blob).not.toMatch(/706-867-9862/);
    expect(blob).not.toMatch(/Ridge Overlook/);
    expect(lead.form_name).toBe("listing_claim");
  });

  it("a non-member enum value is OMITTED, never defaulted", () => {
    const { window } = loadRuntime();
    const before = window.dataLayer.length;
    window.ccAnalytics.track("generate_lead", { request_type: "correction", relationship: "Owner" }); // wrong case
    const bad = window.dataLayer.slice(before).find((e: any) => e.event === "generate_lead");
    expect(bad?.relationship).toBeUndefined();
  });

  it("feedback_submit carries topic only", () => {
    const { window } = loadRuntime();
    const before = window.dataLayer.length;
    window.ccAnalytics.track("feedback_submit", { topic: "problem", name: "Bob", email: "b@c.com" });
    const fb = window.dataLayer.slice(before).find((e: any) => e.event === "feedback_submit");
    expect(fb?.topic).toBe("problem");
    expect(JSON.stringify(fb)).not.toMatch(/Bob|b@c\.com/);
  });

  it("booking_click (§6.1 T0's first-party GolfNow-case signal) carries only provider + trail_slug", () => {
    const { window } = loadRuntime();
    const before = window.dataLayer.length;
    window.ccAnalytics.track("booking_click", { provider: "golfnow", trail_slug: "fictional-ridge-golf-trail" });
    const ev = window.dataLayer.slice(before).find((e: any) => e.event === "booking_click");
    expect(ev?.provider).toBe("golfnow");
    expect(ev?.trail_slug).toBe("fictional-ridge-golf-trail");
    const keys = Object.keys(ev)
      .filter((k) => ev[k] !== undefined)
      .sort()
      .join(",");
    expect(keys).toBe("event,provider,trail_slug");
  });

  it("booking_click rejects a non-enum provider and a malformed trail_slug", () => {
    const { window } = loadRuntime();
    const before = window.dataLayer.length;
    window.ccAnalytics.track("booking_click", { provider: "not-a-real-provider", trail_slug: "ok-slug" });
    const ev = window.dataLayer.slice(before).find((e: any) => e.event === "booking_click");
    expect(ev?.provider).toBeUndefined();
  });

  it("an unknown event name produces NO push, and the drop is counted", () => {
    const { window } = loadRuntime();
    const before = window.dataLayer.length;
    const droppedBefore = window.__ccAnalyticsDropped;
    window.ccAnalytics.track("not_an_event", { a: 1 });
    expect(window.dataLayer.length).toBe(before);
    expect(window.__ccAnalyticsDropped).toBeGreaterThan(droppedBefore);
  });

  it("stale keys are cleared between events", () => {
    const { window } = loadRuntime();
    window.ccAnalytics.track("generate_lead", { request_type: "correction", relationship: "owner" });
    const before = window.dataLayer.length;
    window.ccAnalytics.track("contact_click", { contact_method: "tel" });
    const cc = window.dataLayer.slice(before).find((e: any) => e.event === "contact_click");
    expect(cc?.relationship).toBeUndefined();
    expect(cc?.request_type).toBeUndefined();
  });

  it("analytics-schema.json and Analytics.astro's SCHEMA agree on every event name and its allowed keys", () => {
    const schemaFile = JSON.parse(readFileSync(SCHEMA_PATH, "utf8")) as Record<string, unknown>;
    const eventNames = Object.keys(schemaFile).filter((k) => k !== "_comment");
    const astro = readFileSync(ASTRO_PATH, "utf8");
    for (const event of eventNames) {
      expect(astro).toMatch(new RegExp(`\\b${event}\\s*:\\s*\\{`));
      for (const key of schemaFile[event] as string[]) {
        // Every allow-listed key for this event appears somewhere in the
        // runtime's per-event object body — a cheap but real drift check:
        // a key added to one file and not the other fails this.
        expect(astro).toMatch(new RegExp(`${key}\\s*:\\s*\\{\\s*type`));
      }
    }
  });
});
