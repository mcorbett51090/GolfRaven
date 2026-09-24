/**
 * analytics-runtime.ts — the PII boundary between this site and Tag
 * Manager. Ported from southern-wine-country's `src/components/
 * Analytics.astro` @ 572ff7e, and restructured this round (Opus gate B3,
 * blocking) out of an `is:inline` Astro script into a plain TS module:
 *
 *   - **"Ship the Analytics script as a bundled external file, never
 *     `is:inline`."** `Analytics.astro` now just does
 *     `<script>import { installAnalytics } from "../lib/analytics-runtime";
 *     installAnalytics();</script>` — a normal (non-`is:inline`) script,
 *     which Astro hoists into an external, same-origin, CSP-compliant
 *     bundle exactly like `CourseMap.astro`'s/`SiteSearch.astro`'s own
 *     scripts (see `CourseMap.astro`'s doc for why that matters under
 *     this site's `default-src 'self'` CSP). `<Analytics />` is now
 *     mounted in `BaseLayout.astro` on every page — it stays INERT
 *     (`if (!window.dataLayer) return`) until a real GTM container id
 *     exists (O13), so "the GTM slot stays empty" is unchanged; what
 *     changed is that the PROJECTION logic itself now actually ships as a
 *     real, testable, CSP-compliant file rather than living only in an
 *     unmounted component's inline-script text.
 *   - **A plain module is also what makes the B3 PII test real**, not a
 *     `vm`-sandboxed regex-extraction of inline script text
 *     (`test/analytics-pii.test.ts` now imports this file directly and
 *     calls its exported functions).
 *
 * Tag Manager means tags are configured in a console outside this repo,
 * by whoever holds access — a tag added there can read anything in the
 * dataLayer. The protection sits at the BOUNDARY, not at the sender:
 *
 *   this site -> [schema allowlist + PII shape guard] -> dataLayer -> GTM -> any tag
 *                            ^^^^^^^^^^^^^^^^^^^^^^^^
 *                              PII dropped here
 *
 * **`RULES` below is pinned EXACTLY against `analytics-schema.json`**
 * (this directory's sibling file, one level up from `src/lib/`) — every
 * event's key SET (not just "each JSON key appears somewhere in the
 * runtime", the old, weaker check) must match exactly in both
 * directions. `assertSchemaAgreement()` is that check, run by
 * `test/analytics-pii.test.ts` — a key added to one file and not the
 * other fails it immediately, in CI, not just in a manual review.
 */
import schemaJson from "../../analytics-schema.json";

export type FieldRule =
  | { type: "const"; value: string }
  | { type: "enum"; values: readonly string[] }
  | { type: "pattern"; value: RegExp };

export type EventRules = Record<string, FieldRule>;

const REQUEST_TYPES = ["correction", "new-listing", "feedback"] as const;
const RELATIONSHIPS = ["owner", "staff", "visitor", "other"] as const;
const TOPICS = ["general", "problem", "idea", "listing", "other"] as const;
const BOOKING_PROVIDERS = [
  "golfnow",
  "chronogolf",
  "teeon",
  "club-prophet",
  "course-native",
] as const;
const CSP_DIRECTIVES = [
  "default-src",
  "script-src",
  "script-src-elem",
  "script-src-attr",
  "style-src",
  "style-src-elem",
  "style-src-attr",
  "img-src",
  "connect-src",
  "font-src",
  "frame-src",
  "object-src",
  "media-src",
  "worker-src",
  "manifest-src",
  "base-uri",
  "form-action",
] as const;

/** A catalog slug: lower-case, digits, hyphen — never free text. */
const SLUG_PATTERN = /^[a-z0-9-]{1,80}$/;

/**
 * The RUNTIME'S rules — never add, remove or rename a key here without
 * also updating `analytics-schema.json` (this file's own doc) AND
 * re-running `assertSchemaAgreement()` (the test does this on every
 * `pnpm -r test`).
 */
export const RULES: Record<string, EventRules> = {
  generate_lead: {
    form_name: { type: "const", value: "listing_claim" },
    request_type: { type: "enum", values: REQUEST_TYPES },
    relationship: { type: "enum", values: RELATIONSHIPS },
  },
  feedback_submit: {
    form_name: { type: "const", value: "feedback" },
    topic: { type: "enum", values: TOPICS },
  },
  contact_click: {
    contact_method: { type: "enum", values: ["tel", "mailto"] },
  },
  // §6.1 T0: "A first-party booking_click event (no PII) builds the T1
  // case [for a GolfNow partner-API application]." Both fields are public
  // catalog identifiers, never a visitor's own data.
  booking_click: {
    provider: { type: "enum", values: BOOKING_PROVIDERS },
    trail_slug: { type: "pattern", value: SLUG_PATTERN },
  },
  csp_violation: {
    effective_directive: { type: "enum", values: CSP_DIRECTIVES },
  },
};

/**
 * B3 (blocking): `analytics-schema.json` and `RULES` above must declare
 * the EXACT SAME key set for every event — checked in BOTH directions
 * (a key in one and not the other fails either way), not "every schema
 * key appears somewhere in the runtime's text" (the old, weaker check
 * this replaces). Throws with a precise diff on any mismatch.
 */
export function assertSchemaAgreement(): void {
  const schema = schemaJson as Record<string, unknown>;
  const schemaEvents = Object.keys(schema).filter((k) => k !== "_comment");
  const runtimeEvents = Object.keys(RULES);

  const missingInRuntime = schemaEvents.filter(
    (e) => !runtimeEvents.includes(e),
  );
  const missingInSchema = runtimeEvents.filter(
    (e) => !schemaEvents.includes(e),
  );
  if (missingInRuntime.length || missingInSchema.length) {
    throw new Error(
      `analytics-schema.json/RULES event-name drift: missing in RULES=[${missingInRuntime}], ` +
        `missing in analytics-schema.json=[${missingInSchema}]`,
    );
  }

  for (const event of schemaEvents) {
    const schemaKeys = [...(schema[event] as string[])].sort();
    const runtimeKeys = Object.keys(RULES[event]!).sort();
    const extraInRuntime = runtimeKeys.filter((k) => !schemaKeys.includes(k));
    const extraInSchema = schemaKeys.filter((k) => !runtimeKeys.includes(k));
    if (extraInRuntime.length || extraInSchema.length) {
      throw new Error(
        `analytics-schema.json/RULES key drift for "${event}": extra in RULES=[${extraInRuntime}], ` +
          `extra in analytics-schema.json=[${extraInSchema}]`,
      );
    }
  }
}

/* ---------------------------------------------------------------------
 * PII shape guard — the backstop for a correctly-key-named, wrongly-typed
 * field (Opus gate B3: "Reject values shaped like coordinates
 * (/^-?\d{1,3}\.\d{4,}$/), email addresses and opaque ids (>= 16 hex or
 * base64 characters, UUIDs) in any event payload").
 * ------------------------------------------------------------------- */

const COORDINATE_RE = /^-?\d{1,3}\.\d{4,}$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const HEX_ID_RE = /^[0-9a-f]{16,}$/i;
const BASE64_ID_RE = /^[A-Za-z0-9+/_-]{16,}={0,2}$/;
// A legitimate catalog slug (`trail_slug`, `contact_method`, …) is
// lower-case letters/digits/hyphens ONLY — indistinguishable in SHAPE
// from a lower-case base64url string of the same length (both match
// `[a-z0-9-]{16,}`). Real base64 output is high-entropy and virtually
// never comes out purely lower-case (no digits/uppercase/`+`//`) for a
// 16+ char run by chance, so a pure slug-shaped string is exempted from
// the base64 check specifically — `HEX_ID_RE` above still independently
// catches a slug that HAPPENS to be all hex digits (`0-9a-f`, no letters
// past `f`, no hyphens), which is a different, narrower shape.
const SLUG_SHAPE_RE = /^[a-z0-9-]+$/;
// Kept from SWC's own original guard (long strings, phone numbers, ZIPs) —
// still a real, independent backstop alongside the PII-shape patterns
// above, which target DIFFERENT shapes (coordinates/opaque ids/emails).
const LEGACY_LEAK_RES = [/\d{3}[-.\s]?\d{3}[-.\s]?\d{4}/, /\b\d{5}(-\d{4})?\b/];

export function looksLikePii(rawValue: unknown): boolean {
  const value = String(rawValue);
  if (value.length > 100) return true;
  if (COORDINATE_RE.test(value)) return true;
  if (EMAIL_RE.test(value)) return true;
  if (UUID_RE.test(value)) return true;
  if (HEX_ID_RE.test(value)) return true;
  if (BASE64_ID_RE.test(value) && !SLUG_SHAPE_RE.test(value)) return true;
  if (value.includes("@")) return true; // any "@" at all, not just a full email match
  for (const re of LEGACY_LEAK_RES) if (re.test(value)) return true;
  return false;
}

/** Every key any event can emit — nulled before each push, so a
 * dataLayer variable resolving to "the most recent value" never reports a
 * value left over from an earlier, different event. */
function allKeys(): string[] {
  const seen = new Set<string>();
  for (const spec of Object.values(RULES)) {
    for (const key of Object.keys(spec)) seen.add(key);
  }
  return [...seen];
}

export type DataLayerEvent = { event: string; [key: string]: unknown };

/**
 * Projects `raw` through `RULES[name]` — walks the SCHEMA, never the
 * caller's object, so an unlisted key can never reach the output no
 * matter what the caller passes. Returns `null` when the event name is
 * unknown, OR when any admitted value fails the PII shape guard (the
 * WHOLE event is dropped in that case, not just the offending field).
 */
export function project(
  name: string,
  raw: Record<string, unknown> = {},
): Record<string, unknown> | null {
  const spec = RULES[name];
  if (!spec) return null;
  const out: Record<string, unknown> = {};
  for (const [key, rule] of Object.entries(spec)) {
    let value: unknown;
    if (rule.type === "const") {
      value = rule.value;
    } else if (rule.type === "enum") {
      if (!rule.values.includes(raw[key] as string)) continue; // omitted, never defaulted
      value = raw[key];
    } else if (rule.type === "pattern") {
      if (typeof raw[key] !== "string" || !rule.value.test(raw[key] as string))
        continue;
      value = raw[key];
    } else {
      continue;
    }
    if (looksLikePii(value)) return null;
    out[key] = value;
  }
  return out;
}

export interface AnalyticsHandle {
  track: (name: string, rawParams?: Record<string, unknown>) => void;
  ready: () => boolean;
}

interface AnalyticsWindow {
  dataLayer?: DataLayerEvent[];
  __ccAnalyticsDropped?: number;
}

/** Pure, DOM-free — the piece the B3 unit tests exercise directly (no
 * jsdom, no `vm` sandbox, just a plain object standing in for `window`). */
export function createAnalytics(win: AnalyticsWindow): AnalyticsHandle {
  const keys = allKeys();
  function track(name: string, rawParams: Record<string, unknown> = {}): void {
    try {
      const params = project(name, rawParams);
      if (params === null) {
        win.__ccAnalyticsDropped = (win.__ccAnalyticsDropped ?? 0) + 1;
        return;
      }
      const payload: DataLayerEvent = { event: name };
      for (const k of keys) payload[k] = undefined;
      Object.assign(payload, params);
      win.dataLayer?.push(payload);
    } catch {
      /* analytics must never affect the page it measures */
    }
  }
  return { track, ready: () => !!win.dataLayer };
}

/**
 * DOM-attaching half — called from `Analytics.astro`'s (non-inline)
 * `<script>` on every page. Inert until `window.dataLayer` exists (no GTM
 * container id configured yet, O13).
 */
export function installAnalytics(win: Window & AnalyticsWindow = window): void {
  if (!win.dataLayer) return;
  const handle = createAnalytics(win);
  (win as unknown as { ccAnalytics: AnalyticsHandle }).ccAnalytics = handle;

  win.document.addEventListener(
    "click",
    (ev) => {
      try {
        const target = ev.target as HTMLElement | null;
        const a = target?.closest?.("a[href]") as HTMLAnchorElement | null;
        if (!a) return;
        const href = a.getAttribute("href") ?? "";
        const method = href.startsWith("tel:")
          ? "tel"
          : href.startsWith("mailto:")
            ? "mailto"
            : null;
        if (method) {
          handle.track("contact_click", { contact_method: method });
          return;
        }
        if (a.getAttribute("data-analytics-event") === "booking_click") {
          handle.track("booking_click", {
            provider: a.getAttribute("data-analytics-provider") ?? "",
            trail_slug: a.getAttribute("data-analytics-trail") ?? "",
          });
        }
      } catch {
        /* ignore */
      }
    },
    true,
  );

  win.addEventListener("securitypolicyviolation", (ev) => {
    try {
      handle.track("csp_violation", {
        effective_directive: (ev as SecurityPolicyViolationEvent)
          .effectiveDirective,
      });
    } catch {
      /* ignore */
    }
  });
}
