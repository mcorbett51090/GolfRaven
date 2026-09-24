/**
 * booking-hosts.ts — render-time booking-host gate (build plan §10 P2
 * stage-2 scope item 3: "Render each facility's `booking[]` entries, but
 * only when the host passes the booking-host gate from
 * `config/booking-hosts.json`."; AT(4): "every booking link passes the
 * host gate.").
 *
 * `config/booking-hosts.json` (repo root) is already the SSOT for this
 * allow-list — `tools/catalog/src/config.ts`'s `loadBookingHostAllowList`
 * reads it for the P1 `verify-catalog` gate, and `apps/site/scripts/
 * verify-input.mjs` reads the same file for the site's own prebuild gate.
 * This module reads the identical file (never a second copy) so the
 * PUBLISH-time gate (verify-catalog, which refuses to publish a bad
 * booking entry at all) and this RENDER-time check can never disagree
 * about which hosts are allowed.
 *
 * **Why a render-time check ALSO exists, given verify-catalog already
 * gates this at publish time**: defense in depth (same reasoning as
 * `og-card.ts`'s "verified pages only" being enforced by `getStaticPaths`,
 * not trusted from elsewhere) — a page must never be ABLE to render a
 * link the gate would reject, even if the input the site builds from
 * (`GOLFRAVEN_DATA_DIR`, a test fixture, a future direct-DB path) ever
 * bypassed `verify-catalog` itself.
 */
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { BookingEntry, Facility } from "@golfraven/catalog";
import { assertBookingHostsNotSynthetic } from "./booking-hosts-guard.mjs";

/**
 * **Deliberately `process.cwd()`-based, NOT `import.meta.url`-relative**
 * (unlike `derive.ts`'s `realDataDir`/`PRIMARY_TRAIL_OVERRIDE_PATH`).
 * Confirmed this session: Astro's SSR build can inline this module
 * DIRECTLY into a per-page bundle (`dist/pages/courses/_slug_.astro.mjs`
 * — a different nesting depth than the source file `src/lib/`), which
 * silently breaks a `../../../../` count computed from `import.meta.url`
 * (it resolved to `apps/config/...`, one level short, instead of
 * `config/...`). `apps/site`'s own scripts are ALWAYS invoked with
 * `apps/site` as `cwd` (every `package.json` script, `astro build`
 * itself, and this test suite all run from there), so `process.cwd()` is
 * the stable anchor a bundler's chunking decisions can't move.
 */
export function bookingHostsConfigPath(cwd: string = process.cwd()): string {
  return join(cwd, "..", "..", "config", "booking-hosts.json");
}

export async function loadBookingHostAllowList(): Promise<string[]> {
  const raw = JSON.parse(await readFile(bookingHostsConfigPath(), "utf8")) as {
    hosts?: string[];
    synthetic?: unknown;
    _comment?: unknown;
  };
  // Should-fix (Opus gate, Booking): refuse a production build outright
  // while the allow-list is still the synthetic/test-only P1a fixture.
  assertBookingHostsNotSynthetic(raw);
  return raw.hosts ?? [];
}

/** Known booking-platform hosts → their real display name. Anything
 * allow-listed but NOT in this table falls back to a name derived from
 * the host itself (`derivedPlatformLabel` below) — never a hard-coded
 * "GolfNow" for every non-`course-native` provider (should-fix, Opus
 * gate Booking: "Label links by their actual platform, derived from the
 * host" — the PREVIOUS stage-2 code said "GolfNow" unconditionally for
 * chronogolf/teeon/club-prophet links too, which is simply wrong). */
const KNOWN_HOST_LABELS: Record<string, string> = {
  "www.golfnow.com": "GolfNow",
  "golfnow.com": "GolfNow",
};

/** `chronogolf.com` -> "Chronogolf"; `book.teeon.com` -> "TeeOn" (kept as
 * one word, matching the provider's own brand casing) — else the
 * registrable domain's own label, title-cased. */
function derivedPlatformLabel(host: string): string {
  const bare = host.replace(/^www\./, "");
  // Brand keywords are matched against the WHOLE host, not just one
  // label — a real host is often `book.teeon.com` or
  // `tee-times.clubprophetsystems.com`, where the brand name is not the
  // first dot-separated segment.
  if (/teeon/i.test(bare)) return "TeeOn";
  if (/clubprophet|club-prophet/i.test(bare)) return "Club Prophet";
  if (/chronogolf/i.test(bare)) return "Chronogolf";
  // No known brand keyword: fall back to the REGISTRABLE domain's own
  // label — the segment immediately before the TLD, not the first
  // segment (which is often a subdomain like `book.` or `tee-times.` and
  // would otherwise mislabel the platform by its subdomain instead of
  // its actual domain).
  const segments = bare.split(".").filter(Boolean);
  const labelPart = segments.length >= 2 ? segments[segments.length - 2]! : (segments[0] ?? bare);
  return labelPart.charAt(0).toUpperCase() + labelPart.slice(1);
}

/** The label a booking button should show, derived from the entry's
 * ACTUAL host — `course-native` always reads "the course" (it IS the
 * facility's own site, whatever its domain), every other provider is
 * named from its real host, known or not. */
export function bookingPlatformLabel(entry: BookingEntry): string {
  if (entry.provider === "course-native") return "the course";
  try {
    const host = new URL(entry.url).host;
    return KNOWN_HOST_LABELS[host] ?? derivedPlatformLabel(host);
  } catch {
    return "the booking site";
  }
}

/**
 * Same host rule `verify-catalog`'s `checkBooking` enforces
 * (`tools/catalog/src/verify-catalog.ts`): a `course-native` entry's host
 * must equal the facility's own `url` host; every other provider's host
 * must be on the allow-list.
 */
export function bookingEntryAllowed(
  entry: BookingEntry,
  facility: Facility,
  allowList: string[],
): boolean {
  let host: string;
  try {
    host = new URL(entry.url).host;
  } catch {
    return false;
  }
  if (entry.provider === "course-native") {
    if (!facility.url) return false;
    try {
      return new URL(facility.url).host === host;
    } catch {
      return false;
    }
  }
  return allowList.includes(host);
}

/** Every `booking[]` entry that passes the gate, in the facility's own
 * order (AT(4)). */
export function allowedBookingEntries(facility: Facility, allowList: string[]): BookingEntry[] {
  return facility.booking.filter((entry) => bookingEntryAllowed(entry, facility, allowList));
}
