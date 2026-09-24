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
import { fileURLToPath } from "node:url";
import type { BookingEntry, Facility } from "@golfraven/catalog";

const BOOKING_HOSTS_PATH = fileURLToPath(
  new URL("../../../../config/booking-hosts.json", import.meta.url),
);

export async function loadBookingHostAllowList(): Promise<string[]> {
  const raw = JSON.parse(await readFile(BOOKING_HOSTS_PATH, "utf8")) as { hosts?: string[] };
  return raw.hosts ?? [];
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
