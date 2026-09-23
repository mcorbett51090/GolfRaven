/**
 * The K2 signup count — decision 0001 Addendum D R3 / docs/p0/K2.md step 4,
 * implemented literally:
 *
 *   "distinct lower-cased email addresses whose confirmedAt falls before
 *    day 0 + 14 days (advisory) and before day 0 + 42 days (gate).
 *    Owner/test addresses are excluded only if listed in K2.md's
 *    'Excluded addresses' field before day 0."
 *
 * IMPORTANT: this counts CONFIRMATIONS, not current subscribers. An
 * address that confirmed before the cutoff and later unsubscribed still
 * counts — the rule text is entirely about `confirmedAt`, with no
 * carve-out for a later unsubscribe, so `unsubscribed_at` is deliberately
 * never read by this module. (Whoever reads the count for "how many
 * people are subscribed right now" needs a different query — this one
 * answers "did K2 hit its pre-registered thresholds", which is a
 * historical fact that doesn't change if someone unsubscribes later.)
 *
 * Deliberately a standalone module (no imports) — scripts/k2-count.mjs
 * imports the BUILT `dist/k2-count.js` directly with plain Node ESM,
 * which needs explicit file-extension imports for anything it depends on;
 * keeping this module import-free sidesteps that entirely.
 */

export const ADVISORY_THRESHOLD = 100;
export const GATE_THRESHOLD = 300;
export const ADVISORY_WINDOW_DAYS = 14;
export const GATE_WINDOW_DAYS = 42;

export interface SignupExportRow {
  email_lc: string;
  /** ISO-8601, or null/undefined for a never-confirmed row. */
  confirmed_at?: string | null;
}

export interface K2CountParams {
  rows: SignupExportRow[];
  /** ISO-8601 UTC date/time — decision 0001 Addendum D R3's "Day 0". Required. */
  day0: string;
  /** Raw addresses from K2.md's "Excluded addresses" field, any case. */
  excludedAddresses: string[];
}

export interface K2CountResult {
  day0: string;
  advisoryCutoff: string;
  gateCutoff: string;
  /** Rows in the export, before any filtering. */
  totalRows: number;
  /** Rows with a non-null confirmed_at, before dedup/exclusion. */
  totalConfirmedRaw: number;
  /**
   * Gate finding F17: rows with a non-null `confirmed_at` that fails to
   * parse as a date are skipped (defensively) rather than silently
   * dropped — this surfaces that count instead of hiding it.
   */
  malformedConfirmedAtCount: number;
  /** Distinct lower-cased confirmed emails that matched the exclusion list. */
  excludedMatchCount: number;
  /** Distinct lower-cased confirmed emails, after exclusion — the pool both counts are drawn from. */
  distinctConfirmed: number;
  advisoryCount: number;
  gateCount: number;
  advisoryPass: boolean;
  gatePass: boolean;
}

/**
 * Throws if day 0 is missing/invalid — this function refuses to run
 * without it (decision 0001 Addendum D R3: day 0 must be logged in
 * docs/p0/K2.md before any count is read; there is no meaningful cutoff
 * to compute otherwise).
 */
export function computeK2Counts(params: K2CountParams): K2CountResult {
  if (!params.day0 || typeof params.day0 !== "string" || params.day0.trim() === "") {
    throw new Error(
      "K2 day 0 is not set — refusing to compute a count (decision 0001 Addendum D R3: " +
        "day 0 must be logged in docs/p0/K2.md before any count is read).",
    );
  }
  const day0Date = new Date(params.day0);
  if (Number.isNaN(day0Date.getTime())) {
    throw new Error(`K2 day 0 is not a valid ISO-8601 date/time: ${JSON.stringify(params.day0)}`);
  }

  const dayMs = 24 * 60 * 60 * 1000;
  const advisoryCutoff = new Date(day0Date.getTime() + ADVISORY_WINDOW_DAYS * dayMs);
  const gateCutoff = new Date(day0Date.getTime() + GATE_WINDOW_DAYS * dayMs);

  const excludedSet = new Set(
    (params.excludedAddresses ?? []).map((e) => e.trim().toLowerCase()).filter(Boolean),
  );

  let totalConfirmedRaw = 0;
  let malformedConfirmedAtCount = 0;
  // email_lc -> earliest confirmed_at seen for that address (defensive
  // dedup; D1's UNIQUE constraint on email_lc already guarantees one row
  // per address at the source, but the export is arbitrary JSON, not a
  // live read, so this function doesn't trust that invariant blindly).
  const earliestConfirmedByEmail = new Map<string, Date>();
  let excludedMatchCount = 0;
  const excludedSeen = new Set<string>();

  for (const row of params.rows ?? []) {
    if (!row || typeof row.email_lc !== "string" || !row.confirmed_at) continue;
    totalConfirmedRaw += 1;
    const emailLc = row.email_lc.trim().toLowerCase();
    if (excludedSet.has(emailLc)) {
      if (!excludedSeen.has(emailLc)) {
        excludedSeen.add(emailLc);
        excludedMatchCount += 1;
      }
      continue;
    }
    const confirmedAt = new Date(row.confirmed_at);
    if (Number.isNaN(confirmedAt.getTime())) {
      // Gate finding F17: report this instead of silently dropping it.
      malformedConfirmedAtCount += 1;
      continue;
    }
    const existing = earliestConfirmedByEmail.get(emailLc);
    if (!existing || confirmedAt.getTime() < existing.getTime()) {
      earliestConfirmedByEmail.set(emailLc, confirmedAt);
    }
  }

  let advisoryCount = 0;
  let gateCount = 0;
  for (const confirmedAt of earliestConfirmedByEmail.values()) {
    // Strictly BEFORE the cutoff — a confirmation landing exactly at the
    // cutoff instant does not count (decision 0001 Addendum D R3: "falls
    // before day 0 + N days").
    if (confirmedAt.getTime() < advisoryCutoff.getTime()) advisoryCount += 1;
    if (confirmedAt.getTime() < gateCutoff.getTime()) gateCount += 1;
  }

  return {
    day0: day0Date.toISOString(),
    advisoryCutoff: advisoryCutoff.toISOString(),
    gateCutoff: gateCutoff.toISOString(),
    totalRows: (params.rows ?? []).length,
    totalConfirmedRaw,
    malformedConfirmedAtCount,
    excludedMatchCount,
    distinctConfirmed: earliestConfirmedByEmail.size,
    advisoryCount,
    gateCount,
    advisoryPass: advisoryCount >= ADVISORY_THRESHOLD,
    gatePass: gateCount >= GATE_THRESHOLD,
  };
}
