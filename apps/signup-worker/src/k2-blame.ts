/**
 * Pure, testable decision logic for the K2 count CLI's exclusion-list
 * timing rule (decision 0001 Addendum D R3 / Addendum F "K2 exclusion
 * dating": an owner/test address only excludes a K2 count if it "first
 * appeared" in `docs/p0/K2.md` before Day 0).
 *
 * Gate findings F7/F8 residuals (R3's timing rule): the round-2 fix used
 * per-LINE `git blame` on the current file, which gate round 3 (A-5) found
 * got "listed before day 0" wrong in both directions: (a) a later reformat
 * or whitespace edit of an old, still-present line re-dates it (blame
 * follows the line, not the address), dropping a legitimate pre-day-0
 * exclusion; (b) a shallow clone blames every line to its boundary commit,
 * silently dropping every exclusion while Day 0 still looks committed.
 *
 * Decision 0001 Addendum F fixes this by re-anchoring the rule to CONTENT,
 * not to a line: an address is excluded if it FIRST APPEARED in K2.md's
 * full history in a commit whose COMMITTER time is before Day 0 00:00 UTC.
 * A later reformat or deletion of the line cannot change when the address
 * FIRST appeared, so (a) and (b) above no longer apply.
 *
 * Gate findings F-S2/F-S3 (round-3+1 gate): the round-3 fix's `git log
 * -S<address>` pickaxe still got this wrong two ways — (F-S2) the
 * candidate set was only addresses CURRENTLY listed in K2.md, so deleting
 * an excluded address after Day 0 silently un-excluded it; (F-S3) `-S`
 * counts raw, case-SENSITIVE substring occurrences, not parsed addresses,
 * so `A@X.com` (different case) evaded exclusion and `a@x.com` was
 * wrongly excluded merely for being a substring of an earlier `ba@x.com`.
 * `scripts/k2-count.mjs` now builds `firstAppearanceByAddress` by walking
 * EVERY revision of K2.md's full history (not just HEAD) and diffing
 * consecutive revisions' PARSED, exact, lower-cased address sets (the same
 * decoration-stripping extraction the count itself uses) — so the
 * candidate set is every address ANY revision ever added, dated by exact
 * whole-address identity, independent of whether it survives to HEAD. This
 * module is deliberately Node/git-free (no `child_process`, no filesystem)
 * so it can be unit-tested with fake first-appearance data.
 */

export interface FirstAppearance {
  /**
   * The COMMITTER time (not author time — see Addendum F and
   * `scripts/k2-count.mjs`'s module doc for why) of the EARLIEST revision
   * of `docs/p0/K2.md` whose PARSED "Excluded addresses" set gained this
   * exact address, as an ISO-8601 UTC string — or `null` if the address
   * cannot be dated at all (treated the same as "not excluded" rather than
   * crashing, since an address the tool cannot date must not be trusted to
   * exclude anything).
   */
  committerTimeIso: string | null;
}

export interface ExcludedEntry {
  /** Already-lower-cased, decoration-stripped email address. */
  address: string;
  /** 1-indexed line number within K2.md where this address CURRENTLY
   * appears — kept for reporting ("not excluded" output lines) and to
   * report a historically-excluded address that is no longer listed
   * (F-S2) — no longer used in the exclusion decision itself (Addendum F
   * dates by content, not by line, and F-S2 dates from full history, not
   * just the addresses currently visible). */
  line: number;
}

export interface NotExcludedEntry extends ExcludedEntry {
  note: "not excluded (first committed on/after day 0, or no commit history found)";
}

export interface ResolveK2ExclusionsParams {
  /** Bare "YYYY-MM-DD" Day 0, as parsed by scripts/k2-count.mjs's parseDay0FromK2Doc. */
  day0: string;
  /** EVERY address any revision of K2.md's full history ever added to the
   * Excluded-addresses section (gate finding F-S2: independent of whether
   * it is still listed today), each mapped to its first-appearance
   * committer time. */
  firstAppearanceByAddress: Map<string, FirstAppearance>;
  /** Addresses CURRENTLY listed in K2.md's Excluded-addresses section
   * (with their current line numbers) — used only to report "not
   * excluded" entries a reader can see in the doc today; the exclusion
   * decision itself uses `firstAppearanceByAddress`, not this list. */
  currentEntries: ExcludedEntry[];
}

export type ResolveK2ExclusionsResult = {
  ok: true;
  /** Every address (from the full history) whose first appearance is
   * strictly before day 0 00:00 UTC — this is the exclusion set, applied
   * to the export regardless of whether the address is still listed. */
  excluded: string[];
  /** Currently-listed addresses that are NOT excluded, for reporting. */
  notExcluded: NotExcludedEntry[];
  /** Gate finding F-S2: excluded addresses that no longer appear in the
   * CURRENT K2.md — still applied, but worth surfacing since a reader of
   * today's doc alone would not otherwise know they exist. */
  excludedButNoLongerListed: string[];
  /** Gate finding A-6 / runbook step 9: addresses whose first appearance
   * falls ON day 0 itself (same UTC calendar day, not strictly before) —
   * correctly NOT excluded, but flagged so a same-UTC-day exclusion commit
   * (the runbook mistake this fix targets) is caught, not silently
   * absorbed into the count. */
  excludedOnDay0: string[];
};

/**
 * Resolves which addresses count as excluded, per Addendum F's "first
 * appeared ... before Day 0" rule, from the FULL-HISTORY first-appearance
 * map (gate finding F-S2) — never from only the addresses currently
 * listed. This is a total function (no refusal case) — the refusal this
 * module used to own (an uncommitted Day 0 line) doesn't apply to the
 * content-addressed rule; the caller (`scripts/k2-count.mjs`) owns the ONE
 * remaining refusal condition, a shallow clone, since that is a property
 * of the git checkout, not of any one line.
 */
export function resolveK2Exclusions(
  params: ResolveK2ExclusionsParams,
): ResolveK2ExclusionsResult {
  const cutoffMs = Date.parse(`${params.day0}T00:00:00.000Z`);
  const dayStartMs = cutoffMs;
  const dayEndMs = cutoffMs + 24 * 60 * 60 * 1000;

  const excluded: string[] = [];
  const excludedSet = new Set<string>();
  const excludedOnDay0: string[] = [];

  for (const [address, appearance] of params.firstAppearanceByAddress) {
    const committerTimeIso = appearance?.committerTimeIso ?? null;
    if (committerTimeIso === null) continue;
    const committerMs = Date.parse(committerTimeIso);
    if (Number.isNaN(committerMs)) continue;
    if (committerMs < cutoffMs) {
      excludedSet.add(address);
      excluded.push(address);
    } else if (committerMs >= dayStartMs && committerMs < dayEndMs) {
      excludedOnDay0.push(address);
    }
  }

  const currentAddressSet = new Set(
    params.currentEntries.map((e) => e.address),
  );
  const excludedButNoLongerListed = excluded.filter(
    (a) => !currentAddressSet.has(a),
  );

  const notExcluded: NotExcludedEntry[] = [];
  const seenCurrent = new Set<string>();
  for (const entry of params.currentEntries) {
    if (seenCurrent.has(entry.address)) continue;
    seenCurrent.add(entry.address);
    if (!excludedSet.has(entry.address)) {
      notExcluded.push({
        ...entry,
        note: "not excluded (first committed on/after day 0, or no commit history found)",
      });
    }
  }

  return {
    ok: true,
    excluded,
    notExcluded,
    excludedButNoLongerListed,
    excludedOnDay0,
  };
}
