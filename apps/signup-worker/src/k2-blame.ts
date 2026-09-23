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
 * full history in a commit whose COMMITTER time is before Day 0 00:00 UTC —
 * found via `git log -S<address>` (a pickaxe search: the earliest commit
 * whose diff changed the number of occurrences of that exact string),
 * never `git blame` on the file's current state. A later reformat or
 * deletion of the line cannot change when the address FIRST appeared, so
 * (a) and (b) above no longer apply. This module is deliberately
 * Node/git-free (no `child_process`, no filesystem) so it can be
 * unit-tested with fake first-appearance data — `scripts/k2-count.mjs` owns
 * running `git log -S` (and refusing outright in a shallow clone) and
 * parsing its output into the `FirstAppearance` shape this module consumes.
 */

export interface FirstAppearance {
  /**
   * The COMMITTER time (not author time — see Addendum F and
   * `scripts/k2-count.mjs`'s module doc for why) of the EARLIEST commit in
   * `docs/p0/K2.md`'s full history whose diff added this exact address
   * string, as an ISO-8601 UTC string — or `null` if `git log -S` found no
   * such commit at all (should not normally happen for an address
   * currently listed in the doc, but is treated the same as "not
   * excluded" rather than crashing, since an address the tool cannot date
   * must not be trusted to exclude anything).
   */
  committerTimeIso: string | null;
}

export interface ExcludedEntry {
  /** Already-lower-cased, decoration-stripped email address. */
  address: string;
  /** 1-indexed line number within K2.md where this address CURRENTLY
   * appears — kept for reporting ("not excluded" output lines), no longer
   * used in the exclusion decision itself (Addendum F dates by content,
   * not by line). */
  line: number;
}

export interface NotExcludedEntry extends ExcludedEntry {
  note: "not excluded (first committed on/after day 0, or no commit history found)";
}

export interface ResolveK2ExclusionsParams {
  /** Bare "YYYY-MM-DD" Day 0, as parsed by scripts/k2-count.mjs's parseDay0FromK2Doc. */
  day0: string;
  entries: ExcludedEntry[];
  /** Each CURRENTLY-listed address's first-appearance data (from
   * `git log -S`), keyed by the same lower-cased address as `entries`. */
  firstAppearanceByAddress: Map<string, FirstAppearance>;
}

export type ResolveK2ExclusionsResult = { ok: true; excluded: string[]; notExcluded: NotExcludedEntry[] };

/**
 * Resolves which addresses in K2.md's "Excluded addresses" section
 * actually count as excluded, per Addendum F's "first appeared ... before
 * Day 0" rule. This is now a total function (no refusal case) — the
 * refusal this module used to own (an uncommitted Day 0 line) doesn't
 * apply to the content-addressed rule; the caller (`scripts/k2-count.mjs`)
 * owns the ONE remaining refusal condition, a shallow clone, since that is
 * a property of the git checkout, not of any one line.
 */
export function resolveK2Exclusions(params: ResolveK2ExclusionsParams): ResolveK2ExclusionsResult {
  const cutoffMs = Date.parse(`${params.day0}T00:00:00.000Z`);
  const excluded: string[] = [];
  const excludedSet = new Set<string>();
  const notExcluded: NotExcludedEntry[] = [];

  for (const entry of params.entries) {
    const firstAppearance = params.firstAppearanceByAddress.get(entry.address);
    const committerTimeIso = firstAppearance?.committerTimeIso ?? null;
    const committerMs = committerTimeIso === null ? null : Date.parse(committerTimeIso);
    const isExcluded = committerMs !== null && !Number.isNaN(committerMs) && committerMs < cutoffMs;
    if (isExcluded) {
      if (!excludedSet.has(entry.address)) {
        excludedSet.add(entry.address);
        excluded.push(entry.address);
      }
    } else {
      notExcluded.push({
        ...entry,
        note: "not excluded (first committed on/after day 0, or no commit history found)",
      });
    }
  }

  return { ok: true, excluded, notExcluded };
}
