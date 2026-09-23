/**
 * Pure, testable decision logic for the K2 count CLI's exclusion-list
 * timing rule (decision 0001 Addendum D R3: an owner/test address only
 * excludes a K2 count if it was "listed ... before Day 0").
 *
 * Gate findings F7/F8 residuals: the old CLI (a) let `--k2-doc` point at an
 * arbitrary file, so a caller could substitute a different Day 0 and
 * exclusion list entirely, and (b) never actually checked WHEN an address
 * was added to the list — an address added to K2.md after Day 0 would
 * retroactively exclude prior signups, contradicting R3 literally.
 *
 * The fix: `--k2-doc` is removed (scripts/k2-count.mjs always reads the
 * repo's own docs/p0/K2.md), and every excluded address is checked against
 * `git blame` on that file — it only counts as excluded if its OWN line
 * was committed (author-time) strictly before Day 0 00:00 UTC. This module
 * is deliberately Node/git-free (no `child_process`, no filesystem) so it
 * can be unit-tested with fake blame data instead of a real git checkout —
 * scripts/k2-count.mjs owns running `git blame` and parsing its porcelain
 * output into the `BlameLine` shape this module consumes.
 */

export interface BlameLine {
  /**
   * The commit's author-time (when the change was authored, not when it
   * was rebased/committed-elsewhere), as an ISO-8601 UTC string — or
   * `null` if the line is NOT committed at all (only in the working tree
   * or staged, i.e. `git blame`'s "Not Committed Yet" line).
   */
  authorTimeIso: string | null;
}

export interface ExcludedEntry {
  /** Already-lower-cased, decoration-stripped email address. */
  address: string;
  /** 1-indexed line number within K2.md where this address appears. */
  line: number;
}

export interface NotExcludedEntry extends ExcludedEntry {
  note: "not excluded (added on/after day 0 or uncommitted)";
}

export interface ResolveK2ExclusionsParams {
  /** Bare "YYYY-MM-DD" Day 0, as parsed by scripts/k2-count.mjs's parseDay0FromK2Doc. */
  day0: string;
  /** 1-indexed line number of Day 0's own date token within K2.md. */
  day0Line: number;
  entries: ExcludedEntry[];
  /** `git blame` info for K2.md, keyed by 1-indexed final line number, covering the WHOLE file. */
  blameByLine: Map<number, BlameLine>;
}

export type ResolveK2ExclusionsResult =
  | { ok: true; excluded: string[]; notExcluded: NotExcludedEntry[] }
  | { ok: false; error: string };

/**
 * Resolves which addresses in K2.md's "Excluded addresses" section
 * actually count as excluded, per R3's "listed before Day 0" rule.
 *
 * Refuses outright (Day 0's own line must be committed too) if Day 0's
 * line has no committed blame — an uncommitted Day 0 means the "before Day
 * 0" cutoff itself isn't a fixed, auditable point in history yet, so no
 * count can be trusted (decision 0001 Addendum D R3).
 */
export function resolveK2Exclusions(params: ResolveK2ExclusionsParams): ResolveK2ExclusionsResult {
  const day0Blame = params.blameByLine.get(params.day0Line);
  if (!day0Blame || day0Blame.authorTimeIso === null) {
    return {
      ok: false,
      error:
        `K2.md's own "Day 0" line (line ${params.day0Line}) is not committed — ` +
        "git blame shows it as uncommitted. Day 0 must be committed before any K2 count can be " +
        "read (decision 0001 Addendum D R3): refusing to run.",
    };
  }

  const cutoffMs = Date.parse(`${params.day0}T00:00:00.000Z`);
  const excluded: string[] = [];
  const excludedSet = new Set<string>();
  const notExcluded: NotExcludedEntry[] = [];

  for (const entry of params.entries) {
    const blame = params.blameByLine.get(entry.line);
    const authorTimeIso = blame?.authorTimeIso ?? null;
    const authorMs = authorTimeIso === null ? null : Date.parse(authorTimeIso);
    const isExcluded = authorMs !== null && !Number.isNaN(authorMs) && authorMs < cutoffMs;
    if (isExcluded) {
      if (!excludedSet.has(entry.address)) {
        excludedSet.add(entry.address);
        excluded.push(entry.address);
      }
    } else {
      notExcluded.push({ ...entry, note: "not excluded (added on/after day 0 or uncommitted)" });
    }
  }

  return { ok: true, excluded, notExcluded };
}
