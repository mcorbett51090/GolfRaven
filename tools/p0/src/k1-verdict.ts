#!/usr/bin/env node
/**
 * `k1-verdict` — the K1 operator+sponsor early-read and full-gate verdicts
 * (build plan §10 P0; `docs/p0/K1.md`) from the single K1 log
 * (`docs/partners/k1-outreach.md` §(g), decision 0001 Addendum D R2).
 * Implements the pass bars literally, not reinterpreted:
 *
 * - **Early read** (decision 0001, Addendum D, R1): count of the 5 named
 *   operators whose acceptance of an exploratory call is dated on or
 *   before **2026-10-19**. Pass if ≥ 2.
 * - **Full gate** (decision 0001, Addendum C): count of the same 5 with a
 *   signed non-binding LOI, including stated willingness to pay the
 *   per-season fee, dated on or before **2026-11-30**. Pass needs ≥ 2 of
 *   those, AND ≥ 1 sponsor row with all three qualifiers recorded AND a
 *   sponsor conversation date on or before **2026-11-30** (decision 0001,
 *   Addendum I).
 * - **Oklahoma Golf Trail** counts only when the log marks it as activated
 *   by the X2 swap rule (`okSwapReplaces` non-blank), replacing the named
 *   dropped slate trail in the 5 — never a 6th (K1.md METHOD step 1;
 *   decision 0001 Addendum D R2).
 *
 * Decision 0001, Addendum I fixes what was still open after the first gate
 * round:
 *
 * - **Two separate verdicts, never merged.** The early read and the full
 *   gate each carry their own state and their own verbatim consequence
 *   quote. A full-gate result is never hidden by an early-read miss, and
 *   the reverse is also true. Within the full gate, "operator miss" is
 *   evaluated before "sponsor miss" — the sponsor branch only applies once
 *   operators pass.
 * - **An as-of date** (`--as-of`, default: today's UTC date) gates both
 *   verdicts: before 2026-10-20 the early read is `pending`, and before
 *   2026-12-01 the full gate is `pending` — regardless of the count so
 *   far, since the window hasn't closed. Any logged date later than
 *   as-of is refused outright (a log can't record something that, as of
 *   the read, hasn't happened yet).
 * - **Date sanity.** Every logged date must be on or after 2026-09-23
 *   ("nothing had been sent" before that date) and on or before as-of. An
 *   acceptance or LOI dated before its own row's contacted date is an
 *   error. Dates are plain calendar dates — no timezone conversion.
 */
import {
  readK1Log,
  resolveK1LogPath,
  K1_BASE_FIVE_NAMES,
  type K1Row,
} from "./k1-log.js";

/** Decision 0001, Addendum D, R1: "P0 start 2026-10-05 + 14 days" — dated
 * on or before this counts toward the early read. */
export const K1_EARLY_READ_CUTOFF = "2026-10-19";
/** Decision 0001, Addendum C: "the full-gate window closes on 2026-11-30"
 * — dated on or before this counts toward the full gate (LOIs and sponsor
 * conversations alike, decision 0001 Addendum I). */
export const K1_FULL_GATE_CUTOFF = "2026-11-30";
/** Decision 0001, Addendum I: strictly before this date, the early read
 * has not closed yet and reports "pending" regardless of count. */
export const K1_EARLY_READ_WINDOW_CLOSES = "2026-10-20";
/** Decision 0001, Addendum I: strictly before this date, the full gate has
 * not closed yet and reports "pending" regardless of count. */
export const K1_FULL_GATE_WINDOW_CLOSES = "2026-12-01";
/** Decision 0001, Addendum I: "nothing had been sent" before this date —
 * any logged date earlier than this is an error. */
export const K1_MIN_LOG_DATE = "2026-09-23";

export const K1_CONSEQUENCE_EARLY_MISS =
  "Early read 0–1/5 → replan before P1 (the partner programme is paused; P1–P4 proceed as " +
  "directory + tracking + badges only if K2 and K3 allow).";
export const K1_CONSEQUENCE_OPERATOR_FULL_MISS =
  "Full miss (operators) → P5/P6 do not start; the app launches as directory + tracking + badges " +
  "with the programme off on every trail (O17); K1 is re-run before the next season opening.";
export const K1_CONSEQUENCE_SPONSOR_MISS =
  "Sponsor miss, operators pass → the programme proceeds operator-funded: the trail pays for its " +
  "own special-marker run (O9/O10, §9.7), the fee covers our ops, offers are course- or " +
  "operator-funded, and sponsor outreach continues into P5.";
export const K1_CONSEQUENCE_EARLY_PASS_NOTE =
  "K1.md's Kill consequence section defines no separate text for an early-read pass; none is quoted here.";
export const K1_CONSEQUENCE_FULL_GATE_PASS_NOTE =
  "K1.md's Kill consequence section defines no separate text for a full-gate pass (both the operator and " +
  "sponsor bars met); none is quoted here.";

const ISO_DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

/** Decision 0001, Addendum I ("the read date is real"): a real ISO calendar
 * date — not just digit-shaped (rejects e.g. "2026-13-45"). Shared by every
 * date this module validates, whether it came through the strict table
 * parser or was constructed directly (the pure `compute*` functions accept
 * plain data, so this is validated again here — never assumed). */
function isRealCalendarDate(value: string): boolean {
  if (!ISO_DATE_RE.test(value)) return false;
  const d = new Date(`${value}T00:00:00Z`);
  return !Number.isNaN(d.getTime()) && d.toISOString().slice(0, 10) === value;
}

/** Decision 0001, Addendum I ("the read date is real"): `asOf` must be a
 * real calendar date and must not be later than `today` (UTC) — a read
 * can't be dated after the day it's actually run. `today` is a parameter,
 * never `Date.now()` read internally, so callers (tests, the CLI) control
 * it explicitly. */
function assertValidAsOf(asOf: string, today: string): void {
  if (!isRealCalendarDate(asOf)) {
    throw new Error(
      `computeK1Verdict: malformed --as-of "${asOf}" — not a real ISO "YYYY-MM-DD" calendar date.`,
    );
  }
  if (!isRealCalendarDate(today)) {
    throw new Error(
      `computeK1Verdict: malformed today "${today}" — not a real ISO "YYYY-MM-DD" calendar date.`,
    );
  }
  if (asOf > today) {
    throw new Error(
      `computeK1Verdict: --as-of "${asOf}" is later than today (${today}) — refusing a read dated in the future ` +
        "(decision 0001, Addendum I).",
    );
  }
}

/** Decision 0001, Addendum I "K1 dates" / "the read date is real" /
 * "sponsor dates" / "log integrity": every logged date in a row must be a
 * real calendar date, on or after 2026-09-23, and on or before `asOf`; an
 * acceptance, an LOI, or a sponsor conversation dated before that row's own
 * Contacted date is also an error. Checked over EVERY row (operators, the
 * inactive/dropped ones, and sponsors) regardless of whether that row
 * currently affects a verdict — a bad date is a data-integrity problem on
 * its own, and no row is ever skipped. */
function assertRowDatesSane(row: K1Row, asOf: string): void {
  const fields: [string, string | null][] = [
    ["Contacted date", row.contactedDate],
    ["Call accepted date", row.callAcceptedDate],
    ["LOI date", row.loiDate],
    ["Sponsor conversation date", row.sponsorConversationDate],
  ];
  for (const [label, value] of fields) {
    if (value === null) continue;
    if (!isRealCalendarDate(value)) {
      throw new Error(
        `${row.target}: ${label} "${value}" is not a real calendar date (decision 0001, Addendum I: ` +
          '"the read date is real").',
      );
    }
    if (value < K1_MIN_LOG_DATE) {
      throw new Error(
        `${row.target}: ${label} "${value}" is before ${K1_MIN_LOG_DATE} (decision 0001, Addendum I: ` +
          '"nothing had been sent" before that date).',
      );
    }
    if (value > asOf) {
      throw new Error(
        `${row.target}: ${label} "${value}" is after the as-of date ${asOf} — refusing a logged date ` +
          "from the future (decision 0001, Addendum I).",
      );
    }
  }
  if (row.contactedDate !== null) {
    if (
      row.callAcceptedDate !== null &&
      row.callAcceptedDate < row.contactedDate
    ) {
      throw new Error(
        `${row.target}: Call accepted date "${row.callAcceptedDate}" is before Contacted date ` +
          `"${row.contactedDate}" (decision 0001, Addendum I).`,
      );
    }
    if (row.loiDate !== null && row.loiDate < row.contactedDate) {
      throw new Error(
        `${row.target}: LOI date "${row.loiDate}" is before Contacted date "${row.contactedDate}" ` +
          "(decision 0001, Addendum I).",
      );
    }
    if (
      row.sponsorConversationDate !== null &&
      row.sponsorConversationDate < row.contactedDate
    ) {
      throw new Error(
        `${row.target}: Sponsor conversation date "${row.sponsorConversationDate}" is before Contacted date ` +
          `"${row.contactedDate}" (decision 0001, Addendum I: "sponsor dates").`,
      );
    }
  }
}

export interface K1DateEntry {
  target: string;
  date: string;
}
export interface K1SponsorPartial {
  target: string;
  missing: string[];
}

export type K1EarlyReadState = "pending" | "miss" | "pass";
export type K1FullGateState =
  "pending" | "operator-miss" | "sponsor-miss" | "pass";

export interface K1EarlyReadResult {
  passBar: number;
  cutoff: string;
  windowClosesOn: string;
  accepted: K1DateEntry[];
  late: K1DateEntry[];
  count: number;
  state: K1EarlyReadState;
  consequenceText: string;
}

export interface K1FullGateResult {
  windowClosesOn: string;
  operators: {
    passBar: number;
    cutoff: string;
    qualified: K1DateEntry[];
    late: K1DateEntry[];
    loiWithoutFee: K1DateEntry[];
    count: number;
    pass: boolean;
  };
  sponsors: {
    passBar: number;
    cutoff: string;
    qualified: string[];
    late: K1DateEntry[];
    partial: K1SponsorPartial[];
    count: number;
    pass: boolean;
  };
  state: K1FullGateState;
  consequenceText: string;
}

export interface K1VerdictResult {
  generatedAt: string;
  asOf: string;
  effectiveFive: string[];
  okSwap: { activated: boolean; replaces: string | null };
  earlyRead: K1EarlyReadResult;
  fullGate: K1FullGateResult;
  warnings: string[];
}

export function computeK1Verdict(
  rows: K1Row[],
  asOf: string,
  today: string,
): K1VerdictResult {
  assertValidAsOf(asOf, today);

  const byTarget = new Map(rows.map((r) => [r.target, r]));
  const okRow = byTarget.get("Oklahoma Golf Trail");
  if (!okRow) {
    throw new Error(
      'computeK1Verdict: missing required "Oklahoma Golf Trail" row.',
    );
  }
  for (const name of K1_BASE_FIVE_NAMES) {
    if (!byTarget.has(name)) {
      throw new Error(
        `computeK1Verdict: missing required operator row "${name}".`,
      );
    }
  }

  // Decision 0001, Addendum I "K1 dates" — checked over EVERY row first,
  // before any counting, so a bad date anywhere refuses the whole run.
  for (const row of rows) assertRowDatesSane(row, asOf);

  const replaces = okRow.okSwapReplaces;
  const activated = replaces !== null;
  const effectiveFive: string[] = activated
    ? K1_BASE_FIVE_NAMES.map((n) =>
        n === replaces ? "Oklahoma Golf Trail" : n,
      )
    : [...K1_BASE_FIVE_NAMES];

  const warnings: string[] = [];
  if (!activated) {
    const okHasData =
      okRow.contactedDate !== null ||
      okRow.callAcceptedDate !== null ||
      okRow.loiDate !== null ||
      okRow.feeWillingness !== null;
    if (okHasData) {
      warnings.push(
        'Oklahoma Golf Trail has logged contact/acceptance/LOI data but "OK swap replaces" is blank ' +
          "(the X2 swap is not activated) — excluded from the 5, never counted as a 6th operator.",
      );
    }
  } else {
    // Warn when the swap drops data already logged against the replaced trail.
    const droppedRow = byTarget.get(replaces!)!;
    const droppedHasData =
      droppedRow.contactedDate !== null ||
      droppedRow.callAcceptedDate !== null ||
      droppedRow.loiDate !== null ||
      droppedRow.feeWillingness !== null;
    if (droppedHasData) {
      warnings.push(
        `The Oklahoma Golf Trail swap replaces "${replaces}", which has its own logged data — that data is ` +
          "dropped from the effective 5 now that Oklahoma Golf Trail stands in its place.",
      );
    }
  }

  // Early read (decision 0001, Addendum D, R1)
  const accepted: K1DateEntry[] = [];
  const lateAccepted: K1DateEntry[] = [];
  for (const name of effectiveFive) {
    const row = byTarget.get(name)!;
    if (row.callAcceptedDate === null) continue;
    if (row.callAcceptedDate <= K1_EARLY_READ_CUTOFF) {
      accepted.push({ target: name, date: row.callAcceptedDate });
    } else {
      lateAccepted.push({ target: name, date: row.callAcceptedDate });
    }
  }
  const earlyReadPending = asOf < K1_EARLY_READ_WINDOW_CLOSES;
  const earlyState: K1EarlyReadState = earlyReadPending
    ? "pending"
    : accepted.length >= 2
      ? "pass"
      : "miss";
  const earlyConsequenceText = earlyReadPending
    ? `Pending (${accepted.length} so far) — through ${K1_EARLY_READ_CUTOFF}; readable from ` +
      `${K1_EARLY_READ_WINDOW_CLOSES}. As of ${asOf}, no consequence branch applies yet.`
    : earlyState === "miss"
      ? K1_CONSEQUENCE_EARLY_MISS
      : K1_CONSEQUENCE_EARLY_PASS_NOTE;

  // Full gate — operators (decision 0001, Addendum C)
  const qualified: K1DateEntry[] = [];
  const lateLoi: K1DateEntry[] = [];
  const loiWithoutFee: K1DateEntry[] = [];
  for (const name of effectiveFive) {
    const row = byTarget.get(name)!;
    if (row.loiDate === null) continue;
    if (row.feeWillingness !== "Y") {
      loiWithoutFee.push({ target: name, date: row.loiDate });
      continue;
    }
    if (row.loiDate <= K1_FULL_GATE_CUTOFF) {
      qualified.push({ target: name, date: row.loiDate });
    } else {
      lateLoi.push({ target: name, date: row.loiDate });
    }
  }
  const operatorFullPass = qualified.length >= 2;

  // Full gate — sponsors: all three qualifiers AND a conversation date
  // on or before the full-gate cutoff (decision 0001, Addendum I).
  const sponsorQualified: string[] = [];
  const sponsorLate: K1DateEntry[] = [];
  const sponsorPartial: K1SponsorPartial[] = [];
  for (const row of rows) {
    if (row.type !== "Sponsor") continue;
    const missing: string[] = [];
    if (row.sponsorDecisionMakerNamed !== "Y")
      missing.push("named decision-maker");
    if (row.sponsorBudgetStated !== "Y")
      missing.push("stated season budget range");
    if (row.sponsorAttributionInterest !== "Y")
      missing.push("interest in special-marker attribution");
    if (row.sponsorConversationDate === null)
      missing.push("a recorded sponsor conversation date");
    if (missing.length === 0) {
      if (row.sponsorConversationDate! <= K1_FULL_GATE_CUTOFF) {
        sponsorQualified.push(row.target);
      } else {
        sponsorLate.push({
          target: row.target,
          date: row.sponsorConversationDate!,
        });
      }
    } else if (missing.length < 4) {
      sponsorPartial.push({ target: row.target, missing });
    }
  }
  const sponsorFullPass = sponsorQualified.length >= 1;

  const fullGatePending = asOf < K1_FULL_GATE_WINDOW_CLOSES;
  // Addendum I: operator miss is evaluated BEFORE sponsor miss.
  let fullGateState: K1FullGateState;
  if (fullGatePending) {
    fullGateState = "pending";
  } else if (!operatorFullPass) {
    fullGateState = "operator-miss";
  } else if (!sponsorFullPass) {
    fullGateState = "sponsor-miss";
  } else {
    fullGateState = "pass";
  }
  const fullGateConsequenceText = fullGatePending
    ? `Pending (operators: ${qualified.length} so far, sponsors: ${sponsorQualified.length} so far) — window ` +
      `runs through ${K1_FULL_GATE_CUTOFF}; verdict readable from ${K1_FULL_GATE_WINDOW_CLOSES}. As of ${asOf}, ` +
      "no consequence branch applies yet."
    : fullGateState === "operator-miss"
      ? K1_CONSEQUENCE_OPERATOR_FULL_MISS
      : fullGateState === "sponsor-miss"
        ? K1_CONSEQUENCE_SPONSOR_MISS
        : K1_CONSEQUENCE_FULL_GATE_PASS_NOTE;

  if (lateAccepted.length > 0) {
    warnings.push(
      `${lateAccepted.length} operator acceptance(s) dated after the early-read cutoff ` +
        `(${K1_EARLY_READ_CUTOFF}) and do not count: ${lateAccepted.map((e) => `${e.target} (${e.date})`).join(", ")}.`,
    );
  }
  if (lateLoi.length > 0) {
    warnings.push(
      `${lateLoi.length} LOI(s) dated after the full-gate cutoff (${K1_FULL_GATE_CUTOFF}) and do not ` +
        `count: ${lateLoi.map((e) => `${e.target} (${e.date})`).join(", ")}.`,
    );
  }
  if (loiWithoutFee.length > 0) {
    warnings.push(
      `${loiWithoutFee.length} LOI(s) logged without recorded fee willingness and do not count: ` +
        `${loiWithoutFee.map((e) => `${e.target} (${e.date})`).join(", ")}.`,
    );
  }
  if (sponsorLate.length > 0) {
    warnings.push(
      `${sponsorLate.length} sponsor conversation(s) dated after the full-gate cutoff (${K1_FULL_GATE_CUTOFF}) ` +
        `and do not count: ${sponsorLate.map((e) => `${e.target} (${e.date})`).join(", ")}.`,
    );
  }
  if (sponsorPartial.length > 0) {
    warnings.push(
      `${sponsorPartial.length} sponsor row(s) have at least one but not all qualifiers recorded: ` +
        sponsorPartial
          .map((s) => `${s.target} (missing: ${s.missing.join("; ")})`)
          .join(", ") +
        ".",
    );
  }

  return {
    generatedAt: new Date().toISOString(),
    asOf,
    effectiveFive,
    okSwap: { activated, replaces },
    earlyRead: {
      passBar: 2,
      cutoff: K1_EARLY_READ_CUTOFF,
      windowClosesOn: K1_EARLY_READ_WINDOW_CLOSES,
      accepted,
      late: lateAccepted,
      count: accepted.length,
      state: earlyState,
      consequenceText: earlyConsequenceText,
    },
    fullGate: {
      windowClosesOn: K1_FULL_GATE_WINDOW_CLOSES,
      operators: {
        passBar: 2,
        cutoff: K1_FULL_GATE_CUTOFF,
        qualified,
        late: lateLoi,
        loiWithoutFee,
        count: qualified.length,
        pass: operatorFullPass,
      },
      sponsors: {
        passBar: 1,
        cutoff: K1_FULL_GATE_CUTOFF,
        qualified: sponsorQualified,
        late: sponsorLate,
        partial: sponsorPartial,
        count: sponsorQualified.length,
        pass: sponsorFullPass,
      },
      state: fullGateState,
      consequenceText: fullGateConsequenceText,
    },
    warnings,
  };
}

export function renderK1VerdictMarkdown(result: K1VerdictResult): string {
  const lines: string[] = [];
  lines.push(`**As of:** ${result.asOf}`);
  lines.push(
    `**Effective 5 operators:** ${result.effectiveFive.join(", ")} ` +
      `(Oklahoma Golf Trail swap: ${result.okSwap.activated ? `activated, replaces ${result.okSwap.replaces}` : "not activated"}).`,
  );
  lines.push("");
  lines.push("## Early read");
  lines.push(
    `${result.earlyRead.count} of 5 accepted an exploratory call on or before ${result.earlyRead.cutoff} ` +
      `(bar ≥ ${result.earlyRead.passBar}) — ` +
      `**${result.earlyRead.state === "pending" ? `${result.earlyRead.count} so far` : result.earlyRead.state.toUpperCase()}**.`,
  );
  if (result.earlyRead.accepted.length > 0) {
    lines.push(
      `Accepted: ${result.earlyRead.accepted.map((e) => `${e.target} (${e.date})`).join(", ")}`,
    );
  }
  if (result.earlyRead.late.length > 0) {
    lines.push(
      `Late (do not count): ${result.earlyRead.late.map((e) => `${e.target} (${e.date})`).join(", ")}`,
    );
  }
  lines.push(`> ${result.earlyRead.consequenceText}`);
  const pending = result.fullGate.state === "pending";
  lines.push("");
  lines.push("## Full gate — operators");
  lines.push(
    `${result.fullGate.operators.count} of 5 have a qualifying LOI (fee willingness recorded, dated on or ` +
      `before ${result.fullGate.operators.cutoff}) (bar ≥ ${result.fullGate.operators.passBar}) — ` +
      `**${pending ? `${result.fullGate.operators.count} so far` : result.fullGate.operators.pass ? "PASS" : "MISS"}**.`,
  );
  if (result.fullGate.operators.qualified.length > 0) {
    lines.push(
      `Qualified: ${result.fullGate.operators.qualified.map((e) => `${e.target} (${e.date})`).join(", ")}`,
    );
  }
  lines.push("");
  lines.push("## Full gate — sponsors");
  lines.push(
    `${result.fullGate.sponsors.count} sponsor row(s) with all qualifiers recorded ` +
      `(bar ≥ ${result.fullGate.sponsors.passBar}) — ` +
      `**${pending ? `${result.fullGate.sponsors.count} so far` : result.fullGate.sponsors.pass ? "PASS" : "MISS"}**.`,
  );
  if (result.fullGate.sponsors.qualified.length > 0) {
    lines.push(`Qualified: ${result.fullGate.sponsors.qualified.join(", ")}`);
  }
  lines.push("");
  lines.push(`**Full gate state: ${result.fullGate.state}**`);
  lines.push(`> ${result.fullGate.consequenceText}`);
  if (result.warnings.length > 0) {
    lines.push("");
    lines.push("**Warnings:**");
    for (const w of result.warnings) lines.push(`- ${w}`);
  }
  return lines.join("\n");
}

interface CliArgs {
  outPrefix: string;
  asOf: string;
  /** `--log <path>`: a copy of the K1 log to read instead of the repo's
   * `docs/partners/k1-outreach.md`. For tests only — the recorded K1 verdict is
   * always computed from the repo's own log (the default). */
  logPath: string | undefined;
}

/** The real current date (UTC) — the only place this module reads the
 * system clock. Everything else takes `today`/`asOf` as parameters, so
 * tests can pin them (decision 0001, Addendum I: "The read date is real"). */
function todayUtc(): string {
  return new Date().toISOString().slice(0, 10);
}

function parseArgs(argv: string[]): CliArgs {
  const opts: Record<string, string> = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg && arg.startsWith("--")) {
      opts[arg.slice(2)] = argv[i + 1] ?? "";
      i += 1;
    }
  }
  const today = todayUtc();
  return {
    outPrefix: opts.out || "k1-verdict-result",
    asOf: opts["as-of"] || today,
    logPath: opts.log || undefined,
  };
}

async function main(argv: string[]): Promise<void> {
  const args = parseArgs(argv);
  const rows = await readK1Log(args.logPath);
  // Provenance (gate round 3): every output records which file it was computed
  // from, with its SHA-256, and says loudly when that is not the repo's own
  // K1 log — so a --log/--memo run can never pass for the recorded verdict.
  const { readFile: readSource } = await import("node:fs/promises");
  const { createHash } = await import("node:crypto");
  const { resolve: resolvePath } = await import("node:path");
  const repoPath = resolvePath(resolveK1LogPath());
  const sourcePath = resolvePath(args.logPath ?? repoPath);
  const source = {
    path: sourcePath,
    sha256: createHash("sha256")
      .update(await readSource(sourcePath))
      .digest("hex"),
    isRepoLog: sourcePath === repoPath,
  };
  const banner = source.isRepoLog
    ? ""
    : `> **NOT THE RECORDED K1 LOG.** Computed from \`${sourcePath}\`, not the repo's own K1 log. This output is not a P0 verdict.\n\n`;
  const result = computeK1Verdict(rows, args.asOf, todayUtc());
  const { writeFile } = await import("node:fs/promises");
  await writeFile(
    `${args.outPrefix}.json`,
    `${JSON.stringify({ ...result, source }, null, 2)}\n`,
    "utf8",
  );
  const md = banner + renderK1VerdictMarkdown(result);
  await writeFile(`${args.outPrefix}.md`, `${md}\n`, "utf8");
  process.stdout.write(`${md}\n`);
}

async function isMainModule(): Promise<boolean> {
  if (!process.argv[1]) return false;
  try {
    const { realpath } = await import("node:fs/promises");
    const { fileURLToPath } = await import("node:url");
    const [herePath, argvPath] = await Promise.all([
      realpath(fileURLToPath(import.meta.url)),
      realpath(process.argv[1]),
    ]);
    return herePath === argvPath;
  } catch {
    return false;
  }
}

if (await isMainModule()) {
  main(process.argv.slice(2)).catch((err: unknown) => {
    const message = err instanceof Error ? err.message : String(err);
    process.stderr.write(`k1-verdict: ${message}\n`);
    process.exitCode = 1;
  });
}
