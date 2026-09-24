#!/usr/bin/env node
/**
 * `k1-verdict` — the K1 operator+sponsor early-read and full-gate verdict
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
 *   those, AND ≥ 1 sponsor row with all three qualifiers recorded (a named
 *   decision-maker, a stated season budget range, and interest in
 *   special-marker attribution).
 * - **Oklahoma Golf Trail** counts only when the log marks it as activated
 *   by the X2 swap rule (`okSwapReplaces` non-blank), replacing the named
 *   dropped slate trail in the 5 — never a 6th (K1.md METHOD step 1;
 *   decision 0001 Addendum D R2).
 *
 * The consequence-branch priority (early miss > operator full miss >
 * sponsor miss with operators passing > pass) is this tool's own reading
 * of K1.md's "Kill consequence" section, which lists the branches in that
 * order but does not spell out a selection algorithm — see the task
 * report for the citation.
 */
import { readK1Log, K1_BASE_FIVE_NAMES, type K1Row } from "./k1-log.js";

/** Decision 0001, Addendum D, R1: "P0 start 2026-10-05 + 14 days". */
export const K1_EARLY_READ_CUTOFF = "2026-10-19";
/** Decision 0001, Addendum C: "the full-gate window closes on 2026-11-30". */
export const K1_FULL_GATE_CUTOFF = "2026-11-30";

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
export const K1_CONSEQUENCE_PASS_NOTE =
  "K1.md's Kill consequence section defines only the kill branches above; it states no separate " +
  "consequence text for a full pass (both operator and sponsor bars met), so none is quoted here.";

export interface K1DateEntry {
  target: string;
  date: string;
}
export interface K1SponsorPartial {
  target: string;
  missing: string[];
}

export type K1ConsequenceBranch =
  | "early-miss"
  | "operator-full-miss"
  | "sponsor-miss-operators-pass"
  | "pass";

export interface K1VerdictResult {
  generatedAt: string;
  effectiveFive: string[];
  okSwap: { activated: boolean; replaces: string | null };
  earlyRead: {
    passBar: number;
    accepted: K1DateEntry[];
    late: K1DateEntry[];
    count: number;
    pass: boolean;
  };
  fullGate: {
    operators: {
      passBar: number;
      qualified: K1DateEntry[];
      late: K1DateEntry[];
      loiWithoutFee: K1DateEntry[];
      count: number;
      pass: boolean;
    };
    sponsors: {
      passBar: number;
      qualified: string[];
      partial: K1SponsorPartial[];
      count: number;
      pass: boolean;
    };
    pass: boolean;
  };
  consequenceBranch: K1ConsequenceBranch;
  consequenceText: string;
  warnings: string[];
}

export function computeK1Verdict(rows: K1Row[]): K1VerdictResult {
  const byTarget = new Map(rows.map((r) => [r.target, r]));
  const okRow = byTarget.get("Oklahoma Golf Trail");
  if (!okRow) {
    throw new Error('computeK1Verdict: missing required "Oklahoma Golf Trail" row.');
  }
  for (const name of K1_BASE_FIVE_NAMES) {
    if (!byTarget.has(name)) {
      throw new Error(`computeK1Verdict: missing required operator row "${name}".`);
    }
  }

  const replaces = okRow.okSwapReplaces;
  const activated = replaces !== null;
  const effectiveFive: string[] = activated
    ? K1_BASE_FIVE_NAMES.map((n) => (n === replaces ? "Oklahoma Golf Trail" : n))
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
  const earlyPass = accepted.length >= 2;

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

  // Full gate — sponsors: all three qualifiers recorded
  const sponsorQualified: string[] = [];
  const sponsorPartial: K1SponsorPartial[] = [];
  for (const row of rows) {
    if (row.type !== "Sponsor") continue;
    const missing: string[] = [];
    if (row.sponsorDecisionMakerNamed !== "Y") missing.push("named decision-maker");
    if (row.sponsorBudgetStated !== "Y") missing.push("stated season budget range");
    if (row.sponsorAttributionInterest !== "Y") missing.push("interest in special-marker attribution");
    if (missing.length === 0) {
      sponsorQualified.push(row.target);
    } else if (missing.length < 3) {
      sponsorPartial.push({ target: row.target, missing });
    }
  }
  const sponsorFullPass = sponsorQualified.length >= 1;
  const fullGatePass = operatorFullPass && sponsorFullPass;

  let consequenceBranch: K1ConsequenceBranch;
  let consequenceText: string;
  if (!earlyPass) {
    consequenceBranch = "early-miss";
    consequenceText = K1_CONSEQUENCE_EARLY_MISS;
  } else if (!operatorFullPass) {
    consequenceBranch = "operator-full-miss";
    consequenceText = K1_CONSEQUENCE_OPERATOR_FULL_MISS;
  } else if (!sponsorFullPass) {
    consequenceBranch = "sponsor-miss-operators-pass";
    consequenceText = K1_CONSEQUENCE_SPONSOR_MISS;
  } else {
    consequenceBranch = "pass";
    consequenceText = K1_CONSEQUENCE_PASS_NOTE;
  }

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
  if (sponsorPartial.length > 0) {
    warnings.push(
      `${sponsorPartial.length} sponsor row(s) have at least one but not all three qualifiers recorded: ` +
        sponsorPartial.map((s) => `${s.target} (missing: ${s.missing.join("; ")})`).join(", ") +
        ".",
    );
  }

  return {
    generatedAt: new Date().toISOString(),
    effectiveFive,
    okSwap: { activated, replaces },
    earlyRead: {
      passBar: 2,
      accepted,
      late: lateAccepted,
      count: accepted.length,
      pass: earlyPass,
    },
    fullGate: {
      operators: {
        passBar: 2,
        qualified,
        late: lateLoi,
        loiWithoutFee,
        count: qualified.length,
        pass: operatorFullPass,
      },
      sponsors: {
        passBar: 1,
        qualified: sponsorQualified,
        partial: sponsorPartial,
        count: sponsorQualified.length,
        pass: sponsorFullPass,
      },
      pass: fullGatePass,
    },
    consequenceBranch,
    consequenceText,
    warnings,
  };
}

export function renderK1VerdictMarkdown(result: K1VerdictResult): string {
  const lines: string[] = [];
  lines.push(
    `**Effective 5 operators:** ${result.effectiveFive.join(", ")} ` +
      `(Oklahoma Golf Trail swap: ${result.okSwap.activated ? `activated, replaces ${result.okSwap.replaces}` : "not activated"}).`,
  );
  lines.push("");
  lines.push("## Early read");
  lines.push(
    `${result.earlyRead.count} of 5 accepted an exploratory call on or before ${K1_EARLY_READ_CUTOFF} ` +
      `(bar ≥ ${result.earlyRead.passBar}) — **${result.earlyRead.pass ? "PASS" : "MISS"}**.`,
  );
  if (result.earlyRead.accepted.length > 0) {
    lines.push(`Accepted: ${result.earlyRead.accepted.map((e) => `${e.target} (${e.date})`).join(", ")}`);
  }
  if (result.earlyRead.late.length > 0) {
    lines.push(`Late (do not count): ${result.earlyRead.late.map((e) => `${e.target} (${e.date})`).join(", ")}`);
  }
  lines.push("");
  lines.push("## Full gate — operators");
  lines.push(
    `${result.fullGate.operators.count} of 5 have a qualifying LOI (fee willingness recorded, dated on or ` +
      `before ${K1_FULL_GATE_CUTOFF}) (bar ≥ ${result.fullGate.operators.passBar}) — ` +
      `**${result.fullGate.operators.pass ? "PASS" : "MISS"}**.`,
  );
  if (result.fullGate.operators.qualified.length > 0) {
    lines.push(
      `Qualified: ${result.fullGate.operators.qualified.map((e) => `${e.target} (${e.date})`).join(", ")}`,
    );
  }
  lines.push("");
  lines.push("## Full gate — sponsors");
  lines.push(
    `${result.fullGate.sponsors.count} sponsor row(s) with all 3 qualifiers recorded ` +
      `(bar ≥ ${result.fullGate.sponsors.passBar}) — **${result.fullGate.sponsors.pass ? "PASS" : "MISS"}**.`,
  );
  if (result.fullGate.sponsors.qualified.length > 0) {
    lines.push(`Qualified: ${result.fullGate.sponsors.qualified.join(", ")}`);
  }
  lines.push("");
  lines.push(
    `**Consequence branch: ${result.consequenceBranch}**`,
  );
  lines.push(`> ${result.consequenceText}`);
  if (result.warnings.length > 0) {
    lines.push("");
    lines.push("**Warnings:**");
    for (const w of result.warnings) lines.push(`- ${w}`);
  }
  return lines.join("\n");
}

interface CliArgs {
  outPrefix: string;
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
  return { outPrefix: opts.out || "k1-verdict-result" };
}

async function main(argv: string[]): Promise<void> {
  const args = parseArgs(argv);
  const rows = await readK1Log();
  const result = computeK1Verdict(rows);
  const { writeFile } = await import("node:fs/promises");
  await writeFile(`${args.outPrefix}.json`, `${JSON.stringify(result, null, 2)}\n`, "utf8");
  const md = renderK1VerdictMarkdown(result);
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
