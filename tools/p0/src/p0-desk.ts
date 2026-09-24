#!/usr/bin/env node
/**
 * `p0-desk` — one command that runs, in order: `x5-overpass n-osm`,
 * `x2-fetch`, and (only when a course-map file exists) `x4-verify`,
 * writing all evidence under one timestamped run directory OUTSIDE the
 * source tree (gate finding S7), then prints a status board naming each
 * check's state. A network-policy block is surfaced as "BLOCKED — network
 * policy (<host>)" (see `net.ts`), and the process exits non-zero if any
 * check could not run, or ran only PARTIALLY (gate finding S5 — some
 * sources fetched, some failed/blocked/indeterminate).
 *
 * This tool does NOT run `x1-verdict`, `x2-verdict` or `x5-overpass
 * coverage` — those need a human-written confirmation/course-list input
 * this desk check does not have. It reports what it gathered and, for X2,
 * that a human still needs to write a confirmation file and run
 * `x2-verdict` next ("needs-confirmation").
 */
import { existsSync } from "node:fs";
import { mkdir, readFile, realpath, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  buildNOsmQuery,
  buildUserAgent as buildX5UserAgent,
  DEFAULT_ENDPOINT as X5_DEFAULT_ENDPOINT,
  DEFAULT_TIMEOUT_MS as X5_DEFAULT_TIMEOUT_MS,
  parseNOsm,
  type OverpassResponse,
} from "./x5-overpass.js";
import { fetchWithBlockDetection } from "./net.js";
import {
  resolveDefaultX2ConfigPath,
  runX2Fetch,
  type X2SourceConfig,
} from "./x2-fetch.js";
import {
  resolveDefaultX4CoursesPath,
  runX4Verify,
  type X4CourseMap,
  type X4VerifyResult,
} from "./x4-verify.js";
import { assertOutsideRepoUnlessExplicit, defaultOutsideRepoDir } from "./run-dir.js";

export type CheckState =
  | "ran"
  | "needs-confirmation"
  | "blocked"
  | "partial-blocked"
  | "verdict"
  | "skipped"
  | "error";

export interface CheckRow {
  name: string;
  state: CheckState;
  detail: string;
}

export interface P0DeskResult {
  runDir: string;
  generatedAt: string;
  rows: CheckRow[];
  exitCode: 0 | 1;
}

function hostOf(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}

async function runX5NOsmStep(
  runDir: string,
  endpoint: string,
  timeoutMs: number,
): Promise<CheckRow> {
  const dir = path.join(runDir, "x5-n-osm");
  await mkdir(dir, { recursive: true });
  const query = buildNOsmQuery();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let outcome: Awaited<ReturnType<typeof fetchWithBlockDetection>>;
  try {
    outcome = await fetchWithBlockDetection(endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": buildX5UserAgent(),
      },
      body: `data=${encodeURIComponent(query)}`,
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timer);
  }

  if (outcome.kind === "blocked") {
    return {
      name: "x5-overpass n-osm",
      state: "blocked",
      detail: `BLOCKED — network policy (${outcome.host}): ${outcome.detail}`,
    };
  }
  if (outcome.kind === "error") {
    return {
      name: "x5-overpass n-osm",
      state: "error",
      detail: `fetch error (${outcome.host}): ${outcome.detail}`,
    };
  }

  const response = outcome.response;
  if (!response.ok) {
    const body = await response.text().catch(() => "");
    return {
      name: "x5-overpass n-osm",
      state: "error",
      detail: `HTTP ${response.status} ${response.statusText} — ${body.slice(0, 200)}`,
    };
  }

  let json: OverpassResponse;
  let nOsm: number;
  try {
    json = (await response.json()) as OverpassResponse;
    nOsm = parseNOsm(json);
  } catch (err) {
    return {
      name: "x5-overpass n-osm",
      state: "error",
      detail: err instanceof Error ? err.message : String(err),
    };
  }

  await writeFile(
    path.join(dir, "response.json"),
    `${JSON.stringify({ query, fetchedAt: new Date().toISOString(), response: json }, null, 2)}\n`,
    "utf8",
  );
  return { name: "x5-overpass n-osm", state: "ran", detail: `N_osm = ${nOsm}` };
}

async function runX2FetchStep(
  runDir: string,
  configPath: string,
): Promise<CheckRow> {
  const dir = path.join(runDir, "x2-evidence");
  let config: X2SourceConfig;
  try {
    config = JSON.parse(await readFile(configPath, "utf8")) as X2SourceConfig;
  } catch (err) {
    return {
      name: "x2-fetch",
      state: "error",
      detail: `could not read --x2-config ${configPath}: ${err instanceof Error ? err.message : String(err)}`,
    };
  }

  const manifest = await runX2Fetch(config, dir);
  const allEntries = Object.values(manifest.trails).flat();
  const fetchedCount = allEntries.filter((e) => e.status === "fetched").length;
  const failedEntries = allEntries.filter((e) => e.status === "failed");
  const blockedHosts = [
    ...new Set(failedEntries.filter((e) => e.blocked).map((e) => hostOf(e.url))),
  ];

  if (
    allEntries.length > 0 &&
    fetchedCount === 0 &&
    failedEntries.length > 0 &&
    failedEntries.every((e) => e.blocked)
  ) {
    return {
      name: "x2-fetch",
      state: "blocked",
      detail: `BLOCKED — network policy (${blockedHosts.join(", ")})`,
    };
  }
  if (fetchedCount === 0) {
    return {
      name: "x2-fetch",
      state: "error",
      detail: `all ${failedEntries.length} fetch(es) failed — see ${path.join(dir, "manifest.json")}`,
    };
  }
  if (failedEntries.length > 0) {
    // Gate finding S5: a PARTIAL block/failure must not read as a clean
    // "needs-confirmation" with exit 0 — the caller might never notice a
    // trail's rules page silently never loaded.
    return {
      name: "x2-fetch",
      state: "partial-blocked",
      detail:
        `${fetchedCount}/${allEntries.length} URL(s) fetched into ${dir}; ${failedEntries.length} failed/blocked: ` +
        failedEntries.map((e) => `${e.url} (${e.blocked ? "blocked" : "failed"})`).join(", "),
    };
  }
  return {
    name: "x2-fetch",
    state: "needs-confirmation",
    detail: `${fetchedCount}/${allEntries.length} URL(s) fetched into ${dir} — write a confirmation file and run x2-verdict next`,
  };
}

async function runX4VerifyStep(
  runDir: string,
  coursesPath: string,
): Promise<CheckRow> {
  if (!existsSync(coursesPath)) {
    return {
      name: "x4-verify",
      state: "skipped",
      detail: `no course map file at ${coursesPath} — supply one (X4.md METHOD: hand-looked-up GolfNow facility URLs) once X2's rosters are confirmed`,
    };
  }
  const dir = path.join(runDir, "x4-verify");
  let courseMap: X4CourseMap;
  try {
    courseMap = JSON.parse(await readFile(coursesPath, "utf8")) as X4CourseMap;
  } catch (err) {
    return {
      name: "x4-verify",
      state: "error",
      detail: `could not read course map ${coursesPath}: ${err instanceof Error ? err.message : String(err)}`,
    };
  }

  let result: X4VerifyResult;
  try {
    // p0-desk is an unattended desk check, not an operator running the
    // real X4 slate by hand — it never refuses over a partial/custom
    // course map (gate N7's refusal is for `x4-verify` run deliberately).
    const trailsPresent = [...new Set(Object.values(courseMap).map((e) => e.trail))];
    result = await runX4Verify(courseMap, dir, { slateTrails: trailsPresent });
  } catch (err) {
    return {
      name: "x4-verify",
      state: "error",
      detail: err instanceof Error ? err.message : String(err),
    };
  }

  const attempted = result.perCourse.filter((c) => c.url !== null);
  const blocked = attempted.filter((c) => c.blocked);
  if (attempted.length > 0 && blocked.length === attempted.length) {
    const hosts = [...new Set(blocked.map((c) => hostOf(c.url as string)))];
    return {
      name: "x4-verify",
      state: "blocked",
      detail: `BLOCKED — network policy (${hosts.join(", ")})`,
    };
  }

  // Decision 0001 Addendum H: ANY indeterminate course means the affected
  // trail(s) never get a verdict — that must not read as a clean "verdict"
  // state with exit 0.
  if (result.anyIndeterminate) {
    const notRun = Object.entries(result.perTrail)
      .filter(([, tc]) => tc.verdict === "not-run")
      .map(([trail, tc]) => `${trail}: not run — indeterminate (${tc.indeterminateCount})`)
      .join("; ");
    return {
      name: "x4-verify",
      state: "partial-blocked",
      detail: `${notRun} — see ${path.join(dir, "result.json")}`,
    };
  }

  const perTrailSummary = Object.entries(result.perTrail)
    .map(
      ([trail, tc]) =>
        `${trail} ${tc.liveCount}/${tc.rosterSize} (${(tc.pct ?? 0).toFixed(1)}%) ${tc.verdict.toUpperCase()}`,
    )
    .join("; ");
  return {
    name: "x4-verify",
    state: "verdict",
    detail: perTrailSummary || "no trails in course map",
  };
}

export interface RunP0DeskOptions {
  runDir?: string;
  x2ConfigPath?: string;
  x4CoursesPath?: string;
  endpoint?: string;
  timeoutMs?: number;
}

export async function runP0Desk(
  opts: RunP0DeskOptions = {},
): Promise<P0DeskResult> {
  const runDirExplicit = Boolean(opts.runDir);
  const runDir =
    opts.runDir ?? defaultOutsideRepoDir("p0-desk-run");
  // Gate finding S7: refuse an accidental write into the source tree; an
  // explicitly-chosen `runDir` (even one inside the repo) is trusted.
  assertOutsideRepoUnlessExplicit(runDir, runDirExplicit);
  await mkdir(runDir, { recursive: true });

  const rows: CheckRow[] = [];
  rows.push(
    await runX5NOsmStep(
      runDir,
      opts.endpoint ?? X5_DEFAULT_ENDPOINT,
      opts.timeoutMs ?? X5_DEFAULT_TIMEOUT_MS,
    ),
  );
  rows.push(
    await runX2FetchStep(runDir, opts.x2ConfigPath ?? resolveDefaultX2ConfigPath()),
  );
  rows.push(
    await runX4VerifyStep(
      runDir,
      opts.x4CoursesPath ?? resolveDefaultX4CoursesPath(),
    ),
  );

  const exitCode: 0 | 1 = rows.some(
    (r) => r.state === "blocked" || r.state === "error" || r.state === "partial-blocked",
  )
    ? 1
    : 0;
  const result: P0DeskResult = {
    runDir,
    generatedAt: new Date().toISOString(),
    rows,
    exitCode,
  };
  await writeFile(
    path.join(runDir, "status.json"),
    `${JSON.stringify(result, null, 2)}\n`,
    "utf8",
  );
  return result;
}

const STATE_LABEL: Record<CheckState, string> = {
  ran: "RAN",
  "needs-confirmation": "NEEDS-CONFIRMATION",
  blocked: "BLOCKED",
  "partial-blocked": "PARTIAL-BLOCKED",
  verdict: "VERDICT",
  skipped: "SKIPPED",
  error: "ERROR",
};

export function renderStatusBoard(result: P0DeskResult): string {
  const lines: string[] = [];
  lines.push(`P0 desk check — run dir: ${result.runDir}`);
  lines.push("");
  for (const row of result.rows) {
    lines.push(`[${STATE_LABEL[row.state]}] ${row.name} — ${row.detail}`);
  }
  lines.push("");
  lines.push(
    result.exitCode === 0
      ? "All checks ran (or are legitimately skipped)."
      : "Exiting non-zero: at least one check could not run, or ran only partially — see BLOCKED/PARTIAL-BLOCKED/ERROR rows above.",
  );
  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function parseFlags(argv: string[]): Record<string, string> {
  const flags: Record<string, string> = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg && arg.startsWith("--")) {
      flags[arg.slice(2)] = argv[i + 1] ?? "";
      i += 1;
    }
  }
  return flags;
}

async function main(argv: string[]): Promise<void> {
  const flags = parseFlags(argv);
  const result = await runP0Desk({
    ...(flags["run-dir"] ? { runDir: flags["run-dir"] } : {}),
    ...(flags["x2-config"] ? { x2ConfigPath: flags["x2-config"] } : {}),
    ...(flags["x4-courses"] ? { x4CoursesPath: flags["x4-courses"] } : {}),
    ...(flags.endpoint ? { endpoint: flags.endpoint } : {}),
  });
  process.stdout.write(`${renderStatusBoard(result)}\n`);
  process.exitCode = result.exitCode;
}

async function isMainModule(): Promise<boolean> {
  if (!process.argv[1]) return false;
  try {
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
    process.stderr.write(`p0-desk: ${message}\n`);
    process.exitCode = 1;
  });
}
