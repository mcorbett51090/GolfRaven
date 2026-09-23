#!/usr/bin/env node
/**
 * `x4-verify` — the X4 (build plan §10 P0; `docs/p0/X4.md`) GolfNow
 * facility-page coverage check, evaluated PER TRAIL (decision 0001
 * Addendum G: "X4 is evaluated per trail: each slate trail is its own pass
 * ... or kill ... The X4 row records every trail's result; no combined
 * figure decides anything"). Input is a hand-built JSON map of slate course
 * -> `{trail, golfnowFacilityUrl | null}` (X4.md METHOD: facility ids are
 * looked up BY HAND on golfnow.com — this tool never searches or crawls
 * GolfNow, it only fetches the exact URLs it is given).
 *
 * For each non-null URL, fetches it live or replays a saved response, and
 * applies Addendum G's "live page" definition literally: HTTP 200, the
 * final URL after redirects still contains `/tee-times/facility/<id>-`,
 * and the page text contains the course's name under Addendum F's name
 * normalisation (`namesMatch`, reused from `overpass-geo.ts` verbatim, not
 * reimplemented). A `null` URL and a non-live page both count as "not
 * covered" — X4.md's own rule.
 *
 * Every LIVE response is saved for replay (same `{request, fetchedAt,
 * response}` envelope pattern `x5-overpass.ts` uses for its own live
 * responses), so a verdict can be re-audited offline later.
 */
import { mkdir, readFile, realpath, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { namesMatch } from "./overpass-geo.js";
import { stripHtmlToText } from "./text-extract.js";
import { buildAsciiUserAgent, fetchWithBlockDetection } from "./net.js";

export const X4_DEFAULT_TIMEOUT_MS = 30_000;
export const X4_PASS_BAR_PCT = 80;

export function buildX4UserAgent(): string {
  return buildAsciiUserAgent({
    toolTag: "GolfRaven-P0-X4/0.1",
    docRef: "docs/p0/X4.md",
    envVarName: "X4_CONTACT",
  });
}

export interface X4CourseEntry {
  trail: string;
  golfnowFacilityUrl: string | null;
}
/** slate course name -> its trail + (if known) GolfNow facility URL. */
export type X4CourseMap = Record<string, X4CourseEntry>;

const FACILITY_URL_RE = /\/tee-times\/facility\/[^/]+-/;

/** Decision 0001 Addendum G's "live page" definition, applied literally. */
export function isLiveFacilityPage(
  status: number,
  finalUrl: string,
  pageText: string,
  courseName: string,
): { live: boolean; reason: string } {
  if (status !== 200) {
    return { live: false, reason: `HTTP ${status}, not 200` };
  }
  if (!FACILITY_URL_RE.test(finalUrl)) {
    return {
      live: false,
      reason: `final URL "${finalUrl}" does not contain /tee-times/facility/<id>- (e.g. a redirect to a generic search page)`,
    };
  }
  if (!namesMatch(pageText, courseName)) {
    return {
      live: false,
      reason: `course name "${courseName}" was not found on the page text (Addendum F normalisation)`,
    };
  }
  return { live: true, reason: "live" };
}

export interface X4CheckResult {
  course: string;
  trail: string;
  url: string | null;
  status: "live" | "not-live" | "no-url" | "failed";
  reason: string;
  httpStatus: number | null;
  finalUrl: string | null;
  blocked: boolean;
}

export interface X4TrailCoverage {
  liveCount: number;
  rosterSize: number;
  pct: number;
  verdict: "pass" | "kill";
  /** X4.md kill consequence, applied per trail per decision 0001 Addendum
   * G — `null` on a pass. */
  consequence: string | null;
}

export interface X4VerifyResult {
  generatedAt: string;
  perCourse: X4CheckResult[];
  perTrail: Record<string, X4TrailCoverage>;
  passBarPct: number;
  warnings: string[];
}

/** Coverage per trail = live ÷ that trail's roster size — X4.md/Addendum G:
 * a `null` URL and a non-live page both count as "not covered", so the
 * roster size is every entry for that trail, not just the ones with a URL. */
export function computeX4Coverage(
  perCourse: X4CheckResult[],
): Record<string, X4TrailCoverage> {
  const byTrail = new Map<string, X4CheckResult[]>();
  for (const c of perCourse) {
    const group = byTrail.get(c.trail) ?? [];
    group.push(c);
    byTrail.set(c.trail, group);
  }
  const perTrail: Record<string, X4TrailCoverage> = {};
  for (const [trail, group] of byTrail) {
    const liveCount = group.filter((c) => c.status === "live").length;
    const rosterSize = group.length;
    const pct = rosterSize === 0 ? 0 : (liveCount / rosterSize) * 100;
    const verdict: "pass" | "kill" = pct >= X4_PASS_BAR_PCT ? "pass" : "kill";
    perTrail[trail] = {
      liveCount,
      rosterSize,
      pct,
      verdict,
      consequence:
        verdict === "kill"
          ? `Course-native link becomes primary for ${trail} (X4.md kill consequence, applied per trail per decision 0001 Addendum G).`
          : null,
    };
  }
  return perTrail;
}

export interface X4SavedEnvelope {
  request: { url: string };
  fetchedAt: string;
  response: { status: number; finalUrl: string; bodyText: string };
}

async function checkOneCourse(
  course: string,
  entry: X4CourseEntry,
  timeoutMs: number,
  saved: Record<string, X4SavedEnvelope> | undefined,
  rawToSave: Record<string, X4SavedEnvelope>,
): Promise<X4CheckResult> {
  if (!entry.golfnowFacilityUrl) {
    return {
      course,
      trail: entry.trail,
      url: null,
      status: "no-url",
      reason: "no GolfNow facility URL supplied — counts as not covered",
      httpStatus: null,
      finalUrl: null,
      blocked: false,
    };
  }
  const url = entry.golfnowFacilityUrl;

  let status: number;
  let finalUrl: string;
  let bodyText: string;

  if (saved) {
    // Gate-B-4-style run integrity (x5-overpass.ts): a missing saved
    // response for a course the caller asked about is a hard refusal, not
    // a silent "treat as not-live".
    const envelope = saved[course];
    if (!envelope) {
      throw new Error(
        `No saved response for course "${course}" in --responses file — refusing to treat this as not-live ` +
          "(same run-integrity style as x5-overpass: a missing saved response stops the run).",
      );
    }
    status = envelope.response.status;
    finalUrl = envelope.response.finalUrl;
    bodyText = envelope.response.bodyText;
  } else {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    let outcome: Awaited<ReturnType<typeof fetchWithBlockDetection>>;
    try {
      outcome = await fetchWithBlockDetection(url, {
        method: "GET",
        headers: { "User-Agent": buildX4UserAgent() },
        redirect: "follow",
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timer);
    }
    if (outcome.kind !== "ok") {
      return {
        course,
        trail: entry.trail,
        url,
        status: "failed",
        reason:
          outcome.kind === "blocked"
            ? `BLOCKED — network policy (${outcome.host}): ${outcome.detail}`
            : `fetch error (${outcome.host}): ${outcome.detail}`,
        httpStatus: null,
        finalUrl: null,
        blocked: outcome.kind === "blocked",
      };
    }
    const response = outcome.response;
    status = response.status;
    finalUrl = response.url || url;
    const rawHtml = await response.text().catch(() => "");
    bodyText = stripHtmlToText(rawHtml);
    rawToSave[course] = {
      request: { url },
      fetchedAt: new Date().toISOString(),
      response: { status, finalUrl, bodyText },
    };
  }

  const { live, reason } = isLiveFacilityPage(status, finalUrl, bodyText, course);
  return {
    course,
    trail: entry.trail,
    url,
    status: live ? "live" : "not-live",
    reason,
    httpStatus: status,
    finalUrl,
    blocked: false,
  };
}

export async function runX4Verify(
  courseMap: X4CourseMap,
  outDir: string,
  opts: { responses?: Record<string, X4SavedEnvelope>; timeoutMs?: number } = {},
): Promise<X4VerifyResult> {
  const entries = Object.entries(courseMap);
  if (entries.length === 0) {
    throw new Error(
      "Course map is empty — refusing to compute X4 coverage from zero courses.",
    );
  }
  await mkdir(outDir, { recursive: true });
  const rawToSave: Record<string, X4SavedEnvelope> = {};
  const perCourse: X4CheckResult[] = [];
  for (const [course, entry] of entries) {
    const result = await checkOneCourse(
      course,
      entry,
      opts.timeoutMs ?? X4_DEFAULT_TIMEOUT_MS,
      opts.responses,
      rawToSave,
    );
    perCourse.push(result);
  }
  const perTrail = computeX4Coverage(perCourse);
  const warnings: string[] = [];
  for (const c of perCourse) {
    if (c.status === "failed") warnings.push(`${c.course}: ${c.reason}`);
  }
  const result: X4VerifyResult = {
    generatedAt: new Date().toISOString(),
    perCourse,
    perTrail,
    passBarPct: X4_PASS_BAR_PCT,
    warnings,
  };
  await writeFile(
    path.join(outDir, "result.json"),
    `${JSON.stringify(result, null, 2)}\n`,
    "utf8",
  );
  if (!opts.responses && Object.keys(rawToSave).length > 0) {
    await writeFile(
      path.join(outDir, "responses.json"),
      `${JSON.stringify(rawToSave, null, 2)}\n`,
      "utf8",
    );
  }
  return result;
}

export function renderX4Summary(result: X4VerifyResult): string {
  const lines: string[] = [];
  for (const [trail, tc] of Object.entries(result.perTrail)) {
    lines.push(
      `${trail}: ${tc.liveCount}/${tc.rosterSize} (${tc.pct.toFixed(1)}%) vs ${result.passBarPct}% bar — ${tc.verdict.toUpperCase()}` +
        (tc.consequence ? ` — ${tc.consequence}` : ""),
    );
  }
  if (result.warnings.length > 0) {
    lines.push("Warnings:");
    for (const w of result.warnings) lines.push(`  - ${w}`);
  }
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

/** Repo-relative default path for a course map, resolved from THIS
 * module's own location — mirrors `x2-fetch.ts`'s config resolver. There is
 * no seeded default file at this path (X4.md: facility ids are looked up
 * by hand, once X2's rosters exist); its absence is `p0-desk`'s ordinary
 * "skip X4" case, not an error. */
export function resolveDefaultX4CoursesPath(): string {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const pkgRoot = path.join(here, "..");
  return path.join(pkgRoot, "config", "x4-course-map.json");
}

async function main(argv: string[]): Promise<void> {
  const flags = parseFlags(argv);
  if (!flags.courses) {
    throw new Error(
      "Usage: node dist/x4-verify.js --courses <course-map.json> [--responses <saved.json>] [--out-dir <dir>]",
    );
  }
  const courseMap = JSON.parse(
    await readFile(flags.courses, "utf8"),
  ) as X4CourseMap;
  const responses = flags.responses
    ? (JSON.parse(
        await readFile(flags.responses, "utf8"),
      ) as Record<string, X4SavedEnvelope>)
    : undefined;
  const outDir = flags["out-dir"] || "x4-verify-result";
  const result = await runX4Verify(courseMap, outDir, {
    ...(responses ? { responses } : {}),
  });
  process.stdout.write(`${renderX4Summary(result)}\n`);
  process.stdout.write(`Result written to ${path.join(outDir, "result.json")}\n`);
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
    process.stderr.write(`x4-verify: ${message}\n`);
    process.exitCode = 1;
  });
}
