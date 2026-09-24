#!/usr/bin/env node
/**
 * `x4-verify` — the X4 (build plan §10 P0; `docs/p0/X4.md`) GolfNow
 * facility-page coverage check, evaluated PER TRAIL (decision 0001
 * Addendum G: "X4 is evaluated per trail ... The X4 row records every
 * trail's result; no combined figure decides anything"). Input is a
 * hand-built JSON map of slate course -> `{trail, golfnowFacilityUrl |
 * null}` (X4.md METHOD: facility ids are looked up BY HAND on golfnow.com
 * — this tool never searches or crawls GolfNow, it only fetches the exact
 * URLs it is given).
 *
 * Decision 0001 Addendum H (2026-09-24) makes each course's check a THREE-
 * way outcome, not two:
 *
 *  - LIVE — Addendum G's definition, literally: HTTP 200; final host is
 *    EXACTLY `www.golfnow.com`; final URL PATH contains
 *    `/tee-times/facility/<id>-` for the SAME `<id>` the configured URL
 *    named (gate B2 — the old check matched the pattern ANYWHERE in the
 *    URL string, including the query string, against ANY id); course name
 *    present under Addendum F normalisation.
 *  - NOT COVERED (definitive) — no URL configured, HTTP 404/410, or a
 *    resolved HTTP 200 page that fails the live test (wrong id, generic
 *    search page, foreign host, name absent).
 *  - INDETERMINATE — a network-policy block, timeout, connection error,
 *    HTTP 403/429/5xx, or any other unlisted status. NEVER counted as "not
 *    covered" (gate B1).
 *
 * A trail's verdict is computed ONLY when none of its courses is
 * indeterminate; otherwise the trail is "not run — indeterminate (n)" and
 * the whole runner exits non-zero (Addendum H).
 */
import { mkdir, readFile, realpath, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { namesMatch } from "./overpass-geo.js";
import { stripHtmlToText } from "./text-extract.js";
import { buildAsciiUserAgent, DEFAULT_MAX_RESPONSE_BYTES, fetchWithBlockDetection, readBodyCapped } from "./net.js";
import { SLATE_TRAILS } from "./slate.js";
import { assertOutsideRepoUnlessExplicit, defaultOutsideRepoDir } from "./run-dir.js";

export const X4_DEFAULT_TIMEOUT_MS = 30_000;
export const X4_PASS_BAR_PCT = 80;
export const X4_SLATE_TRAILS = SLATE_TRAILS;

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

const REQUIRED_HOST = "www.golfnow.com";
/** Gate B2: the CONFIGURED URL must itself already be a well-formed
 * facility-search URL on the real host, over https — this is also where
 * the requested `<id>` is parsed from, so a later "same id" check has
 * something to compare against. */
const CONFIGURED_URL_RE =
  /^https:\/\/www\.golfnow\.com\/tee-times\/facility\/(\d+)-[^/]+\/search$/;

/** Parses the facility id from a configured GolfNow facility URL. Throws
 * (refuses the whole run) on a URL that doesn't match the required shape —
 * gate B2: "refuse map entries that don't match" rather than silently
 * treating a malformed entry as anything else. */
export function parseFacilityId(configuredUrl: string): string {
  const m = CONFIGURED_URL_RE.exec(configuredUrl);
  if (!m || !m[1]) {
    throw new Error(
      `Configured GolfNow facility URL "${configuredUrl}" does not match ` +
        "https://www.golfnow.com/tee-times/facility/<id>-<slug>/search (https, exact host, numeric id) " +
        "— refusing (gate finding B2 / decision 0001 Addendum G).",
    );
  }
  return m[1];
}

export type X4Classification = "live" | "not-live" | "indeterminate";

/** Decision 0001 Addendum H's three-way per-course outcome, applied
 * literally. `facilityId` is the id parsed from the CONFIGURED url (gate
 * B2) — the final URL's path must contain `/tee-times/facility/<that same
 * id>-`, not just any id. */
export function isLiveFacilityPage(
  status: number,
  finalUrl: string,
  pageText: string,
  courseName: string,
  facilityId: string,
): { status: X4Classification; reason: string } {
  if (status === 404 || status === 410) {
    return { status: "not-live", reason: `HTTP ${status} — not covered (definitive, Addendum H)` };
  }
  if (status === 403 || status === 429 || (status >= 500 && status < 600)) {
    return {
      status: "indeterminate",
      reason: `HTTP ${status} — indeterminate, never "not covered" (Addendum H)`,
    };
  }
  if (status !== 200) {
    return {
      status: "indeterminate",
      reason: `HTTP ${status} — unlisted status, indeterminate (Addendum H)`,
    };
  }
  let final: URL;
  try {
    final = new URL(finalUrl);
  } catch {
    return { status: "not-live", reason: `final URL "${finalUrl}" is not a valid URL — not live` };
  }
  if (final.hostname !== REQUIRED_HOST) {
    return {
      status: "not-live",
      reason: `final host "${final.hostname}" is not exactly "${REQUIRED_HOST}" (gate B2)`,
    };
  }
  if (!final.pathname.includes(`/tee-times/facility/${facilityId}-`)) {
    return {
      status: "not-live",
      reason:
        `final URL path "${final.pathname}" does not contain /tee-times/facility/${facilityId}- for the ` +
        "SAME id that was requested — a match elsewhere in the URL (e.g. the query string) or for a " +
        "different id does not count (gate B2)",
    };
  }
  if (!namesMatch(pageText, courseName)) {
    return {
      status: "not-live",
      reason: `course name "${courseName}" was not found on the page text (Addendum F normalisation)`,
    };
  }
  return { status: "live", reason: "live" };
}

export interface X4CheckResult {
  course: string;
  trail: string;
  url: string | null;
  status: "live" | "not-live" | "no-url" | "indeterminate";
  reason: string;
  httpStatus: number | null;
  finalUrl: string | null;
  blocked: boolean;
}

export interface X4TrailCoverage {
  liveCount: number;
  rosterSize: number;
  /** `null` when the trail's verdict could not be computed (Addendum H:
   * any indeterminate course blocks the whole trail's verdict). */
  pct: number | null;
  verdict: "pass" | "kill" | "not-run";
  indeterminateCount: number;
  /** X4.md kill consequence, applied per trail per decision 0001 Addendum
   * G — `null` on a pass or a not-run trail. */
  consequence: string | null;
}

export interface X4VerifyResult {
  generatedAt: string;
  perCourse: X4CheckResult[];
  perTrail: Record<string, X4TrailCoverage>;
  passBarPct: number;
  warnings: string[];
  /** Addendum H: true when any trail is "not-run" — the CLI exits non-zero
   * whenever this is true. */
  anyIndeterminate: boolean;
}

/** Coverage per trail = live ÷ that trail's roster size (X4.md/Addendum G:
 * a `null` URL and a non-live page both count as "not covered"). Addendum
 * H: a trail with ANY indeterminate course never gets a pass/kill verdict
 * at all — it is "not run", regardless of how the rest of its roster
 * looks. */
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
    const rosterSize = group.length;
    const indeterminateCount = group.filter((c) => c.status === "indeterminate").length;
    const liveCount = group.filter((c) => c.status === "live").length;
    if (indeterminateCount > 0) {
      perTrail[trail] = {
        liveCount,
        rosterSize,
        pct: null,
        verdict: "not-run",
        indeterminateCount,
        consequence: null,
      };
      continue;
    }
    const pct = rosterSize === 0 ? 0 : (liveCount / rosterSize) * 100;
    const verdict: "pass" | "kill" = pct >= X4_PASS_BAR_PCT ? "pass" : "kill";
    perTrail[trail] = {
      liveCount,
      rosterSize,
      pct,
      verdict,
      indeterminateCount: 0,
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
      reason: "no GolfNow facility URL supplied — counts as not covered (definitive)",
      httpStatus: null,
      finalUrl: null,
      blocked: false,
    };
  }
  const url = entry.golfnowFacilityUrl;
  // Gate B2: refuses (throws) the whole run on a malformed configured URL —
  // see module doc.
  const facilityId = parseFacilityId(url);

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
    // Gate N1: refuse a replay whose saved request URL no longer matches
    // the course map's CURRENT URL for this course — otherwise a changed
    // map entry silently replays a stale, unrelated response as live.
    if (envelope.request.url !== url) {
      throw new Error(
        `Saved response for course "${course}" was recorded for URL "${envelope.request.url}", which differs ` +
          `from the course map's current URL "${url}" — refusing to replay a stale response (gate finding N1).`,
      );
    }
    status = envelope.response.status;
    finalUrl = envelope.response.finalUrl;
    bodyText = envelope.response.bodyText;
  } else {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      let outcome: Awaited<ReturnType<typeof fetchWithBlockDetection>>;
      try {
        outcome = await fetchWithBlockDetection(url, {
          method: "GET",
          headers: { "User-Agent": buildX4UserAgent() },
          redirect: "follow",
          signal: controller.signal,
        });
      } catch (err) {
        return {
          course,
          trail: entry.trail,
          url,
          status: "indeterminate",
          reason: `fetch threw unexpectedly: ${err instanceof Error ? err.message : String(err)}`,
          httpStatus: null,
          finalUrl: null,
          blocked: false,
        };
      }
      if (outcome.kind !== "ok") {
        // Gate B1: a network-policy block, timeout or connection error is
        // ALWAYS indeterminate — never "not covered".
        return {
          course,
          trail: entry.trail,
          url,
          status: "indeterminate",
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
      let rawHtml: string;
      try {
        // Gate S6: the timer stays live through the body read (cleared only
        // in the outer `finally`), with a byte cap enforced while streaming.
        const buf = await readBodyCapped(response, {
          signal: controller.signal,
          maxBytes: DEFAULT_MAX_RESPONSE_BYTES,
        });
        rawHtml = buf.toString("utf8");
      } catch (err) {
        // Gate S6: a body-read failure is indeterminate, not silently "".
        return {
          course,
          trail: entry.trail,
          url,
          status: "indeterminate",
          reason: `body read failed (timeout or size cap): ${err instanceof Error ? err.message : String(err)}`,
          httpStatus: status,
          finalUrl,
          blocked: false,
        };
      }
      bodyText = stripHtmlToText(rawHtml);
      rawToSave[course] = {
        request: { url },
        fetchedAt: new Date().toISOString(),
        response: { status, finalUrl, bodyText },
      };
    } finally {
      clearTimeout(timer);
    }
  }

  const classification = isLiveFacilityPage(status, finalUrl, bodyText, course, facilityId);
  return {
    course,
    trail: entry.trail,
    url,
    status: classification.status,
    reason: classification.reason,
    httpStatus: status,
    finalUrl,
    blocked: false,
  };
}

export async function runX4Verify(
  courseMap: X4CourseMap,
  outDir: string,
  opts: {
    responses?: Record<string, X4SavedEnvelope>;
    timeoutMs?: number;
    /** Gate N7: every one of these trails must have at least one entry in
     * `courseMap`, or the run refuses. Defaults to the pilot slate; pass an
     * explicit (possibly empty) list to evaluate a different/partial set. */
    slateTrails?: readonly string[];
  } = {},
): Promise<X4VerifyResult> {
  const entries = Object.entries(courseMap);
  if (entries.length === 0) {
    throw new Error(
      "Course map is empty — refusing to compute X4 coverage from zero courses.",
    );
  }
  const slateTrails = opts.slateTrails ?? X4_SLATE_TRAILS;
  const presentTrails = new Set(entries.map(([, e]) => e.trail));
  const missingTrails = slateTrails.filter((t) => !presentTrails.has(t));
  if (missingTrails.length > 0) {
    throw new Error(
      `Course map has no entry for trail(s) ${missingTrails.join(", ")} — refusing (gate finding N7: every ` +
        "slate trail must appear in the X4 row, or pass an explicit slateTrails/--slate).",
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
    if (c.status === "indeterminate") warnings.push(`${c.course}: ${c.reason}`);
  }
  const anyIndeterminate = Object.values(perTrail).some((tc) => tc.verdict === "not-run");
  const result: X4VerifyResult = {
    generatedAt: new Date().toISOString(),
    perCourse,
    perTrail,
    passBarPct: X4_PASS_BAR_PCT,
    warnings,
    anyIndeterminate,
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
    if (tc.verdict === "not-run") {
      lines.push(`${trail}: not run — indeterminate (${tc.indeterminateCount})`);
      continue;
    }
    lines.push(
      `${trail}: ${tc.liveCount}/${tc.rosterSize} (${(tc.pct ?? 0).toFixed(1)}%) vs ${result.passBarPct}% bar — ${tc.verdict.toUpperCase()}` +
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
      "Usage: node dist/x4-verify.js --courses <course-map.json> [--responses <saved.json>] [--out-dir <dir>] [--slate TN,VI,RTJ]",
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
  const outDirExplicit = Boolean(flags["out-dir"]);
  const outDir = flags["out-dir"] || defaultOutsideRepoDir("x4-verify-result");
  assertOutsideRepoUnlessExplicit(outDir, outDirExplicit);
  const slateTrails = flags.slate ? flags.slate.split(",").map((s) => s.trim()) : undefined;
  const result = await runX4Verify(courseMap, outDir, {
    ...(responses ? { responses } : {}),
    ...(slateTrails ? { slateTrails } : {}),
  });
  process.stdout.write(`${renderX4Summary(result)}\n`);
  process.stdout.write(`Result written to ${path.join(outDir, "result.json")}\n`);
  if (result.anyIndeterminate) {
    process.exitCode = 1;
  }
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
