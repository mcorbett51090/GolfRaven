#!/usr/bin/env node
/**
 * `x5-overpass` — X5 (build plan §10 P0; `docs/p0/X5.md`) Overpass OSM
 * coverage check: the US+CA `leisure=golf_course` count (`N_osm`, a pace
 * measurement, not pass/fail) and per-pilot-candidate-course polygon
 * coverage against the pre-registered unit, match rule and
 * facility-sharing rules — applied here literally, not reinterpreted.
 *
 * Two subcommands:
 *   node dist/x5-overpass.js n-osm [--endpoint URL] [--from-file path.json] [--timeout-ms N]
 *   node dist/x5-overpass.js coverage --courses courses.json [--endpoint URL] [--responses saved.json] [--bbox-radius-meters N] [--timeout-ms N]
 *
 * `--from-file` / `--responses` read saved Overpass JSON responses instead
 * of making network calls, so the match-rule and coverage logic is
 * testable and re-runnable offline (this is how the test suite exercises
 * it — see `docs/p0/X5.md` STATUS: the public Overpass endpoint is
 * proxy-blocked in this environment as of 2026-09-23).
 */
import { readFile, writeFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";
import { boundingBox, haversineMeters, pointInPolygon, ringCentroid, type LatLon } from "./overpass-geo.js";

export const DEFAULT_ENDPOINT = "https://overpass-api.de/api/interpreter";
export const DEFAULT_BBOX_RADIUS_METERS = 2000;
export const DEFAULT_TIMEOUT_MS = 190_000;
/** Polite User-Agent per Overpass API usage norms `[unverified — training
 * knowledge on the exact expected format; the practice of identifying the
 * client and a contact is well documented across Overpass mirrors' usage
 * policies]`. */
export const USER_AGENT = "GolfRaven-P0-X5/0.1 (P0 desk check, docs/p0/X5.md; contact: matt@ravenpower.net)";

// ---------------------------------------------------------------------------
// Query builders (§1 and §2 of docs/p0/X5.md, reproduced verbatim / templated)
// ---------------------------------------------------------------------------

/** Verbatim from X5.md §1 — the US+CA `leisure=golf_course` count. */
export function buildNOsmQuery(): string {
  return `[out:json][timeout:180];
area["ISO3166-1"="US"][admin_level=2]->.us;
area["ISO3166-1"="CA"][admin_level=2]->.ca;
(
  way["leisure"="golf_course"](area.us);
  relation["leisure"="golf_course"](area.us);
  way["leisure"="golf_course"](area.ca);
  relation["leisure"="golf_course"](area.ca);
);
out count;`;
}

/** Templated from X5.md §2's bbox query shape, for one pilot-candidate
 * course's fetch window (see `boundingBox` doc for why the radius here is
 * a fetch-window choice, not itself part of the pre-registered match
 * rule). */
export function buildCourseCoverageQuery(center: LatLon, radiusMeters: number): string {
  const { south, west, north, east } = boundingBox(center, radiusMeters);
  const bbox = `${south},${west},${north},${east}`;
  return `[out:json][timeout:60];
(
  way["leisure"="golf_course"](${bbox});
  relation["leisure"="golf_course"](${bbox});
);
out geom;
(
  way["golf"="hole"](${bbox});
  relation["golf"="hole"](${bbox});
);
out count;`;
}

// ---------------------------------------------------------------------------
// Overpass response types (minimal — only the fields this tool reads)
// ---------------------------------------------------------------------------

export interface OverpassGeometryElement {
  type: "way" | "relation";
  id: number;
  tags?: Record<string, string>;
  geometry?: LatLon[];
}
export interface OverpassCountElement {
  type: "count";
  id: number;
  tags: { total: string; nodes?: string; ways?: string; relations?: string };
}
export type OverpassElement = OverpassGeometryElement | OverpassCountElement;
export interface OverpassResponse {
  elements: OverpassElement[];
}

export function parseNOsm(response: OverpassResponse): number {
  const countEl = response.elements.find(
    (e): e is OverpassCountElement => e.type === "count",
  );
  if (!countEl) {
    throw new Error(
      "Overpass response has no 'count' element — expected the N_osm query's `out count;` result " +
        "[unverified — training knowledge on the exact response shape].",
    );
  }
  const total = Number(countEl.tags.total);
  if (Number.isNaN(total)) {
    throw new Error(`Overpass count element's tags.total is not a number: ${countEl.tags.total}`);
  }
  return total;
}

export interface CoverageQueryResult {
  matchingElements: OverpassGeometryElement[];
  golfHoleWaysInBbox: number;
}

/** Splits a course-coverage response into its two result sets (the query
 * has two `(...); out ...;` blocks in one request) — the geometry elements
 * (`way`/`relation`, for the match rule) and the `golf=hole` bbox count (a
 * coverage-quality measurement recorded alongside, per X5.md §2, not
 * itself pass/fail; it is the literal bbox count the query asks for, not a
 * polygon-containment refinement X5.md does not specify). */
export function splitCoverageResponse(response: OverpassResponse): CoverageQueryResult {
  const matchingElements = response.elements.filter(
    (e): e is OverpassGeometryElement => e.type === "way" || e.type === "relation",
  );
  const countEl = response.elements.find((e): e is OverpassCountElement => e.type === "count");
  const golfHoleWaysInBbox = countEl ? Number(countEl.tags.total) || 0 : 0;
  return { matchingElements, golfHoleWaysInBbox };
}

// ---------------------------------------------------------------------------
// Match rule (X5.md "Match rule", pre-registered — implemented literally)
// ---------------------------------------------------------------------------

const NAME_MATCH_RADIUS_METERS = 500;

export interface PilotCandidateCourse {
  name: string;
  /** Approximate location — always required; used to build the query bbox
   * and, when no `knownPoint` is available, as the center of the 500 m
   * name-match radius. */
  lat: number;
  lon: number;
  trail: string;
  /** X2's `completionUnit` for this trail (X5.md "Unit"). */
  unit: "course" | "facility" | "hole";
  /** Required when `unit === "facility"`, to group courses sharing one
   * facility polygon (X5.md: "a shared facility polygon counts for every
   * course at that facility ... but it is still one data point per course
   * in the denominator, not one per facility" — see README for how
   * `facilityId` groups the 'facility' unit's denominator entries — decision
   * 0001 Addendum E). */
  facilityId?: string;
  /** X2's confirmed point for this course, when available. Enables the
   * containment branch of the match rule; without it, the rule falls back
   * to name-match-within-500m using `lat`/`lon` above. */
  knownPoint?: LatLon;
}

export type MatchedVia = "point" | "name" | null;

/** X5.md match rule, verbatim: "a candidate leisure=golf_course way/
 * relation counts for a given pilot-candidate course only if it contains
 * that course's known point (from X2's roster, once fetched), or, when no
 * point is available, is name-matched within a 500 m radius of the
 * course's approximate location." Not "any polygon returned by the bbox
 * query." */
export function matchCourse(
  course: PilotCandidateCourse,
  elements: OverpassGeometryElement[],
): MatchedVia {
  if (course.knownPoint) {
    for (const el of elements) {
      if (el.geometry && el.geometry.length >= 3 && pointInPolygon(course.knownPoint, el.geometry)) {
        return "point";
      }
    }
    // Per X5.md: when a known point IS available, the rule is containment
    // — it does not fall back to name-match. No match found.
    return null;
  }

  const courseNameLower = course.name.trim().toLowerCase();
  for (const el of elements) {
    const candidateName = el.tags?.name?.trim().toLowerCase();
    if (!candidateName || candidateName !== courseNameLower) continue;
    const candidatePoint: LatLon | null = el.geometry && el.geometry.length > 0 ? ringCentroid(el.geometry) : null;
    if (!candidatePoint) continue;
    const distance = haversineMeters({ lat: course.lat, lon: course.lon }, candidatePoint);
    if (distance <= NAME_MATCH_RADIUS_METERS) {
      return "name";
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Coverage calculation (X5.md "Coverage calculation" + "Unit")
// ---------------------------------------------------------------------------

export interface CourseCoverageEntry {
  course: PilotCandidateCourse;
  matchedVia: MatchedVia;
  golfHoleWaysInBbox: number;
}

export interface DenominatorEntry {
  /** 'course' unit: the course itself. 'facility' unit: the facilityId.
   * 'hole' unit: one entry per course (decision 0001 Addendum E). */
  key: string;
  trail: string;
  matched: boolean;
  courseNames: string[];
}

export interface TrailCoverage {
  matchedCount: number;
  total: number;
  pct: number;
}

export interface CoverageSummary {
  combined: TrailCoverage;
  perTrail: Record<string, TrailCoverage>;
  passBarPct: number;
  overallVerdict: "pass" | "kill";
  entries: DenominatorEntry[];
  warnings: string[];
}

const PASS_BAR_PCT = 60;

/** Builds denominator entries per X5.md's "Unit" rule: 'course' unit is one
 * entry per course, matched independently, even when several courses share
 * one facility polygon (each course's own point still falls inside that
 * one polygon, so no special-casing is needed here — each is evaluated on
 * its own). 'facility' unit groups by `facilityId` into one entry, matched
 * if any course at that facility matched; 'hole' unit is one entry per
 * course. Both rules are pre-registered in decision 0001 Addendum E. */
export function buildDenominatorEntries(
  coverage: CourseCoverageEntry[],
  warnings: string[],
): DenominatorEntry[] {
  const entries: DenominatorEntry[] = [];
  const facilityGroups = new Map<string, CourseCoverageEntry[]>();

  for (const c of coverage) {
    if (c.course.unit === "facility") {
      const key = c.course.facilityId;
      if (!key) {
        warnings.push(
          `Course "${c.course.name}" has unit: "facility" but no facilityId — treating it as its own facility group.`,
        );
      }
      const groupKey = key ?? `__no-facility-id__${c.course.name}`;
      const group = facilityGroups.get(groupKey) ?? [];
      group.push(c);
      facilityGroups.set(groupKey, group);
      continue;
    }

    // unit: "hole" — one denominator entry per course, same as "course" (decision 0001 Addendum E).

    entries.push({
      key: c.course.name,
      trail: c.course.trail,
      matched: c.matchedVia !== null,
      courseNames: [c.course.name],
    });
  }

  for (const [key, group] of facilityGroups) {
    const first = group[0];
    if (!first) continue;
    const trail = first.course.trail;
    entries.push({
      key,
      trail,
      matched: group.some((c) => c.matchedVia !== null),
      courseNames: group.map((c) => c.course.name),
    });
  }

  return entries;
}

export function computeCoverage(entries: DenominatorEntry[], warnings: string[] = []): CoverageSummary {
  const matchedCount = entries.filter((e) => e.matched).length;
  const total = entries.length;
  const pct = total === 0 ? 0 : (matchedCount / total) * 100;

  const perTrail: Record<string, TrailCoverage> = {};
  const byTrail = new Map<string, DenominatorEntry[]>();
  for (const e of entries) {
    const group = byTrail.get(e.trail) ?? [];
    group.push(e);
    byTrail.set(e.trail, group);
  }
  for (const [trail, group] of byTrail) {
    const m = group.filter((e) => e.matched).length;
    perTrail[trail] = { matchedCount: m, total: group.length, pct: group.length === 0 ? 0 : (m / group.length) * 100 };
  }

  return {
    combined: { matchedCount, total, pct },
    perTrail,
    passBarPct: PASS_BAR_PCT,
    overallVerdict: pct >= PASS_BAR_PCT ? "pass" : "kill",
    entries,
    warnings,
  };
}

// ---------------------------------------------------------------------------
// Network (live) — fetch, --from-file bypasses this entirely
// ---------------------------------------------------------------------------

export async function runOverpassQuery(
  query: string,
  endpoint: string,
  timeoutMs: number,
): Promise<OverpassResponse> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(endpoint, {
      method: "POST",
      // Overpass API's documented POST form `[unverified — training
      // knowledge]`: the query as `data=<query>` in a form-encoded body.
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": USER_AGENT,
      },
      body: `data=${encodeURIComponent(query)}`,
      signal: controller.signal,
    });
    if (!res.ok) {
      const bodyText = await res.text().catch(() => "<no body>");
      throw new Error(`Overpass request failed: HTTP ${res.status} ${res.statusText} — ${bodyText.slice(0, 500)}`);
    }
    return (await res.json()) as OverpassResponse;
  } finally {
    clearTimeout(timer);
  }
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

async function runNOsm(flags: Record<string, string>): Promise<void> {
  const endpoint = flags.endpoint || DEFAULT_ENDPOINT;
  const timeoutMs = flags["timeout-ms"] ? Number(flags["timeout-ms"]) : DEFAULT_TIMEOUT_MS;
  let response: OverpassResponse;
  if (flags["from-file"]) {
    response = JSON.parse(await readFile(flags["from-file"], "utf8")) as OverpassResponse;
  } else {
    response = await runOverpassQuery(buildNOsmQuery(), endpoint, timeoutMs);
  }
  const nOsm = parseNOsm(response);
  process.stdout.write(`N_osm (US+CA leisure=golf_course count): ${nOsm}\n`);
}

async function runCoverage(flags: Record<string, string>): Promise<void> {
  if (!flags.courses) {
    throw new Error("coverage requires --courses <path-to-courses.json>");
  }
  const endpoint = flags.endpoint || DEFAULT_ENDPOINT;
  const timeoutMs = flags["timeout-ms"] ? Number(flags["timeout-ms"]) : DEFAULT_TIMEOUT_MS;
  const bboxRadiusMeters = flags["bbox-radius-meters"]
    ? Number(flags["bbox-radius-meters"])
    : DEFAULT_BBOX_RADIUS_METERS;

  const courses = JSON.parse(await readFile(flags.courses, "utf8")) as PilotCandidateCourse[];

  let savedResponses: Record<string, OverpassResponse> | null = null;
  if (flags.responses) {
    savedResponses = JSON.parse(await readFile(flags.responses, "utf8")) as Record<string, OverpassResponse>;
  }

  const coverage: CourseCoverageEntry[] = [];
  const warnings: string[] = [];
  for (const course of courses) {
    let response: OverpassResponse;
    if (savedResponses) {
      const saved = savedResponses[course.name];
      if (!saved) {
        warnings.push(`No saved Overpass response for course "${course.name}" in --responses file; treating as unmatched.`);
        coverage.push({ course, matchedVia: null, golfHoleWaysInBbox: 0 });
        continue;
      }
      response = saved;
    } else {
      const query = buildCourseCoverageQuery({ lat: course.lat, lon: course.lon }, bboxRadiusMeters);
      response = await runOverpassQuery(query, endpoint, timeoutMs);
    }
    const { matchingElements, golfHoleWaysInBbox } = splitCoverageResponse(response);
    const matchedVia = matchCourse(course, matchingElements);
    coverage.push({ course, matchedVia, golfHoleWaysInBbox });
  }

  const entries = buildDenominatorEntries(coverage, warnings);
  const summary = computeCoverage(entries, warnings);

  const outPrefix = flags.out || "x5-overpass-coverage-result";
  await writeFile(`${outPrefix}.json`, `${JSON.stringify({ coverage, summary }, null, 2)}\n`, "utf8");

  process.stdout.write(
    `X5 coverage: ${summary.combined.matchedCount}/${summary.combined.total} ` +
      `(${summary.combined.pct.toFixed(1)}%) vs ${summary.passBarPct}% bar — ${summary.overallVerdict.toUpperCase()}\n`,
  );
  for (const [trail, tc] of Object.entries(summary.perTrail)) {
    process.stdout.write(`  ${trail}: ${tc.matchedCount}/${tc.total} (${tc.pct.toFixed(1)}%)\n`);
  }
  if (warnings.length > 0) {
    process.stderr.write(`Warnings:\n${warnings.map((w) => `  - ${w}`).join("\n")}\n`);
  }
}

async function main(argv: string[]): Promise<void> {
  const [subcommand, ...rest] = argv;
  const flags = parseFlags(rest);
  if (subcommand === "n-osm") {
    await runNOsm(flags);
  } else if (subcommand === "coverage") {
    await runCoverage(flags);
  } else {
    throw new Error(
      "Usage:\n" +
        "  node dist/x5-overpass.js n-osm [--endpoint URL] [--from-file path.json] [--timeout-ms N]\n" +
        "  node dist/x5-overpass.js coverage --courses courses.json [--endpoint URL] [--responses saved.json] [--bbox-radius-meters N] [--timeout-ms N] [--out prefix]",
    );
  }
}

const isMain = process.argv[1] !== undefined && pathToFileURL(process.argv[1]).href === import.meta.url;
if (isMain) {
  main(process.argv.slice(2)).catch((err: unknown) => {
    const message = err instanceof Error ? err.message : String(err);
    process.stderr.write(`x5-overpass: ${message}\n`);
    process.exitCode = 1;
  });
}
