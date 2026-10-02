// supabase/functions/_shared/catalog/directory-artifact.ts
//
// Hand-rolled parsing of the REAL `facilities/<region>.json` / `trails.json`
// / `designers.json` shards `tools/catalog/src/emit-catalog.ts` actually
// produces (P3e round 2 gate, H2: "Import catalog_facility / catalog_course
// (and trail/hole where the emitter publishes them)... If a real piece of
// the directory contract is ambiguous, pick the reading the emitter
// actually produces and note it").
//
// ⛔ NAMING NOTE: the build plan's own §3.3 prose names a
// `directory/<ISO-region>.json` shard — emit-catalog.ts's own header
// explains why that shard does not actually exist: "`facilities/<region>.json`
// shards by ISO region, exactly as §5.2 already states for 'Directory
// JSON'" (bundle.ts:171-192, confirmed this round against the real
// emitter). This module parses the shard the emitter ACTUALLY writes.
//
// ⛔ WHAT THE EMITTER PUBLISHES vs. WHAT HAS A TARGET TABLE (P3e round 3,
// R3 — checked field by field against `packages/catalog/src/schema.ts` and
// `tools/catalog/src/emit-catalog.ts`; round 2's report wrongly said hole
// ids and roster versions were not published — they are):
//   IMPORTED (published AND has a target):
//     facilities/<region>.json -> app.catalog_facility (id, slug, name, region,
//       tz); each Facility.courses[] -> app.catalog_course (id, facility_id,
//       name, designer_id = first of `designers`, closed, holes);
//       Course.holesDetail[] -> app.catalog_hole (id, course_id, number).
//     trails.json -> app.catalog_trail (id, slug, name) and
//       Trail.rosterVersions[] -> app.catalog_roster_version +
//       app.catalog_roster_member (course / anyOf / facility / hole members).
//     designers.json -> app.catalog_designer (id, name).
//   NOT IMPORTED — published, but NO target column/table exists:
//     Facility: nameFr, town, lat, lng, blurb(Fr), url, access, amenities,
//       booking, prov/derivedFrom/seed, externalIds.
//     Course: slug, par, opened, tees, composite, prov/derivedFrom/seed,
//       externalIds, and every `designers` entry after the first
//       (catalog_course.designer_id is a single column).
//     Trail: nameFr, countries, regions, kind, status, operator, officialUrl,
//       rosterStatus, blurb(Fr), lastReviewed, sources; per-version `source`/
//       `verifiedAt`.
//     Designer: aliases, sources.  offer-terms.json: no catalog table (the
//       offer's `terms_id` is a catalog-owned id, not an FK).
//     osm/** (ODbL layer): no table.
//   NOT PUBLISHED AT ALL (so impossible to import):
//     GEOMETRY. `Course.geometry` is a POINTER ({layer, ref, file, ...}),
//       never inline polygon/point data, and emit-catalog.ts writes no
//       geometry shard ("This bundle carries no geometry payload"). So
//       `catalog_course.boundary`/`radius_center`/`radius_m`/`geometry_kind`
//       stay NULL for every imported course — an imported course can
//       therefore never produce a polygon match or a presence co-signal
//       until the (P1.1+) geometry pipeline exists.
//
const ID_RE = /^(trl|fac|crs|hol|dsg)_[0-9A-HJKMNP-TV-Z]{26}$/;

export type ParseResult<T> = { ok: true; value: T } | { ok: false; issue: string };

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

const VERIFICATION_STATUSES = new Set(["unverified", "listed-verified", "play-verified"]);

export interface ParsedHole {
  id: string;
  number: number;
}

export interface ParsedCourse {
  id: string;
  name: string | null;
  holes: number | null;
  closed: boolean;
  designerId: string | null;
  holesDetail: ParsedHole[];
}

export interface ParsedFacility {
  id: string;
  slug: string;
  region: string;
  tz: string;
  name: string | null;
  verificationStatus: "unverified" | "listed-verified" | "play-verified";
  courses: ParsedCourse[];
}

/** One `facilities/<region>.json` shard — an array of `Facility` (see
 * this module's own header for exactly which fields are read; every
 * OTHER field the real schema carries — booking, amenities, seed
 * provenance, ... — is accepted but ignored, not rejected, since this
 * parser's job is "pull out what app.catalog_facility/catalog_course can
 * hold," not full P1-schema conformance (packages/catalog's own zod
 * schema already owns that, at BUILD time, before this artifact is ever
 * signed). */
export function parseFacilitiesShard(raw: unknown): ParseResult<ParsedFacility[]> {
  if (!Array.isArray(raw)) return { ok: false, issue: "facilities shard: not an array" };
  const out: ParsedFacility[] = [];
  for (let i = 0; i < raw.length; i++) {
    const f = raw[i];
    if (!isPlainObject(f)) return { ok: false, issue: `facilities[${i}]: not an object` };
    if (typeof f.id !== "string" || !ID_RE.test(f.id)) return { ok: false, issue: `facilities[${i}]: id must be a valid facility id` };
    if (typeof f.slug !== "string" || f.slug.length === 0) return { ok: false, issue: `facilities[${i}]: slug must be a non-empty string` };
    if (typeof f.region !== "string" || f.region.length === 0) return { ok: false, issue: `facilities[${i}]: region must be a non-empty string` };
    if (typeof f.tz !== "string" || f.tz.length === 0) return { ok: false, issue: `facilities[${i}]: tz must be a non-empty string` };
    const name = typeof f.name === "string" ? f.name : null;
    const verification = f.verification;
    if (!isPlainObject(verification) || typeof verification.status !== "string" || !VERIFICATION_STATUSES.has(verification.status)) {
      return { ok: false, issue: `facilities[${i}]: verification.status must be one of unverified|listed-verified|play-verified` };
    }
    if (!Array.isArray(f.courses) || f.courses.length === 0) {
      return { ok: false, issue: `facilities[${i}]: courses must be a non-empty array` };
    }
    const courses: ParsedCourse[] = [];
    for (let j = 0; j < f.courses.length; j++) {
      const c = f.courses[j];
      if (!isPlainObject(c)) return { ok: false, issue: `facilities[${i}].courses[${j}]: not an object` };
      if (typeof c.id !== "string" || !ID_RE.test(c.id)) return { ok: false, issue: `facilities[${i}].courses[${j}]: id must be a valid course id` };
      const cName = typeof c.name === "string" ? c.name : null;
      const holes = typeof c.holes === "number" && Number.isInteger(c.holes) && c.holes > 0 ? c.holes : null;
      const closed = c.closed === true;
      let designerId: string | null = null;
      if (Array.isArray(c.designers) && c.designers.length > 0 && typeof c.designers[0] === "string") {
        // app.catalog_course has room for exactly one designer_id — a
        // course with several (packages/catalog's own Course.designers is
        // an array) takes the first, documented here rather than silently.
        designerId = c.designers[0];
      }
      const holesDetail: ParsedHole[] = [];
      if (c.holesDetail !== undefined) {
        if (!Array.isArray(c.holesDetail)) return { ok: false, issue: `facilities[${i}].courses[${j}]: holesDetail must be an array` };
        for (let k = 0; k < c.holesDetail.length; k++) {
          const h = c.holesDetail[k];
          if (!isPlainObject(h) || typeof h.id !== "string" || !ID_RE.test(h.id) || !h.id.startsWith("hol_")) {
            return { ok: false, issue: `facilities[${i}].courses[${j}].holesDetail[${k}]: id must be a valid hole id` };
          }
          if (typeof h.number !== "number" || !Number.isInteger(h.number) || h.number < 1 || h.number > 36) {
            return { ok: false, issue: `facilities[${i}].courses[${j}].holesDetail[${k}]: number must be an integer 1..36` };
          }
          holesDetail.push({ id: h.id, number: h.number });
        }
      }
      courses.push({ id: c.id, name: cName, holes, closed, designerId, holesDetail });
    }
    out.push({ id: f.id, slug: f.slug, region: f.region, tz: f.tz, name, verificationStatus: verification.status as ParsedFacility["verificationStatus"], courses });
  }
  return { ok: true, value: out };
}

export type ParsedRosterMember =
  | { unit: "course"; courseId: string; stopOrder: number | null }
  | { unit: "course"; anyOf: string[]; stopOrder: number | null }
  | { unit: "facility"; facilityId: string; stopOrder: number | null }
  | { unit: "hole"; holeId: string; courseId: string; stopOrder: number | null };

export interface ParsedRule {
  kind: "all" | "n_of_m";
  n: number | null;
  /** `ruleSource.url` — catalog_roster_version stores the rule source as text. */
  source: string | null;
}

export interface ParsedRosterVersion {
  version: number;
  /** ISO date `YYYY-MM-DD` (catalog_roster_version.effective_from is a timestamptz — midnight UTC). */
  effectiveFrom: string;
  completionUnit: "course" | "facility" | "hole";
  markerUnit: "course" | "facility" | "hole";
  completionRule: ParsedRule;
  markerRule: ParsedRule;
  trackingStartsOn: string | null;
  members: ParsedRosterMember[];
}

export interface ParsedTrail {
  id: string;
  slug: string;
  name: string;
  rosterVersions: ParsedRosterVersion[];
}

const ISO_DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const UNITS = new Set(["course", "facility", "hole"]);

function parseRule(raw: unknown, path: string): ParseResult<ParsedRule> {
  if (!isPlainObject(raw)) return { ok: false, issue: `${path}: not an object` };
  if (raw.kind === "all") return { ok: true, value: { kind: "all", n: null, source: null } };
  if (raw.kind === "n-of-m") {
    if (typeof raw.n !== "number" || !Number.isInteger(raw.n) || raw.n < 1) return { ok: false, issue: `${path}.n must be a positive integer` };
    const src = raw.ruleSource;
    if (!isPlainObject(src) || typeof src.url !== "string" || src.url.length === 0) return { ok: false, issue: `${path}.ruleSource.url is required for n-of-m` };
    return { ok: true, value: { kind: "n_of_m", n: raw.n, source: src.url } };
  }
  return { ok: false, issue: `${path}.kind must be "all" or "n-of-m"` };
}

function parseMember(raw: unknown, path: string): ParseResult<ParsedRosterMember> {
  if (!isPlainObject(raw)) return { ok: false, issue: `${path}: not an object` };
  const stopOrder = typeof raw.stopOrder === "number" && Number.isInteger(raw.stopOrder) && raw.stopOrder >= 0 ? raw.stopOrder : null;
  const idOf = (v: unknown, prefix: string): string | null => (typeof v === "string" && ID_RE.test(v) && v.startsWith(prefix) ? v : null);
  switch (raw.unit) {
    case "course": {
      if (Array.isArray(raw.anyOf)) {
        const ids = raw.anyOf.map((x) => idOf(x, "crs_"));
        if (ids.length < 2 || ids.some((x) => x === null)) return { ok: false, issue: `${path}.anyOf must list >= 2 valid course ids` };
        return { ok: true, value: { unit: "course", anyOf: ids as string[], stopOrder } };
      }
      const courseId = idOf(raw.courseId, "crs_");
      if (!courseId) return { ok: false, issue: `${path}.courseId must be a valid course id` };
      return { ok: true, value: { unit: "course", courseId, stopOrder } };
    }
    case "facility": {
      const facilityId = idOf(raw.facilityId, "fac_");
      if (!facilityId) return { ok: false, issue: `${path}.facilityId must be a valid facility id` };
      return { ok: true, value: { unit: "facility", facilityId, stopOrder } };
    }
    case "hole": {
      const holeId = idOf(raw.holeId, "hol_");
      const courseId = idOf(raw.courseId, "crs_");
      if (!holeId || !courseId) return { ok: false, issue: `${path}: hole member needs a valid holeId and courseId` };
      return { ok: true, value: { unit: "hole", holeId, courseId, stopOrder } };
    }
    default:
      return { ok: false, issue: `${path}.unit must be course|facility|hole` };
  }
}

export function parseTrailsShard(raw: unknown): ParseResult<ParsedTrail[]> {
  if (!Array.isArray(raw)) return { ok: false, issue: "trails shard: not an array" };
  const out: ParsedTrail[] = [];
  for (let i = 0; i < raw.length; i++) {
    const t = raw[i];
    if (!isPlainObject(t)) return { ok: false, issue: `trails[${i}]: not an object` };
    if (typeof t.id !== "string" || !ID_RE.test(t.id)) return { ok: false, issue: `trails[${i}]: id must be a valid trail id` };
    if (typeof t.slug !== "string" || t.slug.length === 0) return { ok: false, issue: `trails[${i}]: slug must be a non-empty string` };
    if (typeof t.name !== "string" || t.name.length === 0) return { ok: false, issue: `trails[${i}]: name must be a non-empty string` };
    const rosterVersions: ParsedRosterVersion[] = [];
    // rosterVersions is optional HERE (a minimal/older shard may omit it) —
    // the real P1 schema requires >= 1; absence just means nothing to import.
    if (t.rosterVersions !== undefined) {
      if (!Array.isArray(t.rosterVersions)) return { ok: false, issue: `trails[${i}].rosterVersions must be an array` };
      for (let j = 0; j < t.rosterVersions.length; j++) {
        const rv = t.rosterVersions[j];
        const path = `trails[${i}].rosterVersions[${j}]`;
        if (!isPlainObject(rv)) return { ok: false, issue: `${path}: not an object` };
        if (typeof rv.version !== "number" || !Number.isInteger(rv.version) || rv.version < 1) return { ok: false, issue: `${path}.version must be a positive integer` };
        if (typeof rv.effectiveFrom !== "string" || !ISO_DATE_RE.test(rv.effectiveFrom)) return { ok: false, issue: `${path}.effectiveFrom must be an ISO date` };
        if (typeof rv.completionUnit !== "string" || !UNITS.has(rv.completionUnit)) return { ok: false, issue: `${path}.completionUnit invalid` };
        if (typeof rv.markerUnit !== "string" || !UNITS.has(rv.markerUnit)) return { ok: false, issue: `${path}.markerUnit invalid` };
        const cr = parseRule(rv.completionRule, `${path}.completionRule`);
        if (!cr.ok) return cr;
        const mr = parseRule(rv.markerRule, `${path}.markerRule`);
        if (!mr.ok) return mr;
        let trackingStartsOn: string | null = null;
        if (rv.trackingStartsOn !== undefined) {
          if (typeof rv.trackingStartsOn !== "string" || !ISO_DATE_RE.test(rv.trackingStartsOn)) return { ok: false, issue: `${path}.trackingStartsOn must be an ISO date` };
          trackingStartsOn = rv.trackingStartsOn;
        }
        if (!Array.isArray(rv.members) || rv.members.length === 0) return { ok: false, issue: `${path}.members must be a non-empty array` };
        const members: ParsedRosterMember[] = [];
        for (let k = 0; k < rv.members.length; k++) {
          const m = parseMember(rv.members[k], `${path}.members[${k}]`);
          if (!m.ok) return m;
          members.push(m.value);
        }
        rosterVersions.push({ version: rv.version, effectiveFrom: rv.effectiveFrom, completionUnit: rv.completionUnit as ParsedRosterVersion["completionUnit"], markerUnit: rv.markerUnit as ParsedRosterVersion["markerUnit"], completionRule: cr.value, markerRule: mr.value, trackingStartsOn, members });
      }
    }
    out.push({ id: t.id, slug: t.slug, name: t.name, rosterVersions });
  }
  return { ok: true, value: out };
}

export interface ParsedDesigner {
  id: string;
  name: string;
}

export function parseDesignersShard(raw: unknown): ParseResult<ParsedDesigner[]> {
  if (!Array.isArray(raw)) return { ok: false, issue: "designers shard: not an array" };
  const out: ParsedDesigner[] = [];
  for (let i = 0; i < raw.length; i++) {
    const d = raw[i];
    if (!isPlainObject(d)) return { ok: false, issue: `designers[${i}]: not an object` };
    if (typeof d.id !== "string" || !ID_RE.test(d.id)) return { ok: false, issue: `designers[${i}]: id must be a valid designer id` };
    if (typeof d.name !== "string" || d.name.length === 0) return { ok: false, issue: `designers[${i}]: name must be a non-empty string` };
    out.push({ id: d.id, name: d.name });
  }
  return { ok: true, value: out };
}
