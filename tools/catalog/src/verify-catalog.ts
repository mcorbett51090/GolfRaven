/**
 * `verify-catalog` — the P1 AT(1)/(5)/(7)/(8) gate, over the catalog
 * records this task's scope covers (build plan §10 P1 Acceptance tests;
 * every RuleExpr/achievements fixture is part B, per the task's own scope
 * cut).
 *
 * **How the geometry-diff and contact-field diff gates receive "the
 * previous version" (design note, since the task asks for this to be
 * explained).** Both gates (§10 P1 AT(1): "centroid moved > 150 m ...
 * without the `geometry-reviewed` label"; "`url`/`phone`/booking host
 * changed without `contact-reviewed`") compare the incoming catalog
 * against what was last published, and both need an out-of-band human
 * review signal (a PR label) that plainly cannot live inside catalog JSON.
 * This CLI takes:
 *   - `--base <bundle-file>` — a previously-published `CatalogBundle`
 *     (same shape as the input), read the same way as `--bundle`. Its
 *     absence is not an error: with no `--base`, the diff-shaped gates
 *     (`ROSTER_VERSION_IMMUTABLE_CHANGE`, `GEOMETRY_DIFF_UNREVIEWED`,
 *     `CONTACT_DIFF_UNREVIEWED`) simply have nothing to diff against and
 *     are skipped — exactly decision 0003 S1's own carve-out ("It does not
 *     include `verify-contract`'s breaking-diff check, which has nothing
 *     to diff against before the freeze" — the same reasoning applies to
 *     these per-record diffs before a first version is ever published).
 *   - `--labels a,b,c` — the PR's labels for this run (in CI,
 *     `${{ join(github.event.pull_request.labels.*.name, ',') }}`). A
 *     bundle may also carry its own `labels[]` field, for a self-contained
 *     fixture that doesn't need a CLI flag; `--labels` overrides it when
 *     given.
 */
import { readFile } from "node:fs/promises";
import { realpath } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import {
  COURSE_CONTENT_FIELDS,
  COURSE_DERIVED_FROM_ALLOWED_KEYS,
  FACILITY_CONTENT_FIELDS,
  FACILITY_CONTENT_FIELD_TO_PROV_KEY,
  FACILITY_DERIVED_FROM_ALLOWED_KEYS,
  isIdTombstoned,
  resolveMergedId,
  tzLikelyContainsCoordinates,
  type Course,
  type Facility,
  type IdLedger,
  type RosterMember,
  type RosterVersion,
  type Trail,
} from "@golfraven/catalog";
import { parseCatalogBundle, type CatalogBundle } from "./bundle.js";

export interface CatalogIssue {
  /** A short, stable, upper-snake identifier — asserted on directly by
   * fixture tests (never just "it fails"). */
  code: string;
  /** A dotted path into the bundle, for a human or a test to locate the
   * offending field. */
  path: string;
  message: string;
}

export interface VerifyCatalogOptions {
  base?: CatalogBundle;
  /** Overrides `bundle.labels` when given (see module doc). */
  labels?: string[];
}

export interface VerifyCatalogResult {
  ok: boolean;
  issues: CatalogIssue[];
}

function issue(code: string, path: string, message: string): CatalogIssue {
  return { code, path, message };
}

/** Deterministic structural equality over JSON-safe values (object key
 * order does not matter; array element order does — roster member order
 * is meaningful). Used by the roster-version-immutability and diff gates. */
function deepEqual(a: unknown, b: unknown): boolean {
  return canonicalize(a) === canonicalize(b);
}

function canonicalize(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalize).join(",")}]`;
  }
  if (value !== null && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, v]) => v !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalize(v)}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

/* ------------------------------------------------------------------ */
/* Id collection helpers                                               */
/* ------------------------------------------------------------------ */

interface CourseWithFacility {
  course: Course;
  facility: Facility;
  facilityIndex: number;
  courseIndex: number;
}

function collectCourses(bundle: CatalogBundle): CourseWithFacility[] {
  const out: CourseWithFacility[] = [];
  bundle.facilities.forEach((facility, facilityIndex) => {
    facility.courses.forEach((course, courseIndex) => {
      out.push({ course, facility, facilityIndex, courseIndex });
    });
  });
  return out;
}

/* ------------------------------------------------------------------ */
/* DUPLICATE_ID / REUSED_TOMBSTONED_ID                                 */
/* ------------------------------------------------------------------ */

function checkIds(
  bundle: CatalogBundle,
  courses: CourseWithFacility[],
  issues: CatalogIssue[],
): void {
  const seenAt = new Map<string, string[]>();
  const record = (id: string, path: string) => {
    const paths = seenAt.get(id) ?? [];
    paths.push(path);
    seenAt.set(id, paths);
  };

  bundle.facilities.forEach((f, i) => record(f.id, `facilities[${i}].id`));
  courses.forEach(({ course, facilityIndex, courseIndex }) =>
    record(course.id, `facilities[${facilityIndex}].courses[${courseIndex}].id`),
  );
  bundle.trails.forEach((t, i) => record(t.id, `trails[${i}].id`));
  (bundle.designers ?? []).forEach((d, i) => record(d.id, `designers[${i}].id`));

  for (const [id, paths] of seenAt) {
    if (paths.length > 1) {
      for (const path of paths) {
        issues.push(
          issue(
            "DUPLICATE_ID",
            path,
            `id "${id}" is used by more than one record in this catalog (${paths.join(", ")})`,
          ),
        );
      }
    }
    const ledgerEntry = bundle.idLedger.entries[id];
    if (ledgerEntry?.tombstoned) {
      for (const path of paths) {
        issues.push(
          issue(
            "REUSED_TOMBSTONED_ID",
            path,
            `id "${id}" is tombstoned in the ID ledger (mergedInto: ${ledgerEntry.mergedInto ?? "none"}) and can never be reassigned (§3.5)`,
          ),
        );
      }
    }
  }
}

/* ------------------------------------------------------------------ */
/* Roster member resolution                                            */
/* ------------------------------------------------------------------ */

interface CatalogIndex {
  facilityById: Map<string, Facility>;
  courseById: Map<string, CourseWithFacility>;
}

function buildIndex(bundle: CatalogBundle, courses: CourseWithFacility[]): CatalogIndex {
  const facilityById = new Map(bundle.facilities.map((f) => [f.id, f]));
  const courseById = new Map(courses.map((c) => [c.course.id, c]));
  return { facilityById, courseById };
}

/** Resolves a roster member to the facility it is ultimately judged
 * against, through the ledger's `mergedInto` closure (A2-04). Returns
 * `undefined` for a member this catalog cannot resolve at all — the
 * `ROSTER_MISSING_MEMBER` case. */
function resolveMemberFacility(
  member: RosterMember,
  index: CatalogIndex,
  ledger: IdLedger,
): Facility | undefined {
  const resolveCourse = (courseId: string) => {
    const resolved = resolveMergedId(ledger, courseId);
    return index.courseById.get(resolved) ?? index.courseById.get(courseId);
  };
  switch (member.unit) {
    case "facility": {
      const resolved = resolveMergedId(ledger, member.facilityId);
      return index.facilityById.get(resolved) ?? index.facilityById.get(member.facilityId);
    }
    case "course": {
      if ("courseId" in member) {
        return resolveCourse(member.courseId)?.facility;
      }
      // anyOf (A2-18): resolvable if AT LEAST ONE listed course exists.
      for (const courseId of member.anyOf) {
        const found = resolveCourse(courseId);
        if (found) return found.facility;
      }
      return undefined;
    }
    case "hole": {
      return resolveCourse(member.courseId)?.facility;
    }
  }
}

function memberMissing(
  member: RosterMember,
  index: CatalogIndex,
  ledger: IdLedger,
): boolean {
  const resolveCourse = (courseId: string) => {
    const resolved = resolveMergedId(ledger, courseId);
    return index.courseById.has(resolved) || index.courseById.has(courseId);
  };
  switch (member.unit) {
    case "facility": {
      const resolved = resolveMergedId(ledger, member.facilityId);
      return !(index.facilityById.has(resolved) || index.facilityById.has(member.facilityId));
    }
    case "course": {
      if ("courseId" in member) return !resolveCourse(member.courseId);
      return !member.anyOf.some((id) => resolveCourse(id));
    }
    case "hole": {
      return !resolveCourse(member.courseId);
    }
  }
}

/* ------------------------------------------------------------------ */
/* Roster checks                                                       */
/* ------------------------------------------------------------------ */

function checkRosters(
  bundle: CatalogBundle,
  index: CatalogIndex,
  issues: CatalogIssue[],
): void {
  bundle.trails.forEach((trail, trailIndex) => {
    trail.rosterVersions.forEach((version, versionIndex) => {
      const versionPath = `trails[${trailIndex}].rosterVersions[${versionIndex}]`;

      version.members.forEach((member, memberIndex) => {
        const memberPath = `${versionPath}.members[${memberIndex}]`;
        if (memberMissing(member, index, bundle.idLedger)) {
          issues.push(
            issue(
              "ROSTER_MISSING_MEMBER",
              memberPath,
              `roster member does not resolve to any facility/course/hole in this catalog (through the ledger's mergedInto closure)`,
            ),
          );
          return; // nothing further to check against a member we can't resolve
        }
        if (member.unit !== version.completionUnit) {
          issues.push(
            issue(
              "ROSTER_UNIT_MEMBER_MISMATCH",
              memberPath,
              `member.unit "${member.unit}" does not match this version's completionUnit "${version.completionUnit}" (§4.1/§4.3: unit consistency within a version)`,
            ),
          );
        }
        // O8: a listed-verified+ facility referenced by a roster must
        // carry `access`.
        const facility = resolveMemberFacility(member, index, bundle.idLedger);
        if (
          facility &&
          facility.verification.status !== "unverified" &&
          facility.access === undefined
        ) {
          issues.push(
            issue(
              "ROSTER_MEMBER_MISSING_ACCESS",
              memberPath,
              `facility "${facility.id}" is referenced by a roster and is verified, but has no "access" value (O8)`,
            ),
          );
        }
      });

      // A latest roster version containing a closed course.
      const isLatest =
        version.version === Math.max(...trail.rosterVersions.map((v) => v.version));
      if (isLatest) {
        version.members.forEach((member, memberIndex) => {
          const closedCourseIds = closedCourseIdsOf(member, index, bundle.idLedger);
          for (const courseId of closedCourseIds) {
            issues.push(
              issue(
                "ROSTER_LATEST_CONTAINS_CLOSED_COURSE",
                `${versionPath}.members[${memberIndex}]`,
                `the latest published roster version still contains closed course "${courseId}" (§4.2 promotion table / A2-18)`,
              ),
            );
          }
        });
      }
    });
  });
}

function closedCourseIdsOf(
  member: RosterMember,
  index: CatalogIndex,
  ledger: IdLedger,
): string[] {
  const check = (courseId: string): string[] => {
    const resolved = resolveMergedId(ledger, courseId);
    const entry = index.courseById.get(resolved) ?? index.courseById.get(courseId);
    return entry?.course.closed === true ? [entry.course.id] : [];
  };
  if (member.unit === "course" && "courseId" in member) return check(member.courseId);
  if (member.unit === "course" && "anyOf" in member) {
    return member.anyOf.flatMap(check);
  }
  if (member.unit === "hole") return check(member.courseId);
  return [];
}

/* ------------------------------------------------------------------ */
/* Roster version immutability (needs --base)                          */
/* ------------------------------------------------------------------ */

function checkRosterVersionImmutability(
  bundle: CatalogBundle,
  base: CatalogBundle,
  issues: CatalogIssue[],
): void {
  const baseTrailById = new Map(base.trails.map((t) => [t.id, t]));
  bundle.trails.forEach((trail, trailIndex) => {
    const baseTrail = baseTrailById.get(trail.id);
    if (!baseTrail) return; // a brand-new trail has no published versions yet
    const baseVersionByNumber = new Map(baseTrail.rosterVersions.map((v) => [v.version, v]));
    trail.rosterVersions.forEach((version, versionIndex) => {
      const baseVersion = baseVersionByNumber.get(version.version);
      if (!baseVersion) return; // a new version number — nothing published yet to compare
      if (!deepEqual(version, baseVersion)) {
        issues.push(
          issue(
            "ROSTER_VERSION_IMMUTABLE_CHANGE",
            `trails[${trailIndex}].rosterVersions[${versionIndex}]`,
            `published RosterVersion ${version.version} of trail "${trail.id}" differs from the last published catalog (members or rule parameters, A2-02) — append a new version instead`,
          ),
        );
      }
    });
    baseTrail.rosterVersions.forEach((baseVersion) => {
      const stillPresent = trail.rosterVersions.some((v) => v.version === baseVersion.version);
      if (!stillPresent) {
        issues.push(
          issue(
            "ROSTER_VERSION_REMOVED",
            `trails[${trailIndex}].rosterVersions`,
            `published RosterVersion ${baseVersion.version} of trail "${trail.id}" is missing from this catalog — a published version is append-only and immutable (§4.1)`,
          ),
        );
      }
    });
  });
}

/* ------------------------------------------------------------------ */
/* Booking host gate                                                   */
/* ------------------------------------------------------------------ */

function hostOf(url: string): string | undefined {
  try {
    return new URL(url).host;
  } catch {
    return undefined;
  }
}

function checkBooking(
  bundle: CatalogBundle,
  issues: CatalogIssue[],
): void {
  const allowList = new Set(bundle.bookingHostAllowList ?? []);
  bundle.facilities.forEach((facility, facilityIndex) => {
    // O8: a private facility may carry no booking[] entry at all — checked
    // once per facility, not once per entry.
    if (facility.access === "private" && facility.booking.length > 0) {
      issues.push(
        issue(
          "PRIVATE_FACILITY_HAS_BOOKING",
          `facilities[${facilityIndex}].booking`,
          `facility "${facility.id}" is access: 'private' and must carry no booking[] entry (O8)`,
        ),
      );
    }

    facility.booking.forEach((entry, bookingIndex) => {
      const path = `facilities[${facilityIndex}].booking[${bookingIndex}]`;
      const host = hostOf(entry.url);
      if (entry.provider === "course-native") {
        const facilityHost = facility.url ? hostOf(facility.url) : undefined;
        if (!facilityHost || host !== facilityHost) {
          issues.push(
            issue(
              "BOOKING_COURSE_NATIVE_HOST_MISMATCH",
              path,
              `booking.provider is "course-native" but its host ("${host ?? "?"}") does not match the facility's own domain ("${facilityHost ?? "(facility.url missing)"}")`,
            ),
          );
        }
        return;
      }
      if (!host || !allowList.has(host)) {
        issues.push(
          issue(
            "BOOKING_HOST_NOT_ALLOWED",
            path,
            `booking host "${host ?? entry.url}" is not on the booking-host allow-list for this run`,
          ),
        );
      }
    });
  });
}

/* ------------------------------------------------------------------ */
/* Verification-tier gates                                             */
/* ------------------------------------------------------------------ */

function checkVerificationTiers(bundle: CatalogBundle, issues: CatalogIssue[]): void {
  bundle.facilities.forEach((facility, facilityIndex) => {
    const path = `facilities[${facilityIndex}]`;
    const verified = facility.verification.status !== "unverified";

    if (verified && facility.approx === true) {
      issues.push(
        issue(
          "VERIFIED_APPROX_TRUE",
          `${path}.approx`,
          `facility "${facility.id}" is ${facility.verification.status} and must not have approx: true (§4.2)`,
        ),
      );
    }

    if (facility.verification.status === "play-verified") {
      const everyCourseHasGeometry =
        facility.courses.length > 0 &&
        facility.courses.every((c) => c.geometry !== undefined);
      const facilityWidePolygon = facility.courses.some(
        (c) => c.geometry?.sharedWithFacility === true,
      );
      if (!everyCourseHasGeometry && !facilityWidePolygon) {
        issues.push(
          issue(
            "PLAY_VERIFIED_MISSING_POLYGON",
            `${path}.courses`,
            `facility "${facility.id}" is play-verified but has neither a polygon per course nor a shared facility-wide polygon (§4.2)`,
          ),
        );
      }
    }

    // tz "wrong zone" (the part IanaTimeZoneSchema cannot check, see geo.ts).
    if (facility.lat !== undefined && facility.lng !== undefined) {
      if (!tzLikelyContainsCoordinates(facility.tz, { lat: facility.lat, lng: facility.lng })) {
        issues.push(
          issue(
            "TZ_WRONG_ZONE",
            `${path}.tz`,
            `facility "${facility.id}"'s tz "${facility.tz}" does not plausibly contain its coordinates (G-P0-11)`,
          ),
        );
      }
    }

    if (facility.verification.basis === "course-claim" && !facility.verification.claimProof) {
      // Structurally unreachable (schema.ts's superRefine already rejects
      // this at parse time) — kept as a defence-in-depth assertion, not a
      // fixture target.
      issues.push(
        issue(
          "CLAIM_PROOF_REQUIRED",
          `${path}.verification.claimProof`,
          `verification.basis is "course-claim" but claimProof is missing (§4.1)`,
        ),
      );
    }
  });
}

/* ------------------------------------------------------------------ */
/* prov / derivedFrom (§4.1 "What the gate forbids, exactly")          */
/* ------------------------------------------------------------------ */

/**
 * §4.1 gate rule (a)/(c) each name TWO failure shapes: "no `prov` stamp,
 * **or** `prov: 'osm'`" and "a `derivedFrom` key on any field other than
 * region/tz/slug". This P1a schema (`ProvSchema`, `FacilityDerivedFromSchema`,
 * `CourseDerivedFromSchema`) makes the *second* shape of each pair
 * structurally impossible to even parse: `ProvSchema` never includes
 * `'osm'` as a member, and both `derivedFrom` schemas are `strictObject`s
 * with exactly the allowed keys. So those two sub-cases surface as
 * `SCHEMA_INVALID` (from `parseCatalogBundle`), one layer earlier than
 * this function — see `mf-course-name-prov-osm` and
 * `mf-derived-from-invalid-key` in `test/fixtures/`, both must-fail
 * fixtures that never reach this function at all. The checks below for
 * "`prov === 'osm'`" and an unrecognised `derivedFrom` key are kept as
 * defence-in-depth (never dead in the sense of being wrong, just
 * currently unreachable through this schema) in case a future schema
 * change ever widens either type.
 */
function checkProvenance(
  bundle: CatalogBundle,
  courses: CourseWithFacility[],
  issues: CatalogIssue[],
): void {
  bundle.facilities.forEach((facility, facilityIndex) => {
    const path = `facilities[${facilityIndex}]`;
    for (const field of FACILITY_CONTENT_FIELDS) {
      const value = facility[field as keyof Facility];
      if (value === undefined) continue;
      const provKey = FACILITY_CONTENT_FIELD_TO_PROV_KEY[field];
      if (provKey === undefined) continue; // nameFr: no prov key exists (see schema.ts's doc)
      const prov = facility.prov?.[provKey];
      if (prov === undefined || (prov as string) === "osm") {
        issues.push(
          issue(
            "PROV_MISSING_OR_OSM",
            `${path}.prov.${field}`,
            `facility "${facility.id}" content field "${field}" has no non-OSM prov stamp (§4.1 gate rule (a))`,
          ),
        );
      }
    }
    if (facility.derivedFrom) {
      for (const key of Object.keys(facility.derivedFrom)) {
        if (!(FACILITY_DERIVED_FROM_ALLOWED_KEYS as readonly string[]).includes(key)) {
          issues.push(
            issue(
              "DERIVED_FROM_INVALID_KEY",
              `${path}.derivedFrom.${key}`,
              `facility "${facility.id}" carries derivedFrom on "${key}", which is not one of region/tz/slug (§4.1 gate rule (c))`,
            ),
          );
        }
      }
    }

    // Gate rule (b): a listed-verified+ facility's content fields, and its
    // courses' name/holes, must be PRESENT (not merely prov-stamped when
    // present).
    if (facility.verification.status !== "unverified") {
      for (const field of ["name", "town", "lat", "lng"] as const) {
        if (facility[field] === undefined) {
          issues.push(
            issue(
              "VERIFIED_CONTENT_INCOMPLETE",
              `${path}.${field}`,
              `facility "${facility.id}" is ${facility.verification.status} and is missing required content field "${field}" (§4.1 gate rule (b))`,
            ),
          );
        }
      }
    }
  });

  courses.forEach(({ course, facility, facilityIndex, courseIndex }) => {
    const path = `facilities[${facilityIndex}].courses[${courseIndex}]`;
    for (const field of COURSE_CONTENT_FIELDS) {
      const value = course[field as keyof Course];
      if (value === undefined) continue;
      const prov = course.prov?.[field as keyof NonNullable<Course["prov"]>];
      if (prov === undefined || (prov as string) === "osm") {
        issues.push(
          issue(
            "PROV_MISSING_OR_OSM",
            `${path}.prov.${field}`,
            `course "${course.id}" content field "${field}" has no non-OSM prov stamp (§4.1 gate rule (a), G3-01: "The gate applies to courses exactly as to facilities")`,
          ),
        );
      }
    }
    if (course.derivedFrom) {
      for (const key of Object.keys(course.derivedFrom)) {
        if (!(COURSE_DERIVED_FROM_ALLOWED_KEYS as readonly string[]).includes(key)) {
          issues.push(
            issue(
              "DERIVED_FROM_INVALID_KEY",
              `${path}.derivedFrom.${key}`,
              `course "${course.id}" carries derivedFrom on "${key}", which is not "slug" (§4.1 gate rule (c))`,
            ),
          );
        }
      }
    }
    if (facility.verification.status !== "unverified") {
      for (const field of ["name", "holes"] as const) {
        if (course[field] === undefined) {
          issues.push(
            issue(
              "VERIFIED_CONTENT_INCOMPLETE",
              `${path}.${field}`,
              `course "${course.id}" belongs to a ${facility.verification.status} facility and is missing required content field "${field}" (§4.1 gate rule (b), G3-01)`,
            ),
          );
        }
      }
    }
  });
}

/* ------------------------------------------------------------------ */
/* Geometry-diff / contact-field diff (need --base and labels)         */
/* ------------------------------------------------------------------ */

const GEOMETRY_CENTROID_MOVE_METERS = 150;

function checkDiffs(
  bundle: CatalogBundle,
  base: CatalogBundle,
  labels: Set<string>,
  issues: CatalogIssue[],
): void {
  const baseFacilityById = new Map(base.facilities.map((f) => [f.id, f]));
  bundle.facilities.forEach((facility, facilityIndex) => {
    const baseFacility = baseFacilityById.get(facility.id);
    if (!baseFacility) return; // new facility, nothing to diff
    const path = `facilities[${facilityIndex}]`;

    // Geometry-diff: centroid move only (see module/geo.ts doc for why
    // area-change is not implemented in P1a).
    if (
      facility.lat !== undefined &&
      facility.lng !== undefined &&
      baseFacility.lat !== undefined &&
      baseFacility.lng !== undefined
    ) {
      const distanceMeters = haversineForDiff(
        { lat: facility.lat, lng: facility.lng },
        { lat: baseFacility.lat, lng: baseFacility.lng },
      );
      if (distanceMeters > GEOMETRY_CENTROID_MOVE_METERS && !labels.has("geometry-reviewed")) {
        issues.push(
          issue(
            "GEOMETRY_DIFF_UNREVIEWED",
            `${path}.lat`,
            `facility "${facility.id}"'s centroid moved ${distanceMeters.toFixed(0)} m from the last published catalog (> ${GEOMETRY_CENTROID_MOVE_METERS} m) without the "geometry-reviewed" label`,
          ),
        );
      }
    }

    const contactChanged =
      facility.url !== baseFacility.url ||
      facility.phone !== baseFacility.phone ||
      !deepEqual(
        facility.booking.map((b) => b.url).sort(),
        baseFacility.booking.map((b) => b.url).sort(),
      );
    if (contactChanged && !labels.has("contact-reviewed")) {
      issues.push(
        issue(
          "CONTACT_DIFF_UNREVIEWED",
          path,
          `facility "${facility.id}"'s url, phone or a booking host changed from the last published catalog without the "contact-reviewed" label (FM-21)`,
        ),
      );
    }
  });
}

// Duplicated (not imported) from packages/catalog/src/geo.ts deliberately:
// that module's haversine takes the same 2 points shape, but importing it
// here would be redundant plumbing for one call — inlined instead. (Left
// as a note rather than re-exported to avoid a needless coupling for a
// three-line formula.)
function haversineForDiff(a: { lat: number; lng: number }, b: { lat: number; lng: number }): number {
  const R = 6_371_000;
  const toRad = (d: number) => (d * Math.PI) / 180;
  const dLat = toRad(b.lat - a.lat);
  const dLng = toRad(b.lng - a.lng);
  const lat1 = toRad(a.lat);
  const lat2 = toRad(b.lat);
  const h =
    Math.sin(dLat / 2) ** 2 + Math.cos(lat1) * Math.cos(lat2) * Math.sin(dLng / 2) ** 2;
  return R * (2 * Math.atan2(Math.sqrt(h), Math.sqrt(1 - h)));
}

/* ------------------------------------------------------------------ */
/* Top-level                                                            */
/* ------------------------------------------------------------------ */

export function verifyCatalog(
  bundle: CatalogBundle,
  options: VerifyCatalogOptions = {},
): VerifyCatalogResult {
  const issues: CatalogIssue[] = [];
  const courses = collectCourses(bundle);
  const index = buildIndex(bundle, courses);

  checkIds(bundle, courses, issues);
  checkRosters(bundle, index, issues);
  checkBooking(bundle, issues);
  checkVerificationTiers(bundle, issues);
  checkProvenance(bundle, courses, issues);

  if (options.base) {
    checkRosterVersionImmutability(bundle, options.base, issues);
    const labels = new Set(options.labels ?? bundle.labels ?? []);
    checkDiffs(bundle, options.base, labels, issues);
  }

  return { ok: issues.length === 0, issues };
}

/** Runs schema validation first; on failure, returns `SCHEMA_INVALID`
 * issues without attempting the semantic checks above (which assume a
 * structurally valid bundle). This is also where "roster without a
 * source", "course-claim without claimProof" and "n-of-m without
 * ruleSource" surface — see `bundle.ts` and `schema.ts`'s module docs for
 * why those are schema-level, not separate gate rules. */
export function verifyCatalogRaw(
  raw: unknown,
  options: VerifyCatalogOptions = {},
): VerifyCatalogResult {
  const parsed = parseCatalogBundle(raw);
  if (!parsed.ok) {
    return {
      ok: false,
      issues: parsed.schemaIssues.map((i) => issue("SCHEMA_INVALID", i.path, i.message)),
    };
  }
  return verifyCatalog(parsed.bundle, options);
}

/* ------------------------------------------------------------------ */
/* CLI                                                                  */
/* ------------------------------------------------------------------ */

interface CliArgs {
  bundlePath: string;
  basePath?: string;
  labels?: string[];
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
  const bundlePath = opts["bundle"];
  if (!bundlePath) {
    throw new Error(
      "Usage: node dist/verify-catalog.js --bundle <bundle.json> [--base <bundle.json>] [--labels a,b,c]",
    );
  }
  return {
    bundlePath,
    ...(opts["base"] ? { basePath: opts["base"] } : {}),
    ...(opts["labels"] ? { labels: opts["labels"].split(",").filter(Boolean) } : {}),
  };
}

async function readJson(path: string): Promise<unknown> {
  return JSON.parse(await readFile(path, "utf8"));
}

async function main(argv: string[]): Promise<void> {
  const args = parseArgs(argv);
  const bundleRaw = await readJson(args.bundlePath);
  const baseBundle = args.basePath ? await readJson(args.basePath) : undefined;
  let base: CatalogBundle | undefined;
  if (baseBundle !== undefined) {
    const parsedBase = parseCatalogBundle(baseBundle);
    if (!parsedBase.ok) {
      process.stderr.write(
        `verify-catalog: --base file failed schema validation:\n${parsedBase.schemaIssues
          .map((i) => `  ${i.path}: ${i.message}`)
          .join("\n")}\n`,
      );
      process.exitCode = 1;
      return;
    }
    base = parsedBase.bundle;
  }

  const result = verifyCatalogRaw(bundleRaw, {
    ...(base ? { base } : {}),
    ...(args.labels ? { labels: args.labels } : {}),
  });

  if (result.ok) {
    process.stdout.write("verify-catalog: PASS (0 issues)\n");
    return;
  }
  process.stdout.write(`verify-catalog: FAIL (${result.issues.length} issue(s))\n`);
  for (const i of result.issues) {
    process.stdout.write(`  [${i.code}] ${i.path}: ${i.message}\n`);
  }
  process.exitCode = 1;
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
    process.stderr.write(`verify-catalog: ${message}\n`);
    process.exitCode = 1;
  });
}
