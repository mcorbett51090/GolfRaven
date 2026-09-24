/**
 * `verify-catalog` — the P1 AT(1)/(5)/(7)/(8) gate, over the catalog
 * records this task's scope covers (build plan §10 P1 Acceptance tests;
 * every RuleExpr/achievements fixture is part B, per the task's own scope
 * cut).
 *
 * **How the geometry-diff, contact-field diff and roster-version-immutability
 * gates receive "the previous version" (design note).** All three compare
 * the incoming catalog against what was last published. This CLI takes:
 *   - `--base <bundle-file>` — a previously-published `CatalogBundle`
 *     (same shape as the input), read the same way as `--bundle`. Its
 *     absence is not an error: with no `--base`, the diff-shaped gates
 *     simply have nothing to diff against and are skipped — decision 0003
 *     S1's own carve-out ("nothing to diff against before the freeze")
 *     applies equally to these per-record diffs before a first version is
 *     ever published.
 *   - `--labels a,b,c` — the PR's labels for this run (in CI,
 *     `${{ join(github.event.pull_request.labels.*.name, ',') }}`).
 *
 * **Self-approval fix (gate review, post-e9b3ab0, blocking #2).** Neither
 * the booking-host allow-list nor the review labels can come from the
 * bundle itself any more (see `bundle.ts`'s module doc). The allow-list
 * comes from the committed `config/booking-hosts.json` (`config.ts`,
 * `--booking-hosts <file>` to override, mostly for tests); labels come
 * ONLY from `--labels`. An omitted `--labels` flag and an explicitly empty
 * `--labels ""` both mean "no labels" — there is no other source to fall
 * back to, and the CLI parser treats "flag given with an empty value" and
 * "flag not given" identically (both -> `[]`), rather than letting an
 * empty string be mistaken for "use some other source".
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
  resolveMergedId,
  tzLikelyContainsCoordinates,
  type Course,
  type Facility,
  type IdLedger,
  type OfferTerms,
  type RosterMember,
  type RosterVersion,
  type Trail,
} from "@golfraven/catalog";
import { parseCatalogBundle, type CatalogBundle, type OsmContent } from "./bundle.js";
import { loadBookingHostAllowList } from "./config.js";

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
  /** The booking-host allow-list for this run (see module doc — no bundle
   * fallback any more). Defaults to `[]` (nothing allowed but
   * `course-native` self-matches) when omitted, so a caller that forgets
   * to load `config/booking-hosts.json` gets a strict, safe default rather
   * than an unbounded one. */
  bookingHostAllowList?: string[];
  /** PR labels for this run (see module doc — no bundle fallback). */
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
/* S4: cross-reference checks (gate review, post-e9b3ab0)              */
/* ------------------------------------------------------------------ */

function checkCrossReferences(
  bundle: CatalogBundle,
  courses: CourseWithFacility[],
  issues: CatalogIssue[],
): void {
  const designerIds = new Set((bundle.designers ?? []).map((d) => d.id));
  const courseById: Map<string, CourseWithFacility> = new Map(
    courses.map((c) => [c.course.id, c]),
  );

  // Every catalog id (facility/course/trail/designer) should be minted in
  // the ledger, and its curated slug should match the ledger's recorded
  // (first-come, immutable) slug.
  const checkLedgerBacked = (id: string, slug: string | undefined, path: string, label: string) => {
    const entry = bundle.idLedger.entries[id];
    if (!entry) {
      issues.push(
        issue(
          "CROSS_REF_ID_NOT_IN_LEDGER",
          path,
          `${label} "${id}" has no entry in the ID ledger (every id must be minted there, §3.5)`,
        ),
      );
      return;
    }
    if (slug !== undefined && entry.slug !== undefined && slug !== entry.slug) {
      issues.push(
        issue(
          "CROSS_REF_SLUG_MISMATCH",
          `${path}.slug`,
          `${label} "${id}"'s slug "${slug}" does not match the ledger's recorded slug "${entry.slug}" (slugs are first-come and immutable, §3.5)`,
        ),
      );
    }
  };

  bundle.facilities.forEach((facility, facilityIndex) => {
    checkLedgerBacked(facility.id, facility.slug, `facilities[${facilityIndex}]`, "facility");
  });
  courses.forEach(({ course, facilityIndex, courseIndex }) => {
    checkLedgerBacked(
      course.id,
      course.slug,
      `facilities[${facilityIndex}].courses[${courseIndex}]`,
      "course",
    );
  });
  bundle.trails.forEach((trail, trailIndex) => {
    checkLedgerBacked(trail.id, trail.slug, `trails[${trailIndex}]`, "trail");
  });
  (bundle.designers ?? []).forEach((designer, designerIndex) => {
    checkLedgerBacked(designer.id, undefined, `designers[${designerIndex}]`, "designer");
  });

  // A ledger entry whose map key differs from its own `id` field.
  for (const [key, entry] of Object.entries(bundle.idLedger.entries)) {
    if (key !== entry.id) {
      issues.push(
        issue(
          "LEDGER_KEY_MISMATCH",
          `idLedger.entries.${key}`,
          `ledger entry keyed "${key}" has id "${entry.id}" — the map key must equal the entry's own id`,
        ),
      );
    }
  }

  // Course-level cross-references: composite, designers.
  courses.forEach(({ course, facilityIndex, courseIndex }) => {
    const path = `facilities[${facilityIndex}].courses[${courseIndex}]`;
    if (course.composite) {
      course.composite.forEach((compositeCourseId, i) => {
        const resolved = resolveMergedId(bundle.idLedger, compositeCourseId);
        if (!courseById.has(resolved) && !courseById.has(compositeCourseId)) {
          issues.push(
            issue(
              "CROSS_REF_COMPOSITE_DANGLING",
              `${path}.composite[${i}]`,
              `composite references course "${compositeCourseId}", which does not exist in this catalog`,
            ),
          );
        }
      });
    }
    for (const designerId of course.designers ?? []) {
      if (!designerIds.has(designerId)) {
        issues.push(
          issue(
            "CROSS_REF_UNKNOWN_DESIGNER",
            `${path}.designers`,
            `course "${course.id}" lists designer "${designerId}", which is not in designers[] (§4.1 line 611)`,
          ),
        );
      }
    }
  });

  // Roster-member-level cross-references: dangling holeId, dangling anyOf
  // members (partial — see checkRosters for "every id dangling").
  bundle.trails.forEach((trail, trailIndex) => {
    const seenVersionNumbers = new Map<number, number>();
    trail.rosterVersions.forEach((version, versionIndex) => {
      seenVersionNumbers.set(
        version.version,
        (seenVersionNumbers.get(version.version) ?? 0) + 1,
      );
      const versionPath = `trails[${trailIndex}].rosterVersions[${versionIndex}]`;
      version.members.forEach((member, memberIndex) => {
        const memberPath = `${versionPath}.members[${memberIndex}]`;
        if (member.unit === "hole") {
          const resolvedCourseId = resolveMergedId(bundle.idLedger, member.courseId);
          const entry = courseById.get(resolvedCourseId) ?? courseById.get(member.courseId);
          if (entry) {
            const holeExists = (entry.course.holesDetail ?? []).some(
              (h) => h.id === member.holeId,
            );
            if (!holeExists) {
              issues.push(
                issue(
                  "CROSS_REF_DANGLING_HOLE_ID",
                  `${memberPath}.holeId`,
                  `hole "${member.holeId}" does not exist in course "${member.courseId}"'s holesDetail`,
                ),
              );
            }
          }
          // A dangling courseId itself is already ROSTER_MISSING_MEMBER
          // (checkRosters) — not duplicated here.
        }
        if (member.unit === "course" && "anyOf" in member) {
          member.anyOf.forEach((courseId, i) => {
            const resolved = resolveMergedId(bundle.idLedger, courseId);
            if (!courseById.has(resolved) && !courseById.has(courseId)) {
              issues.push(
                issue(
                  "CROSS_REF_DANGLING_ANYOF_ID",
                  `${memberPath}.anyOf[${i}]`,
                  `anyOf member references course "${courseId}", which does not exist in this catalog`,
                ),
              );
            }
          });
        }
      });
    });
    for (const [versionNumber, count] of seenVersionNumbers) {
      if (count > 1) {
        issues.push(
          issue(
            "ROSTER_DUPLICATE_VERSION_NUMBER",
            `trails[${trailIndex}].rosterVersions`,
            `trail "${trail.id}" has ${count} roster versions numbered ${versionNumber} — version numbers must be unique per trail`,
          ),
        );
      }
    }
  });
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
  const courseById: Map<string, CourseWithFacility> = new Map(
    courses.map((c) => [c.course.id, c]),
  );
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
/* Roster version immutability + trail removal (needs --base)          */
/* ------------------------------------------------------------------ */

function checkRosterVersionImmutability(
  bundle: CatalogBundle,
  base: CatalogBundle,
  issues: CatalogIssue[],
): void {
  const baseTrailById = new Map(base.trails.map((t) => [t.id, t]));
  const currentTrailIds = new Set(bundle.trails.map((t) => t.id));

  // A published trail deleted relative to --base (S4).
  for (const baseTrail of base.trails) {
    if (!currentTrailIds.has(baseTrail.id)) {
      issues.push(
        issue(
          "ROSTER_TRAIL_REMOVED",
          "trails",
          `trail "${baseTrail.id}" was published in the last catalog and is missing from this one — a published trail is never deleted`,
        ),
      );
    }
  }

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
/* S4: ledger append-only against --base                               */
/* ------------------------------------------------------------------ */

function checkLedgerAppendOnly(
  bundle: CatalogBundle,
  base: CatalogBundle,
  issues: CatalogIssue[],
): void {
  for (const [id, baseEntry] of Object.entries(base.idLedger.entries)) {
    const currentEntry = bundle.idLedger.entries[id];
    if (!currentEntry) {
      issues.push(
        issue(
          "LEDGER_ENTRY_REMOVED",
          `idLedger.entries.${id}`,
          `ledger entry "${id}" existed in the last published catalog and is missing from this one — the ledger is append-only (§3.5)`,
        ),
      );
      continue;
    }
    if (baseEntry.tombstoned === true && currentEntry.tombstoned !== true) {
      issues.push(
        issue(
          "LEDGER_UNTOMBSTONED",
          `idLedger.entries.${id}.tombstoned`,
          `ledger entry "${id}" was tombstoned in the last published catalog and is no longer tombstoned — an id is never un-tombstoned (§3.5)`,
        ),
      );
    }
    const baseTransitions = baseEntry.transitions;
    const currentTransitions = currentEntry.transitions;
    const isPrefix =
      currentTransitions.length >= baseTransitions.length &&
      baseTransitions.every((t, i) => deepEqual(t, currentTransitions[i]));
    if (!isPrefix) {
      issues.push(
        issue(
          "LEDGER_TRANSITIONS_NOT_APPEND_ONLY",
          `idLedger.entries.${id}.transitions`,
          `ledger entry "${id}"'s transitions[] in the last published catalog is not a prefix of this catalog's — transitions are append-only (§3.5)`,
        ),
      );
    }
  }
}

/* ------------------------------------------------------------------ */
/* Booking host gate                                                   */
/* ------------------------------------------------------------------ */

/** Nit (gate review, post-e9b3ab0): `.hostname`, not `.host` — `.host`
 * includes a `:port` suffix, which would make an allow-list entry for
 * `www.golfnow.com` fail to match `www.golfnow.com:8443` even though the
 * host itself is identical; the allow-list is about the domain, not the
 * port. */
function hostOf(url: string): string | undefined {
  try {
    return new URL(url).hostname;
  } catch {
    return undefined;
  }
}

function checkBooking(
  bundle: CatalogBundle,
  bookingHostAllowList: string[],
  issues: CatalogIssue[],
): void {
  const allowList = new Set(bookingHostAllowList);
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

/** Facility coordinates for the `tz` check: the facility's own `lat`/`lng`
 * if it has them, or — for a stub — its joined OSM coordinates (plan line
 * 578: "For a stub, those are the joined OSM coordinates"), read from
 * `bundle.osm[facility.seed.osmRef]`. */
function facilityCoordinates(
  facility: Facility,
  osm: Record<string, OsmContent> | undefined,
): { lat: number; lng: number } | undefined {
  if (facility.lat !== undefined && facility.lng !== undefined) {
    return { lat: facility.lat, lng: facility.lng };
  }
  const osmRef = facility.seed.osmRef;
  if (osmRef && osm?.[osmRef]) {
    return { lat: osm[osmRef].lat, lng: osm[osmRef].lng };
  }
  return undefined;
}

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

    // tz "wrong zone" (the part IanaTimeZoneSchema cannot check, see
    // geo.ts) — checked for a stub too, using its joined OSM coordinates
    // (plan line 578).
    const coords = facilityCoordinates(facility, bundle.osm);
    if (coords) {
      if (!tzLikelyContainsCoordinates(facility.tz, coords)) {
        issues.push(
          issue(
            "TZ_WRONG_ZONE",
            `${path}.tz`,
            `facility "${facility.id}"'s tz "${facility.tz}" does not contain its coordinates (G-P0-11)`,
          ),
        );
      }
    } else {
      // Fails closed (gate review round 2, item 4): a facility with no
      // coordinates of its own AND no OSM join to borrow them from cannot
      // have its declared tz checked at all — that is a reason to flag it,
      // not a reason to silently skip the check. Silence here would let an
      // unverifiable tz pass the gate by omission.
      issues.push(
        issue(
          "TZ_UNVERIFIABLE",
          `${path}.tz`,
          `facility "${facility.id}" has no coordinates (own lat/lng or a joined OSM ref) to check its declared tz "${facility.tz}" against — cannot verify (G-P0-11)`,
        ),
      );
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
      // S2 (gate review): every content field, including nameFr, now maps
      // to a real prov key (see schema.ts's FacilityProvSchema doc).
      const provKey = FACILITY_CONTENT_FIELD_TO_PROV_KEY[field];
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
/* S6: OfferTerms — QC offer terms without FR                          */
/* ------------------------------------------------------------------ */

function checkOfferTerms(bundle: CatalogBundle, issues: CatalogIssue[]): void {
  const trailById = new Map(bundle.trails.map((t) => [t.id, t]));
  (bundle.offerTerms ?? []).forEach((offer: OfferTerms, i) => {
    const path = `offerTerms[${i}]`;
    const trail = trailById.get(offer.trailId);
    const isQc = trail?.regions.some((r) => r === "CA-QC") ?? false;
    if (isQc && offer.termsFr === undefined) {
      issues.push(
        issue(
          "OFFER_TERMS_QC_MISSING_FR",
          `${path}.termsFr`,
          `offerTerms "${offer.id}" is linked to a Québec trail ("${offer.trailId}") and has no termsFr (bilingual requirement)`,
        ),
      );
    }
  });
}

/* ------------------------------------------------------------------ */
/* S1: geometry-diff (coordinate-move + field-change) / contact-field  */
/* diff (need --base and labels)                                       */
/* ------------------------------------------------------------------ */

const GEOMETRY_COORDINATE_MOVE_METERS = 150;
// TODO(pipeline): area-change (> 25%) is NOT implemented — it needs the
// real geometry pipeline (OSM -> data/osm/geometry/*, §10 P1 scope), which
// P1a does not build (no real geometry data exists to diff against). This
// is the same limitation the P1a report already named for the courses'
// geometry.file content; tracked here so the geometry-reviewed gate's
// coverage gap is visible at the call site, not just in a report.

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

    // Coordinate-move check (renamed from "geometry-diff" — S1, gate
    // review: this is specifically Facility.lat/lng moving, not a Course's
    // `geometry` object; see the field-change check below for that).
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
      if (
        distanceMeters > GEOMETRY_COORDINATE_MOVE_METERS &&
        !labels.has("geometry-reviewed")
      ) {
        issues.push(
          issue(
            "GEOMETRY_DIFF_UNREVIEWED",
            `${path}.lat`,
            `facility "${facility.id}"'s coordinates moved ${distanceMeters.toFixed(0)} m from the last published catalog (> ${GEOMETRY_COORDINATE_MOVE_METERS} m) without the "geometry-reviewed" label`,
          ),
        );
      }
    }

    // S1: full geometry FIELD-change check, per course — any change to
    // `ref`/`file`/`layer`/`checkedAt`/`sharedWithFacility` (not just a
    // coordinate) requires the label. Area-change is NOT covered (see the
    // TODO above).
    const baseCourseById = new Map(baseFacility.courses.map((c) => [c.id, c]));
    facility.courses.forEach((course, courseIndex) => {
      const baseCourse = baseCourseById.get(course.id);
      if (!baseCourse) return; // new course, nothing to diff
      if (!deepEqual(course.geometry, baseCourse.geometry) && !labels.has("geometry-reviewed")) {
        issues.push(
          issue(
            "GEOMETRY_DIFF_UNREVIEWED",
            `${path}.courses[${courseIndex}].geometry`,
            `course "${course.id}"'s geometry (ref/file/layer/checkedAt/sharedWithFacility) changed from the last published catalog without the "geometry-reviewed" label`,
          ),
        );
      }
    });

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
  checkCrossReferences(bundle, courses, issues);
  checkRosters(bundle, index, issues);
  checkBooking(bundle, options.bookingHostAllowList ?? [], issues);
  checkVerificationTiers(bundle, issues);
  checkProvenance(bundle, courses, issues);
  checkOfferTerms(bundle, issues);

  if (options.base) {
    checkRosterVersionImmutability(bundle, options.base, issues);
    checkLedgerAppendOnly(bundle, options.base, issues);
    const labels = new Set(options.labels ?? []);
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
  /** `undefined` when `--labels` was never given at all; `[]` when it was
   * given with an empty value. Both ultimately mean "no labels" — kept
   * distinct here only so a future caller can tell the two apart if it
   * ever needs to (see module doc). */
  labels?: string[];
  bookingHostsPath?: string;
}

function parseArgs(argv: string[]): CliArgs {
  const opts: Record<string, string> = {};
  const seen = new Set<string>();
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg && arg.startsWith("--")) {
      const key = arg.slice(2);
      opts[key] = argv[i + 1] ?? "";
      seen.add(key);
      i += 1;
    }
  }
  const bundlePath = opts["bundle"];
  if (!bundlePath) {
    throw new Error(
      "Usage: node dist/verify-catalog.js --bundle <bundle.json> [--base <bundle.json>] [--labels a,b,c] [--booking-hosts <file>]",
    );
  }
  return {
    bundlePath,
    ...(opts["base"] ? { basePath: opts["base"] } : {}),
    // An empty string means "no labels" — same as the flag being absent —
    // never a fallback to any other source (blocking #2).
    ...(seen.has("labels")
      ? { labels: (opts["labels"] ?? "").split(",").filter(Boolean) }
      : {}),
    ...(opts["booking-hosts"] ? { bookingHostsPath: opts["booking-hosts"] } : {}),
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

  const bookingHostAllowList = await loadBookingHostAllowList(args.bookingHostsPath);

  const result = verifyCatalogRaw(bundleRaw, {
    ...(base ? { base } : {}),
    labels: args.labels ?? [],
    bookingHostAllowList,
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
