/**
 * The append-only ID ledger (§3.5, §4.1, §4.2) — `data/id-ledger.json`'s
 * format, plus the pure functions that mint, tombstone and transition
 * entries in it. Everything here is a pure data transform: no filesystem
 * or network I/O (packages/catalog "Never does: Hold data or fetch",
 * §3.1 row A) — `tools/catalog` reads/writes the JSON file and calls these
 * functions.
 *
 * > `data/id-ledger.json` is append-only: an ID may be added or
 * > tombstoned (with an optional `mergedInto`), never removed or
 * > reassigned. It also records each facility's **slug** (first-come,
 * > immutable) and its `seedRefs[]` history ... Each facility and course
 * > entry carries a `status` (`stub` | `verified`) and an append-only
 * > `transitions[]` list (`minted`, `verified`, `split`, `merged`,
 * > `closed`, each with the catalog version and date), so promotion is a
 * > recorded event on an unchanged id (G3-01). (§3.5)
 */
import { z } from "zod";
import {
  AnyKnownIdSchema,
  CourseIdSchema,
  FacilityIdSchema,
  ID_KINDS,
  OsmRefIdSchema,
  mintId,
  type CourseId,
  type FacilityId,
  type IdKind,
} from "./ids.js";
import { IsoDateSchema } from "./common.js";
import { normalizedNameSimilarity } from "./name-similarity.js";
import { haversineDistanceMeters } from "./geo.js";

/* ------------------------------------------------------------------ */
/* Schema                                                               */
/* ------------------------------------------------------------------ */

export const LedgerTransitionTypeSchema = z.enum([
  "minted",
  "verified",
  "split",
  "merged",
  "closed",
]);
export type LedgerTransitionType = z.infer<typeof LedgerTransitionTypeSchema>;

/** One `transitions[]` entry: "each with the catalog version and date"
 * (§3.5). `siblingIds` is populated only on a `split` transition, recording
 * the sibling course ids minted alongside the kept id (§4.2 promotion
 * table). */
export const LedgerTransitionSchema = z.strictObject({
  type: LedgerTransitionTypeSchema,
  catalogVersion: z.string().min(1),
  date: IsoDateSchema,
  note: z.string().optional(),
  siblingIds: z.array(AnyKnownIdSchema).optional(),
});
export type LedgerTransition = z.infer<typeof LedgerTransitionSchema>;

export const LedgerEntryStatusSchema = z.enum(["stub", "verified"]);
export type LedgerEntryStatus = z.infer<typeof LedgerEntryStatusSchema>;

export const LedgerEntrySchema = z.strictObject({
  id: AnyKnownIdSchema,
  kind: z.enum(ID_KINDS),
  /** First-come, immutable (§3.5). Facilities, courses and trails carry
   * one; designers don't (`data/designers.json` has no slug field, §4.1). */
  slug: z.string().min(1).optional(),
  /** Facility/course only — "Each facility and course entry carries a
   * status" (§3.5). */
  status: LedgerEntryStatusSchema.optional(),
  transitions: z.array(LedgerTransitionSchema),
  /** Facility/course only — the OSM refs a re-seed has ever matched to
   * this id (§4.2 G-P1-12). */
  seedRefs: z.array(OsmRefIdSchema).optional(),
  /** Set once this id is tombstoned. `mergedInto` is set only when the
   * tombstone is a merge (§3.5: "tombstoned (with an **optional**
   * mergedInto)" — the plan allows a tombstone without one, though the
   * only tombstone kind this plan's text describes is a merge). */
  tombstoned: z.boolean().optional(),
  mergedInto: AnyKnownIdSchema.optional(),
});
export type LedgerEntry = z.infer<typeof LedgerEntrySchema>;

/** `data/id-ledger.json`'s top-level shape: entries keyed by id for O(1)
 * lookup (the file is read as a whole on every `verify-catalog` run and by
 * the `import-catalog` Edge Function, §3.3 — a keyed map is the natural
 * shape for that access pattern; the plan does not prescribe array vs. map
 * so this is a design choice, not a literal reading). */
export const IdLedgerSchema = z.strictObject({
  entries: z.record(z.string(), LedgerEntrySchema),
});
export type IdLedger = z.infer<typeof IdLedgerSchema>;

export function emptyLedger(): IdLedger {
  return { entries: {} };
}

/* ------------------------------------------------------------------ */
/* Lookups                                                              */
/* ------------------------------------------------------------------ */

export function getLedgerEntry(
  ledger: IdLedger,
  id: string,
): LedgerEntry | undefined {
  return ledger.entries[id];
}

export function isIdKnown(ledger: IdLedger, id: string): boolean {
  return id in ledger.entries;
}

export function isIdTombstoned(ledger: IdLedger, id: string): boolean {
  return ledger.entries[id]?.tombstoned === true;
}

/** A2-04: "Every id resolves through the ledger's `mergedInto` closure
 * first." Follows `mergedInto` links until reaching an id that is not
 * itself tombstoned-with-a-survivor, guarding against a cycle (which would
 * itself be a ledger corruption bug, not a valid state). */
export function resolveMergedId(ledger: IdLedger, id: string): string {
  const seen = new Set<string>();
  let current = id;
  while (true) {
    if (seen.has(current)) {
      throw new Error(
        `resolveMergedId: mergedInto cycle detected starting at "${id}"`,
      );
    }
    seen.add(current);
    const entry = ledger.entries[current];
    if (!entry || !entry.mergedInto) return current;
    current = entry.mergedInto;
  }
}

/* ------------------------------------------------------------------ */
/* Slugs (AT(7))                                                        */
/* ------------------------------------------------------------------ */

/**
 * AT(7): "A slug collision suffixes the newcomer and leaves the existing
 * slug unchanged." Scans every entry's `slug` (ledger-wide — slugs are a
 * single namespace across facilities/courses/trails, since the plan does
 * not scope them per-kind) and, on collision, appends `-2`, `-3`, … until
 * free. Pure: returns the slug to use; does not mutate the ledger.
 */
export function mintSlug(ledger: IdLedger, desiredSlug: string): string {
  const taken = new Set(
    Object.values(ledger.entries)
      .map((e) => e.slug)
      .filter((s): s is string => s !== undefined),
  );
  if (!taken.has(desiredSlug)) return desiredSlug;
  let n = 2;
  while (taken.has(`${desiredSlug}-${n}`)) {
    n += 1;
  }
  return `${desiredSlug}-${n}`;
}

/* ------------------------------------------------------------------ */
/* Minting                                                              */
/* ------------------------------------------------------------------ */

function withEntry(ledger: IdLedger, entry: LedgerEntry): IdLedger {
  return { entries: { ...ledger.entries, [entry.id]: entry } };
}

export interface MintStubFacilityInput {
  /** A plain string, validated and branded internally via
   * `OsmRefIdSchema` — callers (JSON fixtures, the future `seed-osm.mjs`)
   * hold plain strings, so the ledger API takes one rather than asking
   * every caller to brand it first. */
  osmRef: string;
  desiredSlug: string;
  catalogVersion: string;
  date: string;
  now?: Date;
}

export interface MintStubFacilityResult {
  ledger: IdLedger;
  facilityId: FacilityId;
  courseId: CourseId;
  slug: string;
}

/**
 * G3-01: "`seed-osm` mints a `crs_` id for the stub course of every stub
 * facility, verified or not" — one facility id and exactly one course id,
 * both ledgered as `stub`, both carrying the same `seedRefs[0]` (the OSM
 * object that was seeded, §4.2: "A re-seed matches the stub course through
 * the same `seedRefs[]`"). Mints the facility's slug via `mintSlug` at the
 * same time (first-come).
 */
export function mintStubFacility(
  ledger: IdLedger,
  input: MintStubFacilityInput,
): MintStubFacilityResult {
  const facilityId = mintId("fac", input.now) as FacilityId;
  // Offset the course mint by 1ms so the two ids are never identical even
  // if the ULID's random half collided (astronomically unlikely, but the
  // ledger's uniqueness guarantee should not rest on that).
  const courseId = mintId(
    "crs",
    input.now ? new Date(input.now.getTime() + 1) : undefined,
  ) as CourseId;
  const osmRef = OsmRefIdSchema.parse(input.osmRef);
  const slug = mintSlug(ledger, input.desiredSlug);
  const transition: LedgerTransition = {
    type: "minted",
    catalogVersion: input.catalogVersion,
    date: input.date,
  };
  let next = withEntry(ledger, {
    id: facilityId,
    kind: "fac",
    slug,
    status: "stub",
    transitions: [transition],
    seedRefs: [osmRef],
  });
  next = withEntry(next, {
    id: courseId,
    kind: "crs",
    status: "stub",
    transitions: [transition],
    seedRefs: [osmRef],
  });
  return { ledger: next, facilityId, courseId, slug };
}

/* ------------------------------------------------------------------ */
/* Re-seed (AT(5), §4.2 G-P1-12, FM-14)                                  */
/* ------------------------------------------------------------------ */

export interface ReseedCandidate {
  facilityId: FacilityId;
  courseId: CourseId;
  name: string;
  lat: number;
  lng: number;
}

export interface IncomingOsmObject {
  /** Plain string — see `MintStubFacilityInput.osmRef`'s doc. */
  osmRef: string;
  name: string;
  lat: number;
  lng: number;
  desiredSlug: string;
  catalogVersion: string;
  date: string;
}

const SPATIAL_MATCH_RADIUS_METERS = 150;
const NAME_SIMILARITY_THRESHOLD = 0.8;

export type ReseedOutcome =
  | { kind: "already-known"; facilityId: FacilityId; courseId: CourseId }
  | { kind: "matched"; facilityId: FacilityId; courseId: CourseId; ledger: IdLedger }
  | { kind: "ambiguous"; candidateFacilityIds: FacilityId[] }
  | {
      kind: "minted";
      facilityId: FacilityId;
      courseId: CourseId;
      slug: string;
      ledger: IdLedger;
    };

/**
 * G-P1-12 / FM-14: "`seed-osm.mjs` matches every incoming OSM object
 * **spatially first** (centroid within 150 m **and** normalised-name
 * similarity ≥ 0.8) against existing facilities. A spatial match appends
 * the new ref to that facility's `seedRefs[]` in the ledger and never
 * mints an ID; an ambiguous match goes to a 'possible duplicate' report
 * for a human and is never auto-minted. Only an object with no spatial
 * match gets a new `fac_` ID, and with it exactly one stub course."
 *
 * This is also AT(5)'s "way→relation remap" case: OSM upgrading a way to a
 * relation for the same real-world object changes `osmRef`'s element kind
 * (`way/123` → `relation/456`) while its coordinates and name stay the
 * same, so it spatially matches its own previous facility and only
 * extends `seedRefs[]` — never mints a second id.
 */
export function reseedFacility(
  ledger: IdLedger,
  incoming: IncomingOsmObject,
  candidates: ReseedCandidate[],
): ReseedOutcome {
  const osmRef = OsmRefIdSchema.parse(incoming.osmRef);
  const alreadyKnown = candidates.find((c) =>
    (ledger.entries[c.facilityId]?.seedRefs ?? []).includes(osmRef),
  );
  if (alreadyKnown) {
    return {
      kind: "already-known",
      facilityId: alreadyKnown.facilityId,
      courseId: alreadyKnown.courseId,
    };
  }

  const matches = candidates.filter(
    (c) =>
      haversineDistanceMeters(incoming, c) <= SPATIAL_MATCH_RADIUS_METERS &&
      normalizedNameSimilarity(incoming.name, c.name) >=
        NAME_SIMILARITY_THRESHOLD,
  );

  if (matches.length > 1) {
    return {
      kind: "ambiguous",
      candidateFacilityIds: matches.map((m) => m.facilityId),
    };
  }

  if (matches.length === 1) {
    const match = matches[0];
    if (!match) {
      throw new Error("unreachable: matches.length === 1 but matches[0] is undefined");
    }
    const facilityEntry = ledger.entries[match.facilityId];
    const courseEntry = ledger.entries[match.courseId];
    if (!facilityEntry || !courseEntry) {
      throw new Error(
        `reseedFacility: candidate ${match.facilityId}/${match.courseId} is not in the ledger`,
      );
    }
    let next = withEntry(ledger, {
      ...facilityEntry,
      seedRefs: [...(facilityEntry.seedRefs ?? []), osmRef],
    });
    next = withEntry(next, {
      ...courseEntry,
      seedRefs: [...(courseEntry.seedRefs ?? []), osmRef],
    });
    return {
      kind: "matched",
      facilityId: match.facilityId,
      courseId: match.courseId,
      ledger: next,
    };
  }

  const minted = mintStubFacility(ledger, {
    osmRef: incoming.osmRef,
    desiredSlug: incoming.desiredSlug,
    catalogVersion: incoming.catalogVersion,
    date: incoming.date,
  });
  return {
    kind: "minted",
    facilityId: minted.facilityId,
    courseId: minted.courseId,
    slug: minted.slug,
    ledger: minted.ledger,
  };
}

/* ------------------------------------------------------------------ */
/* Promotion (§4.2 promotion table, G3-01, AT(8))                       */
/* ------------------------------------------------------------------ */

export interface TransitionMeta {
  catalogVersion: string;
  date: string;
}

function appendTransition(
  ledger: IdLedger,
  id: string,
  transition: LedgerTransition,
): IdLedger {
  const entry = ledger.entries[id];
  if (!entry) {
    throw new Error(`appendTransition: unknown ledger id "${id}"`);
  }
  return withEntry(ledger, {
    ...entry,
    transitions: [...entry.transitions, transition],
  });
}

/** The common promotion case (§4.2 table row 1): "`stub → verified` on
 * both ids", with "None" effect on plays already recorded (the id doesn't
 * change). Sets `status: 'verified'` on every given id and appends a
 * `verified` transition to each. */
export function promoteToVerified(
  ledger: IdLedger,
  ids: string[],
  meta: TransitionMeta,
): IdLedger {
  let next = ledger;
  for (const id of ids) {
    const entry = next.entries[id];
    if (!entry) {
      throw new Error(`promoteToVerified: unknown ledger id "${id}"`);
    }
    next = withEntry(next, { ...entry, status: "verified" });
    next = appendTransition(next, id, {
      type: "verified",
      catalogVersion: meta.catalogVersion,
      date: meta.date,
    });
  }
  return next;
}

export interface SplitCourseResult {
  ledger: IdLedger;
  siblingIds: CourseId[];
}

/** §4.2 table row 3: "One stub course covers several real courses ... the
 * stub id is kept for one course ... and new `crs_` ids are minted for the
 * others and recorded as its siblings." The kept id gets a `split`
 * transition listing the new sibling ids; each new sibling gets its own
 * `minted` transition. Neither the kept id nor any sibling is re-keyed. */
export function splitCourse(
  ledger: IdLedger,
  keptCourseId: string,
  siblingCount: number,
  meta: TransitionMeta,
  now?: Date,
): SplitCourseResult {
  if (!ledger.entries[keptCourseId]) {
    throw new Error(`splitCourse: unknown ledger id "${keptCourseId}"`);
  }
  const siblingIds: CourseId[] = [];
  let next = ledger;
  for (let i = 0; i < siblingCount; i += 1) {
    const siblingId = mintId(
      "crs",
      now ? new Date(now.getTime() + i + 1) : undefined,
    ) as CourseId;
    siblingIds.push(siblingId);
    next = withEntry(next, {
      id: siblingId,
      kind: "crs",
      status: "verified",
      transitions: [
        {
          type: "minted",
          catalogVersion: meta.catalogVersion,
          date: meta.date,
          note: `split from ${keptCourseId}`,
        },
      ],
    });
  }
  next = appendTransition(next, keptCourseId, {
    type: "split",
    catalogVersion: meta.catalogVersion,
    date: meta.date,
    siblingIds: siblingIds as unknown as z.infer<typeof AnyKnownIdSchema>[],
  });
  return { ledger: next, siblingIds };
}

/** §4.2 table row 2: "Several stub facilities are one site ... The extra
 * facilities are `merged` into one survivor; each stub course keeps its id
 * and moves under the survivor." Tombstones each id in `tombstoneIds`
 * with `mergedInto: survivorId` and a `merged` transition; the survivor is
 * untouched by this function (its own `verified`/other transitions, if
 * any, are appended separately). */
export function mergeIntoSurvivor(
  ledger: IdLedger,
  tombstoneIds: string[],
  survivorId: string,
  meta: TransitionMeta,
): IdLedger {
  if (!ledger.entries[survivorId]) {
    throw new Error(`mergeIntoSurvivor: unknown survivor id "${survivorId}"`);
  }
  let next = ledger;
  for (const id of tombstoneIds) {
    const entry = next.entries[id];
    if (!entry) {
      throw new Error(`mergeIntoSurvivor: unknown ledger id "${id}"`);
    }
    next = withEntry(next, {
      ...entry,
      tombstoned: true,
      mergedInto: survivorId as z.infer<typeof AnyKnownIdSchema>,
    });
    next = appendTransition(next, id, {
      type: "merged",
      catalogVersion: meta.catalogVersion,
      date: meta.date,
      note: `merged into ${survivorId}`,
    });
  }
  return next;
}

/** §4.2 table row 5: "The object is not a playable course (closed, a range
 * only) ... `closed`." Appends a `closed` transition; the id stays live
 * (not tombstoned) — "The play stays visible in Played and is never
 * counted", which only makes sense if the id remains resolvable. */
export function recordClosed(
  ledger: IdLedger,
  id: string,
  meta: TransitionMeta,
): IdLedger {
  return appendTransition(ledger, id, {
    type: "closed",
    catalogVersion: meta.catalogVersion,
    date: meta.date,
  });
}

export { FacilityIdSchema, CourseIdSchema };
export type { IdKind };
