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
  /** Course entries only — the facility this course belongs to. Not named
   * in §3.5's ledger-entry prose, but added (gate review, post-e9b3ab0) so
   * a re-seed's "already-known" check can resolve a matched `osmRef` to
   * its full facility+course pair from the ledger alone, without needing
   * the caller to have already guessed the right candidate (see
   * `findLedgerIdBySeedRef`/`reseedFacility` below). */
  facilityId: FacilityIdSchema.optional(),
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
/**
 * Nit (gate review round 2): a `mergedInto` cycle in the ledger is
 * reported as an issue by `verify-catalog`'s `checkMergeCycles`
 * (`LEDGER_MERGE_CYCLE`), never thrown here. `resolveMergedId` is called
 * from many places across this package and `tools/catalog` while
 * resolving ordinary references, and a malformed/adversarial ledger
 * (however it got that way) must not be able to crash the whole
 * `verify-catalog` run just by making one id's chain cyclic — a thrown
 * exception here would do exactly that, everywhere this function is
 * called, not just at the one place meant to report the problem. On a
 * cycle, this stops and returns the id where the repeat was detected
 * (a safe, deterministic "best effort" answer) rather than looping
 * forever or throwing; `detectMergeCycle` below is the actual yes/no
 * check `checkMergeCycles` uses to raise the issue.
 */
export function resolveMergedId(ledger: IdLedger, id: string): string {
  const seen = new Set<string>();
  let current = id;
  while (true) {
    if (seen.has(current)) {
      return current;
    }
    seen.add(current);
    const entry = ledger.entries[current];
    if (!entry || !entry.mergedInto) return current;
    current = entry.mergedInto;
  }
}

/** `true` if following `id`'s `mergedInto` chain ever revisits an id
 * already seen — i.e. the chain cannot terminate. Non-throwing, same
 * walk `resolveMergedId` does, used by `verify-catalog`'s
 * `checkMergeCycles` to report `LEDGER_MERGE_CYCLE` as an ordinary issue. */
export function detectMergeCycle(ledger: IdLedger, id: string): boolean {
  const seen = new Set<string>();
  let current = id;
  while (true) {
    if (seen.has(current)) return true;
    seen.add(current);
    const entry = ledger.entries[current];
    if (!entry || !entry.mergedInto) return false;
    current = entry.mergedInto;
  }
}

/* ------------------------------------------------------------------ */
/* Slugs (AT(7))                                                        */
/* ------------------------------------------------------------------ */

/** A conservative URL-slug pattern: lowercase ASCII letters, digits and
 * single hyphens, no leading/trailing/doubled hyphen. Rejects anything
 * that isn't already slugified (gate review, post-e9b3ab0 nit) — minting
 * never silently slugifies a raw name for the caller. */
const SLUG_PATTERN = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

/**
 * AT(7): "A slug collision suffixes the newcomer and leaves the existing
 * slug unchanged." Scans every entry's `slug` (ledger-wide — slugs are a
 * single namespace across facilities/courses/trails, since the plan does
 * not scope them per-kind) and, on collision, appends `-2`, `-3`, … until
 * free. Pure: returns the slug to use; does not mutate the ledger.
 */
export function mintSlug(ledger: IdLedger, desiredSlug: string): string {
  if (!SLUG_PATTERN.test(desiredSlug)) {
    throw new Error(
      `mintSlug: "${desiredSlug}" is not already slugified (expected lowercase letters/digits/hyphens only, e.g. "pebble-hills") — slugify it before calling mintSlug`,
    );
  }
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
    facilityId,
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
  | {
      kind: "matched";
      facilityId: FacilityId;
      courseId: CourseId;
      ledger: IdLedger;
    }
  | { kind: "ambiguous"; candidateFacilityIds: FacilityId[] }
  | {
      kind: "minted";
      facilityId: FacilityId;
      courseId: CourseId;
      slug: string;
      ledger: IdLedger;
    };

/**
 * Scans the **whole ledger** (every entry, not just the caller's
 * `candidates` shortlist) for one whose `seedRefs` already contains
 * `osmRef`, and resolves it through the `mergedInto` closure (A2-04) to
 * its live survivor. Returns the survivor's `{ facilityId, courseId }`
 * pair, using the `facilityId` link `mintStubFacility`/`splitCourse` stamp
 * on every course entry to find the facility's course id (or vice
 * versa) without needing the caller to already know it.
 *
 * **Gate-review fix (post-e9b3ab0, blocking #4).** The previous
 * implementation only checked `osmRef` against the caller-supplied
 * `candidates` array — a shortlist the caller (e.g. `seed-osm.mjs`,
 * spatially pre-filtering) might not include every already-known owner
 * in, especially the survivor of a merge that happened after the object
 * moved or was renamed. That let an already-minted id's `osmRef` fall
 * through to spatial matching with an empty/wrong candidate list and mint
 * a **second** id for the same real-world object — exactly what G-P1-12
 * forbids. This lookup no longer depends on `candidates` at all.
 *
 * **Round-2 fix (gate review, "merge re-parenting"): prefer the COURSE
 * entry that actually carries the ref, not "a" course found by working
 * backward from the facility.** `mintStubFacility` mirrors a fresh
 * `osmRef` onto both the facility entry AND its one stub course entry, so
 * historically either could be used to find "the" course — but once
 * `mergeIntoSurvivor` re-parents a merged facility's courses under the
 * survivor (§4.2 row 2), a survivor can end up with more than one course
 * entry, and picking "any course under this facility" is no longer
 * necessarily the RIGHT course for this specific ref. The course-level
 * record is the canonical anchor for a ref (§4.2: "the stub course
 * through the same seedRefs[]"), so this now searches course entries
 * FIRST, resolves that specific course through its own `mergedInto` chain,
 * and reads the facility off that course's CURRENT `facilityId` link
 * (correct even after re-parenting, because re-parenting updates exactly
 * that field and never the course's own id). Only when no course entry
 * carries the ref (a facility-only ref — not how `mintStubFacility` mints
 * today, kept as a defensive fallback) does it fall back to resolving via
 * the facility and picking one of its courses.
 */
export function findLedgerIdBySeedRef(
  ledger: IdLedger,
  osmRef: string,
): { facilityId: FacilityId; courseId: CourseId } | undefined {
  const parsedRef = OsmRefIdSchema.parse(osmRef);
  const entries = Object.values(ledger.entries);

  const courseOwner = entries.find(
    (e) => e.kind === "crs" && (e.seedRefs ?? []).includes(parsedRef),
  );
  if (courseOwner) {
    const resolvedCourseId = resolveMergedId(ledger, courseOwner.id);
    const courseEntry = ledger.entries[resolvedCourseId];
    if (!courseEntry) {
      throw new Error(
        `findLedgerIdBySeedRef: "${osmRef}" resolved to course "${resolvedCourseId}", which is not in the ledger`,
      );
    }
    const facilityId = courseEntry.facilityId;
    if (!facilityId) {
      throw new Error(
        `findLedgerIdBySeedRef: course "${resolvedCourseId}" (owner of "${osmRef}") has no facilityId link in the ledger`,
      );
    }
    return { facilityId, courseId: resolvedCourseId as CourseId };
  }

  const facilityOwner = entries.find(
    (e) => e.kind === "fac" && (e.seedRefs ?? []).includes(parsedRef),
  );
  if (!facilityOwner) return undefined;

  const survivorFacilityId = resolveMergedId(ledger, facilityOwner.id);
  const facilityEntry = ledger.entries[survivorFacilityId];
  if (!facilityEntry) {
    throw new Error(
      `findLedgerIdBySeedRef: "${osmRef}" resolved to facility "${survivorFacilityId}", which is not in the ledger`,
    );
  }
  const courseEntry = entries.find(
    (e) =>
      e.kind === "crs" && !e.tombstoned && e.facilityId === survivorFacilityId,
  );
  if (!courseEntry) {
    throw new Error(
      `findLedgerIdBySeedRef: facility "${survivorFacilityId}" (survivor of "${osmRef}") has no linked course entry in the ledger`,
    );
  }
  return {
    facilityId: survivorFacilityId as FacilityId,
    courseId: courseEntry.id as CourseId,
  };
}

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
 *
 * **S9 (gate review, post-e9b3ab0): proximity without a name match is
 * ambiguous, not "no match".** An object within 150 m of an existing
 * facility whose name similarity falls short of 0.8 is exactly the case a
 * human should look at (a rename? a genuinely distinct adjacent course?
 * a near-duplicate OSM entry?) — it is never silently treated as "no
 * spatial match found" and auto-minted as if it were unrelated.
 */
export function reseedFacility(
  ledger: IdLedger,
  incoming: IncomingOsmObject,
  candidates: ReseedCandidate[],
): ReseedOutcome {
  const osmRef = OsmRefIdSchema.parse(incoming.osmRef);

  const known = findLedgerIdBySeedRef(ledger, osmRef);
  if (known) {
    return { kind: "already-known", ...known };
  }

  const nearby = candidates.filter(
    (c) => haversineDistanceMeters(incoming, c) <= SPATIAL_MATCH_RADIUS_METERS,
  );

  if (nearby.length > 0) {
    const nameMatches = nearby.filter(
      (c) =>
        normalizedNameSimilarity(incoming.name, c.name) >=
        NAME_SIMILARITY_THRESHOLD,
    );
    // Exactly one nearby candidate AND its name matches: a clean spatial
    // match. Anything else nearby — zero name matches (S9), or more than
    // one — is ambiguous, never auto-minted.
    if (nameMatches.length !== 1) {
      return {
        kind: "ambiguous",
        candidateFacilityIds: nearby.map((c) => c.facilityId),
      };
    }
    const match = nameMatches[0];
    if (!match) {
      throw new Error(
        "unreachable: nameMatches.length === 1 but nameMatches[0] is undefined",
      );
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
    // S8 (gate review, post-e9b3ab0): a tombstoned id is dead — §3.5's
    // "never removed or reassigned" means a merged-away id can never
    // re-enter the promotion lifecycle under its own name again.
    if (entry.tombstoned) {
      throw new Error(
        `promoteToVerified: "${id}" is tombstoned (mergedInto: ${entry.mergedInto ?? "?"}) and cannot be promoted`,
      );
    }
    // S8: a second `verified` transition would silently double-record a
    // one-time promotion event — reject rather than allow it, matching
    // §3.5's "promotion is a recorded event", singular.
    if (entry.transitions.some((t) => t.type === "verified")) {
      throw new Error(
        `promoteToVerified: "${id}" already has a "verified" transition`,
      );
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
  const keptEntry = ledger.entries[keptCourseId];
  if (!keptEntry) {
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
      // Siblings belong to the same facility as the course they were
      // split from.
      ...(keptEntry.facilityId ? { facilityId: keptEntry.facilityId } : {}),
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
  const survivorEntry = ledger.entries[survivorId];
  if (!survivorEntry) {
    throw new Error(`mergeIntoSurvivor: unknown survivor id "${survivorId}"`);
  }
  for (const id of tombstoneIds) {
    const entry = ledger.entries[id];
    if (!entry) {
      throw new Error(`mergeIntoSurvivor: unknown ledger id "${id}"`);
    }
    // S8 (gate review, post-e9b3ab0):
    // - self-merge: an id cannot be tombstoned into itself.
    if (id === survivorId) {
      throw new Error(
        `mergeIntoSurvivor: "${id}" cannot be merged into itself`,
      );
    }
    // - cross-kind merge: a course can only merge into a course, a
    //   facility only into a facility (§4.2's promotion table only ever
    //   merges "several stub facilities" into "one survivor" — same kind).
    if (entry.kind !== survivorEntry.kind) {
      throw new Error(
        `mergeIntoSurvivor: cannot merge a "${entry.kind}" id ("${id}") into a "${survivorEntry.kind}" survivor ("${survivorId}")`,
      );
    }
    // - merge cycle: if the survivor already (transitively) resolves to
    //   the very id we're about to tombstone, tombstoning it into the
    //   survivor would close a loop (A→survivor→...→A).
    const survivorResolvesTo = resolveMergedId(ledger, survivorId);
    if (survivorResolvesTo === id) {
      throw new Error(
        `mergeIntoSurvivor: merging "${id}" into "${survivorId}" would create a mergedInto cycle (survivor already resolves back to "${id}")`,
      );
    }
  }
  let next = ledger;
  for (const id of tombstoneIds) {
    const entry = next.entries[id];
    if (!entry) {
      throw new Error(`mergeIntoSurvivor: unknown ledger id "${id}"`);
    }
    // Round-2 fix (gate review, "merge re-parenting"): §4.2 row 2 — "each
    // stub course keeps its id and moves under the survivor." Re-parent
    // every course whose facilityId currently points at the id being
    // tombstoned, BEFORE tombstoning it, by updating that link to the
    // survivor. The course's own id, status and transitions are untouched
    // — only which facility it belongs to changes. (Course-kind merges
    // have no children to re-parent; `entry.kind === survivorEntry.kind`
    // is already enforced above, so this only ever fires for a facility.)
    if (entry.kind === "fac") {
      for (const courseEntry of Object.values(next.entries)) {
        if (courseEntry.kind === "crs" && courseEntry.facilityId === id) {
          next = withEntry(next, {
            ...courseEntry,
            facilityId: survivorId as FacilityId,
          });
        }
      }
    }
    next = withEntry(next, {
      ...next.entries[id]!,
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
