/**
 * The §4.1 catalog schema sketch, implemented literally, including every
 * A2-/G3-/O-numbered rule cited in its comments. `packages/catalog` is the
 * catalog *shape* SSOT only (build plan §3.1 row A: "Never does: Hold data
 * or fetch") — this module defines types and structural validation; the
 * cross-record and cross-version gate rules that need more than one record
 * to judge (duplicate ids, prov-vs-verification-tier, roster-version
 * immutability, geometry/contact diffs, …) live in `tools/catalog`'s
 * `verify-catalog`, per §10 P1's own naming of that as a separate tool.
 *
 * **Scope note (corrected post-e9b3ab0, gate review S6; updated for part B).**
 * `AchievementDef` needs `RuleExpr` (`AchievementDef.rule`) and is now
 * implemented in the sibling `rule-expr.ts` (part B), not in this file —
 * kept separate so this file stays the pure §4.1 structural-record schema
 * and `rule-expr.ts` owns the one recursive AST type. **`OfferTerms` IS
 * implemented below** — the original comment here wrongly grouped it with
 * `AchievementDef` as also needing `RuleExpr`. It doesn't: §4.1 states
 * plainly that `OfferTerms` is *"public, reviewed legal text only"* (`id,
 * trailId, title, terms, termsFr?, mode`) and that *"Offer INSTANCES and
 * parameters (facility, eligibility RuleExpr, budget, validity,
 * maxRedemptions, funder) live in the DB under operator scope"* — the
 * `RuleExpr` lives on the DB-side offer instance, never on `OfferTerms`
 * itself. Every other §4.1 entity is implemented.
 */
import { z } from "zod";
import {
  CourseIdSchema,
  DesignerIdSchema,
  FacilityIdSchema,
  HoleIdSchema,
  OfferTermsIdSchema,
  OsmRefIdSchema,
  TrailIdSchema,
} from "./ids.js";
import {
  HttpsUrlSchema,
  IanaTimeZoneSchema,
  IsoDateSchema,
  ProvSchema,
  RegionCodeSchema,
  SourceSchema,
} from "./common.js";

export { CourseIdSchema, DesignerIdSchema, FacilityIdSchema, HoleIdSchema, OfferTermsIdSchema, OsmRefIdSchema, TrailIdSchema };
export { HttpsUrlSchema, IanaTimeZoneSchema, IsoDateSchema, ProvSchema, RegionCodeSchema, SourceSchema };

/* ------------------------------------------------------------------ */
/* Region                                                              */
/* ------------------------------------------------------------------ */

/** `Region { code, country: 'US'|'CA', slug, name, nameFr?, polygonFile }`
 * (§4.1). */
export const RegionSchema = z.strictObject({
  code: RegionCodeSchema,
  country: z.enum(["US", "CA"]),
  slug: z.string().min(1),
  name: z.string().min(1),
  nameFr: z.string().optional(),
  polygonFile: z.string().min(1),
});
export type Region = z.infer<typeof RegionSchema>;

/* ------------------------------------------------------------------ */
/* Hole, Tee                                                           */
/* ------------------------------------------------------------------ */

/** `Hole { id, number, name?, signature? }` — "for completionUnit = 'hole'
 * trails" (§4.1). */
export const HoleSchema = z.strictObject({
  id: HoleIdSchema,
  number: z.int().min(1).max(36),
  name: z.string().optional(),
  signature: z.boolean().optional(),
});
export type Hole = z.infer<typeof HoleSchema>;

/** `Tee { name, gender?, yards?, meters?, rating?, slope?, source,
 * checkedAt }` (§4.1). */
export const TeeSchema = z.strictObject({
  name: z.string().min(1),
  gender: z.enum(["M", "F", "X"]).optional(),
  yards: z.number().positive().optional(),
  meters: z.number().positive().optional(),
  rating: z.number().positive().optional(),
  slope: z.number().positive().optional(),
  source: SourceSchema,
  checkedAt: IsoDateSchema,
});
export type Tee = z.infer<typeof TeeSchema>;

/* ------------------------------------------------------------------ */
/* Designer (data/designers.json, G3-02)                               */
/* ------------------------------------------------------------------ */

/** `Designer { id, name, aliases?, sources }` — "`data/designers.json`,
 * curated by PR (data lane)" (§4.1, G3-02). */
export const DesignerSchema = z.strictObject({
  id: DesignerIdSchema,
  name: z.string().min(1),
  aliases: z.array(z.string().min(1)).optional(),
  sources: z.array(SourceSchema),
});
export type Designer = z.infer<typeof DesignerSchema>;

/* ------------------------------------------------------------------ */
/* OfferTerms (S6, gate review post-e9b3ab0 — see this file's module doc) */
/* ------------------------------------------------------------------ */

export const OfferTermsModeSchema = z.enum(["portal-verify", "code-pool"]);
export type OfferTermsMode = z.infer<typeof OfferTermsModeSchema>;

/**
 * `OfferTerms { id: 'oft_…', trailId, title, terms, termsFr?, mode:
 * 'portal-verify'|'code-pool' }` (§4.1) — "public, reviewed legal text
 * only". Offer *instances* (facility, eligibility `RuleExpr`, budget,
 * validity, `maxRedemptions`, funder) are explicitly DB-side (§4.4
 * `offer`), not part of this record, which is why `OfferTerms` needs no
 * `RuleExpr` and is in scope for P1a.
 *
 * `termsFr` is optional here at the schema level for the same reason the
 * rest of this file keeps conditional requirements out of the Zod shape:
 * it is required only for a trail whose `regions` include a Québec code
 * (`CA-QC`), which needs the linked `Trail` record to evaluate — a
 * cross-record gate rule (`tools/catalog`'s `OFFER_TERMS_QC_MISSING_FR`),
 * not a schema-level one.
 */
export const OfferTermsSchema = z.strictObject({
  id: OfferTermsIdSchema,
  trailId: TrailIdSchema,
  title: z.string().min(1),
  terms: z.string().min(1),
  termsFr: z.string().min(1).optional(),
  mode: OfferTermsModeSchema,
});
export type OfferTerms = z.infer<typeof OfferTermsSchema>;

/* ------------------------------------------------------------------ */
/* Facility.verification (FM-07)                                       */
/* ------------------------------------------------------------------ */

export const VerificationBasisSchema = z.enum([
  "operator",
  "primary-source",
  "course-claim",
  "two-source-match",
]);
export type VerificationBasis = z.infer<typeof VerificationBasisSchema>;

export const ClaimProofSchema = z.enum(["domain-email", "dns-txt"]);
export type ClaimProof = z.infer<typeof ClaimProofSchema>;

export const VerificationStatusSchema = z.enum([
  "unverified",
  "listed-verified",
  "play-verified",
]);
export type VerificationStatus = z.infer<typeof VerificationStatusSchema>;

/**
 * `verification: { status, basis?, verifiedAt?, source?, claimProof? }`
 * (§4.1). `claimProof` is "required when basis = course-claim", and (S3,
 * gate review post-e9b3ab0, plan line 677) `basis`, `verifiedAt` and
 * `source` are each required once `status` is `listed-verified` or
 * `play-verified` — both are cross-field rules Zod's plain object shape
 * cannot express as required/optional per-branch without a discriminated
 * union on `status`/`basis`, which the plan's sketch does not use (both
 * are independent flat fields). Implemented with `superRefine` instead, so
 * both rules still land inside one Zod parse (surfaced by `verify-catalog`
 * as `SCHEMA_INVALID` issues at the specific missing field) rather than as
 * separate cross-record gate rules.
 */
export const VerificationSchema = z
  .strictObject({
    status: VerificationStatusSchema,
    basis: VerificationBasisSchema.optional(),
    verifiedAt: IsoDateSchema.optional(),
    source: SourceSchema.optional(),
    claimProof: ClaimProofSchema.optional(),
  })
  .superRefine((value, ctx) => {
    if (value.basis === "course-claim" && value.claimProof === undefined) {
      ctx.addIssue({
        code: "custom",
        path: ["claimProof"],
        message:
          'claimProof is required when verification.basis is "course-claim" (§4.1)',
      });
    }
    // S3 / plan line 677: `listed-verified` requires "... an operator
    // source, a primary-source fetch, a course claim ... or a
    // two-source-match ...; a source" — i.e. basis, verifiedAt and source
    // are all required once the tier is above `unverified`.
    if (value.status !== "unverified") {
      if (value.basis === undefined) {
        ctx.addIssue({
          code: "custom",
          path: ["basis"],
          message: `basis is required when verification.status is "${value.status}" (§4.1, plan line 677)`,
        });
      }
      if (value.verifiedAt === undefined) {
        ctx.addIssue({
          code: "custom",
          path: ["verifiedAt"],
          message: `verifiedAt is required when verification.status is "${value.status}" (§4.1, plan line 677)`,
        });
      }
      if (value.source === undefined) {
        ctx.addIssue({
          code: "custom",
          path: ["source"],
          message: `source is required when verification.status is "${value.status}" (§4.1, plan line 677)`,
        });
      }
    }
  });
export type Verification = z.infer<typeof VerificationSchema>;

/* ------------------------------------------------------------------ */
/* Facility.seed / Course.seed (§4.1, G3-01)                           */
/* ------------------------------------------------------------------ */

export const SeedOriginSchema = z.enum(["osm", "manual", "trail-roster"]);
export type SeedOrigin = z.infer<typeof SeedOriginSchema>;

/** Facility's `seed` is required: every facility, stub or verified, was
 * seeded from somewhere (§4.1: `seed: { origin, osmRef? }`). */
export const FacilitySeedSchema = z.strictObject({
  origin: SeedOriginSchema,
  osmRef: OsmRefIdSchema.optional(),
});
export type FacilitySeed = z.infer<typeof FacilitySeedSchema>;

/** Course's `seed` is optional — only a stub course (or one otherwise
 * OSM-matched) carries it (§4.1: `seed?: { osmRef: OsmRefId }`). */
export const CourseSeedSchema = z.strictObject({
  osmRef: OsmRefIdSchema,
});
export type CourseSeed = z.infer<typeof CourseSeedSchema>;

/* ------------------------------------------------------------------ */
/* prov / derivedFrom                                                  */
/* ------------------------------------------------------------------ */

/**
 * `prov?: { name?, town?, coord? }` (Facility, §4.1) — **plus `nameFr`**
 * (S2, gate review post-e9b3ab0, plan lines 561–562/569). The literal
 * type declaration at line 472 only ever shows three keys, but §4.1's own
 * gate-rule prose (line 562) lists `nameFr` among the Facility content
 * fields that need a non-OSM `prov` stamp, and line 569 makes the general
 * rule explicit: *"Verification replaces OSM content with sourced
 * content"* — an OSM `name:fr` tag is exactly the kind of OSM content that
 * rule exists to keep out of a curated record. Earlier (e9b3ab0) this was
 * read as the type declaration overriding the prose and `nameFr` was left
 * unstamped; the gate review corrected that reading, so `nameFr` gets its
 * own key here, and `FACILITY_CONTENT_FIELD_TO_PROV_KEY` below maps to it
 * directly instead of leaving it `undefined`.
 */
export const FacilityProvSchema = z.strictObject({
  name: ProvSchema.optional(),
  nameFr: ProvSchema.optional(),
  town: ProvSchema.optional(),
  coord: ProvSchema.optional(),
  /**
   * Plan-gap decision (stage-1 gate review, applied here): §4.1 gives
   * `Facility` no `blurb` field at all, but §5.1's R1 predicate
   * ("blurb ≥ 40") and the `courses/[slug]` page slots ("blurb") both
   * assume one. Added as an optional editorial field, stamped with its own
   * `prov` key exactly like every other content field (never `'osm'` —
   * editorial copy is never OSM-derived).
   */
  blurb: ProvSchema.optional(),
  blurbFr: ProvSchema.optional(),
});
export type FacilityProv = z.infer<typeof FacilityProvSchema>;

/** `prov?: { name?, holes?, par?, designers?, opened? }` (Course, §4.1,
 * G3-01: "the same per-field rule as Facility"). */
export const CourseProvSchema = z.strictObject({
  name: ProvSchema.optional(),
  holes: ProvSchema.optional(),
  par: ProvSchema.optional(),
  designers: ProvSchema.optional(),
  opened: ProvSchema.optional(),
});
export type CourseProv = z.infer<typeof CourseProvSchema>;

/** `derivedFrom?: { region?: 'osm', tz?: 'osm', slug?: 'osm' }` (Facility,
 * §4.1). "Keys computed from a seed are not copied content" — the value is
 * always the literal `'osm'` in the current plan (only OSM ever seeds a
 * derived key), so each key is `'osm'` or absent, never another `Prov`. */
export const FacilityDerivedFromSchema = z.strictObject({
  region: z.literal("osm").optional(),
  tz: z.literal("osm").optional(),
  slug: z.literal("osm").optional(),
});
export type FacilityDerivedFrom = z.infer<typeof FacilityDerivedFromSchema>;

/** `derivedFrom?: { slug?: 'osm' }` (Course, §4.1). */
export const CourseDerivedFromSchema = z.strictObject({
  slug: z.literal("osm").optional(),
});
export type CourseDerivedFrom = z.infer<typeof CourseDerivedFromSchema>;

/* ------------------------------------------------------------------ */
/* booking                                                             */
/* ------------------------------------------------------------------ */

export const BookingProviderSchema = z.enum([
  "golfnow",
  "chronogolf",
  "teeon",
  "club-prophet",
  "course-native",
]);
export type BookingProvider = z.infer<typeof BookingProviderSchema>;

/** One `booking[]` entry: `{ provider, url, externalId?, source, checkedAt
 * }` (§4.1). `url` is `https:`-only (S7, gate review post-e9b3ab0) — a
 * `javascript:`/`http:`/other-scheme booking URL is never legitimate. */
export const BookingEntrySchema = z.strictObject({
  provider: BookingProviderSchema,
  url: HttpsUrlSchema,
  externalId: z.string().optional(),
  source: SourceSchema,
  checkedAt: IsoDateSchema,
});
export type BookingEntry = z.infer<typeof BookingEntrySchema>;

/* ------------------------------------------------------------------ */
/* Course.geometry, Course.composite                                   */
/* ------------------------------------------------------------------ */

/** `geometry?: { layer, ref, file, checkedAt, sharedWithFacility }`
 * (§4.1). `ref` is `OsmRefId | 'manual'`. */
export const GeometrySchema = z.strictObject({
  layer: z.enum(["osm", "own"]),
  ref: z.union([OsmRefIdSchema, z.literal("manual")]),
  file: z.string().min(1),
  checkedAt: IsoDateSchema,
  sharedWithFacility: z.boolean(),
});
export type Geometry = z.infer<typeof GeometrySchema>;

/**
 * `composite?: [CourseId, CourseId]` — "an 18 formed from two nines"
 * (§4.1, G-P0-13). Two DISTINCT nines — a course cannot be composed with
 * itself (nit, gate review round 2: rejects `[X, X]`).
 */
export const CompositeSchema = z
  .tuple([CourseIdSchema, CourseIdSchema])
  .refine(([a, b]) => a !== b, {
    error: "composite must name two distinct courses, not the same course twice",
  });
export type Composite = z.infer<typeof CompositeSchema>;

export const ExternalIdsSchema = z.strictObject({
  ghin: z.string().optional(),
  arccos: z.string().optional(),
  garmin: z.string().optional(),
  golfnow: z.string().optional(),
});
export type ExternalIds = z.infer<typeof ExternalIdsSchema>;

/* ------------------------------------------------------------------ */
/* Course                                                               */
/* ------------------------------------------------------------------ */

/**
 * `Course { id, slug, name?, holes?, par?, designers?, opened?, closed?,
 * prov?, derivedFrom?, seed?, composite?, tees?, externalIds?, geometry?,
 * holesDetail? }` (§4.1).
 *
 * The sketch's `holes?: 9|18|number` is read as "9 or 18 are the common
 * cases, but any positive playable-unit count is valid" — `number` already
 * subsumes the two literals, so this is `z.int().positive()` with a comment
 * rather than a `9 | 18 | number` union (which would be redundant: every
 * value a `9 | 18` literal accepts, `number` already accepts too).
 */
export const CourseSchema = z.strictObject({
  id: CourseIdSchema,
  slug: z.string().min(1),
  name: z.string().min(1).optional(),
  /** A playable unit; 27/36-hole sites are several `Course` rows (§4.1). */
  holes: z.int().positive().optional(),
  par: z.int().positive().optional(),
  /** `dsg_…` ids from `data/designers.json`, never free text (G3-02). */
  designers: z.array(DesignerIdSchema).optional(),
  opened: z.int().min(1600).optional(),
  /** A2-18. */
  closed: z.boolean().optional(),
  prov: CourseProvSchema.optional(),
  derivedFrom: CourseDerivedFromSchema.optional(),
  seed: CourseSeedSchema.optional(),
  composite: CompositeSchema.optional(),
  tees: z.array(TeeSchema).optional(),
  externalIds: ExternalIdsSchema.optional(),
  geometry: GeometrySchema.optional(),
  holesDetail: z.array(HoleSchema).optional(),
});
export type Course = z.infer<typeof CourseSchema>;

/* ------------------------------------------------------------------ */
/* Facility                                                             */
/* ------------------------------------------------------------------ */

export const FacilityAccessSchema = z.enum([
  "public",
  "semi-private",
  "resort",
  "municipal",
  "private",
]);
export type FacilityAccess = z.infer<typeof FacilityAccessSchema>;

export const AmenitySchema = z.strictObject({
  key: z.string().min(1),
  value: z.boolean(),
  source: SourceSchema,
});
export type Amenity = z.infer<typeof AmenitySchema>;

/**
 * `Facility { id, slug, region, tz, name?, nameFr?, town?, lat?, lng?,
 * approx?, coordSource?, prov?, derivedFrom?, access?, url?, phone?,
 * closed?, verification, seed, booking, amenities?, factsCheckedAt?,
 * courses }` (§4.1).
 *
 * A2-03: content fields (`name`, `nameFr`, `town`, `lat`, `lng`) are
 * OPTIONAL at the Zod-shape level — required-ness is *conditional* on
 * `verification.status` ("REQUIRED, with a non-OSM `prov`, from
 * `listed-verified` on"), which Zod's static object shape cannot express
 * without a discriminated union keyed on `verification.status` (which the
 * plan's sketch does not use — `Facility` is one flat shape whatever the
 * tier). That conditional requirement is therefore a `verify-catalog` gate
 * rule (`VERIFIED_CONTENT_INCOMPLETE`), not a schema-level one — exactly
 * where §4.1 itself places it: *"What the gate forbids ... (b) a
 * `listed-verified` or `play-verified` facility whose content fields ...
 * are missing"*.
 */
export const FacilitySchema = z.strictObject({
  id: FacilityIdSchema,
  slug: z.string().min(1),
  region: RegionCodeSchema,
  /** REQUIRED, e.g. 'America/Chicago' (G-P0-11). */
  tz: IanaTimeZoneSchema,
  name: z.string().min(1).optional(),
  nameFr: z.string().optional(),
  /** Plan-gap decision (§5.1 R1's "blurb ≥ 40", §4.1's content-field
   * pattern) — see `FacilityProvSchema`'s doc above. Editorial copy only;
   * never a verbatim copy of any external source (matching SWC's own S1
   * rule that meta never quotes the blurb verbatim). */
  blurb: z.string().optional(),
  blurbFr: z.string().optional(),
  town: z.string().min(1).optional(),
  lat: z.number().min(-90).max(90).optional(),
  lng: z.number().min(-180).max(180).optional(),
  approx: z.boolean().optional(),
  coordSource: SourceSchema.optional(),
  prov: FacilityProvSchema.optional(),
  derivedFrom: FacilityDerivedFromSchema.optional(),
  /** REQUIRED from `listed-verified` on for any facility in a roster
   * version (O8); a `verify-catalog` gate rule, not a schema-level one —
   * see `ROSTER_MEMBER_MISSING_ACCESS`. */
  access: FacilityAccessSchema.optional(),
  /** `https:`-only (S7, gate review post-e9b3ab0). */
  url: HttpsUrlSchema.optional(),
  phone: z.string().optional(),
  closed: z.boolean().optional(),
  verification: VerificationSchema,
  seed: FacilitySeedSchema,
  booking: z.array(BookingEntrySchema),
  amenities: z.array(AmenitySchema).optional(),
  factsCheckedAt: IsoDateSchema.optional(),
  courses: z.array(CourseSchema).min(1),
});
export type Facility = z.infer<typeof FacilitySchema>;

/* ------------------------------------------------------------------ */
/* Trail / RosterVersion                                                */
/* ------------------------------------------------------------------ */

export const TrailKindSchema = z.enum([
  "state-agency",
  "statutory-commission",
  "dmo",
  "co-op",
  "commercial-network",
  "pass-programme",
  "resort-portfolio",
]);
export type TrailKind = z.infer<typeof TrailKindSchema>;

export const TrailStatusSchema = z.enum(["active", "developing", "defunct"]);
export type TrailStatus = z.infer<typeof TrailStatusSchema>;

export const RosterStatusSchema = z.enum([
  "verified",
  "conflicting",
  "unverified",
]);
export type RosterStatus = z.infer<typeof RosterStatusSchema>;

export const OperatorSchema = z.strictObject({
  name: z.string().min(1),
  /** `https:`-only (gate review nit, matching Facility.url and
   * booking[].url's own S7 rule) — an operator's `http:`/other-scheme URL
   * is never legitimate on a curated record. */
  url: HttpsUrlSchema,
  type: z.string().min(1),
});
export type Operator = z.infer<typeof OperatorSchema>;

export const CompletionUnitSchema = z.enum(["course", "facility", "hole"]);
export type CompletionUnit = z.infer<typeof CompletionUnitSchema>;

/** `markerUnit: 'facility'` — "the default and, in v1, the only value"
 * (§4.3). Modelled as a single-member enum (not `z.literal`) so a future
 * value is a MINOR schema change, matching how the rest of this file
 * models closed-but-single-value fields. */
export const MarkerUnitSchema = z.enum(["facility"]);
export type MarkerUnit = z.infer<typeof MarkerUnitSchema>;

/**
 * `completionRule` / `markerRule`: `{ kind: 'all' } | { kind: 'n-of-m', n,
 * ruleSource }` (§4.1). Modelled as a discriminated union on `kind`, which
 * makes `n` and `ruleSource` structurally required exactly when
 * `kind === 'n-of-m'` — this is what makes the v6 AT(1) fixture ("a roster
 * version with `completionRule` or `markerRule` `n-of-m` and no
 * `ruleSource`", O15) a plain Zod parse failure (`SCHEMA_INVALID` at
 * `.ruleSource`) rather than a separate gate rule, which is the most
 * literal reading of the sketch's own `|` union shape.
 */
export const CompletionOrMarkerRuleSchema = z.discriminatedUnion("kind", [
  z.strictObject({ kind: z.literal("all") }),
  z.strictObject({
    kind: z.literal("n-of-m"),
    n: z.int().positive(),
    ruleSource: SourceSchema,
  }),
]);
export type CompletionOrMarkerRule = z.infer<
  typeof CompletionOrMarkerRuleSchema
>;

/** A roster member, `unit`-tagged (§4.1, §4.3). Not a `discriminatedUnion`
 * on `unit` alone: two variants both carry `unit: 'course'`
 * (`{courseId}` vs the A2-18 `{anyOf}` form), which a discriminant requires
 * to be unique per branch — hence a plain `z.union`. `stopOrder` is the
 * sketch's `& { stopOrder?: number }` intersected onto every variant. */
const StopOrderSchema = z.int().nonnegative().optional();

export const CourseMemberSchema = z.strictObject({
  unit: z.literal("course"),
  courseId: CourseIdSchema,
  stopOrder: StopOrderSchema,
});
export type CourseMember = z.infer<typeof CourseMemberSchema>;

/** A2-18: "an operator's stop that is 'the 27-hole facility' on a
 * course-unit trail". */
export const CourseAnyOfMemberSchema = z.strictObject({
  unit: z.literal("course"),
  anyOf: z.array(CourseIdSchema).min(2),
  stopOrder: StopOrderSchema,
});
export type CourseAnyOfMember = z.infer<typeof CourseAnyOfMemberSchema>;

export const FacilityMemberSchema = z.strictObject({
  unit: z.literal("facility"),
  facilityId: FacilityIdSchema,
  stopOrder: StopOrderSchema,
});
export type FacilityMember = z.infer<typeof FacilityMemberSchema>;

export const HoleMemberSchema = z.strictObject({
  unit: z.literal("hole"),
  holeId: HoleIdSchema,
  courseId: CourseIdSchema,
  stopOrder: StopOrderSchema,
});
export type HoleMember = z.infer<typeof HoleMemberSchema>;

export const RosterMemberSchema = z.union([
  CourseMemberSchema,
  CourseAnyOfMemberSchema,
  FacilityMemberSchema,
  HoleMemberSchema,
]);
export type RosterMember = z.infer<typeof RosterMemberSchema>;

/**
 * `RosterVersion { version, effectiveFrom, effectiveTo?, source,
 * verifiedAt, completionUnit, markerUnit, completionRule, markerRule,
 * trackingStartsOn?, members }` (§4.1 v3/A2-02: the unit and rule fields
 * moved INTO `RosterVersion` so each is immutable per version).
 */
export const RosterVersionSchema = z.strictObject({
  version: z.int().positive(),
  /** Labels + removal dating only, NOT a play window (§4.1). */
  effectiveFrom: IsoDateSchema,
  effectiveTo: IsoDateSchema.optional(),
  source: SourceSchema,
  verifiedAt: IsoDateSchema,
  completionUnit: CompletionUnitSchema,
  markerUnit: MarkerUnitSchema,
  completionRule: CompletionOrMarkerRuleSchema,
  markerRule: CompletionOrMarkerRuleSchema,
  /** FM-01: earliest play date that counts IN THIS VERSION; absent = no
   * lower bound. */
  trackingStartsOn: IsoDateSchema.optional(),
  members: z.array(RosterMemberSchema).min(1),
});
export type RosterVersion = z.infer<typeof RosterVersionSchema>;

/**
 * `Trail { id, slug, name, nameFr?, countries, regions, kind, status,
 * operator, officialUrl, rosterStatus, rosterVersions, blurb?, blurbFr?,
 * lastReviewed, sources }` (§4.1).
 */
export const TrailSchema = z.strictObject({
  id: TrailIdSchema,
  slug: z.string().min(1),
  name: z.string().min(1),
  nameFr: z.string().optional(),
  countries: z.array(z.enum(["US", "CA"])).min(1),
  regions: z.array(RegionCodeSchema).min(1),
  kind: TrailKindSchema,
  status: TrailStatusSchema,
  operator: OperatorSchema,
  /** `https:`-only (gate review nit — same S7 rule as Facility.url,
   * booking[].url and Operator.url). */
  officialUrl: HttpsUrlSchema,
  rosterStatus: RosterStatusSchema,
  rosterVersions: z.array(RosterVersionSchema).min(1),
  blurb: z.string().optional(),
  blurbFr: z.string().optional(),
  lastReviewed: IsoDateSchema,
  sources: z.array(SourceSchema).min(1),
});
export type Trail = z.infer<typeof TrailSchema>;

/* ------------------------------------------------------------------ */
/* Content fields (§4.1 "What the gate forbids, exactly")              */
/* ------------------------------------------------------------------ */

/** The Facility content fields §4.1's gate rule (a) names by exact list:
 * *"The content fields are: Facility `name`, `nameFr`, `town`, `lat`,
 * `lng`"*, **plus `blurb`/`blurbFr`** (the stage-1 plan-gap decision — see
 * `FacilitySchema`'s doc): the same "no prov stamp, or `prov: 'osm'`, is a
 * gate failure" rule applies to editorial copy exactly as to every other
 * content field. Exported so `verify-catalog` iterates this exact list
 * rather than re-deriving it (and risking drift) from the schema shape. */
export const FACILITY_CONTENT_FIELDS = [
  "name",
  "nameFr",
  "town",
  "lat",
  "lng",
  "blurb",
  "blurbFr",
] as const;

/** Course content fields, same rule: *"Course `name`, `holes`, `par`,
 * `designers`, `opened`"*. */
export const COURSE_CONTENT_FIELDS = [
  "name",
  "holes",
  "par",
  "designers",
  "opened",
] as const;

/** The only keys `derivedFrom` may carry on a Facility (§4.1 gate rule
 * (c)). */
export const FACILITY_DERIVED_FROM_ALLOWED_KEYS = [
  "region",
  "tz",
  "slug",
] as const;

/** The only key `derivedFrom` may carry on a Course (§4.1 gate rule (c):
 * "`derivedFrom` key on any field other than `region`, `tz` or `slug`" is
 * the Facility list; a Course's own sketch only ever shows `derivedFrom?:
 * { slug?: 'osm' }`, so a Course's allowed set is the subset that applies
 * to it). */
export const COURSE_DERIVED_FROM_ALLOWED_KEYS = ["slug"] as const;

/**
 * Maps each Facility content field (§4.1 gate rule (a)'s list above) to
 * the `prov` key that stamps it.
 *
 * **Not a 1:1 mapping.** `lat` and `lng` are always sourced together as
 * one coordinate pair, so both map to the single `coord` key. `nameFr` DID
 * map to `undefined` ("exempt") through e9b3ab0 — that was the wrong
 * reading (see `FacilityProvSchema`'s doc, S2 gate-review correction):
 * `nameFr` now has its own `prov` key and maps to it directly, so it is
 * fully covered by the prov-required check like every other content field.
 */
export const FACILITY_CONTENT_FIELD_TO_PROV_KEY: Record<
  (typeof FACILITY_CONTENT_FIELDS)[number],
  keyof FacilityProv
> = {
  name: "name",
  nameFr: "nameFr",
  town: "town",
  lat: "coord",
  lng: "coord",
  blurb: "blurb",
  blurbFr: "blurbFr",
};
