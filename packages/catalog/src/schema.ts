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
 * **Scope note (see the P1a report for the full list).** `AchievementDef`
 * and `OfferTerms` are the two §4.1 top-level entities *not* implemented
 * here. Both require `RuleExpr` (`AchievementDef.rule`, and `OfferTerms`'
 * eligibility rules live in the DB under the same grammar, §4.1), and the
 * task's own out-of-scope list names "`packages/rules` (completion and
 * `RuleExpr`)" as part B. Every other §4.1 entity is implemented.
 */
import { z } from "zod";
import {
  CourseIdSchema,
  DesignerIdSchema,
  FacilityIdSchema,
  HoleIdSchema,
  OsmRefIdSchema,
  TrailIdSchema,
} from "./ids.js";
import {
  IanaTimeZoneSchema,
  IsoDateSchema,
  ProvSchema,
  RegionCodeSchema,
  SourceSchema,
} from "./common.js";

export { CourseIdSchema, DesignerIdSchema, FacilityIdSchema, HoleIdSchema, OsmRefIdSchema, TrailIdSchema };
export { IanaTimeZoneSchema, IsoDateSchema, ProvSchema, RegionCodeSchema, SourceSchema };

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
 * (§4.1). `claimProof` is "required when basis = course-claim" — a
 * cross-field rule Zod's plain object shape cannot express as
 * required/optional per-branch without a discriminated union on `basis`,
 * which the plan's sketch does not use (`basis` is optional and
 * independent of `status`). Implemented with `superRefine` instead, so the
 * rule still lands inside one Zod parse (surfaced by `verify-catalog` as a
 * `SCHEMA_INVALID` issue at `verification.claimProof`) rather than as a
 * separate cross-record gate rule.
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

/** `prov?: { name?, town?, coord? }` (Facility, §4.1). */
export const FacilityProvSchema = z.strictObject({
  name: ProvSchema.optional(),
  town: ProvSchema.optional(),
  coord: ProvSchema.optional(),
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
 * }` (§4.1). */
export const BookingEntrySchema = z.strictObject({
  provider: BookingProviderSchema,
  url: z.url(),
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

/** `composite?: [CourseId, CourseId]` — "an 18 formed from two nines"
 * (§4.1, G-P0-13). */
export const CompositeSchema = z.tuple([CourseIdSchema, CourseIdSchema]);
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
  url: z.url().optional(),
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
  url: z.url(),
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
  officialUrl: z.url(),
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
 * `lng`"*. Exported so `verify-catalog` iterates this exact list rather
 * than re-deriving it (and risking drift) from the schema shape. */
export const FACILITY_CONTENT_FIELDS = [
  "name",
  "nameFr",
  "town",
  "lat",
  "lng",
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
 * **Not a 1:1 mapping, and this is a genuine tension in the plan's own
 * text, not a free design choice.** The `prov` type is declared exactly
 * once, as `{ name?: Prov, town?: Prov, coord?: Prov }` (§4.1) — three
 * keys. But gate rule (a) separately lists five content fields including
 * `nameFr` and separate `lat`/`lng`. Reading the explicit type declaration
 * as authoritative for what `prov` can express (the more literal,
 * structured source): `lat` and `lng` are always sourced together as one
 * coordinate pair, so both map to the single `coord` key; `nameFr` has no
 * matching `prov` key at all, so a facility's `nameFr` is not
 * provenance-tracked in this schema version — `undefined` here means
 * "exempt from the prov-required check", not "always fails it". See the
 * P1a report's ambiguity list.
 */
export const FACILITY_CONTENT_FIELD_TO_PROV_KEY: Record<
  (typeof FACILITY_CONTENT_FIELDS)[number],
  keyof FacilityProv | undefined
> = {
  name: "name",
  nameFr: undefined,
  town: "town",
  lat: "coord",
  lng: "coord",
};
