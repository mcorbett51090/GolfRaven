/**
 * The R1 predicate (§5.1, adapting SWC's `src/lib/indexable.ts`): a
 * generated course page is indexed only if it carries substantive, unique
 * content — otherwise it stays a stable, crawlable page (a thin/unverified
 * row still links to a claim CTA) but ships `noindex` and drops out of the
 * sitemap, so a directory full of thin stubs never triggers host-level
 * thin-content demotion of the whole domain (the SWC precedent this ports,
 * `swc-analysis.md`'s R1).
 *
 * §5.1's exact wording: *"R1 predicate: `verification = verified` **and**
 * (own `url` or blurb ≥ 40 or ≥ 1 sourced course fact or a verified
 * amenity). Trail membership alone is not enough (thin-content guard)."*
 * This predicate therefore never consults `trailsOfFacility`/roster
 * membership — being on a trail's roster is not, by itself, a reason to
 * index a page.
 *
 * "verified" is §4.2's unqualified sense: `listed-verified` or better
 * (`verification.status !== 'unverified'`) — never `play-verified` only.
 *
 * **Schema note (resolved ambiguity).** `FacilitySchema` (§4.1, as
 * implemented) has no `blurb` field — only `Trail.blurb`/`blurbFr` exist
 * today. §5.1's "blurb ≥ 40" branch is therefore implemented against a
 * defensive, duck-typed read (`hasSourcedBlurb` below): it never throws on
 * a real, schema-valid `Facility` (which structurally cannot carry the
 * field, `z.strictObject` rejects it), and it activates automatically the
 * day `Facility` gains an editorial blurb field, with no change needed
 * here.
 */
import type { Facility } from "./schema.js";

const BLURB_MIN_LENGTH = 40;

/** "own `url`" — a non-empty official site URL on the facility itself. */
export function hasOwnUrl(facility: Facility): boolean {
  return typeof facility.url === "string" && facility.url.trim() !== "";
}

/** "blurb ≥ 40" — see this module's doc note on why this is a defensive,
 * forward-compatible read rather than a direct `facility.blurb` access. */
export function hasSourcedBlurb(facility: Facility): boolean {
  const blurb = (facility as unknown as { blurb?: unknown }).blurb;
  return typeof blurb === "string" && blurb.trim().length >= BLURB_MIN_LENGTH;
}

/** "≥ 1 sourced course fact" — at least one course at the facility carries
 * a `prov`-stamped content field (name/holes/par/designers/opened with a
 * non-OSM `prov`, §4.1) — i.e. a fact someone actually sourced, not just
 * the OSM-joined stub content every unverified course shows. */
export function hasSourcedCourseFact(facility: Facility): boolean {
  return facility.courses.some(
    (course) => course.prov !== undefined && Object.keys(course.prov).length > 0,
  );
}

/** "a verified amenity" — `Amenity` (§4.1) always carries a `source`, so
 * any entry in `amenities[]` is by construction sourced. */
export function hasVerifiedAmenity(facility: Facility): boolean {
  return Array.isArray(facility.amenities) && facility.amenities.length > 0;
}

/** §4.2: "'verified' with no qualifier means `listed-verified` or better." */
export function isVerified(facility: Facility): boolean {
  return facility.verification.status !== "unverified";
}

/** The R1 predicate, exactly as §5.1 defines it. */
export function isIndexable(facility: Facility): boolean {
  return (
    isVerified(facility) &&
    (hasOwnUrl(facility) ||
      hasSourcedBlurb(facility) ||
      hasSourcedCourseFact(facility) ||
      hasVerifiedAmenity(facility))
  );
}

/** R1 thin-stub mirror of `!isIndexable`, kept as a named predicate for the
 * same reason SWC kept `isThinStub` — template/CTA promotion stays tied to
 * the one gate that drives `noindex` + sitemap exclusion, never a second,
 * independently-drifting formula. */
export function isThinStub(facility: Facility): boolean {
  return !isIndexable(facility);
}
