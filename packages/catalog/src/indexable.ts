/**
 * The R1 predicate (§5.1, adapting SWC's `src/lib/indexable.ts`): a
 * generated course page is indexed only if it carries substantive, unique
 * content — otherwise it stays a stable, crawlable page (S4: every
 * *verified* facility still gets a page; R1 decides only whether it is
 * indexed) but ships `noindex` and drops out of the sitemap, so a
 * directory full of thin stubs never triggers host-level thin-content
 * demotion of the whole domain.
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
 * **`blurb` (stage-1 gate-review decision, applied here).** §4.1 gave
 * `Facility` no `blurb` field, but this predicate and the course-page
 * slots both assumed one; `blurb`/`blurbFr` are now real, optional,
 * `prov`-stamped `Facility` fields (`schema.ts`'s `FacilityProvSchema`
 * doc). This module reads the real field directly — no more duck typing.
 *
 * **"≥ 1 sourced course fact" (gate-review fix).** `name` and `holes` are
 * REQUIRED (with a non-OSM `prov`) on every course of a `listed-verified`+
 * facility (§4.1 gate rule (b), G3-01) — every verified course therefore
 * always has them, which would make this branch of R1 true unconditionally
 * and the thin-content guard never bite. Only the fields that are
 * genuinely OPTIONAL extra research — `par`, `designers`, `opened` (each
 * needing its own non-OSM `prov` stamp), or a non-empty `tees[]` (each
 * `Tee` always carries its own `source`, never an OSM tag — tees are never
 * OSM-derived at all) — count as a "sourced course fact" here.
 */
import type { Facility } from "./schema.js";

const BLURB_MIN_LENGTH = 40;

/** The optional-research course fields that count toward R1's "sourced
 * course fact" — deliberately excludes `name`/`holes` (mandatory, always
 * present+`prov`-stamped on a verified course; see this module's doc). */
const OPTIONAL_SOURCED_COURSE_FIELDS = ["par", "designers", "opened"] as const;

/** "own `url`" — a non-empty official site URL on the facility itself. */
export function hasOwnUrl(facility: Facility): boolean {
  return typeof facility.url === "string" && facility.url.trim() !== "";
}

/** "blurb ≥ 40" — the real `Facility.blurb` field (see this module's doc). */
export function hasSourcedBlurb(facility: Facility): boolean {
  return (facility.blurb ?? "").trim().length >= BLURB_MIN_LENGTH;
}

/** "≥ 1 sourced course fact" — see this module's doc for exactly which
 * fields count and why `name`/`holes` are deliberately excluded. */
export function hasSourcedCourseFact(facility: Facility): boolean {
  return facility.courses.some((course) => {
    const hasOptionalProvField = OPTIONAL_SOURCED_COURSE_FIELDS.some((field) => {
      const prov = course.prov?.[field];
      return course[field] !== undefined && prov !== undefined && (prov as string) !== "osm";
    });
    const hasSourcedTee = Array.isArray(course.tees) && course.tees.length > 0;
    return hasOptionalProvField || hasSourcedTee;
  });
}

/** "a verified amenity" — an amenity entry `Amenity` always carries a
 * `source`, so any entry is by construction sourced; but only an entry
 * whose `value` is actually `true` describes a real, confirmed amenity — a
 * sourced-and-confirmed **absence** (`value: false`) is not "a verified
 * amenity" in R1's sense (it is data, just not a reason to index). */
export function hasVerifiedAmenity(facility: Facility): boolean {
  return Array.isArray(facility.amenities) && facility.amenities.some((a) => a.value === true);
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
