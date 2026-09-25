// GENERATED FILE — DO NOT EDIT BY HAND.
// Copied verbatim from packages/rules/dist or packages/catalog/dist (built
// from packages/rules/src / packages/catalog/src — the single source of
// truth) by supabase/functions/_shared/scoring/generate-bundle.sh, which
// also rewrote its "@golfraven/catalog" import to a relative one. Every
// other import (zod, @noble/hashes/*, tz-lookup) is untouched, resolved
// through supabase/functions/deno.json's pinned import map. Re-run that
// script after `pnpm -r build` and commit the result.
// supabase/tests/unit/rules-vendor-freshness.test.ts fails CI on drift.
/**
 * Shared building blocks for the §4.1 catalog schema: `Source`, `Prov`,
 * `ISODate`, the region-code pattern, and `tz` (IANA time zone) validation
 * (G-P0-11).
 */
import { z } from "zod";
import regionCodesData from "./region-codes.json" with { type: "json" };
/** Date-only ISO 8601 string (`YYYY-MM-DD`). The plan's `ISODate` fields
 * (`RosterVersion.effectiveFrom`, `verifiedAt`, `Source.retrieved`,
 * `checkedAt`, …) are read facility-locally throughout §4.1/§4.5 (e.g.
 * "computed in the facility's tz"), never as instants, so a date-only
 * string is the literal reading — not a full timestamp. */
export const IsoDateSchema = z.iso.date();
/** `Prov = 'editor'|'operator'|'claim'|'primary-source'` (§4.1). `'osm'` is
 * deliberately never a member: a content field's `prov` may equal `'osm'`
 * as a *value the gate rejects* (§4.1 "(a)"), but it is not one of the four
 * values a curated record is allowed to carry. */
export const ProvSchema = z.enum([
    "editor",
    "operator",
    "claim",
    "primary-source",
]);
/** `Source { url, retrieved: ISODate, label? }` (§4.1). */
export const SourceSchema = z.strictObject({
    url: z.url(),
    retrieved: IsoDateSchema,
    label: z.string().optional(),
});
/**
 * `Region.code` — ISO 3166-2 (`'US-AL'|'CA-QC'|…`). The plan's sketch shows
 * a handful of examples followed by `…`, read as "any ISO 3166-2 US/CA
 * subdivision code".
 *
 * **Round 2 (gate-review nit): validated against a pinned list, not a
 * shape-only pattern.** The original `^(US|CA)-[A-Z]{2,3}$` regex let
 * `US-ZZ` (not a real state) through — it checked the *shape* of a region
 * code, not that the code actually names a US state/territory or Canadian
 * province/territory. `region-codes.json` (this directory) is the full,
 * pinned ISO 3166-2:US / ISO 3166-2:CA list (69 codes: 50 states + DC + 5
 * inhabited territories + 13 Canadian provinces/territories); see that
 * file's `_comment` for the exact source.
 */
/** Exported (not just used internally) so `@golfraven/rules`'s static
 * checker can bound `countDistinct("region")`'s domain size (S5, gate
 * review) without duplicating or re-deriving the pinned list. */
export const REGION_CODES = new Set(regionCodesData.codes);
export const RegionCodeSchema = z.string().refine((value) => REGION_CODES.has(value), {
    error: "must be a real ISO 3166-2 US/CA subdivision code (see region-codes.json)",
});
/**
 * `tz: IANAZone` (G-P0-11) — "is this a real IANA zone name" half of the
 * check. **Not** `Intl.supportedValuesOf('timeZone')` (gate-review
 * correction, post-e9b3ab0): that API is a fairly recent addition (Node
 * 18+) and its populated list is an ICU implementation detail that can
 * vary between runtimes/ICU data versions, so a name it doesn't happen to
 * enumerate could be wrongly rejected even though `Intl.DateTimeFormat`
 * itself accepts it. `new Intl.DateTimeFormat('en', { timeZone })` is the
 * more portable check: every environment with `Intl` support implements
 * it, and it throws a `RangeError` on an unrecognised zone name — that
 * throw/no-throw is what this validates, offline, no network fetch, no
 * pinned dataset needed for this half. See `tzLikelyContainsCoordinates`
 * in `geo.ts` for the "wrong zone" half, which DOES use a pinned dataset
 * (via the `tz-lookup` package).
 */
export function isValidIanaTimeZoneName(value) {
    try {
        // eslint-disable-next-line no-new
        new Intl.DateTimeFormat("en", { timeZone: value });
        return true;
    }
    catch {
        return false;
    }
}
export const IanaTimeZoneSchema = z
    .string()
    .refine((value) => isValidIanaTimeZoneName(value), {
    error: "must be a valid IANA time zone name",
});
/**
 * S7 (gate review, post-e9b3ab0): every URL this schema accepts on a
 * curated record must be `https:` — `z.url()` alone accepts any scheme,
 * including `javascript:`, `http:`, `data:`, etc. Scoped to exactly what
 * the gate review named (Facility `url`, booking `url`); see `schema.ts`.
 */
export const HttpsUrlSchema = z.url().refine((value) => {
    try {
        return new URL(value).protocol === "https:";
    }
    catch {
        return false;
    }
}, { error: "must be an https: URL" });
