/**
 * Shared building blocks for the §4.1 catalog schema: `Source`, `Prov`,
 * `ISODate`, the region-code pattern, and `tz` (IANA time zone) validation
 * (G-P0-11).
 */
import { z } from "zod";

/** Date-only ISO 8601 string (`YYYY-MM-DD`). The plan's `ISODate` fields
 * (`RosterVersion.effectiveFrom`, `verifiedAt`, `Source.retrieved`,
 * `checkedAt`, …) are read facility-locally throughout §4.1/§4.5 (e.g.
 * "computed in the facility's tz"), never as instants, so a date-only
 * string is the literal reading — not a full timestamp. */
export const IsoDateSchema = z.iso.date();
export type IsoDate = z.infer<typeof IsoDateSchema>;

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
export type Prov = z.infer<typeof ProvSchema>;

/** `Source { url, retrieved: ISODate, label? }` (§4.1). */
export const SourceSchema = z.strictObject({
  url: z.url(),
  retrieved: IsoDateSchema,
  label: z.string().optional(),
});
export type Source = z.infer<typeof SourceSchema>;

/**
 * `Region.code` — ISO 3166-2 (`'US-AL'|'CA-QC'|…`). The plan's sketch shows
 * a handful of examples followed by `…`, which this schema reads as
 * "any ISO 3166-2 US/CA subdivision code", not as an exhaustive literal
 * union — see the P1a report's ambiguity list for why a pattern was chosen
 * over hand-typing all 51 + 13 codes.
 */
export const RegionCodeSchema = z
  .string()
  .regex(/^(US|CA)-[A-Z]{2,3}$/, "must be an ISO 3166-2 US/CA code");
export type RegionCode = z.infer<typeof RegionCodeSchema>;

const IANA_TIME_ZONES = new Set(Intl.supportedValuesOf("timeZone"));

/** `tz: IANAZone` (G-P0-11) — validates against the runtime's own ICU time
 * zone database (`Intl.supportedValuesOf('timeZone')`), which is offline
 * and needs no network fetch or pinned dataset for the "is this a real IANA
 * zone name" half of the check. See `tzLikelyContainsCoordinates` in
 * `geo.ts` for the "wrong zone" half. */
export const IanaTimeZoneSchema = z
  .string()
  .refine((value) => IANA_TIME_ZONES.has(value), {
    error: "must be a valid IANA time zone name",
  });
export type IanaTimeZone = z.infer<typeof IanaTimeZoneSchema>;
