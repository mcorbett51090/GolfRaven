/**
 * ID kinds and prefixes (build plan §3.5 "Identity", §4.1).
 *
 * > IDs are opaque and immutable: `trl_`/`fac_`/`crs_`/`hol_`/`dsg_` + ULID
 * > (`dsg_` = a course designer, §4.1).
 *
 * A ULID is 26 characters of Crockford base32 (no `I`, `L`, `O`, `U`, to
 * avoid visual confusion) encoding a 48-bit timestamp followed by 80 bits
 * of randomness. IDs are opaque per the plan, so nothing here decodes the
 * timestamp back out — `mintId` only needs to produce one.
 */
import { randomBytes } from "node:crypto";
import { z } from "zod";

/** Crockford's base32 alphabet, as ULID uses it. */
const CROCKFORD_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

const ULID_PATTERN = "[0-9A-HJKMNP-TV-Z]{26}";

/** The id "kinds" the plan defines (§3.5, §4.1). `ach_` (`AchievementDef`)
 * is now in scope (part B: `RuleExpr` + `AchievementDef`, see
 * `rule-expr.ts`). `oft_` (`OfferTerms`) was already in scope (S6, gate
 * review post-e9b3ab0): `OfferTerms` itself carries no `RuleExpr` field at
 * all — only offer *instances*, which live in the DB under operator scope
 * (§4.1), do. */
export const ID_KINDS = ["trl", "fac", "crs", "hol", "dsg", "oft", "ach"] as const;
export type IdKind = (typeof ID_KINDS)[number];

function idSchema<P extends string>(prefix: P) {
  return z
    .string()
    .regex(
      new RegExp(`^${prefix}_${ULID_PATTERN}$`),
      `must be "${prefix}_" followed by a 26-character Crockford-base32 ULID`,
    )
    .brand(`${prefix}Id` as const);
}

export const TrailIdSchema = idSchema("trl");
export const FacilityIdSchema = idSchema("fac");
export const CourseIdSchema = idSchema("crs");
export const HoleIdSchema = idSchema("hol");
export const DesignerIdSchema = idSchema("dsg");
export const OfferTermsIdSchema = idSchema("oft");
export const AchievementIdSchema = idSchema("ach");

export type TrailId = z.infer<typeof TrailIdSchema>;
export type FacilityId = z.infer<typeof FacilityIdSchema>;
export type CourseId = z.infer<typeof CourseIdSchema>;
export type HoleId = z.infer<typeof HoleIdSchema>;
export type DesignerId = z.infer<typeof DesignerIdSchema>;
export type OfferTermsId = z.infer<typeof OfferTermsIdSchema>;
export type AchievementId = z.infer<typeof AchievementIdSchema>;

/** Any of the id kinds implemented so far, unbranded (used where the caller
 * genuinely needs to accept more than one kind, e.g. the ledger). */
export const AnyKnownIdSchema = z.union([
  TrailIdSchema,
  FacilityIdSchema,
  CourseIdSchema,
  HoleIdSchema,
  DesignerIdSchema,
  OfferTermsIdSchema,
  AchievementIdSchema,
]);

const PREFIX_BY_KIND: Record<IdKind, string> = {
  trl: "trl",
  fac: "fac",
  crs: "crs",
  hol: "hol",
  dsg: "dsg",
  oft: "oft",
  ach: "ach",
};

/** Generates a fresh, valid ULID using cryptographically strong randomness
 * (`node:crypto`'s `randomBytes`, offline — no network, no external ulid
 * dependency). Not monotonic across the same millisecond; the plan does not
 * require monotonicity, only opacity and immutability (§3.5). */
export function generateUlid(now: Date = new Date()): string {
  const time = now.getTime();
  if (!Number.isFinite(time) || time < 0) {
    throw new Error(`generateUlid: invalid timestamp ${String(now)}`);
  }
  // 48-bit timestamp -> 10 Crockford chars.
  let timePart = "";
  let t = time;
  for (let i = 0; i < 10; i += 1) {
    timePart = CROCKFORD_ALPHABET[t % 32] + timePart;
    t = Math.floor(t / 32);
  }
  // 80 bits of randomness -> 16 Crockford chars (5 bits each).
  const randomBuf = randomBytes(10);
  let bits = 0n;
  for (const byte of randomBuf) {
    bits = (bits << 8n) | BigInt(byte);
  }
  let randomPart = "";
  for (let i = 0; i < 16; i += 1) {
    const shift = BigInt(5 * (15 - i));
    const idx = Number((bits >> shift) & 0x1fn);
    randomPart += CROCKFORD_ALPHABET[idx];
  }
  return timePart + randomPart;
}

/** Mints a new, opaque id of the given kind. */
export function mintId(kind: IdKind, now?: Date): string {
  return `${PREFIX_BY_KIND[kind]}_${generateUlid(now)}`;
}

/** `OsmRefId` — a reference into `data/osm/`, never inlined into a curated
 * record (§4.1: `seed: { origin, osmRef? }`, "→ data/osm/, never inlined").
 * Modelled as `<osm-element-kind>/<numeric-id>`, mirroring how OSM itself
 * names elements (`node`/`way`/`relation`), because AT(5)'s "way→relation
 * remap" fixture needs the element kind to be part of the ref's identity —
 * a remap is exactly this string changing while the matched facility/course
 * id does not. This shape is not stated verbatim in §4.1 (which only says
 * "OsmRefId"); it is the most literal reading of "→ data/osm/" plus OSM's
 * own id convention. */
export const OsmRefIdSchema = z
  .string()
  .regex(
    /^(node|way|relation)\/\d+$/,
    'must be "<node|way|relation>/<numeric id>"',
  )
  .brand("OsmRefId");
export type OsmRefId = z.infer<typeof OsmRefIdSchema>;
