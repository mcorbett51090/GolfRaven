/**
 * `@golfraven/catalog` — the catalog *shape* SSOT (build plan §3.1 row A):
 * the §4.1 Zod schema, generating both `contract/catalog.schema.json`
 * (via `tools/catalog`'s `verify-contract`, §3.5) and the TS types below,
 * plus the ID ledger (§3.5, §4.2, §4.3). It holds no data itself (data
 * lives in `data/`, §3.1 row B) and does no network fetch.
 *
 * P1a scope (this package): the full §4.1 schema except `AchievementDef`
 * and `OfferTerms` (part B, `packages/rules`'s `RuleExpr` — see
 * `schema.ts`'s module doc), plus the ID ledger and slug rule. `loadCatalog()`
 * and the directory-base-layer loader are not implemented here — see the
 * P1a report for why.
 */
import { z } from "zod";

/** Bumped on any breaking change to the catalog contract (semver MAJOR).
 * Stays 0 through P1a — the contract freeze (`contractVersion 1`) is a
 * later, owner-visible step (build plan §10 P1 "M-freeze"). */
export const CONTRACT_VERSION = 0;

export * from "./ids.js";
export * from "./common.js";
export * from "./geo.js";
export * from "./name-similarity.js";
export * from "./schema.js";
export * from "./ledger.js";

/** Retained from the P0 placeholder only so `CONTRACT_VERSION` stays
 * exercised by a real Zod parse in this package's own tests, independent
 * of the (much larger) §4.1 schema. Not used by anything else. */
export const ContractVersionSchema = z.object({
  contractVersion: z.literal(CONTRACT_VERSION),
});
