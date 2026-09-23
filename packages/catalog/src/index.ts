import { z } from "zod";

/**
 * P0 placeholder.
 *
 * `@golfraven/catalog` is the catalog *shape* SSOT (build plan §3.1 row A):
 * a Zod schema that generates both `contract/catalog.schema.json` and the
 * TS types, plus `loadCatalog()` and the one enrichment function. It holds
 * no data itself (data lives in `data/`, build plan §3.1 row B).
 *
 * None of that exists yet. P1 defines the real schema (build plan §4.1) and
 * `verify-contract.mjs` (build plan §15) regenerates the committed JSON
 * Schema from it. This module only proves the package builds, typechecks
 * and can depend on zod, so the P1 work has a workspace to land in.
 */

/** Bumped on any breaking change to the catalog contract (semver MAJOR). */
export const CONTRACT_VERSION = 0;

/**
 * Placeholder schema so the zod dependency is exercised by a real check.
 * Replaced by the real catalog schema in P1 (build plan §4.1).
 */
export const PlaceholderCatalogSchema = z.object({
  contractVersion: z.literal(CONTRACT_VERSION),
});

export type PlaceholderCatalog = z.infer<typeof PlaceholderCatalogSchema>;
