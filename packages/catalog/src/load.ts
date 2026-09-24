/**
 * `loadCatalog()` — the ONE catalog loader every consumer (the site,
 * scripts, the app, the `import-catalog` Edge Function) is meant to share
 * (§3.1 row A: "Single source of truth for… `loadCatalog()`, the one
 * enrichment function"; §5.1: SWC's `src/lib/geo.ts` is rewritten into
 * `packages/catalog/src/load.ts` plus `apps/site/src/lib/derive.ts`).
 *
 * Two input shapes, same output (`Catalog`):
 *
 *  (a) **A `data/` directory tree** (`loadCatalogFromDataDir` /
 *      `loadCatalog({ dataDir })`) — `regions/*.json`, `facilities/*.json`,
 *      `trails/*.json`, `designers.json`, `achievements/*.json`,
 *      `id-ledger.json`, matching what this repo's `data/` already commits
 *      today (`data/achievements/*.json`, `data/id-ledger.json` —
 *      `data/README.md`). A missing subdirectory or file reads as empty,
 *      because P1a's `data/` "carries no real facility/trail content yet"
 *      (`data/README.md`) — stage 1 (this package + `apps/site`) must not
 *      fail just because the real catalog hasn't been authored.
 *
 *  (b) **An in-memory bundle** (`loadCatalog({ bundle })`) — e.g. a
 *      synthetic demo dataset assembled at build time
 *      (`apps/site/fixtures/demo-catalog`), or a fixture in a test. No
 *      filesystem access at all on this path. `bundle` is `unknown` and
 *      validated the same way the directory path validates each file, so a
 *      malformed fixture fails loud with a normal Zod error rather than
 *      silently producing a half-built catalog.
 *
 * No network fetch either way (packages/catalog "Never does: Hold data or
 * fetch", §3.1 row A) — every read here is local disk or an
 * already-in-memory object.
 */
import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import {
  DesignerSchema,
  FacilitySchema,
  RegionSchema,
  TrailSchema,
  type Designer,
  type Facility,
  type Region,
  type Trail,
} from "./schema.js";
import { AchievementDefSchema, type AchievementDef } from "./rule-expr.js";
import { IdLedgerSchema, emptyLedger, type IdLedger } from "./ledger.js";

/** The loaded, validated catalog — one shape whichever input path produced
 * it. Every array defaults to empty rather than being optional, so callers
 * never have to null-check before iterating (`data/` with nothing authored
 * yet and an empty bundle both produce the same shape). */
export interface Catalog {
  regions: Region[];
  facilities: Facility[];
  trails: Trail[];
  designers: Designer[];
  achievements: AchievementDef[];
  idLedger: IdLedger;
}

/** The bundle shape accepted by `loadCatalog({ bundle })` and validated by
 * `CatalogBundleSchema` below. Deliberately smaller than `tools/catalog`'s
 * `CatalogBundle` (no `contractVersion`, `offerTerms` or `osm`): this
 * package's `loadCatalog()` only ever needs to produce the fields the site
 * (and the other stage-1 consumers named above) reads, and `verify-catalog`
 * remains the one place that owns the full gate-relevant bundle shape.
 */
export const CatalogBundleSchema = z.strictObject({
  regions: z.array(RegionSchema).optional(),
  facilities: z.array(FacilitySchema).optional(),
  trails: z.array(TrailSchema).optional(),
  designers: z.array(DesignerSchema).optional(),
  achievements: z.array(AchievementDefSchema).optional(),
  idLedger: IdLedgerSchema.optional(),
});
export type CatalogBundleInput = z.infer<typeof CatalogBundleSchema>;

export interface LoadCatalogFromDirOptions {
  /** Path to a `data/`-shaped directory (this repo's own `data/`, a demo
   * fixture directory, or a test fixture). */
  dataDir: string;
}
export interface LoadCatalogFromBundleOptions {
  /** A single in-memory (or already-`JSON.parse`d) bundle — see
   * `CatalogBundleSchema`. Validated the same as a directory read; throws a
   * `ZodError` on a malformed bundle rather than producing a partial
   * catalog. */
  bundle: unknown;
}
export type LoadCatalogOptions =
  | LoadCatalogFromDirOptions
  | LoadCatalogFromBundleOptions;

function isEnoent(err: unknown): boolean {
  return (
    typeof err === "object" &&
    err !== null &&
    "code" in err &&
    (err as { code?: unknown }).code === "ENOENT"
  );
}

/** Reads every `*.json` file directly inside `dir` (sorted by filename, for
 * a deterministic order) and parses each through `schema`. A missing `dir`
 * reads as `[]` — see this module's doc on why that must not throw. */
async function readEntityDir<T>(
  dir: string,
  schema: z.ZodType<T>,
): Promise<T[]> {
  let entries: string[];
  try {
    entries = await readdir(dir);
  } catch (err) {
    if (isEnoent(err)) return [];
    throw err;
  }
  const files = entries.filter((f) => f.endsWith(".json")).sort();
  const out: T[] = [];
  for (const file of files) {
    const raw = JSON.parse(await readFile(join(dir, file), "utf8"));
    out.push(schema.parse(raw));
  }
  return out;
}

/** Reads one JSON file and parses it through `schema`, or returns
 * `fallback` if the file does not exist. */
async function readJsonFileOptional<T>(
  path: string,
  schema: z.ZodType<T>,
  fallback: T,
): Promise<T> {
  let raw: string;
  try {
    raw = await readFile(path, "utf8");
  } catch (err) {
    if (isEnoent(err)) return fallback;
    throw err;
  }
  return schema.parse(JSON.parse(raw));
}

/** Loads a `Catalog` from a `data/`-shaped directory. See this module's
 * doc, path (a). */
export async function loadCatalogFromDataDir(dataDir: string): Promise<Catalog> {
  const [regions, facilities, trails, designers, achievements, idLedger] =
    await Promise.all([
      readEntityDir(join(dataDir, "regions"), RegionSchema),
      readEntityDir(join(dataDir, "facilities"), FacilitySchema),
      readEntityDir(join(dataDir, "trails"), TrailSchema),
      readJsonFileOptional(
        join(dataDir, "designers.json"),
        z.array(DesignerSchema),
        [],
      ),
      readEntityDir(join(dataDir, "achievements"), AchievementDefSchema),
      readJsonFileOptional(
        join(dataDir, "id-ledger.json"),
        IdLedgerSchema,
        emptyLedger(),
      ),
    ]);
  return { regions, facilities, trails, designers, achievements, idLedger };
}

/** Loads a `Catalog` from an in-memory bundle. See this module's doc, path
 * (b). */
export function loadCatalogFromBundle(bundle: unknown): Catalog {
  const parsed = CatalogBundleSchema.parse(bundle);
  return {
    regions: parsed.regions ?? [],
    facilities: parsed.facilities ?? [],
    trails: parsed.trails ?? [],
    designers: parsed.designers ?? [],
    achievements: parsed.achievements ?? [],
    idLedger: parsed.idLedger ?? emptyLedger(),
  };
}

/** The one entry point (§3.1 row A). Dispatches on which option was given —
 * see `LoadCatalogOptions`. */
export async function loadCatalog(options: LoadCatalogOptions): Promise<Catalog> {
  if ("bundle" in options) {
    return loadCatalogFromBundle(options.bundle);
  }
  return loadCatalogFromDataDir(options.dataDir);
}

/** True when the catalog carries no real content (no facilities and no
 * trails) — the "`data/` is empty today" case `apps/site`'s build uses to
 * decide whether it may fall back to the synthetic demo dataset. Achievement
 * defs and designers alone don't count as "real content": this repo's own
 * `data/` already ships `data/achievements/*.json` with zero facilities or
 * trails (`data/README.md`), and that must still read as empty. */
export function isCatalogEmpty(catalog: Catalog): boolean {
  return catalog.facilities.length === 0 && catalog.trails.length === 0;
}
