/**
 * The read model the screens use, built from a VERIFIED catalog's shards.
 * Types come from `@golfraven/catalog` via `import type` only: that
 * package's runtime entry imports `node:crypto`/`node:fs` (ids.ts, load.ts)
 * and so cannot be bundled by Metro today (SPIKE.md, "finding F2"). Shard
 * contents were already authenticated by SHA-256 against the signed
 * manifest, so the guards below only catch a publisher bug, not an attack.
 */
import type { Facility, Trail } from "@golfraven/catalog";

export interface CatalogSnapshot {
  catalogVersion: string;
  /** ISO timestamp from the signed manifest. */
  generatedAt: string;
  trails: Trail[];
  facilities: Facility[];
}

export class SnapshotParseError extends Error {}

function parseJson(text: string, label: string): unknown {
  try {
    return JSON.parse(text);
  } catch (err) {
    throw new SnapshotParseError(`${label}: ${err instanceof Error ? err.message : String(err)}`);
  }
}

function asArray(v: unknown, label: string): unknown[] {
  if (!Array.isArray(v)) throw new SnapshotParseError(`${label}: not an array`);
  return v;
}

function hasIdPrefix(v: unknown, prefix: string): v is Record<string, unknown> & { id: string } {
  return typeof v === "object" && v !== null && typeof (v as { id?: unknown }).id === "string" && (v as { id: string }).id.startsWith(prefix);
}

export function parseTrailsShard(text: string): Trail[] {
  const arr = asArray(parseJson(text, "trails.json"), "trails.json");
  return arr.map((t, i) => {
    const o = t as Record<string, unknown>;
    if (!hasIdPrefix(t, "trl_") || typeof o["name"] !== "string" || !Array.isArray(o["rosterVersions"]) || !Array.isArray(o["regions"])) {
      throw new SnapshotParseError(`trails.json[${i}]: not a Trail`);
    }
    return t as unknown as Trail;
  });
}

export function parseFacilitiesShard(text: string, path: string): Facility[] {
  const arr = asArray(parseJson(text, path), path);
  return arr.map((f, i) => {
    const o = f as Record<string, unknown>;
    if (!hasIdPrefix(f, "fac_") || typeof o["region"] !== "string" || !Array.isArray(o["courses"])) {
      throw new SnapshotParseError(`${path}[${i}]: not a Facility`);
    }
    return f as unknown as Facility;
  });
}

const FACILITY_SHARD_RE = /^facilities\/[a-z0-9-]+\.json$/;

export function buildSnapshot(args: {
  catalogVersion: string;
  generatedAt: string;
  shards: readonly { path: string; text: string }[];
}): CatalogSnapshot {
  let trails: Trail[] = [];
  const facilities: Facility[] = [];
  for (const s of args.shards) {
    if (s.path === "trails.json") trails = parseTrailsShard(s.text);
    else if (FACILITY_SHARD_RE.test(s.path)) facilities.push(...parseFacilitiesShard(s.text, s.path));
  }
  return { catalogVersion: args.catalogVersion, generatedAt: args.generatedAt, trails, facilities };
}
