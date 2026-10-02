/**
 * Persistence for the last GOOD catalog (build plan §7.6: "catalog shards
 * … are cached in SQLite and refreshed through the signed manifest"). The
 * store holds the verified artifact as text exactly as fetched; `manager.ts`
 * re-verifies it on every load, so a cache that was tampered with at rest is
 * dropped rather than trusted (fail closed).
 *
 * Text round-trips byte-exactly because every stored document was strictly
 * UTF-8-decoded on the way in (`bytes.ts`), so `utf8Encode(text)` equals the
 * fetched bytes and the manifest's SHA-256s still match.
 */
import { compareCatalogVersions, parseCatalogVersion } from "@golfraven/catalog-tools/manifest-core";
import type { SqlDatabase } from "../db/sql";

/** The persisted anti-rollback high-water mark: the greatest `catalogVersion`
 * whose manifest this install has ever fully verified. It is meta, NOT part
 * of the cached catalog, so it outlives a dropped / corrupt / replaced cache
 * (a keyset change, a revocation, a failed re-verification). */
export const META_MAX_VERIFIED_VERSION = "maxVerifiedCatalogVersion";

/** The result of reading the stored floor: `none` (fresh install), a valid
 * version, or `corrupt` (present but not a `yyyymmdd-sha7` version). */
export type FloorRead = { kind: "none" } | { kind: "ok"; version: string } | { kind: "corrupt" };

export function readFloor(raw: string | null): FloorRead {
  if (raw === null) return { kind: "none" };
  return parseCatalogVersion(raw) ? { kind: "ok", version: raw } : { kind: "corrupt" };
}

/** Whether a catalog of `catalogVersion` may be written given the stored
 * floor: refused when below it, or when the floor row is corrupt (fail closed). */
function floorAllows(floor: FloorRead, catalogVersion: string): boolean {
  if (floor.kind === "corrupt") return false;
  return floor.kind === "none" || compareCatalogVersions(catalogVersion, floor.version) >= 0;
}

/** The higher of two catalog versions (the persisted floor only ever rises). */
export function maxCatalogVersion(a: string, b: string): string {
  return compareCatalogVersions(a, b) >= 0 ? a : b;
}

/** The next value of the floor row when a manifest at `version` has verified:
 * the higher of the two, as the `updateMeta` callback wants it (`undefined` =
 * leave the row unchanged). NEVER lowers the floor, and never heals a corrupt
 * row (that is the reset action's job, and only an explicit one). */
export function raisedFloor(current: string | null, version: string): string | undefined {
  const f = readFloor(current);
  if (f.kind === "corrupt") return undefined;
  if (f.kind === "ok" && compareCatalogVersions(f.version, version) >= 0) return undefined;
  return version;
}

/** Asserted by the store, atomically with the write: `catalogVersion` is the
 * version of the catalog being saved. */
export interface SaveGuard {
  catalogVersion: string;
}

export interface StoredCatalog {
  manifestText: string;
  manifestSigText: string;
  versionsText: string;
  versionsSigText: string;
  /** In manifest order; `path` is relative to `catalog/v1/`. */
  shards: { path: string; text: string }[];
  /** The manifest's ETag from the last successful fetch, if the server sent one. */
  etag: string | null;
  fetchedAt: string;
}

export interface CatalogCacheStore {
  loadCatalog(): Promise<StoredCatalog | null>;
  /** Atomically replaces the whole stored catalog: a reader sees the old
   * one or the new one, never a mixture.
   *
   * With a `guard`, the anti-rollback floor is re-checked INSIDE the same
   * atomic step: the save is refused (`false`, nothing written) when
   * `guard.catalogVersion` is below the persisted floor or the floor row is
   * corrupt; otherwise the floor is raised to it and the catalog is written
   * (`true`). A slow refresh that verified an older manifest therefore
   * cannot overwrite a newer catalog saved while it was in flight. */
  saveCatalog(catalog: StoredCatalog, guard?: SaveGuard): Promise<boolean>;
  /** Drops ONLY the cached catalog (its files and its `etag` / `fetchedAt`).
   * Every other meta row — the anti-rollback floor, the revoked set, a stored
   * update requirement — is untouched. */
  clearCatalog(): Promise<void>;
  readMeta(key: string): Promise<string | null>;
  writeMeta(key: string, value: string): Promise<void>;
  deleteMeta(key: string): Promise<void>;
  /** Atomic read-modify-write of one meta row: `fn` gets the current value
   * (or `null`) and returns the new one (`null` deletes, `undefined` leaves
   * it unchanged). Used for rows two overlapping writers must not clobber
   * (the revoked set, the version floor). Resolves to the resulting value. */
  updateMeta(key: string, fn: (current: string | null) => string | null | undefined): Promise<string | null>;
}

function clone<T>(v: T): T {
  return JSON.parse(JSON.stringify(v)) as T;
}

export class MemoryCatalogCacheStore implements CatalogCacheStore {
  private catalog: StoredCatalog | null = null;
  private readonly meta = new Map<string, string>();

  loadCatalog(): Promise<StoredCatalog | null> {
    return Promise.resolve(this.catalog ? clone(this.catalog) : null);
  }
  saveCatalog(catalog: StoredCatalog, guard?: SaveGuard): Promise<boolean> {
    if (guard) {
      const floor = readFloor(this.meta.get(META_MAX_VERIFIED_VERSION) ?? null);
      if (!floorAllows(floor, guard.catalogVersion)) return Promise.resolve(false);
      this.raiseFloor(floor, guard.catalogVersion);
    }
    this.catalog = clone(catalog);
    return Promise.resolve(true);
  }
  clearCatalog(): Promise<void> {
    this.catalog = null;
    return Promise.resolve();
  }
  private raiseFloor(floor: FloorRead, version: string): void {
    this.meta.set(META_MAX_VERIFIED_VERSION, floor.kind === "ok" ? maxCatalogVersion(floor.version, version) : version);
  }
  readMeta(key: string): Promise<string | null> {
    return Promise.resolve(this.meta.get(key) ?? null);
  }
  writeMeta(key: string, value: string): Promise<void> {
    this.meta.set(key, value);
    return Promise.resolve();
  }
  deleteMeta(key: string): Promise<void> {
    this.meta.delete(key);
    return Promise.resolve();
  }
  updateMeta(key: string, fn: (current: string | null) => string | null | undefined): Promise<string | null> {
    // Synchronous between the read and the write, so no other caller interleaves.
    const cur = this.meta.get(key) ?? null;
    const next = fn(cur);
    if (next === undefined) return Promise.resolve(cur);
    if (next === null) this.meta.delete(key);
    else this.meta.set(key, next);
    return Promise.resolve(next);
  }
}

const SHARD_PREFIX = "shard:";

export class SqliteCatalogCacheStore implements CatalogCacheStore {
  constructor(private readonly db: SqlDatabase) {}

  async loadCatalog(): Promise<StoredCatalog | null> {
    const rows = await this.db.all<{ name: string; body: string }>("SELECT name, body FROM catalog_files ORDER BY rowid");
    if (rows.length === 0) return null;
    const get = (name: string): string | undefined => rows.find((r) => r.name === name)?.body;
    const manifestText = get("manifest.json");
    const manifestSigText = get("manifest.sig.json");
    const versionsText = get("versions.json");
    const versionsSigText = get("versions.sig.json");
    if (manifestText === undefined || manifestSigText === undefined || versionsText === undefined || versionsSigText === undefined) {
      return null; // an incomplete write is never treated as a catalog
    }
    const meta = await this.db.all<{ key: string; value: string }>("SELECT key, value FROM catalog_meta WHERE key IN ('etag','fetchedAt')");
    const metaGet = (k: string): string | null => meta.find((m) => m.key === k)?.value ?? null;
    return {
      manifestText,
      manifestSigText,
      versionsText,
      versionsSigText,
      shards: rows.filter((r) => r.name.startsWith(SHARD_PREFIX)).map((r) => ({ path: r.name.slice(SHARD_PREFIX.length), text: r.body })),
      etag: metaGet("etag"),
      fetchedAt: metaGet("fetchedAt") ?? "",
    };
  }

  async saveCatalog(c: StoredCatalog, guard?: SaveGuard): Promise<boolean> {
    return this.db.transaction(async (tx) => {
      if (guard) {
        const rows = await tx.all<{ value: string }>("SELECT value FROM catalog_meta WHERE key = ?", [META_MAX_VERIFIED_VERSION]);
        const floor = readFloor(rows[0]?.value ?? null);
        if (!floorAllows(floor, guard.catalogVersion)) return false;
        const next = floor.kind === "ok" ? maxCatalogVersion(floor.version, guard.catalogVersion) : guard.catalogVersion;
        await tx.run("INSERT INTO catalog_meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", [META_MAX_VERIFIED_VERSION, next]);
      }
      await tx.run("DELETE FROM catalog_files");
      const put = (name: string, body: string): Promise<{ changes: number }> =>
        tx.run("INSERT INTO catalog_files (name, body) VALUES (?, ?)", [name, body]);
      await put("manifest.json", c.manifestText);
      await put("manifest.sig.json", c.manifestSigText);
      await put("versions.json", c.versionsText);
      await put("versions.sig.json", c.versionsSigText);
      for (const s of c.shards) await put(SHARD_PREFIX + s.path, s.text);
      const meta = (key: string, value: string | null): Promise<{ changes: number }> =>
        value === null
          ? tx.run("DELETE FROM catalog_meta WHERE key = ?", [key])
          : tx.run("INSERT INTO catalog_meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", [key, value]);
      await meta("etag", c.etag);
      await meta("fetchedAt", c.fetchedAt);
      return true;
    });
  }

  async clearCatalog(): Promise<void> {
    await this.db.transaction(async (tx) => {
      await tx.run("DELETE FROM catalog_files");
      await tx.run("DELETE FROM catalog_meta WHERE key IN ('etag', 'fetchedAt')");
    });
  }

  async readMeta(key: string): Promise<string | null> {
    const rows = await this.db.all<{ value: string }>("SELECT value FROM catalog_meta WHERE key = ?", [key]);
    return rows[0]?.value ?? null;
  }
  async writeMeta(key: string, value: string): Promise<void> {
    await this.db.run("INSERT INTO catalog_meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", [key, value]);
  }
  async deleteMeta(key: string): Promise<void> {
    await this.db.run("DELETE FROM catalog_meta WHERE key = ?", [key]);
  }
  async updateMeta(key: string, fn: (current: string | null) => string | null | undefined): Promise<string | null> {
    return this.db.transaction(async (tx) => {
      const rows = await tx.all<{ value: string }>("SELECT value FROM catalog_meta WHERE key = ?", [key]);
      const cur = rows[0]?.value ?? null;
      const next = fn(cur);
      if (next === undefined) return cur;
      if (next === null) await tx.run("DELETE FROM catalog_meta WHERE key = ?", [key]);
      else await tx.run("INSERT INTO catalog_meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", [key, next]);
      return next;
    });
  }
}
