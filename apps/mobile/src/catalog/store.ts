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
import type { SqlDatabase } from "../db/sql";

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
   * one or the new one, never a mixture. */
  saveCatalog(catalog: StoredCatalog): Promise<void>;
  readMeta(key: string): Promise<string | null>;
  writeMeta(key: string, value: string): Promise<void>;
  deleteMeta(key: string): Promise<void>;
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
  saveCatalog(catalog: StoredCatalog): Promise<void> {
    this.catalog = clone(catalog);
    return Promise.resolve();
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

  async saveCatalog(c: StoredCatalog): Promise<void> {
    await this.db.transaction(async (tx) => {
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
}
