import { describe, expect, it } from "vitest";
import { SCHEMA_VERSION, migrate } from "../src/db/sql";
import { SqliteCatalogCacheStore } from "../src/catalog/store";
import { SqliteOutboxStore, createItem } from "../src/outbox";
import { openNodeSqlite } from "./support/node-sqlite";

describe("SQLite schema", () => {
  it("migrate is idempotent and leaves user_version at SCHEMA_VERSION", async () => {
    const db = await openNodeSqlite(); // already migrated once
    await migrate(db);
    await migrate(db);
    expect((await db.all<{ user_version: number }>("PRAGMA user_version"))[0]?.user_version).toBe(SCHEMA_VERSION);
    const tables = (await db.all<{ name: string }>("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")).map((t) => t.name);
    expect(tables).toEqual(["catalog_files", "catalog_meta", "device_flags", "outbox"]);
  });

  it("refuses a database written by a newer build (never downgrades silently)", async () => {
    const db = await openNodeSqlite();
    await db.exec(`PRAGMA user_version = ${SCHEMA_VERSION + 1}`);
    await expect(migrate(db)).rejects.toThrow(/newer than this build/);
  });

  it("a failed transaction rolls back completely", async () => {
    const db = await openNodeSqlite();
    await expect(
      db.transaction(async (tx) => {
        await tx.run("INSERT INTO device_flags (key, value) VALUES ('a', '1')");
        throw new Error("boom");
      }),
    ).rejects.toThrow("boom");
    expect(await db.all("SELECT * FROM device_flags")).toEqual([]);
  });
});

describe("persistence survives a restart (new store objects over the same database)", () => {
  it("outbox items, in event-time order", async () => {
    const db = await openNodeSqlite();
    const first = new SqliteOutboxStore(db);
    await first.insertIfAbsent(createItem({ id: "b", sourceRef: "r:b", courseId: "crs_1", catalogVersion: "v1", payload: { n: 2 } }, 2_000));
    await first.insertIfAbsent(createItem({ id: "a", sourceRef: "r:a", courseId: null, catalogVersion: null, payload: { n: 1 } }, 1_000));
    const second = new SqliteOutboxStore(db);
    expect((await second.list()).map((i) => i.id)).toEqual(["a", "b"]);
    expect((await second.get("a"))?.courseId).toBeNull();
  });

  it("a catalog save is atomic: a failure midway leaves the previous catalog intact", async () => {
    const db = await openNodeSqlite();
    const store = new SqliteCatalogCacheStore(db);
    const good = { manifestText: "m1", manifestSigText: "s1", versionsText: "v1", versionsSigText: "vs1", shards: [{ path: "trails.json", text: "[]" }], etag: '"e1"', fetchedAt: "2026-01-01T00:00:00.000Z" };
    await store.saveCatalog(good);
    // a duplicate shard path violates the PRIMARY KEY partway through the write
    await expect(store.saveCatalog({ ...good, manifestText: "m2", shards: [{ path: "a.json", text: "1" }, { path: "a.json", text: "2" }] })).rejects.toThrow();
    expect(await store.loadCatalog()).toEqual(good);
  });

  it("an incomplete stored catalog (a root document missing) is not treated as a catalog", async () => {
    const db = await openNodeSqlite();
    await db.run("INSERT INTO catalog_files (name, body) VALUES ('manifest.json', '{}')");
    expect(await new SqliteCatalogCacheStore(db).loadCatalog()).toBeNull();
  });
});
