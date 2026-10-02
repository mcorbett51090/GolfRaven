/**
 * The smallest SQL surface the app's persistence needs, so every store
 * (catalog cache, outbox, device flags) is written once against this
 * interface and runs on `expo-sqlite` in the app (`expo-sqlite-adapter.ts`)
 * and on Node's built-in `node:sqlite` in the tests — i.e. the SQL itself,
 * not just an in-memory stand-in, is exercised by `pnpm test`.
 */
export type SqlValue = string | number | null;

export interface SqlQueryable {
  /** One or more statements, no parameters (DDL, PRAGMA). */
  exec(sql: string): Promise<void>;
  run(sql: string, params?: readonly SqlValue[]): Promise<{ changes: number }>;
  all<T = Record<string, SqlValue>>(sql: string, params?: readonly SqlValue[]): Promise<T[]>;
}

export interface SqlDatabase extends SqlQueryable {
  /** Runs `fn` in one exclusive transaction: commit if it resolves, roll back
   * if it throws (the error is re-thrown). */
  transaction<T>(fn: (tx: SqlQueryable) => Promise<T>): Promise<T>;
}

/** Bump with a new entry in `MIGRATIONS` below; never edit a shipped one. */
export const SCHEMA_VERSION = 1;

const MIGRATIONS: readonly string[] = [
  // v1
  `
  CREATE TABLE catalog_files (
    name TEXT PRIMARY KEY NOT NULL,
    body TEXT NOT NULL
  );
  CREATE TABLE catalog_meta (
    key TEXT PRIMARY KEY NOT NULL,
    value TEXT NOT NULL
  );
  CREATE TABLE outbox (
    id TEXT PRIMARY KEY NOT NULL,
    source_ref TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL,
    next_attempt_at INTEGER,
    created_at INTEGER NOT NULL,
    item_json TEXT NOT NULL
  );
  CREATE INDEX outbox_status_idx ON outbox (status, next_attempt_at);
  CREATE TABLE device_flags (
    key TEXT PRIMARY KEY NOT NULL,
    value TEXT NOT NULL
  );
  `,
];

/** Idempotent: brings the database to `SCHEMA_VERSION`. */
export async function migrate(db: SqlDatabase): Promise<void> {
  const rows = await db.all<{ user_version: number }>("PRAGMA user_version");
  const current = rows[0]?.user_version ?? 0;
  if (current > SCHEMA_VERSION) {
    throw new Error(`database schema v${current} is newer than this build understands (v${SCHEMA_VERSION})`);
  }
  for (let v = current; v < SCHEMA_VERSION; v += 1) {
    const sql = MIGRATIONS[v];
    if (!sql) throw new Error(`missing migration for v${v + 1}`);
    await db.transaction(async (tx) => {
      await tx.exec(sql);
      await tx.exec(`PRAGMA user_version = ${v + 1}`);
    });
  }
}
