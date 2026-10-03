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
export const SCHEMA_VERSION = 2;

/** A migration is SQL, or (when it must rewrite data, not only shape) a function run in the same transaction. `now` is the migration clock. */
type Migration = string | ((tx: SqlQueryable, now: () => number) => Promise<void>);

const MIGRATIONS: readonly Migration[] = [
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
  // v2 (P4.2b-0): every outbox row belongs to the user whose session created it.
  migrateOutboxToOwned,
];

/** v2. SQLite cannot add a NOT NULL column without a default, and a DEFAULT would let a buggy insert silently create an ownerless row, so the
 * table is rebuilt: `owner_user_id TEXT NOT NULL` with no default, `UNIQUE (owner_user_id, source_ref)` (the server's idempotency key is per
 * user: one player's `source_ref` must never collide with, or return, another's), and the selection index `(owner_user_id, status, next_attempt_at)`.
 *
 * LEGACY ROWS. Rows written before this version have no owner, and the owner of a queued play cannot be inferred, so they must never be sent
 * (B signing in on A's device would otherwise submit A's plays under B). FM-03 ("no item is dropped silently") rules out deleting them, so each
 * becomes a dead letter: owner `UNOWNED` (""; never a user id, so no session ever matches it), status `needs_attention`, reason `owner_unknown`,
 * `deadLetteredAt` = the migration time. The 90-day dead-letter expiry then applies to them like any other dead letter. Honest limits: no
 * account sees them (the Played list is filtered to the signed-in user), so "needs attention" is a record on the device, not a prompt to a
 * person; and no released build ever transmitted a play (the P4.2a client's `submitEvidence` never reaches the network), so these rows can only be
 * development data. */
async function migrateOutboxToOwned(tx: SqlQueryable, now: () => number): Promise<void> {
  await tx.exec(`
    CREATE TABLE outbox_v2 (
      id TEXT PRIMARY KEY NOT NULL,
      source_ref TEXT NOT NULL,
      owner_user_id TEXT NOT NULL,
      status TEXT NOT NULL,
      next_attempt_at INTEGER,
      created_at INTEGER NOT NULL,
      item_json TEXT NOT NULL,
      UNIQUE (owner_user_id, source_ref)
    );
  `);
  const legacy = await tx.all<{ id: string; source_ref: string; created_at: number; item_json: string }>(
    "SELECT id, source_ref, created_at, item_json FROM outbox ORDER BY created_at ASC, id ASC",
  );
  const at = now();
  for (const row of legacy) {
    const item = {
      ...(JSON.parse(row.item_json) as Record<string, unknown>),
      ownerUserId: "",
      status: "needs_attention",
      reason: "owner_unknown",
      rematch: false,
      nextAttemptAt: null,
      deadLetteredAt: at,
      updatedAt: at,
    };
    await tx.run("INSERT INTO outbox_v2 (id, source_ref, owner_user_id, status, next_attempt_at, created_at, item_json) VALUES (?, ?, ?, ?, ?, ?, ?)", [
      row.id,
      row.source_ref,
      "",
      "needs_attention",
      null,
      row.created_at,
      JSON.stringify(item),
    ]);
  }
  await tx.exec(`
    DROP TABLE outbox;
    ALTER TABLE outbox_v2 RENAME TO outbox;
    CREATE INDEX outbox_owner_status_idx ON outbox (owner_user_id, status, next_attempt_at);
  `);
}

export interface MigrateOptions {
  /** The migration clock (stamps `deadLetteredAt` on legacy outbox rows). */
  now?: () => number;
  /** Stop at this version instead of `SCHEMA_VERSION` (tests build an old database to exercise the upgrade). */
  upTo?: number;
}

/** Idempotent: brings the database to `SCHEMA_VERSION`. */
export async function migrate(db: SqlDatabase, opts: MigrateOptions = {}): Promise<void> {
  const now = opts.now ?? Date.now;
  const target = opts.upTo ?? SCHEMA_VERSION;
  const rows = await db.all<{ user_version: number }>("PRAGMA user_version");
  const current = rows[0]?.user_version ?? 0;
  if (current > SCHEMA_VERSION) {
    throw new Error(`database schema v${current} is newer than this build understands (v${SCHEMA_VERSION})`);
  }
  for (let v = current; v < target; v += 1) {
    const step = MIGRATIONS[v];
    if (!step) throw new Error(`missing migration for v${v + 1}`);
    await db.transaction(async (tx) => {
      if (typeof step === "string") await tx.exec(step);
      else await step(tx, now);
      await tx.exec(`PRAGMA user_version = ${v + 1}`);
    });
  }
}
