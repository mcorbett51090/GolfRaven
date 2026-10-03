/**
 * `SqlDatabase` over Node's built-in `node:sqlite` (stable in the Node 24
 * this repo targets; experimental-but-present on 22.13+), so the stores'
 * real SQL runs under `pnpm test`.
 */
import { DatabaseSync } from "node:sqlite";
import { migrate, type SqlDatabase, type SqlQueryable, type SqlValue } from "../../src/db/sql";

function queryable(db: DatabaseSync): SqlQueryable {
  return {
    exec: (sql) => {
      db.exec(sql);
      return Promise.resolve();
    },
    run: (sql, params) => {
      const r = db.prepare(sql).run(...((params ?? []) as SqlValue[]));
      return Promise.resolve({ changes: Number(r.changes) });
    },
    all: <T>(sql: string, params?: readonly SqlValue[]) =>
      Promise.resolve(db.prepare(sql).all(...((params ?? []) as SqlValue[])) as unknown as T[]),
  };
}

/** `upTo`: stop migrating at that schema version (to build an OLD database for the upgrade tests). */
export async function openNodeSqlite(upTo?: number, now?: () => number): Promise<SqlDatabase & { raw: DatabaseSync }> {
  const raw = new DatabaseSync(":memory:");
  const q = queryable(raw);
  // One connection: overlapping `transaction()` calls must queue (expo-sqlite's
  // `withExclusiveTransactionAsync` does the same), not hit a nested BEGIN.
  let queue: Promise<unknown> = Promise.resolve();
  const db = {
    ...q,
    raw,
    transaction<T>(fn: (tx: SqlQueryable) => Promise<T>): Promise<T> {
      const run = queue.then(async () => {
        raw.exec("BEGIN IMMEDIATE");
        try {
          const out = await fn(q);
          raw.exec("COMMIT");
          return out;
        } catch (err) {
          raw.exec("ROLLBACK");
          throw err;
        }
      });
      queue = run.catch(() => undefined);
      return run;
    },
  };
  await migrate(db, { ...(upTo === undefined ? {} : { upTo }), ...(now ? { now } : {}) });
  return db;
}
