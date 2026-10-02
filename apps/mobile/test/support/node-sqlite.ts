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

export async function openNodeSqlite(): Promise<SqlDatabase & { raw: DatabaseSync }> {
  const raw = new DatabaseSync(":memory:");
  const q = queryable(raw);
  const db = {
    ...q,
    raw,
    async transaction<T>(fn: (tx: SqlQueryable) => Promise<T>): Promise<T> {
      raw.exec("BEGIN IMMEDIATE");
      try {
        const out = await fn(q);
        raw.exec("COMMIT");
        return out;
      } catch (err) {
        raw.exec("ROLLBACK");
        throw err;
      }
    },
  };
  await migrate(db);
  return db;
}
