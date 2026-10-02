/**
 * `SqlDatabase` over `expo-sqlite` (57.0.3). Imported only by the app
 * composition root (`src/runtime/services.ts`); tests use `test/support/node-sqlite.ts`
 * instead. Type-checked against the package's real `.d.ts`, but NOT run on a
 * device or simulator in this environment `[unverified — device behaviour]`.
 */
import * as SQLite from "expo-sqlite";
import { migrate, type SqlDatabase, type SqlQueryable, type SqlValue } from "./sql";

type Queryable = Pick<SQLite.SQLiteDatabase, "execAsync" | "runAsync" | "getAllAsync">;

function wrap(q: Queryable): SqlQueryable {
  return {
    exec: (sql) => q.execAsync(sql),
    run: async (sql, params) => {
      const r = await q.runAsync(sql, (params ?? []) as SqlValue[]);
      return { changes: r.changes };
    },
    all: <T>(sql: string, params?: readonly SqlValue[]) => q.getAllAsync<T>(sql, (params ?? []) as SqlValue[]),
  };
}

export async function openAppDatabase(name = "golfraven.db"): Promise<SqlDatabase> {
  const native = await SQLite.openDatabaseAsync(name);
  await native.execAsync("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;");
  const db: SqlDatabase = {
    ...wrap(native),
    async transaction<T>(fn: (tx: SqlQueryable) => Promise<T>): Promise<T> {
      let result: T | undefined;
      await native.withExclusiveTransactionAsync(async (txn) => {
        result = await fn(wrap(txn));
      });
      return result as T;
    },
  };
  await migrate(db);
  return db;
}
