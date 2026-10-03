import type { SqlDatabase } from "../db/sql";

/** Tiny device-local key/value store (SQLite `device_flags`). Not for anything sensitive: the O18 under-age flag moved to the
 * secure store (`secure-flags.ts`); what stays here (e.g. the language choice) is a preference. */
export interface DeviceFlagStore {
  get(key: string): Promise<string | null>;
  set(key: string, value: string): Promise<void>;
  delete(key: string): Promise<void>;
}

export class MemoryDeviceFlagStore implements DeviceFlagStore {
  private readonly m = new Map<string, string>();
  get(key: string): Promise<string | null> {
    return Promise.resolve(this.m.get(key) ?? null);
  }
  set(key: string, value: string): Promise<void> {
    this.m.set(key, value);
    return Promise.resolve();
  }
  delete(key: string): Promise<void> {
    this.m.delete(key);
    return Promise.resolve();
  }
}

export class SqliteDeviceFlagStore implements DeviceFlagStore {
  constructor(private readonly db: SqlDatabase) {}
  async get(key: string): Promise<string | null> {
    const rows = await this.db.all<{ value: string }>("SELECT value FROM device_flags WHERE key = ?", [key]);
    return rows[0]?.value ?? null;
  }
  async set(key: string, value: string): Promise<void> {
    await this.db.run("INSERT INTO device_flags (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", [key, value]);
  }
  async delete(key: string): Promise<void> {
    await this.db.run("DELETE FROM device_flags WHERE key = ?", [key]);
  }
}
