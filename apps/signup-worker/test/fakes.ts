/**
 * In-memory fakes for D1/KV, used instead of @cloudflare/vitest-pool-workers
 * (see README.md "Testing approach" for why: this repo pins narrow storage
 * interfaces — D1Like/KVLike in src/config.ts — specifically so a plain
 * object can stand in for the real binding in tests).
 *
 * FakeD1 is tailored to the exact, small set of prepared statements
 * src/db.ts and src/index.ts issue (dispatched below via `sql.includes(...)`)
 * — it is not a general SQL engine.
 */

import type { D1Like, D1PreparedLike, KVLike } from "../src/config";
import type { SignupRow } from "../src/db";

function makePrepared(sql: string, rows: SignupRow[]): D1PreparedLike {
  let bound: unknown[] = [];

  async function run(): Promise<unknown> {
    if (sql.startsWith("INSERT INTO signups")) {
      const [id, emailLc, consentVersion, source, createdAt, confirmTokenHash, confirmExpiresAt, unsubscribeTokenHash] =
        bound as [string, string, string, string | null, string, string, string, string];
      // Mirrors the real `ON CONFLICT(email_lc) DO NOTHING` (gate finding
      // F3): a concurrent insert for an already-present email_lc is a
      // silent no-op with meta.changes: 0, not a thrown error.
      if (rows.some((r) => r.email_lc === emailLc)) {
        return { success: true, meta: { changes: 0 } };
      }
      rows.push({
        id,
        email_lc: emailLc,
        consent_version: consentVersion,
        age_confirmed: 1,
        source,
        created_at: createdAt,
        confirmed_at: null,
        unsubscribed_at: null,
        confirm_token_hash: confirmTokenHash,
        confirm_expires_at: confirmExpiresAt,
        unsubscribe_token_hash: unsubscribeTokenHash,
      });
      return { success: true, meta: { changes: 1 } };
    }
    if (sql.includes("SET consent_version = ?2")) {
      const [id, consentVersion, source, confirmTokenHash, confirmExpiresAt] = bound as [
        string,
        string,
        string | null,
        string,
        string,
      ];
      const row = rows.find((r) => r.id === id);
      if (row) {
        row.consent_version = consentVersion;
        row.source = source;
        row.confirm_token_hash = confirmTokenHash;
        row.confirm_expires_at = confirmExpiresAt;
      }
      return { success: true, meta: { changes: row ? 1 : 0 } };
    }
    if (sql.includes("SET confirmed_at = COALESCE(confirmed_at, ?2)")) {
      const [id, confirmedAt] = bound as [string, string];
      const row = rows.find((r) => r.id === id);
      if (row) {
        row.confirmed_at = row.confirmed_at ?? confirmedAt;
        row.unsubscribed_at = null;
        // Gate finding F4: single-use — clear the confirm token on success.
        row.confirm_token_hash = null;
        row.confirm_expires_at = null;
      }
      return { success: true, meta: { changes: row ? 1 : 0 } };
    }
    if (sql.includes("SET unsubscribed_at = ?2")) {
      const [id, unsubscribedAt] = bound as [string, string];
      const row = rows.find((r) => r.id === id);
      if (row) row.unsubscribed_at = unsubscribedAt;
      return { success: true, meta: { changes: row ? 1 : 0 } };
    }
    if (sql.includes("SET unsubscribe_token_hash = ?2")) {
      const [id, hash] = bound as [string, string];
      const row = rows.find((r) => r.id === id);
      if (row) row.unsubscribe_token_hash = hash;
      return { success: true, meta: { changes: row ? 1 : 0 } };
    }
    if (sql.startsWith("DELETE FROM signups") && sql.includes("confirmed_at IS NULL")) {
      const [createdBefore, now] = bound as [string, string];
      const before = rows.length;
      const kept = rows.filter(
        (r) =>
          !(
            r.confirmed_at === null &&
            r.created_at < createdBefore &&
            (r.confirm_expires_at === null || r.confirm_expires_at < now)
          ),
      );
      const deleted = before - kept.length;
      rows.length = 0;
      rows.push(...kept);
      return { success: true, meta: { changes: deleted } };
    }
    if (sql.startsWith("DELETE FROM signups") && sql.includes("unsubscribed_at IS NOT NULL")) {
      const [unsubscribedBefore] = bound as [string];
      const before = rows.length;
      const kept = rows.filter((r) => !(r.unsubscribed_at !== null && r.unsubscribed_at < unsubscribedBefore));
      const deleted = before - kept.length;
      rows.length = 0;
      rows.push(...kept);
      return { success: true, meta: { changes: deleted } };
    }
    throw new Error(`FakeD1: no run() handler for query: ${sql}`);
  }

  async function first<T>(): Promise<T | null> {
    if (sql.includes("WHERE email_lc = ?1")) {
      return (rows.find((r) => r.email_lc === bound[0]) as unknown as T) ?? null;
    }
    if (sql.includes("WHERE confirm_token_hash = ?1")) {
      return (rows.find((r) => r.confirm_token_hash === bound[0]) as unknown as T) ?? null;
    }
    if (sql.includes("WHERE unsubscribe_token_hash = ?1")) {
      return (rows.find((r) => r.unsubscribe_token_hash === bound[0]) as unknown as T) ?? null;
    }
    throw new Error(`FakeD1: no first() handler for query: ${sql}`);
  }

  async function all<T>(): Promise<{ results: T[] }> {
    return { results: rows as unknown as T[] };
  }

  const prepared: D1PreparedLike = {
    bind(...values: unknown[]): D1PreparedLike {
      bound = values;
      return prepared;
    },
    run,
    first,
    all,
  };
  return prepared;
}

export class FakeD1 implements D1Like {
  rows: SignupRow[] = [];

  prepare(sql: string): D1PreparedLike {
    return makePrepared(sql, this.rows);
  }
}

export class FakeKV implements KVLike {
  store = new Map<string, string>();

  async get(key: string): Promise<string | null> {
    return this.store.get(key) ?? null;
  }

  async put(key: string, value: string): Promise<void> {
    this.store.set(key, value);
  }

  /**
   * Not part of KVLike (the real Worker never needs to delete a rate-limit
   * key — TTL handles that) — a test-only convenience so a test can
   * simulate a KV TTL expiring without this fake having to implement real
   * TTL semantics.
   */
  delete(key: string): void {
    this.store.delete(key);
  }
}
