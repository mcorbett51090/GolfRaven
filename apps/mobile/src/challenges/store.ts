/**
 * Prefetched check-in challenges, persisted per OWNER (the Supabase user) and per DEVICE id (build plan §7.6 "Offline attestation", FM-10).
 *
 * Rules the stores enforce (each has a test, `test/challenges.test.ts`):
 *  - OWNER ISOLATION: every operation takes the owner; a challenge is selected only for the user it was issued to (a challenge is bound to that
 *    user's session at the server too), never for another. The ownerless sentinel (`""`) is nobody: nothing is stored or selected for it.
 *  - DEVICE: only challenges issued for this install's device id are selected (a restored backup carries rows from another device).
 *  - SINGLE USE, ATOMICALLY: `consumeOne` selects a challenge and marks it consumed in ONE transaction (a conditional UPDATE that must change
 *    exactly one row). A consumed row is never selected again, never un-consumed, and never overwritten by a later insert of the same id; it is
 *    consumed BEFORE it is used anywhere, so a send that then fails can never reuse it.
 *  - EXPIRY: an expired challenge is never selected (`expires_at` must be after BOTH the capture time and `now`, with `MIN_REMAINING_MS` to spare);
 *    `purgeExpired` deletes expired rows.
 *  - DORMANT ON SIGN-OUT, like outbox items: nothing here is touched by a sign-out. Account deletion removes the deleted user's rows
 *    (`deleteOwner`); a sign-out/sign-in of another user never reads them.
 *  - CAP: at most `MAX_PREFETCHED` usable challenges per (owner, device); the manager requests only the shortfall and the store refuses to hold more.
 */
import type { SqlDatabase } from "../db/sql";

/** Build plan §4.4 / §4.7.8: "up to 10 prefetched per player device". The server enforces the same cap (`challenge-handler.ts`). */
export const MAX_PREFETCHED = 10;
/** A challenge with less than this left at check-in is not worth consuming: it will almost surely expire before the device reconnects. */
export const MIN_REMAINING_MS = 60_000;
export const UNOWNED_CHALLENGE_OWNER = "";

export interface IssuedChallengeInput {
  id: string;
  nonce: string;
  kind: "live" | "prefetched";
  facilityId: string | null;
  /** Epoch ms. */
  expiresAt: number;
}

export interface StoredChallenge extends IssuedChallengeInput {
  ownerUserId: string;
  deviceId: string;
  /** When the device received it (a lower bound for the server's `issued_at`): a fix captured earlier is never matched to it. */
  issuedAt: number;
  consumedAt: number | null;
}

export interface ChallengeStore {
  /** Stores challenges issued to `ownerUserId` for `deviceId`. Duplicate ids (same owner) are ignored, so a consumed row is never resurrected.
   * At most `MAX_PREFETCHED - usable` are stored; returns how many were. Throws for the ownerless sentinel. */
  insertMany(ownerUserId: string, deviceId: string, items: readonly IssuedChallengeInput[], now: number): Promise<number>;
  /** Unconsumed and not expired at `now`, for this owner and device. */
  countUsable(ownerUserId: string, deviceId: string, now: number): Promise<number>;
  /** Atomically takes one usable challenge for a check-in captured at `capturedAt` and marks it consumed; `null` when none qualifies.
   * Prefers the challenge with the LATEST expiry (the longest window to get back online before it ends). */
  consumeOne(ownerUserId: string, deviceId: string, capturedAt: number, now: number): Promise<StoredChallenge | null>;
  /** Deletes every expired row (consumed or not), of every owner (it deletes nothing that could still be used). */
  purgeExpired(now: number): Promise<number>;
  /** Every row of one owner, consumed or not (diagnostics and tests). */
  listByOwner(ownerUserId: string): Promise<StoredChallenge[]>;
  /** Account deletion: the deleted user's rows. */
  deleteOwner(ownerUserId: string): Promise<void>;
  /** Wipes everything (tests; not used by the app). */
  deleteAll(): Promise<void>;
}

function qualifies(c: StoredChallenge, owner: string, device: string, capturedAt: number, now: number): boolean {
  return (
    c.ownerUserId === owner &&
    c.deviceId === device &&
    c.consumedAt === null &&
    c.issuedAt <= capturedAt &&
    c.expiresAt - MIN_REMAINING_MS >= capturedAt &&
    c.expiresAt - MIN_REMAINING_MS >= now
  );
}

function assertOwner(owner: string): void {
  if (typeof owner !== "string" || owner === UNOWNED_CHALLENGE_OWNER) throw new Error("challenges: an owner (the signed-in user) is required");
}

function better(a: StoredChallenge, b: StoredChallenge): boolean {
  return a.expiresAt > b.expiresAt || (a.expiresAt === b.expiresAt && a.id < b.id);
}

export class MemoryChallengeStore implements ChallengeStore {
  private rows: StoredChallenge[] = [];

  insertMany(owner: string, deviceId: string, items: readonly IssuedChallengeInput[], now: number): Promise<number> {
    try {
      assertOwner(owner);
    } catch (e) {
      return Promise.reject(e instanceof Error ? e : new Error(String(e)));
    }
    let room = MAX_PREFETCHED - this.usable(owner, deviceId, now);
    let added = 0;
    for (const it of items) {
      if (room <= 0) break;
      if (this.rows.some((r) => r.ownerUserId === owner && r.id === it.id)) continue;
      this.rows.push({ ...it, ownerUserId: owner, deviceId, issuedAt: now, consumedAt: null });
      room -= 1;
      added += 1;
    }
    return Promise.resolve(added);
  }

  private usable(owner: string, device: string, now: number): number {
    return this.rows.filter((r) => r.ownerUserId === owner && r.deviceId === device && r.consumedAt === null && r.expiresAt > now).length;
  }

  countUsable(owner: string, deviceId: string, now: number): Promise<number> {
    return Promise.resolve(owner === UNOWNED_CHALLENGE_OWNER ? 0 : this.usable(owner, deviceId, now));
  }

  consumeOne(owner: string, deviceId: string, capturedAt: number, now: number): Promise<StoredChallenge | null> {
    if (owner === UNOWNED_CHALLENGE_OWNER) return Promise.resolve(null);
    let pick: StoredChallenge | null = null;
    for (const r of this.rows) if (qualifies(r, owner, deviceId, capturedAt, now) && (pick === null || better(r, pick))) pick = r;
    if (!pick) return Promise.resolve(null);
    pick.consumedAt = now;
    return Promise.resolve({ ...pick });
  }

  purgeExpired(now: number): Promise<number> {
    const before = this.rows.length;
    this.rows = this.rows.filter((r) => r.expiresAt > now);
    return Promise.resolve(before - this.rows.length);
  }

  listByOwner(owner: string): Promise<StoredChallenge[]> {
    return Promise.resolve(this.rows.filter((r) => r.ownerUserId === owner).map((r) => ({ ...r })));
  }

  deleteOwner(owner: string): Promise<void> {
    this.rows = this.rows.filter((r) => r.ownerUserId !== owner);
    return Promise.resolve();
  }

  deleteAll(): Promise<void> {
    this.rows = [];
    return Promise.resolve();
  }
}

interface Row {
  owner_user_id: string;
  id: string;
  device_id: string;
  facility_id: string | null;
  nonce: string;
  kind: string;
  issued_at: number;
  expires_at: number;
  consumed_at: number | null;
}

const COLS = "owner_user_id, id, device_id, facility_id, nonce, kind, issued_at, expires_at, consumed_at";

function fromRow(r: Row): StoredChallenge {
  return {
    ownerUserId: r.owner_user_id,
    id: r.id,
    deviceId: r.device_id,
    facilityId: r.facility_id,
    nonce: r.nonce,
    kind: r.kind === "live" ? "live" : "prefetched",
    issuedAt: r.issued_at,
    expiresAt: r.expires_at,
    consumedAt: r.consumed_at,
  };
}

export class SqliteChallengeStore implements ChallengeStore {
  constructor(private readonly db: SqlDatabase) {}

  async insertMany(owner: string, deviceId: string, items: readonly IssuedChallengeInput[], now: number): Promise<number> {
    assertOwner(owner);
    return this.db.transaction(async (tx) => {
      const c = await tx.all<{ n: number }>(
        "SELECT COUNT(*) AS n FROM checkin_challenge WHERE owner_user_id = ? AND device_id = ? AND consumed_at IS NULL AND expires_at > ?",
        [owner, deviceId, now],
      );
      let room = MAX_PREFETCHED - Number(c[0]?.n ?? 0);
      let added = 0;
      for (const it of items) {
        if (room <= 0) break;
        // OR IGNORE: an id this owner already has (possibly consumed) is left exactly as it is.
        const r = await tx.run(`INSERT OR IGNORE INTO checkin_challenge (${COLS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)`, [
          owner,
          it.id,
          deviceId,
          it.facilityId,
          it.nonce,
          it.kind,
          now,
          it.expiresAt,
        ]);
        if (r.changes === 1) {
          room -= 1;
          added += 1;
        }
      }
      return added;
    });
  }

  async countUsable(owner: string, deviceId: string, now: number): Promise<number> {
    if (owner === UNOWNED_CHALLENGE_OWNER) return 0;
    const c = await this.db.all<{ n: number }>(
      "SELECT COUNT(*) AS n FROM checkin_challenge WHERE owner_user_id = ? AND device_id = ? AND consumed_at IS NULL AND expires_at > ?",
      [owner, deviceId, now],
    );
    return Number(c[0]?.n ?? 0);
  }

  async consumeOne(owner: string, deviceId: string, capturedAt: number, now: number): Promise<StoredChallenge | null> {
    if (owner === UNOWNED_CHALLENGE_OWNER) return null;
    return this.db.transaction(async (tx) => {
      const rows = await tx.all<Row>(
        `SELECT ${COLS} FROM checkin_challenge
         WHERE owner_user_id = ? AND device_id = ? AND consumed_at IS NULL AND issued_at <= ? AND expires_at - ? >= ? AND expires_at - ? >= ?
         ORDER BY expires_at DESC, id ASC LIMIT 1`,
        [owner, deviceId, capturedAt, MIN_REMAINING_MS, capturedAt, MIN_REMAINING_MS, now],
      );
      const row = rows[0];
      if (!row) return null;
      // The conditional UPDATE is the atomic step: it must change exactly this one, still-unconsumed row.
      const r = await tx.run("UPDATE checkin_challenge SET consumed_at = ? WHERE owner_user_id = ? AND id = ? AND consumed_at IS NULL", [now, owner, row.id]);
      if (r.changes !== 1) return null;
      return { ...fromRow(row), consumedAt: now };
    });
  }

  async purgeExpired(now: number): Promise<number> {
    const r = await this.db.run("DELETE FROM checkin_challenge WHERE expires_at <= ?", [now]);
    return r.changes;
  }

  async listByOwner(owner: string): Promise<StoredChallenge[]> {
    const rows = await this.db.all<Row>(`SELECT ${COLS} FROM checkin_challenge WHERE owner_user_id = ? ORDER BY expires_at DESC, id ASC`, [owner]);
    return rows.map(fromRow);
  }

  async deleteOwner(owner: string): Promise<void> {
    await this.db.run("DELETE FROM checkin_challenge WHERE owner_user_id = ?", [owner]);
  }

  async deleteAll(): Promise<void> {
    await this.db.run("DELETE FROM checkin_challenge");
  }
}
