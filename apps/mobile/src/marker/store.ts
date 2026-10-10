/**
 * The local queue of "Buying a marker" co-signals (build plan §7.6 "Offline marker purchase", G2-03): a foreground fix, taken at the facility, against a challenge the device already
 * holds, kept until the sender (`marker/send.ts`) redeems it and POSTs `marker-scan` (P5 §52 / S2a cosignal intake).
 *
 * Producer: `marker/capture.ts` (behind `MARKER_COSIGNAL_UI_ENABLED` + `CHECKIN_UI_ENABLED`). Consumer: `marker/send.ts` → `api.scanMarker` (fix-only). Capture stays flag-gated;
 * drain of already-queued rows runs on sync even while the flags are false so a field build that captured under an injected flag can still clear the queue.
 *
 * Per owner like the outbox and the challenge pool (a sign-out leaves a user's records dormant, another user never sees them, account deletion removes the deleted user's: it is a location
 * record).
 */
import type { SqlDatabase } from "../db/sql";
import type { FixChallenge, FixTemplate } from "../evidence/payload";

export interface MarkerCosignal {
  readonly id: string;
  readonly ownerUserId: string;
  readonly facilityId: string;
  /** The site catalog version the facility was matched against. */
  readonly catalogVersion: string;
  readonly deviceId: string;
  /** The foreground fix (the same template an evidence fix uses). */
  readonly fix: FixTemplate;
  /** The challenge consumed for it: `held` until the sender redeems it at `checkin-token`, then `redeemed` with the jti the scan carries. */
  readonly challenge: FixChallenge;
  readonly createdAt: number;
}

export interface MarkerCosignalStore {
  /** Idempotent on `(ownerUserId, id)`. Throws for an ownerless record. */
  insert(record: MarkerCosignal): Promise<void>;
  /** Replace an existing row (redeemed jti crash-safety before `marker-scan`). No-op if missing. */
  update(record: MarkerCosignal): Promise<void>;
  /** One owner's records, newest first. */
  listByOwner(ownerUserId: string): Promise<MarkerCosignal[]>;
  /** Remove one record after a successful send or a terminal drop. */
  deleteById(ownerUserId: string, id: string): Promise<void>;
  /** Account deletion: the deleted user's records. */
  deleteOwner(ownerUserId: string): Promise<void>;
}

/** How many of `owner`'s marker records on `deviceId` still hold a prefetched challenge the SERVER counts as open: consumed locally (`held`), not yet redeemed by the sender, not yet
 * expired. The challenge manager's top-up subtracts this from its room (`ChallengeManagerDeps.openElsewhere`) so the client's estimate matches the server's cap of 10 open per device. */
export async function heldOpenCount(store: Pick<MarkerCosignalStore, "listByOwner">, owner: string, deviceId: string, now: number): Promise<number> {
  const rows = await store.listByOwner(owner);
  return rows.filter((r) => r.deviceId === deviceId && r.challenge.state === "held" && r.challenge.expiresAt > now).length;
}

function assertOwned(r: MarkerCosignal): void {
  if (typeof r.ownerUserId !== "string" || r.ownerUserId === "") throw new Error("marker: refusing to store a co-signal with no owner");
}

const clone = <T>(v: T): T => JSON.parse(JSON.stringify(v)) as T;

export class MemoryMarkerCosignalStore implements MarkerCosignalStore {
  private rows: MarkerCosignal[] = [];

  insert(r: MarkerCosignal): Promise<void> {
    try {
      assertOwned(r);
    } catch (e) {
      return Promise.reject(e instanceof Error ? e : new Error(String(e)));
    }
    if (!this.rows.some((x) => x.ownerUserId === r.ownerUserId && x.id === r.id)) this.rows.push(clone(r));
    return Promise.resolve();
  }

  update(r: MarkerCosignal): Promise<void> {
    try {
      assertOwned(r);
    } catch (e) {
      return Promise.reject(e instanceof Error ? e : new Error(String(e)));
    }
    const i = this.rows.findIndex((x) => x.ownerUserId === r.ownerUserId && x.id === r.id);
    if (i >= 0) this.rows[i] = clone(r);
    return Promise.resolve();
  }

  listByOwner(owner: string): Promise<MarkerCosignal[]> {
    return Promise.resolve(this.rows.filter((r) => r.ownerUserId === owner).map(clone).sort((a, b) => b.createdAt - a.createdAt || (a.id < b.id ? -1 : 1)));
  }

  deleteById(owner: string, id: string): Promise<void> {
    this.rows = this.rows.filter((r) => !(r.ownerUserId === owner && r.id === id));
    return Promise.resolve();
  }

  deleteOwner(owner: string): Promise<void> {
    this.rows = this.rows.filter((r) => r.ownerUserId !== owner);
    return Promise.resolve();
  }
}

export class SqliteMarkerCosignalStore implements MarkerCosignalStore {
  constructor(private readonly db: SqlDatabase) {}

  async insert(r: MarkerCosignal): Promise<void> {
    assertOwned(r);
    await this.db.run("INSERT OR IGNORE INTO marker_cosignal (owner_user_id, id, facility_id, captured_at, created_at, record_json) VALUES (?, ?, ?, ?, ?, ?)", [
      r.ownerUserId,
      r.id,
      r.facilityId,
      r.fix.capturedAt,
      r.createdAt,
      JSON.stringify(r),
    ]);
  }

  async update(r: MarkerCosignal): Promise<void> {
    assertOwned(r);
    await this.db.run("UPDATE marker_cosignal SET facility_id = ?, captured_at = ?, created_at = ?, record_json = ? WHERE owner_user_id = ? AND id = ?", [
      r.facilityId,
      r.fix.capturedAt,
      r.createdAt,
      JSON.stringify(r),
      r.ownerUserId,
      r.id,
    ]);
  }

  async listByOwner(owner: string): Promise<MarkerCosignal[]> {
    const rows = await this.db.all<{ record_json: string }>("SELECT record_json FROM marker_cosignal WHERE owner_user_id = ? ORDER BY created_at DESC, id ASC", [owner]);
    return rows.map((x) => JSON.parse(x.record_json) as MarkerCosignal);
  }

  async deleteById(owner: string, id: string): Promise<void> {
    await this.db.run("DELETE FROM marker_cosignal WHERE owner_user_id = ? AND id = ?", [owner, id]);
  }

  async deleteOwner(owner: string): Promise<void> {
    await this.db.run("DELETE FROM marker_cosignal WHERE owner_user_id = ?", [owner]);
  }
}
