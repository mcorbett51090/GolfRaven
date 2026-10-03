/**
 * The local queue of "Buying a marker" co-signals (build plan §7.6 "Offline marker purchase", G2-03): a foreground fix, taken at the facility, against a challenge the device already
 * holds, kept until a server path can take it.
 *
 * ⚠ LOCAL ONLY, NOTHING SENDS IT. No server path accepts a marker-purchase co-signal today (no `marker-scan` / partner function exists; `POST evidence` refuses `staff_presence` and has
 * no other kind for it; see README, "Marker purchase: what the server does not have yet"). So this is a queue with a producer (`marker/capture.ts`) and NO consumer: nothing here is
 * ever passed to the outbox runner or to an API client, and the wire shape is NOT invented. The record keeps exactly what the plan says the server will need ("a co-signal fix, taken
 * against a prefetched challenge", within ±10 min of the staff code's step, sent within 7 days): the fix and the challenge it consumed.
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
  /** The challenge consumed for it: `held` (a prefetched one, consumed locally, never redeemed because nothing sends this yet). */
  readonly challenge: FixChallenge;
  readonly createdAt: number;
}

export interface MarkerCosignalStore {
  /** Idempotent on `(ownerUserId, id)`. Throws for an ownerless record. */
  insert(record: MarkerCosignal): Promise<void>;
  /** One owner's records, newest first. */
  listByOwner(ownerUserId: string): Promise<MarkerCosignal[]>;
  /** Account deletion: the deleted user's records. */
  deleteOwner(ownerUserId: string): Promise<void>;
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

  listByOwner(owner: string): Promise<MarkerCosignal[]> {
    return Promise.resolve(this.rows.filter((r) => r.ownerUserId === owner).map(clone).sort((a, b) => b.createdAt - a.createdAt || (a.id < b.id ? -1 : 1)));
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

  async listByOwner(owner: string): Promise<MarkerCosignal[]> {
    const rows = await this.db.all<{ record_json: string }>("SELECT record_json FROM marker_cosignal WHERE owner_user_id = ? ORDER BY created_at DESC, id ASC", [owner]);
    return rows.map((x) => JSON.parse(x.record_json) as MarkerCosignal);
  }

  async deleteOwner(owner: string): Promise<void> {
    await this.db.run("DELETE FROM marker_cosignal WHERE owner_user_id = ?", [owner]);
  }
}
