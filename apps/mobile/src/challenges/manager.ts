/**
 * Check-in challenges for the app (build plan §7.6 "Offline attestation", FM-10).
 *
 *  - `prefetch()`: while online and signed in, tops the signed-in user's pool up to `MAX_PREFETCHED` (10) single-use challenges for this device
 *    (`checkin-challenge` with `prefetchCount`; the server's TTL is 24 h, read from each challenge's own `expiresAt`, and the server caps a device
 *    at 10 unused ones too). Only the shortfall is requested and no more than the shortfall is kept. Never throws; says what happened.
 *  - `acquireForFix()`: what a check-in calls ONCE per fix. It returns the `FixChallenge` to store with the evidence:
 *      1. when online and `live` is asked for: a LIVE challenge, requested and redeemed on the spot (`redeemed`);
 *      2. otherwise one prefetched challenge, consumed atomically (`held`: consumed here and now, redeemed when the item is sent);
 *      3. otherwise `none / none_available`: the evidence goes with no challenge and the server applies the x0.6 penalty (§4.5). The item records
 *         that (`evidencePenaltyApplies`), so it is visible rather than silent.
 *    A challenge is consumed BEFORE it is used, exactly once, and is never offered again, whatever happens to the send afterwards.
 *
 * Every call is for ONE owner and uses THAT owner's credentials (`session.accessTokenFor(owner)`, not whoever is signed in by then); the store
 * never mixes owners. Honest limit: a challenge consumed offline stays "open" at the server until it is redeemed (at send time) or expires, and the
 * server counts open prefetched ones against the same cap of 10, so a prefetch right after an offline round may get `rate_limited` until the outbox
 * has sent the round; `prefetch()` reports it and a later call succeeds.
 */
import { isApiError } from "../api/errors";
import type { CheckinApi, IssuedChallenge } from "../api/types";
import type { FixChallenge } from "../evidence/payload";
import type { OutboxSession } from "../outbox";
import { MAX_PREFETCHED, type ChallengeStore } from "./store";

export interface ChallengeManagerDeps {
  store: ChallengeStore;
  api: CheckinApi;
  session: OutboxSession;
  deviceId: () => Promise<string>;
  now: () => number;
  /** P4.2c-1: how many of this owner's challenges the SERVER still counts as open although the device has consumed them locally and will not redeem them soon (the marker co-signal
   * records hold a prefetched challenge for 24 h: `marker/store.ts` `heldOpenCount`). The top-up subtracts it, so the client's room estimate matches the server's cap of 10 open
   * prefetched challenges per device. Absent = 0. */
  openElsewhere?: (owner: string, deviceId: string, now: number) => Promise<number>;
}

export type PrefetchOutcome =
  | { kind: "filled"; added: number; usable: number }
  | { kind: "full"; usable: number }
  | { kind: "skipped"; reason: "signed_out" | "no_token" | "user_changed" }
  | { kind: "failed"; reason: "rate_limited" | "network" | "rejected" | "bad_response" | "no_device" };

export interface AcquireOptions {
  /** Online: try a live challenge first. Default false (use the pool).
   *
   * ⚠ CONTRACT (P4.2c): the server accepts a fix as a co-signal for a challenge only when `challenge.issued_at <= fix.capturedAt <= challenge.expires_at`
   * (`consumeForFix`). A live challenge requested HERE is requested after the fix was taken, so its `issued_at` is later than `capturedAt` and the fix is
   * outside its window: the evidence would carry a token the server cannot consume (no co-signal). The check-in flow therefore never passes `live` here; it takes
   * the live challenge BEFORE the fix (`acquireLive`) and hands it to `enqueueEvidence` (`EvidenceInput.challenge`). `live: true` is kept only for a caller whose
   * fix is taken after the call. */
  live?: boolean;
  facilityId?: string;
}

/** A live challenge taken BEFORE the fix it will cover (`acquireLive`). */
export interface LiveChallenge {
  /** `redeemed`: the token is already minted (online by construction). */
  challenge: Extract<FixChallenge, { state: "redeemed" }>;
  /** The device clock when the challenge was received: a fix captured at or after it is surely after the server's `issued_at` (clock skew aside). */
  receivedAt: number;
  /** The server's expiry (epoch ms): a fix captured after it is outside the window. */
  expiresAt: number;
  /** Whose challenge it is and which device it was issued to (P4.2c-1): `enqueueEvidence` refuses it for any other signed-in user or device. */
  ownerUserId: string;
  deviceId: string;
}

export class ChallengeManager {
  private inFlight = new Map<string, Promise<PrefetchOutcome>>();

  constructor(private readonly deps: ChallengeManagerDeps) {}

  /** Tops up the signed-in user's pool. Single-flight per user. */
  prefetch(): Promise<PrefetchOutcome> {
    const owner = this.deps.session.currentUserId();
    if (owner === null || owner === "") return Promise.resolve({ kind: "skipped", reason: "signed_out" });
    const running = this.inFlight.get(owner);
    if (running) return running;
    const p = this.doPrefetch(owner).finally(() => this.inFlight.delete(owner));
    this.inFlight.set(owner, p);
    return p;
  }

  private async doPrefetch(owner: string): Promise<PrefetchOutcome> {
    const { store, api, session, now } = this.deps;
    let deviceId: string;
    try {
      deviceId = await this.deps.deviceId();
    } catch {
      return { kind: "failed", reason: "no_device" };
    }
    await store.purgeExpired(now());
    const usable = await store.countUsable(owner, deviceId, now());
    let held = 0;
    try {
      held = this.deps.openElsewhere ? await this.deps.openElsewhere(owner, deviceId, now()) : 0;
    } catch {
      held = 0;
    }
    const want = MAX_PREFETCHED - usable - held;
    if (want <= 0) return { kind: "full", usable };
    let accessToken: string | null;
    try {
      accessToken = await session.accessTokenFor(owner);
    } catch {
      accessToken = null;
    }
    if (accessToken === null) return { kind: "skipped", reason: session.currentUserId() === owner ? "no_token" : "user_changed" };
    let issued: IssuedChallenge[];
    try {
      issued = await api.requestCheckinChallenges({ deviceId, prefetchCount: want }, { userId: owner, accessToken });
    } catch (e) {
      if (!isApiError(e)) return { kind: "failed", reason: "network" };
      return { kind: "failed", reason: e.kind === "rate_limited" ? "rate_limited" : e.kind === "network" || e.kind === "server" || e.kind === "unavailable" ? "network" : e.kind === "bad_response" ? "bad_response" : "rejected" };
    }
    // The response is untrusted input: keep only prefetched, unexpired challenges, and never more than the shortfall asked for.
    const t = now();
    const usableNow = issued
      .filter((c) => c.kind === "prefetched" && Date.parse(c.expiresAt) > t)
      .slice(0, want)
      .map((c) => ({ id: c.id, nonce: c.nonce, kind: c.kind, facilityId: null, expiresAt: Date.parse(c.expiresAt) }));
    // Stored under the user the credentials belong to: even if the signed-in user changed meanwhile, these are `owner`'s challenges.
    const added = await store.insertMany(owner, deviceId, usableNow, t);
    return { kind: "filled", added, usable: await store.countUsable(owner, deviceId, now()) };
  }

  /** The challenge for one fix captured at `capturedAt` (epoch ms), for `owner` (who must be the signed-in user). */
  async acquireForFix(owner: string, capturedAt: number, opts: AcquireOptions = {}): Promise<FixChallenge> {
    const { store, session, now } = this.deps;
    const none: FixChallenge = { state: "none", reason: "none_available" };
    if (owner === "" || session.currentUserId() !== owner) return none;
    let deviceId: string;
    try {
      deviceId = await this.deps.deviceId();
    } catch {
      return none;
    }
    if (opts.live) {
      const live = await this.tryLive(owner, deviceId, opts.facilityId);
      if (live) return live.challenge;
    }
    const c = await store.consumeOne(owner, deviceId, capturedAt, now());
    if (!c) return none;
    return { state: "held", challengeId: c.id, nonce: c.nonce, kind: c.kind, expiresAt: c.expiresAt };
  }

  /** How many prefetched challenges `owner` could consume right now on this device (unconsumed, unexpired). 0 for a user who is not signed in or when the device id is unavailable. */
  async usableCount(owner: string): Promise<number> {
    const { store, session, now } = this.deps;
    if (owner === "" || session.currentUserId() !== owner) return 0;
    try {
      return await store.countUsable(owner, await this.deps.deviceId(), now());
    } catch {
      return 0;
    }
  }

  /** A LIVE challenge for a fix that is about to be taken (P4.2c; see `AcquireOptions.live` for why it must come first). Online only: any failure (offline,
   * rate limited, refused, signed out, a user switch) is `null` and the caller falls back to the pool. Never throws. The challenge is requested and redeemed on the
   * spot (`redeemed`), so the evidence must be sent within the token's lifetime (15 minutes, server): use it only for a check-in that is enqueued right away. */
  async acquireLive(owner: string, facilityId?: string): Promise<LiveChallenge | null> {
    const { session } = this.deps;
    if (owner === "" || session.currentUserId() !== owner) return null;
    let deviceId: string;
    try {
      deviceId = await this.deps.deviceId();
    } catch {
      return null;
    }
    const live = await this.tryLive(owner, deviceId, facilityId);
    // The user may have changed while the request was in flight: a challenge of `owner` is never handed to a screen now showing someone else.
    return live !== null && session.currentUserId() === owner ? live : null;
  }

  private async tryLive(owner: string, deviceId: string, facilityId: string | undefined): Promise<LiveChallenge | null> {
    const { api, session, now } = this.deps;
    try {
      const accessToken = await session.accessTokenFor(owner);
      if (accessToken === null) return null;
      const credentials = { userId: owner, accessToken };
      const [c] = await api.requestCheckinChallenges({ deviceId, ...(facilityId !== undefined ? { facilityId } : {}) }, credentials);
      const receivedAt = now();
      const expiresAt = c ? Date.parse(c.expiresAt) : Number.NaN;
      if (!c || c.kind !== "live" || !(expiresAt > receivedAt)) return null;
      const token = await api.redeemCheckinChallenge({ challengeId: c.id, nonce: c.nonce, deviceId }, credentials);
      return { challenge: { state: "redeemed", challengeId: c.id, kind: "live", jti: token.jti, grade: token.attestationGrade }, receivedAt, expiresAt, ownerUserId: owner, deviceId };
    } catch {
      return null; // offline, rate limited, refused: fall back to the pool
    }
  }
}
