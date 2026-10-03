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
}

export type PrefetchOutcome =
  | { kind: "filled"; added: number; usable: number }
  | { kind: "full"; usable: number }
  | { kind: "skipped"; reason: "signed_out" | "no_token" | "user_changed" }
  | { kind: "failed"; reason: "rate_limited" | "network" | "rejected" | "bad_response" | "no_device" };

export interface AcquireOptions {
  /** Online: try a live challenge first. Default false (use the pool). */
  live?: boolean;
  facilityId?: string;
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
    const want = MAX_PREFETCHED - usable;
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
      if (live) return live;
    }
    const c = await store.consumeOne(owner, deviceId, capturedAt, now());
    if (!c) return none;
    return { state: "held", challengeId: c.id, nonce: c.nonce, kind: c.kind, expiresAt: c.expiresAt };
  }

  private async tryLive(owner: string, deviceId: string, facilityId: string | undefined): Promise<FixChallenge | null> {
    const { api, session, now } = this.deps;
    try {
      const accessToken = await session.accessTokenFor(owner);
      if (accessToken === null) return null;
      const credentials = { userId: owner, accessToken };
      const [c] = await api.requestCheckinChallenges({ deviceId, ...(facilityId !== undefined ? { facilityId } : {}) }, credentials);
      if (!c || c.kind !== "live" || !(Date.parse(c.expiresAt) > now())) return null;
      const token = await api.redeemCheckinChallenge({ challengeId: c.id, nonce: c.nonce, deviceId }, credentials);
      return { state: "redeemed", challengeId: c.id, kind: "live", jti: token.jti, grade: token.attestationGrade };
    } catch {
      return null; // offline, rate limited, refused: fall back to the pool
    }
  }
}
