/**
 * The offline code for the app (build plan §7.6 "Offline staff path (G-P1-07)"): provisioning the per-(account, device) seed while online, keeping it in the secure store, and
 * computing the 6-digit code from it with no network.
 *
 *  - `provision({ rotate })`: `POST me-offline-seed { deviceId, rotate? }` as the signed-in user, validate the answer, store the seed BYTES and `seedVersion` (`store.ts`). Single-flight
 *    per user. Says what happened (`ProvisionOutcome`) and never throws. The device must already be registered to the account (the server never creates one): a 404 is `not_ready`,
 *    not an error, and nothing here loops on it.
 *  - `provisionIfMissing()`: the automatic path (launch, sign-in): provisions only when this user has no seed on this device (or a rotation is unconfirmed), and after an attempt that could not
 *    finish does not try again automatically for `AUTO_PROVISION_COOLDOWN_MS` (a `Retry-After` longer than that is honoured). The server limits reveals to 20 an hour; a build whose device
 *    is not registered yet must not spend them.
 *  - `view()`: the signed-in user's current code, with no network: the seed from the secure store, the code from the device clock (`totp.ts`), the seconds to the next change, and the clock
 *    offset estimated at provisioning (DISPLAY ONLY: it never changes a digit; the server accepts +-1 step of its own clock, so a device clock off by less than one step is always accepted).
 *  - `wipeUser(userId)`: account deletion.
 *
 * Every request is made for ONE owner with THAT owner's credentials (`session.accessTokenFor(owner)`, never whoever is signed in by the time it is made), the answer is stored under that
 * owner, and the token's `sub` must be that owner: a seed provisioned for one account is never stored under another. The seed is never logged, never put in an error message and never
 * leaves this module except as the bytes `view()` hands to the screen that is showing the code.
 */
import { isApiError } from "../api/errors";
import type { OfflineCodeApi } from "../api/types";
import { jwtSubject } from "../attest/jwt";
import type { OutboxSession } from "../outbox";
import { base32Decode } from "./base32";
import { AUTO_PROVISION_COOLDOWN_MS, CLOCK_SKEW_WARN_MS, OFFLINE_SEED_BYTES } from "./params";
import { OfflineSeedStore, type StoredSeed } from "./store";
import { codeAt, secondsToNextStep } from "./totp";

export type ProvisionOutcome =
  /** The seed is stored. `rotated`: this call asked for a new one. */
  | { status: "ready"; seedVersion: number; rotated: boolean; clock: ClockSkew }
  | { status: "signed_out" }
  /** The server answered 401 (the session is no longer valid): sign in again. */
  | { status: "sign_in_required" }
  /** 404: this device is not registered to the account yet (push token / challenge prefetch register it). Not an error; the player comes back later. */
  | { status: "not_ready" }
  | { status: "rate_limited"; retryAfterSeconds: number | null }
  /** 502 / 503 (`offline_seed_unavailable`: the server's key is not provisioned yet) / 504 / 5xx: retry later. */
  | { status: "unavailable" }
  /** No network (or a timeout). */
  | { status: "offline" }
  | { status: "failed"; reason: "not_configured" | "rejected" | "bad_response" | "storage" | "no_device" | "account_mismatch" };

export interface ClockSkew {
  /** Server clock minus device clock at provisioning (ms): positive = the device clock runs BEHIND. */
  offsetMs: number;
  /** The offset is one step or more, so a code MAY be refused (`CLOCK_SKEW_WARN_MS`). */
  warn: boolean;
}

export type CodeView =
  | {
      status: "ready";
      /** Six digits, leading zeros kept. */
      code: string;
      /** Whole seconds until the code changes, 1 to 600. */
      secondsRemaining: number;
      seedVersion: number;
      clock: ClockSkew;
      /** A rotation's outcome is unknown: the code may not match the server's seed until the next successful provisioning. */
      resyncNeeded: boolean;
    }
  | { status: "no_seed" }
  | { status: "signed_out" }
  | { status: "unavailable" };

export interface OfflineCodeManagerDeps {
  store: OfflineSeedStore;
  api: OfflineCodeApi;
  session: OutboxSession;
  deviceId: () => Promise<string>;
  now: () => number;
}

export function clockSkewOf(issuedAtMs: number, receivedAtMs: number): ClockSkew {
  const offsetMs = issuedAtMs - receivedAtMs;
  return { offsetMs, warn: Math.abs(offsetMs) >= CLOCK_SKEW_WARN_MS };
}

export class OfflineCodeManager {
  private readonly inFlight = new Map<string, Promise<ProvisionOutcome>>();
  /** Per user: no AUTOMATIC attempt before this time (epoch ms). In memory only: a relaunch is a fresh start, which is one attempt, not a loop. */
  private readonly autoNotBefore = new Map<string, number>();

  constructor(private readonly deps: OfflineCodeManagerDeps) {}

  /** Provisions (or rotates) the signed-in user's seed. Single-flight per user: a second call while one is running gets the same answer. */
  provision(opts: { rotate?: boolean } = {}): Promise<ProvisionOutcome> {
    const owner = this.deps.session.currentUserId();
    if (owner === null || owner === "") return Promise.resolve({ status: "signed_out" });
    const key = `${owner}:${opts.rotate === true ? "rotate" : "reveal"}`;
    const running = this.inFlight.get(key);
    if (running) return running;
    const p = this.doProvision(owner, opts.rotate === true).finally(() => this.inFlight.delete(key));
    this.inFlight.set(key, p);
    return p;
  }

  /** The automatic path: only when this user has no seed on this device (or a rotation is unconfirmed), and not again for a while after an attempt that could not finish. */
  async provisionIfMissing(): Promise<ProvisionOutcome | { status: "skipped"; reason: "have_seed" | "cooldown" }> {
    const owner = this.deps.session.currentUserId();
    if (owner === null || owner === "") return { status: "signed_out" };
    let deviceId: string;
    try {
      deviceId = await this.deps.deviceId();
    } catch {
      return { status: "failed", reason: "no_device" };
    }
    let have: StoredSeed | null;
    try {
      have = await this.deps.store.load(owner, deviceId);
    } catch {
      return { status: "failed", reason: "storage" };
    }
    if (have !== null && !have.resyncNeeded) return { status: "skipped", reason: "have_seed" };
    if (this.deps.now() < (this.autoNotBefore.get(owner) ?? 0)) return { status: "skipped", reason: "cooldown" };
    const outcome = await this.provision();
    if (outcome.status === "not_ready" || outcome.status === "unavailable" || outcome.status === "offline") this.autoNotBefore.set(owner, this.deps.now() + AUTO_PROVISION_COOLDOWN_MS);
    else if (outcome.status === "rate_limited") this.autoNotBefore.set(owner, this.deps.now() + Math.max(AUTO_PROVISION_COOLDOWN_MS, (outcome.retryAfterSeconds ?? 0) * 1000));
    return outcome;
  }

  /** The signed-in user's current code, from the secure store and the device clock. Needs no network. */
  async view(): Promise<CodeView> {
    const owner = this.deps.session.currentUserId();
    if (owner === null || owner === "") return { status: "signed_out" };
    let stored: StoredSeed | null;
    try {
      stored = await this.deps.store.load(owner, await this.deps.deviceId());
    } catch {
      return { status: "unavailable" };
    }
    if (stored === null) return { status: "no_seed" };
    return this.viewOf(stored);
  }

  /** The code for an already loaded seed at the device clock (the screen calls this every second without touching the store). */
  viewOf(stored: StoredSeed, nowMs: number = this.deps.now()): CodeView & { status: "ready" } {
    return {
      status: "ready",
      code: codeAt(stored.seed, nowMs),
      secondsRemaining: secondsToNextStep(nowMs),
      seedVersion: stored.seedVersion,
      clock: clockSkewOf(stored.issuedAtMs, stored.receivedAtMs),
      resyncNeeded: stored.resyncNeeded,
    };
  }

  /** The stored seed of the signed-in user, for the screen that shows the code (it keeps the bytes in memory only while it is visible). `null`: none, signed out or unreadable. */
  async loadSeed(): Promise<StoredSeed | null> {
    const owner = this.deps.session.currentUserId();
    if (owner === null || owner === "") return null;
    try {
      return await this.deps.store.load(owner, await this.deps.deviceId());
    } catch {
      return null;
    }
  }

  /** Account deletion: removes the deleted user's seed on this device. Throws if the secure store cannot be written (the caller reports a partial wipe). */
  async wipeUser(userId: string): Promise<void> {
    await this.deps.store.wipe(userId, await this.deps.deviceId());
  }

  private async doProvision(owner: string, rotate: boolean): Promise<ProvisionOutcome> {
    const { api, session, store, now } = this.deps;
    let deviceId: string;
    try {
      deviceId = await this.deps.deviceId();
    } catch {
      return { status: "failed", reason: "no_device" };
    }
    let accessToken: string | null;
    try {
      accessToken = await session.accessTokenFor(owner);
    } catch {
      return { status: "offline" }; // a refresh that could not reach the server
    }
    if (accessToken === null) return { status: session.currentUserId() === owner ? "sign_in_required" : "signed_out" };
    // The seed is stored under `owner`; the token must be `owner`'s (the server derives the seed for the token's account).
    const sub = jwtSubject(accessToken);
    if (sub === null || sub.toLowerCase() !== owner.toLowerCase()) return { status: "failed", reason: "account_mismatch" };

    let before: StoredSeed | null = null;
    try {
      before = await store.load(owner, deviceId);
    } catch {
      return { status: "failed", reason: "storage" };
    }
    if (rotate && before !== null) {
      // The rotation may be applied at the server although its answer never arrives: remember that BEFORE asking, so the next provisioning fetches the server's current seed.
      try {
        await store.save(owner, deviceId, { ...before, resyncNeeded: true });
      } catch {
        return { status: "failed", reason: "storage" };
      }
    }

    let result;
    try {
      result = await api.provisionOfflineSeed({ deviceId, ...(rotate ? { rotate: true } : {}) }, { userId: owner, accessToken });
    } catch (e) {
      if (!isApiError(e)) return { status: "offline" };
      // A definite refusal of the rotation (4xx) left the server's seed alone: the earlier record is current again.
      if (rotate && before !== null && e.status !== null && e.status >= 400 && e.status < 500) await store.save(owner, deviceId, before).catch(() => undefined);
      switch (e.kind) {
        case "not_found":
          return { status: "not_ready" };
        case "rate_limited":
          return { status: "rate_limited", retryAfterSeconds: e.retryAfterSeconds };
        case "unavailable":
        case "server":
          return { status: "unavailable" };
        case "network":
          return { status: "offline" };
        case "unauthenticated":
          return { status: "sign_in_required" };
        case "not_configured":
          return { status: "failed", reason: "not_configured" };
        case "bad_response":
          return { status: "failed", reason: "bad_response" };
        default:
          return { status: "failed", reason: "rejected" };
      }
    }

    const seed = base32Decode(result.seed);
    if (seed === null || seed.length !== OFFLINE_SEED_BYTES) return { status: "failed", reason: "bad_response" };
    const receivedAtMs = now();
    const issuedAtMs = Date.parse(result.issuedAt);
    try {
      await store.save(owner, deviceId, { seed, seedVersion: result.seedVersion, issuedAtMs, receivedAtMs, resyncNeeded: false });
    } catch {
      return { status: "failed", reason: "storage" };
    } finally {
      seed.fill(0); // best effort: the decoded bytes do not outlive this call here
    }
    return { status: "ready", seedVersion: result.seedVersion, rotated: rotate, clock: clockSkewOf(issuedAtMs, receivedAtMs) };
  }
}
