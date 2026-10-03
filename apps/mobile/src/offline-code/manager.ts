/**
 * The offline code for the app (build plan §7.6 "Offline staff path (G-P1-07)"): provisioning the per-(account, device) seed while online, keeping it in the secure store, and
 * computing the 6-digit code from it with no network.
 *
 *  - `provision({ rotate })`: `POST me-offline-seed { deviceId, rotate? }` as the signed-in user, validate the answer, store the seed BYTES and `seedVersion` (`store.ts`). Single-flight
 *    per USER, whatever the mode (PR #44 gate LOW-2): at most one request of a user is in flight, so a reveal and a rotation can never answer out of order. A second call of the same kind
 *    (or a reveal while anything runs) joins the running request; a ROTATION asked while a reveal is in flight waits for it and then runs (it is never dropped and never merged into the
 *    reveal: the player asked for a new seed). Independently, `store.save` never lets a lower `seedVersion` replace a higher one. Says what happened (`ProvisionOutcome`) and never throws. The device must already be registered to the account (the server never creates one): a 404 is `not_ready`,
 *    not an error, and nothing here loops on it. While `OFFLINE_CODE_UI_ENABLED` is on, a 404 first registers the device through `POST checkin-challenge` (`deviceRegistrationFor`,
 *    `gate.ts`; `registerDeviceOnce` below) and asks again once; that is what lets the code become ready on a build with no push and no challenge prefetch.
 *  - `provisionIfMissing()`: the automatic path (launch, sign-in): provisions only when this user has no seed on this device (or a rotation is unconfirmed), and after an attempt that could not
 *    finish does not try again automatically for `AUTO_PROVISION_COOLDOWN_MS` (a `Retry-After` longer than that is honoured). The server limits reveals to 20 an hour; a build whose device
 *    is not registered yet must not spend them.
 *  - `view()`: the signed-in user's current code, with no network: the seed from the secure store, the code from the device clock (`totp.ts`), the seconds to the next change, and the clock
 *    offset estimated at provisioning (DISPLAY ONLY: it never changes a digit; the server accepts +-1 step of its own clock, so a device clock off by less than one step is always accepted).
 *    It is the ONLY way a screen gets the code: the seed is read, used and dropped inside the manager and never handed out (PR #44 gate NIT: the card holds the derived code, not the seed).
 *  - `wipeUser(userId)`: account deletion.
 *
 * Every request is made for ONE owner with THAT owner's credentials (`session.accessTokenFor(owner)`, never whoever is signed in by the time it is made), the answer is stored under that
 * owner, and the token's `sub` must be that owner: a seed provisioned for one account is never stored under another. The seed is never logged, never put in an error message and never
 * leaves this module: not in a log, an error, an outcome or a `CodeView`.
 */
import { isApiError } from "../api/errors";
import type { OfflineCodeApi, OfflineSeedResult } from "../api/types";
import { jwtSubject } from "../attest/jwt";
import type { OutboxSession } from "../outbox";
import { base32Decode } from "./base32";
import { AUTO_PROVISION_COOLDOWN_MS, CLOCK_SKEW_WARN_MS, OFFLINE_SEED_BYTES } from "./params";
import { OfflineSeedStore, type SaveOutcome, type StoredSeed } from "./store";
import { codeAt, secondsToNextStep } from "./totp";

export type ProvisionOutcome =
  /** The seed is stored. `rotated`: this call asked for a new one. */
  | { status: "ready"; seedVersion: number; rotated: boolean; clock: ClockSkew }
  | { status: "signed_out" }
  /** The server answered 401 (the session is no longer valid): sign in again. */
  | { status: "sign_in_required" }
  /** 404: this device is not registered to the account yet and could not be registered now (see `registerDeviceOnce`; with no registration path, push token / challenge prefetch register it). Not an error; the player comes back later. */
  | { status: "not_ready" }
  | { status: "rate_limited"; retryAfterSeconds: number | null }
  /** 502 / 503 (`offline_seed_unavailable`: the server's key is not provisioned yet) / 504 / 5xx: retry later. */
  | { status: "unavailable" }
  /** No network (or a timeout). */
  | { status: "offline" }
  /** `stale_seed`: the server's answer carries a LOWER `seedVersion` than the record on this device, which is kept (a late answer must never take a seed back to an older one). */
  | { status: "failed"; reason: "not_configured" | "rejected" | "bad_response" | "storage" | "no_device" | "account_mismatch" | "stale_seed" };

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
  /**
   * Registers THIS device to the account at the server, so the seed endpoint (which never creates one) can find it. Supplied only while `OFFLINE_CODE_UI_ENABLED` is on
   * (`deviceRegistrationFor`, `gate.ts`); absent, a 404 stays "not ready" and nothing is registered. Throws `ApiError`.
   */
  registerDevice?: (req: { deviceId: string; userId: string; accessToken: string }) => Promise<void>;
}

/** One provisioning request of one user (`provision`): started when it takes the user's slot. */
interface Flight {
  rotate: boolean;
  promise: Promise<ProvisionOutcome>;
  start: () => void;
}

export function clockSkewOf(issuedAtMs: number, receivedAtMs: number): ClockSkew {
  const offsetMs = issuedAtMs - receivedAtMs;
  return { offsetMs, warn: Math.abs(offsetMs) >= CLOCK_SKEW_WARN_MS };
}

/** Thrown inside `requestSeed` when the record of an unconfirmed rotation cannot be written. */
class StorageFailure extends Error {
  constructor(cause: unknown) {
    super("the offline seed store could not be written");
    this.name = "StorageFailure";
    this.cause = cause;
  }
}

/** What an error of the seed request (or of the device registration) means for the caller. */
function outcomeOfError(e: unknown): ProvisionOutcome {
  if (e instanceof StorageFailure) return { status: "failed", reason: "storage" };
  if (!isApiError(e)) return { status: "offline" };
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

export class OfflineCodeManager {
  /** Per user: the request running now. At most one per user, whatever its mode (LOW-2). */
  private readonly active = new Map<string, Flight>();
  /** Per user: a rotation waiting for the running reveal. At most one; further rotation calls join it. */
  private readonly queued = new Map<string, Flight>();
  /** Per user: no AUTOMATIC attempt before this time (epoch ms). In memory only: a relaunch is a fresh start, which is one attempt, not a loop. */
  private readonly autoNotBefore = new Map<string, number>();
  /** Per user: no device registration before this time (epoch ms). A registration spends one of the account's 30-an-hour live challenges, so it is tried at most once per cooldown. */
  private readonly registerNotBefore = new Map<string, number>();

  constructor(private readonly deps: OfflineCodeManagerDeps) {}

  /** Provisions (or rotates) the signed-in user's seed. Single-flight PER USER, whatever the mode (LOW-2): see the header. */
  provision(opts: { rotate?: boolean } = {}): Promise<ProvisionOutcome> {
    const owner = this.deps.session.currentUserId();
    if (owner === null || owner === "") return Promise.resolve({ status: "signed_out" });
    const rotate = opts.rotate === true;
    const running = this.active.get(owner);
    if (running === undefined) return this.begin(owner, this.flight(owner, rotate)).promise;
    const waiting = this.queued.get(owner);
    // A reveal joins the newest request of its user (a reveal that runs after a rotation would only fetch the seed the rotation just stored). A rotation joins a running rotation
    // (two taps, one request), or the rotation already waiting.
    if (!rotate) return (waiting ?? running).promise;
    if (running.rotate) return (waiting ?? running).promise;
    if (waiting !== undefined) return waiting.promise;
    const next = this.flight(owner, true);
    this.queued.set(owner, next);
    return next.promise;
  }

  private flight(owner: string, rotate: boolean): Flight {
    let start!: () => void;
    const gate = new Promise<void>((resolve) => {
      start = resolve;
    });
    const f: Flight = { rotate, start, promise: gate.then(() => this.doProvision(owner, rotate)).finally(() => this.finished(owner, f)) };
    return f;
  }

  private begin(owner: string, f: Flight): Flight {
    this.active.set(owner, f);
    f.start();
    return f;
  }

  /** The running request settled: the waiting rotation (if any) takes its place in the same step, so no other call can slip in between. */
  private finished(owner: string, f: Flight): void {
    if (this.active.get(owner) !== f) return;
    this.active.delete(owner);
    const next = this.queued.get(owner);
    if (next !== undefined) {
      this.queued.delete(owner);
      this.begin(owner, next);
    }
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

  /** The signed-in user's current code, from the secure store and the device clock (`nowMs`: tests and the screen's clock; default the manager's). Needs no network. The seed is read
   * here and dropped here: the answer carries the six digits, never the seed. */
  async view(nowMs?: number): Promise<CodeView> {
    const owner = this.deps.session.currentUserId();
    if (owner === null || owner === "") return { status: "signed_out" };
    let stored: StoredSeed | null;
    try {
      stored = await this.deps.store.load(owner, await this.deps.deviceId());
    } catch {
      return { status: "unavailable" };
    }
    if (stored === null) return { status: "no_seed" };
    return this.viewOf(stored, nowMs);
  }

  /** The code for an already loaded seed at the device clock. Pure; used by `view()`. */
  private viewOf(stored: StoredSeed, nowMs: number = this.deps.now()): CodeView & { status: "ready" } {
    return {
      status: "ready",
      code: codeAt(stored.seed, nowMs),
      secondsRemaining: secondsToNextStep(nowMs),
      seedVersion: stored.seedVersion,
      clock: clockSkewOf(stored.issuedAtMs, stored.receivedAtMs),
      resyncNeeded: stored.resyncNeeded,
    };
  }

  /** Account deletion: removes the deleted user's seed on this device. Throws if the secure store cannot be written (the caller reports a partial wipe). */
  async wipeUser(userId: string): Promise<void> {
    await this.deps.store.wipe(userId, await this.deps.deviceId());
  }

  /** One `POST me-offline-seed`, with the bookkeeping a rotation needs. Never throws: the error comes back for `outcomeOfError`. */
  private async requestSeed(owner: string, deviceId: string, accessToken: string, rotate: boolean, before: StoredSeed | null): Promise<{ ok: true; result: OfflineSeedResult } | { ok: false; error: unknown }> {
    const { api, store } = this.deps;
    if (rotate && before !== null) {
      // The rotation may be applied at the server although its answer never arrives: remember that BEFORE asking, so the next provisioning fetches the server's current seed.
      try {
        await store.save(owner, deviceId, { ...before, resyncNeeded: true });
      } catch (e) {
        return { ok: false, error: new StorageFailure(e) };
      }
    }
    try {
      return { ok: true, result: await api.provisionOfflineSeed({ deviceId, ...(rotate ? { rotate: true } : {}) }, { userId: owner, accessToken }) };
    } catch (e) {
      // A definite refusal of the rotation (4xx) left the server's seed alone: the earlier record is current again.
      if (rotate && before !== null && isApiError(e) && e.status !== null && e.status >= 400 && e.status < 500) await store.save(owner, deviceId, before).catch(() => undefined);
      return { ok: false, error: e };
    }
  }

  /**
   * The documented device-registration path (build plan §7.6; PR #44 gate NIT "the offline code never becomes ready"). `POST me-offline-seed` never creates a device
   * (`offline-seed-handler.ts`: another account's device, or none, is a 404), and today nothing else registers one (challenge prefetch is gated off, push is not installed). The cheapest
   * endpoint the app can already call that registers a device is `POST checkin-challenge` with `{ deviceId }`: its handler runs `device.ensureOwn(deviceId, null)` (platform left unknown, set
   * by the first platform-bearing use) before it issues one LIVE challenge, which simply expires unused after 120 s. `me-push-token` cannot do it (it refuses an empty `expoToken`), and
   * `devices-attest-key` / `rewards-activate` need an attestation. Cost: one of the account's 30 live challenges an hour, shared with live check-in, so this is tried at most once per
   * `AUTO_PROVISION_COOLDOWN_MS` per user, and only after the seed endpoint itself answered 404. Returns `null` when the device is now registered (ask again), else the outcome to report.
   */
  private async registerDeviceOnce(owner: string, deviceId: string, accessToken: string): Promise<ProvisionOutcome | null> {
    const register = this.deps.registerDevice;
    if (register === undefined) return { status: "not_ready" };
    if (this.deps.now() < (this.registerNotBefore.get(owner) ?? 0)) return { status: "not_ready" };
    this.registerNotBefore.set(owner, this.deps.now() + AUTO_PROVISION_COOLDOWN_MS); // before the request: a failure or a crash of it must not become a loop
    try {
      await register({ deviceId, userId: owner, accessToken });
      return null;
    } catch (e) {
      return outcomeOfError(e); // 429, a network failure, 401, a 422 `device_limit_exceeded`...: each has its own line; the next automatic attempt is held back by the cooldown
    }
  }

  private async doProvision(owner: string, rotate: boolean): Promise<ProvisionOutcome> {
    const { session, store, now } = this.deps;
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

    let attempt = await this.requestSeed(owner, deviceId, accessToken, rotate, before);
    if (!attempt.ok && isApiError(attempt.error) && attempt.error.kind === "not_found" && this.deps.registerDevice !== undefined) {
      // 404: the server has no such device for this account. With the registration path on (`registerDevice`), register it ONCE and ask again; otherwise it is simply "not ready".
      const registered = await this.registerDeviceOnce(owner, deviceId, accessToken);
      if (registered !== null) return registered;
      attempt = await this.requestSeed(owner, deviceId, accessToken, rotate, before);
    }
    if (!attempt.ok) return outcomeOfError(attempt.error);
    const result = attempt.result;

    const seed = base32Decode(result.seed);
    if (seed === null || seed.length !== OFFLINE_SEED_BYTES) return { status: "failed", reason: "bad_response" };
    const receivedAtMs = now();
    const issuedAtMs = Date.parse(result.issuedAt);
    let saved: SaveOutcome;
    try {
      saved = await store.save(owner, deviceId, { seed, seedVersion: result.seedVersion, issuedAtMs, receivedAtMs, resyncNeeded: false });
    } catch {
      return { status: "failed", reason: "storage" };
    } finally {
      seed.fill(0); // best effort: the decoded bytes do not outlive this call here
    }
    if (saved === "kept_newer") return { status: "failed", reason: "stale_seed" };
    return { status: "ready", seedVersion: result.seedVersion, rotated: rotate, clock: clockSkewOf(issuedAtMs, receivedAtMs) };
  }
}
