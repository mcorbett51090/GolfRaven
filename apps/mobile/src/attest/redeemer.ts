/**
 * Redeeming a check-in challenge (`POST checkin-token`) WITH device attestation (P4.2b-2). The one place that decides what a redemption request carries.
 *
 * THE RULES (each is a test in `test/attest-redeemer.test.ts`):
 *  1. HONEST CAPABILITY. `hardwareSupportsAttestation` is true if and only if the request carries an attestation block. Never true without a token: the server
 *     grades "claims it can, sent nothing" `failed` and opens a fraud signal. (`wireRequest` is the only constructor of the wire body, so there is one place to check.)
 *  2. NEVER TOKEN-LESS ONCE THE DEVICE HAS SHOWN IT CAN ATTEST. The server grades a request with no token `failed` + fraud signal, whatever it claims, when the device row has
 *     a REGISTERED App Attest key (iOS) or an earlier token graded `attested` (Android) (`token-handler.ts` `deviceHasShownAttestation`). So after a local failure the client
 *     does not send a token-less request in those states: it throws `AttestationDeferred` and the send is retried later (the held challenge stays). `evidence/send.ts`
 *     counts the deferrals on the held challenge and, after `ATTEST_MAX_DEFERRALS`, drops the challenge: the play goes with no challenge (x0.6, no co-signal, no fraud
 *     signal) rather than as a token-less request that would raise one. A device that has never shown it can attest sends token-less with `false` (`unattestable`).
 *  3. ONE ASSERTION IN FLIGHT PER KEY (iOS), AND ONE CHECK-IN OR ACTIVATION AT A TIME PER DEVICE (Android). The lock for (user, device) is taken before the key is read or registered
 *     (iOS) / before the Play Integrity call (Android) and released when the HTTP response of the request that carries the assertion or token returns or fails: `mutex.ts`. On Android
 *     there is no counter; the lock makes "read the attested-before mark, send token-less, write the mark" atomic against a concurrent activation or check-in (PR #44 gate LOW-1). The hold timeout does not abandon a running holder: it ABORTS it. The holder calls `guard.check()` before every side
 *     effect (state write, native call, HTTP request), runs a SENT request through `guard.effect` (the lock is kept until it settles), and each native call has its own timeout.
 *     An aborted holder therefore performs no further effect, so it can never register a key or send a request outside the lock (PR #42 gate HIGH-1).
 *  4. A 503 `attestation_unavailable` / `attestation_not_configured` from `checkin-token` is the vendor being down: the challenge was NOT consumed. It is rethrown as the ApiError it is
 *     (`evidence/send.ts` answers a retry and leaves the held challenge untouched); nothing here drops or consumes anything.
 *  5. iOS key lifecycle: no registered key -> `generateKey`, register at `devices-attest-key` (LIVE challenge, key id bound), keep it in the secure store; `DCError.invalidKey` on an
 *     assertion (a reinstall destroyed the key) -> drop it and register a fresh one, ONCE per redemption.
 *  6. STALE KEY RECOVERY (the server's `rekey: true` hint on `checkin-token`; `docs/security/p3-money-path-requirements.md` "Stale App Attest key recovery"). The token is valid whatever grade
 *     it carries (its jti is used as normal, never discarded). INSIDE the assertion lock the local key is marked `stale` (persisted, per user and device). At the NEXT iOS assertion need
 *     (a check-in, or an activation: `obtainIosAssertion` is shared) a FRESH key is generated (the stale one is never asserted with or registered again; a key that Apple attested once
 *     cannot be attested again), registered at `devices-attest-key` and used; the answer there is 200 `replaced: true` (counter restarts at 0) or 201. NEVER A LOOP: a recovery's
 *     registration request is preceded by a persisted cooldown (`registrationBackoffMs`, 1 h), written whatever the outcome, so at most ONE recovery registration per cooldown: a second `rekey`
 *     inside it (or a 429, a refusal, a lost answer) leaves the key `stale` and the need DEFERS (rule 2: the server holds a key, so never token-less) until the cooldown ends. A 409
 *     `key_previously_retired` means that key is dead on the server: ONE more fresh key is tried, then the registration backoff is set and the need defers. `rewards-activate` carries no hint:
 *     a stale key found there changes nothing; the next check-in's hint starts the recovery.
 */
import { isApiError, type ApiError } from "../api/errors";
import type { CheckinTokenRequest, CheckinTokenResult, IssuedChallenge } from "../api/types";
import { androidCheckinRequestBinding, attestKeyBinding, iosCheckinBinding } from "./binding";
import { jwtSubject } from "./jwt";
import { KeyedMutex, LockAbortedError, LockTimeoutError, withAssertionLock, type LockGuard } from "./mutex";
import type { AttestStateStore } from "./state-store";
import type { AttestResult, Attestor } from "./types";

/** After this many deferrals of one held challenge the next local failure drops it. With the outbox's backoff (15 s doubling, capped at 1 h, jittered) 8 deferrals
 * span roughly 30 to 60 minutes of retrying; a challenge also expires on its own (24 h prefetched). */
export const ATTEST_MAX_DEFERRALS = 8;

/** How long a holder may keep taking its own steps before the lock aborts it (`mutex.ts`). A request already sent is never abandoned, whatever this is. */
export const ASSERTION_LOCK_HOLD_MS = 90_000;

/** Each native call (generateKey, attestKey, generateAssertion, the integrity request) is bounded on its own; past this it counts as a transient local failure and its late
 * result, if any, is discarded. Below the lock hold time, so one stuck call cannot by itself use up the lock. */
export const NATIVE_CALL_TIMEOUT_MS = 30_000;

/** After the server answers that it cannot hold an App Attest key (503 `attestation_not_configured` from `devices-attest-key`, or a refusal of the key itself) or the device cannot
 * do App Attest at all, key registration is not attempted again for this long (persisted per user and device). Without it every outbox retry would spend a live challenge (the
 * 30/h limit is shared with live check-in) and an Apple `attestKey`. An hour: long enough to stop the churn, short enough to pick up a fixed deployment the same session. */
export const REGISTRATION_BACKOFF_MS = 60 * 60_000;

/** The attestation could not be produced right now and a token-less request must NOT be sent instead (rule 2). Retry later. */
export class AttestationDeferred extends Error {
  constructor(readonly reason: string) {
    super(`attestation deferred: ${reason}`);
    this.name = "AttestationDeferred";
  }
}

export interface RedeemInput {
  challengeId: string;
  /** The raw nonce text the challenge endpoint returned. */
  nonce: string;
  /** The device id the challenge was issued to. */
  deviceId: string;
  /** The account the credentials belong to. */
  userId: string;
  /** Its bearer token (the binding names its `sub`). */
  accessToken: string;
}

export interface AttestKeyRegistration {
  deviceId: string;
  challengeId: string;
  nonce: string;
  keyId: string;
  attestation: string;
}

/** The HTTP the redeemer needs, supplied by the API client (which owns the transport, the timeout and the bearer). Each throws `ApiError`. */
export interface RedeemIo {
  /** `POST checkin-token` with exactly this body. */
  post(req: CheckinTokenRequest): Promise<CheckinTokenResult>;
  /** A LIVE check-in challenge for this device (`POST checkin-challenge`), used to register an App Attest key. */
  requestLiveChallenge(): Promise<IssuedChallenge>;
  /** `POST devices-attest-key`. */
  registerKey(req: AttestKeyRegistration): Promise<void>;
}

export interface CheckinRedeemer {
  redeem(input: RedeemInput, io: RedeemIo): Promise<CheckinTokenResult>;
}

/** The wire body. The ONLY constructor: `hardwareSupportsAttestation` is `attestation !== undefined`, never a free input (rule 1). */
export function wireRequest(base: { challengeId: string; nonce: string }, attestation?: NonNullable<CheckinTokenRequest["attestation"]>): CheckinTokenRequest {
  return { challengeId: base.challengeId, nonce: base.nonce, hardwareSupportsAttestation: attestation !== undefined, ...(attestation !== undefined ? { attestation } : {}) };
}

/** No attestation, ever: builds, tests, web, Expo Go, a device that cannot attest. Claims `false`, so the server grades `unattestable`. */
export class PlainRedeemer implements CheckinRedeemer {
  redeem(input: RedeemInput, io: RedeemIo): Promise<CheckinTokenResult> {
    return io.post(wireRequest(input));
  }
}

export interface NativeRedeemerDeps {
  attestor: Attestor;
  state: AttestStateStore;
  locks: KeyedMutex;
  /** Epoch ms. Default `Date.now`. */
  now?: () => number;
  /** Per native call. Default `NATIVE_CALL_TIMEOUT_MS`. */
  nativeTimeoutMs?: number;
  /** Default `REGISTRATION_BACKOFF_MS`. */
  registrationBackoffMs?: number;
}

/** ApiError kinds that are the transport or the account, not an answer about the attestation: they pass through unchanged (the send is retried / the session is refreshed). */
const PASS_THROUGH = new Set(["network", "server", "unavailable", "rate_limited", "unauthenticated", "forbidden", "not_supported"]);

/** The registration answered with a refusal of the key itself (as opposed to a refusal of the challenge or the request): nothing was registered, and retrying the same
 * kind of key cannot help. `devices-attest-key` answers these two codes with a 422. */
const KEY_REFUSED_CODES = new Set(["attestation_rejected", "platform_mismatch"]);

/** `devices-attest-key` answers this 503 BEFORE it reads or writes anything (`attest-key-handler.ts`, recorded `attestkey_503_not_configured`): the deployment cannot hold an
 * App Attest key, nothing was applied, and asking again soon cannot change that. */
function isNotConfigured503(e: unknown): boolean {
  return isApiError(e) && e.status === 503 && e.code === "attestation_not_configured";
}

/** Did this failed request DEFINITELY not take effect at the server? A 4xx (including 429 and 401) was refused before any grading; a 503 `attestation_*` is the vendor-outage
 * rollback of `checkin-token`. Anything else (a lost response, a 5xx or 502 / 503 / 504 without that code, a 2xx whose body could not be read) MAY have been applied. */
export function isDefiniteNonApplication(e: unknown): boolean {
  if (!isApiError(e)) return false;
  if (e.kind === "not_configured") return true; // no request was made at all
  if (e.status !== null && e.status >= 400 && e.status < 500) return true;
  return e.status === 503 && e.code !== null && e.code.startsWith("attestation_");
}

export class NativeRedeemer implements CheckinRedeemer {
  private readonly now: () => number;
  private readonly nativeTimeoutMs: number;
  private readonly backoffMs: number;

  constructor(private readonly d: NativeRedeemerDeps) {
    this.now = d.now ?? Date.now;
    this.nativeTimeoutMs = d.nativeTimeoutMs ?? NATIVE_CALL_TIMEOUT_MS;
    this.backoffMs = d.registrationBackoffMs ?? REGISTRATION_BACKOFF_MS;
  }

  async redeem(input: RedeemInput, io: RedeemIo): Promise<CheckinTokenResult> {
    const sub = jwtSubject(input.accessToken);
    if (sub === null) throw new AttestationDeferred("no_account_binding"); // the binding names the token's `sub`; without it nothing honest can be bound
    if (sub.toLowerCase() !== input.userId.toLowerCase()) throw new AttestationDeferred("account_mismatch");
    const ctx = { ...input, userId: sub };
    const platform = this.d.attestor.capability.platform;
    if (platform === "ios") return this.redeemIos(ctx, io);
    if (platform === "android") return this.redeemAndroid(ctx, io);
    return io.post(wireRequest(input));
  }

  /** One native call, bounded: past the timeout it is a transient local failure and its late result is discarded. Public: reward activation (`activator.ts`) bounds its own native calls the same way. */
  native<T>(call: () => Promise<AttestResult<T>>): Promise<AttestResult<T>> {
    return new Promise((resolve) => {
      const timer = setTimeout(() => resolve({ kind: "failed", message: `the native call did not answer within ${this.nativeTimeoutMs} ms`, code: "unavailable" }), this.nativeTimeoutMs);
      let p: Promise<AttestResult<T>>;
      try {
        p = call();
      } catch (e) {
        clearTimeout(timer);
        resolve({ kind: "failed", message: e instanceof Error ? e.message : "native call threw" });
        return;
      }
      p.then(
        (r) => {
          clearTimeout(timer);
          resolve(r);
        },
        (e: unknown) => {
          clearTimeout(timer);
          resolve({ kind: "failed", message: e instanceof Error ? e.message : "native call rejected" });
        },
      );
    });
  }

  // ---- Android ----------------------------------------------------------------------------------------------------------------------------

  /**
   * Android check-in, under the SAME assertion lock as iOS and as every activation (`assertionLockKey`; PR #44 gate LOW-1). Android has no counter to keep in order, but it has a
   * read-then-act race on the "attested before" mark: an activation whose request carries a token is in flight and its `attested` verdict has not committed yet; a check-in whose
   * Play Integrity call fails locally reads "never attested" and sends a TOKEN-LESS request; the verdict commits first, and the server grades that check-in `failed` + fraud signal
   * (rule 2). Two concurrent Android check-ins have the same shape. Under the lock the read of the mark, the token-less request and the write of the mark are one critical
   * section, so the later holder always sees what the earlier one recorded. Abort semantics are iOS's: `check()` before each native call, state read and write-before-send, a SENT
   * request through `effect`, and the mark written after a sent token is recorded without an abort check (the state must follow the server).
   */
  private redeemAndroid(ctx: RedeemInput, io: RedeemIo): Promise<CheckinTokenResult> {
    return withAssertionLock(this.d.locks, ctx.userId, ctx.deviceId, (g) => this.redeemAndroidLocked(ctx, io, g)).catch((e: unknown) => {
      if (e instanceof LockTimeoutError) throw new AttestationDeferred("assertion_lock_timeout");
      throw e;
    });
  }

  private async redeemAndroidLocked(ctx: RedeemInput, io: RedeemIo, g: LockGuard): Promise<CheckinTokenResult> {
    let hash: Uint8Array | null;
    try {
      hash = androidCheckinRequestBinding({ challengeId: ctx.challengeId, deviceId: ctx.deviceId, userId: ctx.userId }, ctx.nonce);
    } catch {
      hash = null; // a non-canonical nonce (the binding refuses it): the same local failure
    }
    let token: string | null = null;
    if (hash !== null) {
      const h = hash;
      g.check();
      const r = await this.native(() => this.d.attestor.integrityToken(h));
      g.check(); // a native call that returned after the lock gave up on this holder changes nothing
      if (r.kind === "ok") token = r.value.integrityToken;
    }
    if (token === null) {
      // A LOCAL failure. Rule 2: if this device ever attested, a token-less request is graded `failed` + fraud signal: retry later instead.
      g.check();
      let attestedBefore: boolean;
      try {
        attestedBefore = await this.d.state.hasAttestedAndroid(ctx.userId, ctx.deviceId);
      } catch {
        attestedBefore = true; // cannot tell: the unsafe reading is "never attested"
      }
      if (attestedBefore) throw new AttestationDeferred("integrity_token_unavailable");
      return g.effect(() => io.post(wireRequest(ctx)));
    }
    const sent = token;
    let result: CheckinTokenResult;
    try {
      result = await g.effect(() => io.post(wireRequest(ctx, { platform: "android", integrityToken: sent })));
    } catch (e) {
      // The token was SENT. Unless the request DEFINITELY did not take effect (`isDefiniteNonApplication`), the server may have graded it `attested` (a lost response, a 5xx, a gateway
      // 502 / 504, a 503 without an `attestation_*` code, a 2xx body that could not be read): treat the device as having attested (the unsafe reading is "never"), so a later local
      // failure defers instead of sending a token-less request.
      if (!isDefiniteNonApplication(e)) await g.settle(() => this.d.state.markAttestedAndroid(ctx.userId, ctx.deviceId).catch(() => undefined));
      throw e;
    }
    // The mark follows the server: no abort check, but held through `settle`, so the hold timeout cannot release the lock (and throw the real answer away) while it is being written.
    if (result.attestationGrade === "attested") await g.settle(() => this.d.state.markAttestedAndroid(ctx.userId, ctx.deviceId).catch(() => undefined));
    return result;
  }

  // ---- iOS --------------------------------------------------------------------------------------------------------------------------------

  private redeemIos(ctx: RedeemInput, io: RedeemIo): Promise<CheckinTokenResult> {
    return withAssertionLock(this.d.locks, ctx.userId, ctx.deviceId, (g) => this.redeemIosLocked(ctx, io, g)).catch((e: unknown) => {
      if (e instanceof LockTimeoutError) throw new AttestationDeferred("assertion_lock_timeout");
      throw e;
    });
  }

  private async redeemIosLocked(ctx: RedeemInput, io: RedeemIo, g: LockGuard): Promise<CheckinTokenResult> {
    const { state } = this.d;
    const got = await this.obtainIosAssertion(ctx, io, g, async () => {
      try {
        return iosCheckinBinding({ challengeId: ctx.challengeId, deviceId: ctx.deviceId, userId: ctx.userId, nonce: ctx.nonce });
      } catch {
        return null; // e.g. a non-canonical nonce: the binding refuses it
      }
    });
    // The server holds no key for this device and cannot take one: unattestable, honestly.
    if (got.kind === "none") return g.effect(() => io.post(wireRequest(ctx)));

    const result = await g.effect(() => io.post(wireRequest(ctx, { platform: "ios", keyId: got.keyId, assertion: got.assertion })));
    if (result.rekey === true) {
      // Rule 6. The server says the key we just asserted with is not the one it holds (`failed`), or holds none (`unattestable`). The token and its grade are used as they are: the answer is
      // returned untouched. The mark is written with no abort check, like the clears below: the request was SENT, its answer is real, the lock is still held (an effect kept it), and the
      // state must follow the server. A store that cannot be written loses only the mark: the next assertion with this key brings the same hint.
      await g.settle(() => state.setIosKey(ctx.userId, ctx.deviceId, { state: "stale", keyId: got.keyId }).catch(() => undefined));
    } else if (result.attestationGrade === "unattestable") {
      // We presented a verifiable assertion and the server has no registered key for this device (`key_not_registered`): our record is wrong (the server was reset, or a
      // registration we believe succeeded did not). Drop it so the next redemption registers again.
      await g.settle(() => state.clearIosKey(ctx.userId, ctx.deviceId).catch(() => undefined));
    }
    return result;
  }

  /**
   * The iOS half that check-in redemption and reward activation SHARE (P4.2b-3b): the App Attest key lifecycle and one assertion, under a lock the CALLER already holds
   * (`g`; `withAssertionLock`, the one lock of this (user, device) key). It exists once so a second copy cannot drift from the first (PR #42 gate HIGH-1, MEDIUM-2).
   *
   * Returns `{ kind: "assertion" }` with the key id and the base64 assertion, or `{ kind: "none" }` when the server holds no key for this device and cannot take one (the device
   * cannot do App Attest at all, a deployment with no App Attest configuration, a refused key) and no earlier registration is on record: the caller then sends its request without
   * an attestation, claiming `false`. Every other failure throws `AttestationDeferred` (a local failure: no token-less request while the device may hold a key, rule 2) or the
   * `ApiError` of a registration-phase transport failure.
   *
   * `hashFor` builds the 32-byte `clientDataHash` the assertion signs. It is called AFTER the key is known (so a device that cannot attest never costs the caller a challenge) and
   * again, with the same closure, only on the one `invalid_key` retry. `null` = it could not be built (a local failure); anything it throws propagates unchanged, because an activation's
   * `hashFor` makes a request (its live challenge) whose `ApiError` must reach the caller as it is.
   */
  async obtainIosAssertion(
    ctx: { userId: string; deviceId: string },
    io: Pick<RedeemIo, "requestLiveChallenge" | "registerKey">,
    g: LockGuard,
    hashFor: () => Promise<Uint8Array | null>,
  ): Promise<{ kind: "none" } | { kind: "assertion"; keyId: string; assertion: string }> {
    const { state } = this.d;
    let rec: Awaited<ReturnType<AttestStateStore["getIosKey"]>>;
    try {
      rec = await state.getIosKey(ctx.userId, ctx.deviceId);
    } catch {
      throw new AttestationDeferred("key_state_unreadable");
    }
    let keyId: string | null = null;
    let reregistered = false;
    if (rec?.state === "registered") keyId = rec.keyId;
    else {
      // `stale`: a recovery (rule 6). The server holds a key for this device that is not the one we have, so a refusal below defers (`rec !== null`) instead of going token-less.
      const recovering = rec?.state === "stale";
      let backoffUntil: number;
      let cooldownUntil = 0;
      try {
        backoffUntil = await state.getRegistrationBackoffUntil(ctx.userId, ctx.deviceId);
        if (recovering) cooldownUntil = await state.getRekeyCooldownUntil(ctx.userId, ctx.deviceId);
      } catch {
        throw new AttestationDeferred("key_state_unreadable");
      }
      // At most one recovery registration per cooldown. A cooldown further away than the cooldown itself is a clock that moved: it is not honoured past one cooldown.
      if (recovering && this.now() < cooldownUntil && cooldownUntil - this.now() <= this.backoffMs) throw new AttestationDeferred("rekey_cooldown");
      let reg: string | "refused";
      if (this.now() < backoffUntil) reg = "refused"; // the server (or the device) cannot hold a key: not asked again until the backoff ends
      else reg = await this.registerKey(ctx, io, g, rec !== null, recovering);
      if (reg === "refused") {
        // `rec` is `pending` when an earlier registration's outcome is unknown: the server may already hold a key for this device, so a refusal must not read as "none".
        if (rec !== null) throw new AttestationDeferred("key_registration_refused"); // the server may hold a key: no token-less request (rule 2)
        return { kind: "none" }; // the server holds no key for this device and cannot take one: unattestable, honestly
      }
      keyId = reg;
      reregistered = true;
    }

    const assertOnce = async (k: string): Promise<AttestResult<{ assertion: string }>> => {
      const hash = await hashFor();
      if (hash === null) return { kind: "failed", message: "assertion could not be built" };
      g.check();
      return this.native(() => this.d.attestor.assert(k, hash));
    };
    let r = await assertOnce(keyId);
    if (r.kind === "failed" && r.code === "invalid_key" && !reregistered) {
      // The key is gone (a reinstall destroys the Secure Enclave key; the Keychain item survives). The record is downgraded to `pending` (the server still holds the OLD key, so a
      // token-less request stays forbidden) and a fresh key is registered, once.
      g.check();
      try {
        await state.setIosKey(ctx.userId, ctx.deviceId, { state: "pending" });
      } catch {
        throw new AttestationDeferred("key_state_unwritable");
      }
      const reg = await this.registerKey(ctx, io, g, true, false);
      if (reg === "refused") throw new AttestationDeferred("key_registration_refused"); // the server still holds the old key: no token-less request (rule 2)
      keyId = reg;
      r = await assertOnce(keyId);
    }
    if (r.kind !== "ok") throw new AttestationDeferred(r.kind === "failed" && r.code === "invalid_key" ? "key_invalid_after_registration" : "assertion_unavailable");
    return { kind: "assertion", keyId, assertion: r.value.assertion };
  }

  /** Registers an App Attest key. Returns its key id, or `"refused"` when the server cannot or will not hold a key for this device (a refusal of the key itself, a deployment with no
   * App Attest configuration) or the device cannot do App Attest at all: the registration is then not attempted again until the backoff ends. Throws `AttestationDeferred` for a
   * local failure and the `ApiError` for a transport failure. `hadKey`: a key may already be on record at the server (a registered key was dropped, or an earlier registration's
   * outcome is unknown), so a refusal keeps the `pending` mark instead of clearing it.
   *
   * ORDER, so that a failure never costs more than it must: the key is made (or the unattested one from an earlier try reused) BEFORE the live challenge is requested, so a local
   * failure never spends a live challenge (the 30/h limit is shared with live check-in); `pending` is written right before the registration request is sent, so a failure before it
   * leaves no record. Every step first checks the lock guard (`mutex.ts`): an aborted holder does nothing more.
   *
   * `recovering` (a `stale` key, rule 6): the stale record is KEPT through the attempt (it already says "the server holds a key": no token-less request) instead of being replaced by `pending`,
   * and the recovery cooldown is written right before the request, whatever the outcome. A 409 `key_previously_retired` (the server remembers this key as dead on the device) burns that key
   * and ONE more fresh key is registered; a second one sets the registration backoff and defers. */
  private async registerKey(ctx: { userId: string; deviceId: string }, io: Pick<RedeemIo, "requestLiveChallenge" | "registerKey">, g: LockGuard, hadKey: boolean, recovering: boolean): Promise<string | "refused"> {
    let r = await this.registerOnce(ctx, io, g, hadKey, recovering);
    if (r === "retired") r = await this.registerOnce(ctx, io, g, hadKey, recovering); // exactly one more fresh key: the one just refused is burned (`clearUnattestedKey` ran), so this one is new
    if (r === "retired") {
      await g.settle(() => this.d.state.setRegistrationBackoffUntil(ctx.userId, ctx.deviceId, this.now() + this.backoffMs).catch(() => undefined));
      throw new AttestationDeferred("registration_key_previously_retired"); // the server holds a key (a retired one proves it): never token-less
    }
    return r;
  }

  private async registerOnce(ctx: { userId: string; deviceId: string }, io: Pick<RedeemIo, "requestLiveChallenge" | "registerKey">, g: LockGuard, hadKey: boolean, recovering: boolean): Promise<string | "refused" | "retired"> {
    const { state, attestor } = this.d;
    const backoff = async (): Promise<void> => {
      await state.setRegistrationBackoffUntil(ctx.userId, ctx.deviceId, this.now() + this.backoffMs).catch(() => undefined);
    };

    // 1. the key (local)
    let keyId: string | null = null;
    try {
      keyId = await state.getUnattestedKey(ctx.userId, ctx.deviceId);
    } catch {
      keyId = null;
    }
    if (keyId === null) {
      g.check();
      const gen = await this.native(() => attestor.generateKey());
      g.check(); // a native call that returned after the lock gave up on this holder changes nothing
      if (gen.kind === "unattestable") {
        await backoff();
        return "refused"; // this device cannot do App Attest at all
      }
      if (gen.kind !== "ok") throw new AttestationDeferred("generate_key_failed");
      keyId = gen.value.keyId;
      g.check();
      await state.setUnattestedKey(ctx.userId, ctx.deviceId, keyId).catch(() => undefined); // an optimisation only: lets a retry reuse the SAME key
    }

    // 2. the live challenge (a request: it is held as an effect, so the lock is not released under it)
    const live = await this.guardApi(() => g.effect(() => io.requestLiveChallenge()));

    // 3. attestKey (local; Apple's service)
    g.check();
    const att = await this.native(() => attestor.attestKey(keyId!, attestKeyBinding({ challengeId: live.id, deviceId: ctx.deviceId, keyId: keyId!, nonce: live.nonce })));
    g.check();
    if (att.kind !== "ok") {
      if (att.kind === "failed" && att.code === "unavailable") throw new AttestationDeferred("attest_key_unavailable"); // Apple's service: the SAME key is kept and retried next time
      await state.clearUnattestedKey(ctx.userId, ctx.deviceId).catch(() => undefined); // any other failure burns this key
      if (att.kind === "unattestable") {
        await backoff();
        return "refused";
      }
      throw new AttestationDeferred("attest_key_failed");
    }
    await state.clearUnattestedKey(ctx.userId, ctx.deviceId).catch(() => undefined); // attested: it cannot be attested again, whatever the server says next
    const attestation = att.value.attestation;

    // 4. the registration request. From here on the server MAY know this device can attest (a registration can be applied although its answer is lost), so `pending` is written
    //    BEFORE the request, and no token-less request is sent while it stands.
    g.check();
    try {
      if (recovering) await state.setRekeyCooldownUntil(ctx.userId, ctx.deviceId, this.now() + this.backoffMs); // the cap: written BEFORE the request, so no outcome of it can be retried inside the cooldown
      else await state.setIosKey(ctx.userId, ctx.deviceId, { state: "pending" });
    } catch {
      throw new AttestationDeferred("key_state_unwritable");
    }
    try {
      await g.effect(() => io.registerKey({ deviceId: ctx.deviceId, challengeId: live.id, nonce: live.nonce, keyId: keyId!, attestation }));
    } catch (e) {
      if (isApiError(e) && e.kind === "conflict" && e.code === "key_already_registered") {
        // The server already holds exactly this key (an earlier request of ours was applied and its answer was lost): it is registered.
      } else if (isApiError(e) && e.kind === "conflict" && e.code === "key_previously_retired") {
        // The server remembers this key as replaced on this device: it can never be registered. Nothing was applied; the caller tries ONE more fresh key. The record is untouched
        // (`pending`, or `stale` in a recovery): the server holds a key.
        return "retired";
      } else if ((isApiError(e) && e.kind === "rejected" && e.code !== null && KEY_REFUSED_CODES.has(e.code)) || isNotConfigured503(e)) {
        // Nothing was registered: a refusal of the key, or a deployment that cannot hold one (answered before anything is read or written). Without an earlier key the server holds none:
        // clear the mark; either way do not ask again for a while.
        if (!hadKey) await g.settle(() => state.clearIosKey(ctx.userId, ctx.deviceId).catch(() => undefined));
        await g.settle(backoff);
        return "refused";
      } else {
        throw this.registrationError(e);
      }
    }
    // The registration took effect: record it (no abort check: the lock is still held by this holder, and the state must follow the server).
    // Held through `settle`: the hold timeout cannot release the lock mid-write (PR #42 gate NIT), or the next holder would read a record that does not yet name the key the server holds.
    try {
      await g.settle(() => state.setIosKey(ctx.userId, ctx.deviceId, { state: "registered", keyId }));
    } catch {
      throw new AttestationDeferred("key_state_unwritable");
    }
    await g.settle(() => state.clearRegistrationBackoff(ctx.userId, ctx.deviceId).catch(() => undefined));
    return keyId;
  }

  private async guardApi<T>(fn: () => Promise<T>): Promise<T> {
    try {
      return await fn();
    } catch (e) {
      throw this.registrationError(e);
    }
  }

  /** A registration-phase error. Transport / account errors pass through (the caller's retry logic handles them); any other answer here is about the REGISTRATION (a used or
   * expired live challenge, a malformed request), never about the held check-in challenge, so it must not reach `evidence/send.ts` as a refusal of that challenge. */
  private registrationError(e: unknown): unknown {
    if (e instanceof LockAbortedError) return e;
    if (isApiError(e)) return PASS_THROUGH.has((e as ApiError).kind) ? e : new AttestationDeferred(`registration_${e.code ?? e.kind}`);
    return new AttestationDeferred("registration_failed");
  }
}
