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
 *  3. ONE ASSERTION IN FLIGHT PER KEY (iOS). The lock for (user, device) is taken before the key is read or registered and released when the HTTP response of the request that
 *     carries the assertion returns or fails (or the hold timeout fires): `mutex.ts`.
 *  4. A 503 `attestation_unavailable` / `attestation_not_configured` from `checkin-token` is the vendor being down: the challenge was NOT consumed. It is rethrown as the ApiError it is
 *     (`evidence/send.ts` answers a retry and leaves the held challenge untouched); nothing here drops or consumes anything.
 *  5. iOS key lifecycle: no registered key -> `generateKey`, register at `devices-attest-key` (LIVE challenge, key id bound), keep it in the secure store; `DCError.invalidKey` on an
 *     assertion (a reinstall destroyed the key) -> drop it and register a fresh one, ONCE per redemption.
 */
import { isApiError, type ApiError } from "../api/errors";
import type { CheckinTokenRequest, CheckinTokenResult, IssuedChallenge } from "../api/types";
import { androidCheckinRequestBinding, attestKeyBinding, iosCheckinBinding } from "./binding";
import { jwtSubject } from "./jwt";
import { KeyedMutex, LockTimeoutError } from "./mutex";
import type { AttestStateStore } from "./state-store";
import type { AttestResult, Attestor } from "./types";

/** After this many deferrals of one held challenge the next local failure drops it. With the outbox's backoff (15 s doubling, capped at 1 h, jittered) 8 deferrals
 * span roughly 30 to 60 minutes of retrying; a challenge also expires on its own (24 h prefetched). */
export const ATTEST_MAX_DEFERRALS = 8;

/** Longest one assertion lock may be held: above the HTTP timeout (20 s) plus the native call and a key registration round trip. */
export const ASSERTION_LOCK_HOLD_MS = 90_000;

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
}

/** ApiError kinds that are the transport or the account, not an answer about the attestation: they pass through unchanged (the send is retried / the session is refreshed). */
const PASS_THROUGH = new Set(["network", "server", "unavailable", "rate_limited", "unauthenticated", "forbidden", "not_supported"]);

/** The registration answered with a refusal of the key itself (as opposed to a refusal of the challenge or the request): nothing was registered, and retrying the same
 * kind of key cannot help. `devices-attest-key` answers these two codes with a 422. */
const KEY_REFUSED_CODES = new Set(["attestation_rejected", "platform_mismatch"]);

export class NativeRedeemer implements CheckinRedeemer {
  constructor(private readonly d: NativeRedeemerDeps) {}

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

  // ---- Android ----------------------------------------------------------------------------------------------------------------------------

  private async redeemAndroid(ctx: RedeemInput, io: RedeemIo): Promise<CheckinTokenResult> {
    let token: string | null = null;
    try {
      const r = await this.d.attestor.integrityToken(androidCheckinRequestBinding({ challengeId: ctx.challengeId, deviceId: ctx.deviceId, userId: ctx.userId }, ctx.nonce));
      if (r.kind === "ok") token = r.value.integrityToken;
    } catch {
      token = null; // a non-canonical nonce (the binding refuses it) or a native failure: the same local failure
    }
    if (token === null) {
      // A LOCAL failure. Rule 2: if this device ever attested, a token-less request is graded `failed` + fraud signal: retry later instead.
      let attestedBefore: boolean;
      try {
        attestedBefore = await this.d.state.hasAttestedAndroid(ctx.userId, ctx.deviceId);
      } catch {
        attestedBefore = true; // cannot tell: the unsafe reading is "never attested"
      }
      if (attestedBefore) throw new AttestationDeferred("integrity_token_unavailable");
      return io.post(wireRequest(ctx));
    }
    let result: CheckinTokenResult;
    try {
      result = await io.post(wireRequest(ctx, { platform: "android", integrityToken: token }));
    } catch (e) {
      // The token was SENT and the outcome is unknown (a lost response, a 5xx): the server may have graded it `attested`. Treat the device as having attested (the unsafe reading is
      // "never"): a later local failure then defers instead of sending a token-less request. A 503 attestation_* (vendor outage) and every 4xx are definite non-applications.
      if (isApiError(e) && (e.kind === "network" || e.kind === "server")) await this.d.state.markAttestedAndroid(ctx.userId, ctx.deviceId).catch(() => undefined);
      throw e;
    }
    if (result.attestationGrade === "attested") await this.d.state.markAttestedAndroid(ctx.userId, ctx.deviceId).catch(() => undefined);
    return result;
  }

  // ---- iOS --------------------------------------------------------------------------------------------------------------------------------

  private redeemIos(ctx: RedeemInput, io: RedeemIo): Promise<CheckinTokenResult> {
    return this.d.locks.run(`ios:${ctx.userId}:${ctx.deviceId.toLowerCase()}`, () => this.redeemIosLocked(ctx, io)).catch((e: unknown) => {
      if (e instanceof LockTimeoutError) throw new AttestationDeferred("assertion_lock_timeout");
      throw e;
    });
  }

  private async redeemIosLocked(ctx: RedeemInput, io: RedeemIo): Promise<CheckinTokenResult> {
    const { state, attestor } = this.d;
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
      // `rec` is `pending` when an earlier registration's outcome is unknown: the server may already hold a key for this device, so a refusal must not read as "none".
      const reg = await this.registerKey(ctx, io, rec !== null);
      if (reg === "refused") {
        if (rec !== null) throw new AttestationDeferred("key_registration_refused"); // the server may still hold a key: no token-less request (rule 2)
        return io.post(wireRequest(ctx)); // the server refused our key and holds none for this device: unattestable, honestly
      }
      keyId = reg;
      reregistered = true;
    }

    const assertOnce = (k: string): Promise<AttestResult<{ assertion: string }>> => {
      try {
        return attestor.assert(k, iosCheckinBinding({ challengeId: ctx.challengeId, deviceId: ctx.deviceId, userId: ctx.userId, nonce: ctx.nonce })).catch((): AttestResult<{ assertion: string }> => ({ kind: "failed", message: "assertion threw" }));
      } catch {
        return Promise.resolve({ kind: "failed", message: "assertion could not be built" }); // e.g. a non-canonical nonce: the binding refuses it
      }
    };
    let r = await assertOnce(keyId);
    if (r.kind === "failed" && r.code === "invalid_key" && !reregistered) {
      // The key is gone (a reinstall destroys the Secure Enclave key; the Keychain item survives). The record is downgraded to `pending` (the server still holds the OLD key, so a
      // token-less request stays forbidden) and a fresh key is registered, once.
      try {
        await state.setIosKey(ctx.userId, ctx.deviceId, { state: "pending" });
      } catch {
        throw new AttestationDeferred("key_state_unwritable");
      }
      const reg = await this.registerKey(ctx, io, true);
      if (reg === "refused") throw new AttestationDeferred("key_registration_refused"); // the server still holds the old key: no token-less request (rule 2)
      keyId = reg;
      r = await assertOnce(keyId);
    }
    if (r.kind !== "ok") throw new AttestationDeferred(r.kind === "failed" && r.code === "invalid_key" ? "key_invalid_after_registration" : "assertion_unavailable");

    const result = await io.post(wireRequest(ctx, { platform: "ios", keyId, assertion: r.value.assertion }));
    if (result.attestationGrade === "unattestable") {
      // We presented a verifiable assertion and the server has no registered key for this device (`key_not_registered`): our record is wrong (the server was reset, or a
      // registration we believe succeeded did not). Drop it so the next redemption registers again.
      await state.clearIosKey(ctx.userId, ctx.deviceId).catch(() => undefined);
    }
    return result;
  }

  /** Registers a fresh App Attest key. Returns its key id, or `"refused"` when the server refused the key itself (a build / configuration mismatch). Throws
   * `AttestationDeferred` for a local failure and the `ApiError` for a transport failure. `hadKey`: a key may already be on record at the server (a registered key was
   * dropped, or an earlier registration's outcome is unknown), so a refusal keeps the `pending` mark instead of clearing it. */
  private async registerKey(ctx: RedeemInput, io: RedeemIo, hadKey: boolean): Promise<string | "refused"> {
    const { state, attestor } = this.d;
    const live = await this.guardApi(() => io.requestLiveChallenge());
    const gen = await attestor.generateKey().catch(() => null);
    if (gen === null || gen.kind !== "ok") throw new AttestationDeferred("generate_key_failed");
    const keyId = gen.value.keyId;
    const binding = { challengeId: live.id, deviceId: ctx.deviceId, keyId, nonce: live.nonce };
    let attestation: string;
    try {
      const att = await attestor.attestKey(keyId, attestKeyBinding(binding));
      if (att.kind !== "ok") throw new Error("attestKey");
      attestation = att.value.attestation;
    } catch {
      throw new AttestationDeferred("attest_key_failed");
    }
    // Everything above is local or a read: nothing has been sent that could register a key. From here on the server MAY know this device can attest (a registration can be
    // applied although its answer is lost), so `pending` is written BEFORE the request, and no token-less request is sent while it stands.
    try {
      await state.setIosKey(ctx.userId, ctx.deviceId, { state: "pending" });
    } catch {
      throw new AttestationDeferred("key_state_unwritable");
    }
    try {
      await io.registerKey({ deviceId: ctx.deviceId, challengeId: live.id, nonce: live.nonce, keyId, attestation });
    } catch (e) {
      if (isApiError(e) && e.kind === "conflict" && e.code === "key_already_registered") {
        // The server already holds exactly this key (an earlier request of ours was applied and its answer was lost): it is registered.
      } else if (isApiError(e) && e.kind === "rejected" && e.code !== null && KEY_REFUSED_CODES.has(e.code)) {
        if (!hadKey) await state.clearIosKey(ctx.userId, ctx.deviceId).catch(() => undefined);
        return "refused";
      } else {
        throw this.registrationError(e);
      }
    }
    try {
      await state.setIosKey(ctx.userId, ctx.deviceId, { state: "registered", keyId });
    } catch {
      throw new AttestationDeferred("key_state_unwritable");
    }
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
    if (isApiError(e)) return PASS_THROUGH.has((e as ApiError).kind) ? e : new AttestationDeferred(`registration_${e.code ?? e.kind}`);
    return new AttestationDeferred("registration_failed");
  }
}
