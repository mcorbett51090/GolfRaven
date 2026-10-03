/**
 * Activating a reward (`POST rewards-activate/{id}`) WITH device attestation (P4.2b-3b; build plan §7.5 "Earned on the server, activated on a device"). The one place that decides what
 * an activation request carries, built on the same pieces check-in redemption uses (`redeemer.ts`) so the two cannot disagree about the App Attest key, its counter, or what a device
 * that can attest may send.
 *
 * THE RULES (each is a test in `test/attest-activator.test.ts`):
 *  1. ONE ASSERTION IN FLIGHT PER KEY, ACROSS BOTH ENDPOINTS (PR #40 gate LOW-1; mandatory). `rewards-activate` shares its App Attest counter with `checkin-token`: two assertions that
 *     arrive out of order grade an honest client `failed` plus a fraud signal. Every activation therefore runs inside `withAssertionLock(locks, userId, deviceId, ...)`, the lock check-in
 *     redemption takes (`assertionLockKey`), from the key lookup until the HTTP response of the request that carries the assertion has returned or failed. It is taken on Android too: an
 *     activation there has no counter, but "an activation runs under the (user, device) lock" is then true without exception. The lock's cooperative abort (`mutex.ts`) applies unchanged.
 *  2. HONEST CAPABILITY. `attestation.kind: "none"` always claims `hardwareSupportsAttestation: false`; `activationWireRequest` is the only constructor of the wire body, so there is one
 *     place to check (a claim of "I can attest" with no token is graded `failed` plus a fraud signal, `attestation-evidence.ts`). A token is sent as `kind: "ios"` / `"android"`, never as `none`.
 *  3. A DEVICE THAT CAN ATTEST NEVER SENDS A TOKEN-LESS ACTIVATION BECAUSE OF A LOCAL FAILURE. An activation that is held waits for a HUMAN and activation never releases it (`handleActivation`
 *     step 2), so sending `none` after a transient failure would turn a retry-in-a-minute into a review queue entry. `none` is sent only when the platform says it CANNOT attest at all
 *     (`unattestable`: no Play Integrity, no App Attest, a deployment that refuses the key), and on Android only if no token was ever graded `attested` on this device (the server grades
 *     that token-less request `failed` + fraud signal, rule 2 of `redeemer.ts`). Every other local failure throws `AttestationDeferred` and the caller says "try again later".
 *  4. The iOS key lifecycle is the redeemer's (`obtainIosAssertion`): one implementation. The activation's own LIVE challenge (`consumeLiveChallenge`: live only, 120 s) is requested AFTER the key
 *     is known, so a device that cannot attest costs no challenge, and inside the lock as an effect. The binding is `iosActivationBinding` / `androidRequestBinding` (`binding.ts`), compared
 *     in tests with the vectors the server's own functions produced.
 *  5. ANDROID "ATTESTED BEFORE" (`markAttestedActivation`). The server grades a token-less CHECK-IN `failed` once the device has an `attested` check-in token OR an `attested` activation verdict
 *     (0043). The activation answer carries no grade (`ActivationResult`: id, kind, state, held, replay), so the client reads it from what the server did: a non-replay answer to a request that
 *     carried a token means the server graded that token and recorded a verdict on the device, which may be `attested` (every `issued` / `redeemable` answer is: the decision table activates only an
 *     attested grade) or, for a `held_review`, any grade (the hold can come from the bits, the account, or the grade; the answer does not say which). The mark only ever makes the client
 *     MORE cautious (a later local failure defers instead of going token-less), so a hold of unknown grade is marked too. A `replay` answer wrote nothing, and a definite non-application (a 4xx,
 *     a 503 `attestation_*`) recorded no verdict: neither marks. An outcome that is UNKNOWN after the request was sent (a lost response, a 5xx) marks, as `redeemer.ts` does.
 */
import { sha256 } from "@noble/hashes/sha2.js";
import type { ActivationAnswer, ActivationAttestation, ActivationWireRequest, IssuedChallenge } from "../api/types";
import { utf8Encode } from "../catalog/bytes";
import { androidRequestBinding, bytesToHex, iosActivationBinding, nonceBytesStrict } from "./binding";
import { jwtSubject } from "./jwt";
import { LockTimeoutError, type LockGuard } from "./mutex";
import { AttestationDeferred, isDefiniteNonApplication, type AttestKeyRegistration, type NativeRedeemer } from "./redeemer";
import type { AttestStateStore } from "./state-store";
import type { Attestor } from "./types";

export interface ActivateInput {
  rewardId: string;
  deviceId: string;
  /** The account the credentials belong to. */
  userId: string;
  /** Its bearer token (its `sub` must be `userId`: the attestation state is per account). */
  accessToken: string;
}

/** The HTTP an activation needs, supplied by the API client (which owns the transport, the timeout and the bearer). Each throws `ApiError`. */
export interface ActivateIo {
  /** `POST rewards-activate/{rewardId}` with exactly this body. */
  post(req: ActivationWireRequest): Promise<ActivationAnswer>;
  /** A LIVE challenge for this device (`POST checkin-challenge`): the activation's own, and the one a key registration uses. */
  requestLiveChallenge(): Promise<IssuedChallenge>;
  /** `POST devices-attest-key`. */
  registerKey(req: AttestKeyRegistration): Promise<void>;
}

export interface RewardActivator {
  activate(input: ActivateInput, io: ActivateIo): Promise<ActivationAnswer>;
}

/** The platform this build runs on is neither iOS nor Android (web, tests): there is nothing an activation can honestly say. */
export class ActivationUnsupportedPlatform extends Error {
  constructor() {
    super("reward activation needs an iOS or Android device");
    this.name = "ActivationUnsupportedPlatform";
  }
}

/** What an activation proves, by platform. */
export type ActivationProof =
  | { kind: "ios"; challenge: { id: string; nonce: string }; keyId: string; assertion: string; deviceCheckToken: string }
  | { kind: "android"; challenge: { id: string; nonce: string }; integrityToken: string }
  /** No token. Never claims capability. */
  | { kind: "none"; deviceCheckToken?: string };

/**
 * The wire body. The ONLY constructor: with a token the attestation block is `ios` / `android` and carries the challenge it was bound to; without one it is `none` and
 * `hardwareSupportsAttestation` is the literal `false`, never a free input (rule 2). `installLinkId` is Android only (the server refuses it on iOS) and rides on a `none` request too, where it is
 * an unauthenticated link hint; with a token it is bound into the request hash, so `androidRequestBinding` must have been given the same value.
 */
export function activationWireRequest(base: { deviceId: string; platform: "ios" | "android"; installLinkId?: string }, proof: ActivationProof): ActivationWireRequest {
  const link = base.platform === "android" && base.installLinkId !== undefined ? { installLinkId: base.installLinkId } : {};
  const head = { deviceId: base.deviceId, platform: base.platform };
  if (proof.kind === "ios") {
    const attestation: ActivationAttestation = { kind: "ios", keyId: proof.keyId, assertion: proof.assertion, deviceCheckToken: proof.deviceCheckToken };
    return { ...head, challengeId: proof.challenge.id, nonce: proof.challenge.nonce, attestation };
  }
  if (proof.kind === "android") {
    return { ...head, challengeId: proof.challenge.id, nonce: proof.challenge.nonce, ...link, attestation: { kind: "android", integrityToken: proof.integrityToken } };
  }
  return { ...head, ...link, attestation: { kind: "none", hardwareSupportsAttestation: false, ...(proof.deviceCheckToken !== undefined ? { deviceCheckToken: proof.deviceCheckToken } : {}) } };
}

const asPlatform = (p: string): "ios" | "android" | null => (p === "ios" || p === "android" ? p : null);

/** No attestation, ever: builds, tests, web, Expo Go, a device that cannot attest. Claims `false`, so the server grades `unattestable` and holds the reward for a human (§7.5: never refused). */
export class PlainActivator implements RewardActivator {
  constructor(private readonly osPlatform: string) {}

  activate(input: ActivateInput, io: ActivateIo): Promise<ActivationAnswer> {
    const platform = asPlatform(this.osPlatform);
    if (platform === null) return Promise.reject(new ActivationUnsupportedPlatform());
    return io.post(activationWireRequest({ deviceId: input.deviceId, platform }, { kind: "none" }));
  }
}

export interface NativeActivatorDeps {
  redeemer: NativeRedeemer;
  attestor: Attestor;
  state: AttestStateStore;
  /** `createAttestation(...).withAssertionLock`: the lock check-in uses (rule 1). */
  withLock<T>(userId: string, deviceId: string, fn: (guard: LockGuard) => Promise<T>): Promise<T>;
  /** `createAttestation(...).markAttestedActivation` (rule 5). Never throws. */
  markAttestedActivation(userId: string, deviceId: string): Promise<void>;
}

export class NativeActivator implements RewardActivator {
  constructor(private readonly d: NativeActivatorDeps) {}

  async activate(input: ActivateInput, io: ActivateIo): Promise<ActivationAnswer> {
    const sub = jwtSubject(input.accessToken);
    if (sub === null) throw new AttestationDeferred("no_account_binding"); // the attestation state is per account: without the token's `sub` nothing honest can be recorded
    if (sub.toLowerCase() !== input.userId.toLowerCase()) throw new AttestationDeferred("account_mismatch");
    const platform = this.d.attestor.capability.platform;
    if (platform !== "ios" && platform !== "android") throw new ActivationUnsupportedPlatform();
    const ctx = { ...input, userId: sub };
    try {
      return await this.d.withLock(ctx.userId, ctx.deviceId, (g) => (platform === "ios" ? this.activateIos(ctx, io, g) : this.activateAndroid(ctx, io, g)));
    } catch (e) {
      if (e instanceof LockTimeoutError) throw new AttestationDeferred("assertion_lock_timeout");
      throw e;
    }
  }

  // ---- iOS ---------------------------------------------------------------------------------------------------------------------------------

  private async activateIos(ctx: ActivateInput, io: ActivateIo, g: LockGuard): Promise<ActivationAnswer> {
    interface Prepared {
      hash: Uint8Array;
      challenge: { id: string; nonce: string };
      deviceCheckToken: string;
    }
    let prepared: Prepared | null | undefined;
    // Runs after the key is known, once (the `invalid_key` retry reuses it): the DeviceCheck token, the activation's own live challenge, and the hash that binds both.
    const prepare = async (): Promise<Prepared | null> => {
      g.check();
      const dc = await this.d.redeemer.native(() => this.d.attestor.deviceCheckToken());
      if (dc.kind !== "ok") throw new AttestationDeferred(dc.kind === "unattestable" ? "devicecheck_unsupported" : "devicecheck_unavailable");
      const live = await g.effect(() => io.requestLiveChallenge()); // an ApiError (429, 401, 5xx) reaches the caller as it is
      if (nonceBytesStrict(live.nonce) === null) return null; // the server refuses a non-canonical nonce: nothing honest can be bound
      const hash = iosActivationBinding({ rewardId: ctx.rewardId, deviceId: ctx.deviceId, challengeId: live.id, deviceCheckTokenSha256: bytesToHex(sha256(utf8Encode(dc.value.token))), nonce: live.nonce });
      return { hash, challenge: { id: live.id, nonce: live.nonce }, deviceCheckToken: dc.value.token };
    };
    const hashFor = async (): Promise<Uint8Array | null> => {
      if (prepared === undefined) prepared = await prepare();
      return prepared === null ? null : prepared.hash;
    };

    const got = await this.d.redeemer.obtainIosAssertion({ userId: ctx.userId, deviceId: ctx.deviceId }, io, g, hashFor);
    if (got.kind === "none") {
      // The server holds no key for this device and cannot take one, and nothing was asked of the challenge service for this activation. The reward goes in for a human (unattestable),
      // with the DeviceCheck token if the device can give one (it lets the reviewer see the bits and raises the flagged-device signal): best effort, never a reason to fail.
      g.check();
      const dc = await this.d.redeemer.native(() => this.d.attestor.deviceCheckToken());
      const deviceCheckToken = dc.kind === "ok" ? dc.value.token : undefined;
      return g.effect(() => io.post(activationWireRequest({ deviceId: ctx.deviceId, platform: "ios" }, { kind: "none", ...(deviceCheckToken !== undefined ? { deviceCheckToken } : {}) })));
    }
    // `obtainIosAssertion` returns an assertion only after `hashFor` produced a hash, so `prepared` is set.
    const p = prepared;
    if (!p) throw new AttestationDeferred("assertion_unavailable");
    return g.effect(() => io.post(activationWireRequest({ deviceId: ctx.deviceId, platform: "ios" }, { kind: "ios", challenge: p.challenge, keyId: got.keyId, assertion: got.assertion, deviceCheckToken: p.deviceCheckToken })));
  }

  // ---- Android -----------------------------------------------------------------------------------------------------------------------------

  private async activateAndroid(ctx: ActivateInput, io: ActivateIo, g: LockGuard): Promise<ActivationAnswer> {
    const { state, attestor, redeemer } = this.d;
    // The install link the server links device rows on (A20). `unattestable`: this device has none (the activation is held for want of a signal); a transient failure is a deferral.
    g.check();
    const link = await redeemer.native(() => attestor.installLinkId());
    if (link.kind === "failed") throw new AttestationDeferred("install_link_unavailable");
    const installLinkId = link.kind === "ok" ? link.value.installLinkId : undefined;
    const base = { deviceId: ctx.deviceId, platform: "android" as const, ...(installLinkId !== undefined ? { installLinkId } : {}) };

    const live = await g.effect(() => io.requestLiveChallenge());
    if (nonceBytesStrict(live.nonce) === null) throw new AttestationDeferred("challenge_unusable");
    const hash = androidRequestBinding({ rewardId: ctx.rewardId, deviceId: ctx.deviceId, challengeId: live.id, ...(installLinkId !== undefined ? { installLinkId } : {}) }, live.nonce);
    g.check();
    const token = await redeemer.native(() => attestor.integrityToken(hash));

    if (token.kind !== "ok") {
      if (token.kind === "failed") throw new AttestationDeferred("integrity_token_unavailable"); // transient: rule 3, a held activation is not undone by a retry
      // `unattestable`: the platform says this device cannot get a token. Token-less and claiming false, unless the server may already know it can (rule 3, and `redeemer.ts` rule 2).
      let attestedBefore: boolean;
      try {
        attestedBefore = await state.hasAttestedAndroid(ctx.userId, ctx.deviceId);
      } catch {
        attestedBefore = true; // cannot tell: the unsafe reading is "never attested"
      }
      if (attestedBefore) throw new AttestationDeferred("integrity_token_unavailable");
      return g.effect(() => io.post(activationWireRequest(base, { kind: "none" })));
    }

    let answer: ActivationAnswer;
    try {
      answer = await g.effect(() => io.post(activationWireRequest(base, { kind: "android", challenge: { id: live.id, nonce: live.nonce }, integrityToken: token.value.integrityToken })));
    } catch (e) {
      // The token was SENT. Unless the request DEFINITELY did not take effect, the server may have graded it and recorded a verdict (a lost response, a 5xx, a 2xx body that could not be read).
      if (!isDefiniteNonApplication(e)) await this.d.markAttestedActivation(ctx.userId, ctx.deviceId);
      throw e;
    }
    // A non-replay answer means the server graded the token (rule 5); a replay wrote nothing.
    if (!answer.replay) await this.d.markAttestedActivation(ctx.userId, ctx.deviceId);
    return answer;
  }
}
