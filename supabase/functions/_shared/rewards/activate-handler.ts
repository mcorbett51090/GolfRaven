// supabase/functions/_shared/rewards/activate-handler.ts
//
// Pure, DI'd core of `POST /v1/rewards/{id}/activate` (Edge Function
// `rewards-activate`; build plan §7.5, A2-08, §9.4 step 2).
//
// A reward is EARNED on the server with no device in the request (a scored
// play, a re-score, a queued_catalog drain, a roster verification, a staff scan
// ...) and that earning reads and sets NO device bits. The player ACTIVATES it
// by opening it in the Wallet; THIS is the request that carries the activating
// device's App Attest assertion / Play Integrity token and a DeviceCheck token,
// and the §7.5 decision table (decision-table.ts) runs HERE, on that device's
// bits — nowhere else.
//
// Everything is injected: the `Repo` (already scoped to the actor — no method
// takes a user id), the attestation ports (vendor clients, or fakes), SHA-256.
// The handler therefore runs identically under vitest (in-memory fake repo, fake
// ports), under Deno against a real Postgres (the integration suite), and in
// production (privileged.ts's real Repo, production-ports.ts's real adapters).
//
// ORDER OF OPERATIONS (each step fails closed, and nothing is written before
// the reward is proven to be the caller's own):
//   1. lock the caller's OWN reward; anything else — nonexistent or someone
//      else's — is the same 404 (never 403);
//   2. idempotent short-circuits (already held; already active on THIS device);
//   3. terminal / expired -> 409;
//   4. resolve the device (device cap, platform);
//   5. grade the activating device: consume the single-use challenge, verify the
//      assertion (iOS: clientDataHash = SHA-256(UTF-8(S)), S a canonical string carrying the nonce as text, string-binding.ts) / integrity verdict (Android: requestHash = SHA-256(canonical_body ‖ challenge), binding.ts),
//      advance the App Attest counter atomically;
//   6. read the persistent bits: DeviceCheck on iOS; on Android the server-side
//      substitute (§7.5, A20) from the `device` rows linked by install id / attest
//      key / account, after recording this install link;
//   7. raise fraud_signal(attestation_failed) AT INTAKE if the grade is `failed`;
//   8. run the table; raise the signals of EVERY matching row; record the verdict;
//  8b. on row 6 (iOS), set bit0 at the vendor BEFORE the transition, so no vendor
//      I/O happens while the offer row (or any advisory lock) is held (N2). A
//      failure here throws and rolls the whole transaction back — the reward
//      stays `earned` and a retry is safe.
//   9. apply the transition in the database (which re-checks rows 2 and 3
//      itself, independently of this code, and — for a hold — records what the
//      reviewer sees: the bits, the matched rows, DeviceCheck's last-update month);
//
// A failed verification never refuses: it opens the signal and the reward goes
// to `held_review`. The only 5xx outcomes are vendor unavailability or an
// unconfigured deployment — never a silent "clean" reading.

import { Errors, HttpError } from "../http.ts";
import type { Repo } from "../types.ts";
import { computeRequestBinding, fromBase64UrlStrict, toBase64Url, toHex, type BoundBody, type Sha256Fn } from "./binding.ts";
import { decideActivation, type BitsInput } from "./decision-table.ts";
import { computeIosActivationBinding } from "./string-binding.ts";
import type { ActivationRequest } from "./request-shape.ts";
import {
  type AndroidInstallSignals,
  type AttestationPorts,
  type DeviceBits,
  type Grade,
  type OwnReward,
  type RewardKind,
  VendorNotConfiguredError,
  VendorRejectedError,
  VendorUnavailableError,
} from "./types.ts";

/** Build plan §4.7 item 8: "Reward activation (`rewards-activate`) | 10/user/h, 20/device/day". */
export const RATE_LIMIT_PER_USER_HOUR = 10;
export const RATE_LIMIT_PER_DEVICE_DAY = 20;
// Same accepted-follow-up constant evidence/handler.ts, checkin/
// challenge-handler.ts and me/push-token-handler.ts already use (no plan-stated
// number; not yet centralised).
const MAX_DEVICES_PER_USER = 20;

export interface ActivationDeps {
  ports: AttestationPorts;
  sha256: Sha256Fn;
}

export interface ActivationResult {
  id: string;
  kind: RewardKind;
  /** `issued` | `redeemable` | `held_review`. The matched table row and its
   * reasons are server-side diagnostics only and are never returned. */
  state: string;
  held: boolean;
  /** true when nothing was (re)written: the reward was already held, or
   * already active on this very device. */
  replay: boolean;
}

export interface RateLimitFn {
  (bucketKey: string, windowSeconds: number, max: number): Promise<{ ok: boolean; retryAfterSeconds?: number }>;
}

/** The two reward-activation buckets (§4.7 item 8). Called by the entrypoint
 * BEFORE `withOwnership` opens (privileged.ts#hitRateLimitForActor must never
 * run from inside a transaction — P3c gate round 4). The user bucket is hit
 * first and short-circuits, so a user over their hourly cap does not also burn
 * their device's daily budget. */
export async function enforceActivationRateLimits(hit: RateLimitFn, deviceId: string): Promise<{ ok: true } | { ok: false; retryAfterSeconds?: number }> {
  const user = await hit("rewards-activate:user", 3_600, RATE_LIMIT_PER_USER_HOUR);
  if (!user.ok) return { ok: false, retryAfterSeconds: user.retryAfterSeconds };
  const device = await hit(`rewards-activate:device:${deviceId}`, 86_400, RATE_LIMIT_PER_DEVICE_DAY);
  if (!device.ok) return { ok: false, retryAfterSeconds: device.retryAfterSeconds };
  return { ok: true };
}

const fail503 = (code: "attestation_not_configured" | "attestation_unavailable", message: string) => new HttpError(503, code, message);

/** Vendor error -> the HTTP error the handler throws. NotConfigured and
 * Unavailable are both 503 (fail closed, nothing written, safe to retry);
 * anything else is not ours to interpret and propagates. */
function mapVendorError(e: unknown): unknown {
  if (e instanceof VendorNotConfiguredError) {
    console.error("rewards-activate: attestation vendor is not configured:", e.message);
    return fail503("attestation_not_configured", "device attestation is not available on this deployment; the reward was not changed");
  }
  if (e instanceof VendorUnavailableError) {
    console.error("rewards-activate: attestation vendor unavailable:", e.message);
    return fail503("attestation_unavailable", "device attestation is temporarily unavailable; the reward was not changed — retry");
  }
  return e;
}

interface Assessment {
  grade: Grade;
  reasons: string[];
  tokenHash: string | null;
  /** iOS only (a DeviceCheck token in the request): null = nothing a
   * persistent-bit lookup can use. Android reads the server-side substitute. */
  readBits: (() => Promise<DeviceBits>) | null;
  setBit0: ((known: DeviceBits) => Promise<void>) | null;
}

function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

/** Single-use challenge, bound to this device and live (120 s TTL). Exported
 * for `devices-attest-key` (App Attest key registration), which consumes the
 * SAME kind of challenge the SAME way. Every failure is the same 422 — which of "wrong id", "wrong device", "used",
 * "expired", "wrong nonce" it was is not something to tell a prober. */
export async function consumeLiveChallenge(
  req: { challengeId?: string; nonce?: string },
  deviceId: string,
  repo: Pick<Repo, "challenge" | "now">,
  sha256: Sha256Fn,
): Promise<Uint8Array> {
  const notConsumable = () => Errors.unprocessable("challenge_not_consumable", "this challenge could not be used (already used, expired, or not issued to this device)");
  const nonceBytes = req.nonce !== undefined ? fromBase64UrlStrict(req.nonce) : null;
  if (!req.challengeId || !nonceBytes) throw Errors.badRequest("challengeId and an unpadded base64url nonce are required");
  const challenge = await repo.challenge.getOwn(req.challengeId);
  if (
    !challenge ||
    challenge.deviceId !== deviceId ||
    challenge.kind !== "live" ||
    challenge.usedAt !== null ||
    Date.parse(challenge.expiresAt) <= repo.now().getTime()
  ) {
    throw notConsumable();
  }
  const nonceHash = toHex(await sha256(nonceBytes));
  if (!(await repo.challenge.consume(req.challengeId, nonceHash))) throw notConsumable();
  return nonceBytes;
}

async function assessActivatingDevice(rewardId: string, deviceId: string, req: ActivationRequest, repo: Repo, deps: ActivationDeps): Promise<Assessment> {
  const att = req.attestation;

  // G3-08: "A submission that carries no token ... on hardware that supports
  // attestation it is `failed`, and otherwise `unattestable`." Omitting the
  // token never avoids both — it can only reach `failed` or `unattestable`,
  // and both are held.
  if (att.kind === "none") {
    const port = att.deviceCheckToken !== undefined ? deps.ports.ios : null;
    const token = att.deviceCheckToken;
    return {
      grade: att.hardwareSupportsAttestation ? "failed" : "unattestable",
      reasons: ["no_attestation_token"],
      tokenHash: token !== undefined ? toHex(await deps.sha256(utf8(token))) : null,
      readBits: port && token !== undefined ? () => port.readBits(token) : null,
      setBit0: null,
    };
  }

  if (att.kind === "ios") {
    const port = deps.ports.ios;
    if (!port) throw fail503("attestation_not_configured", "iOS device attestation is not configured on this deployment; the reward was not changed");
    await consumeLiveChallenge(req, deviceId, repo, deps.sha256);
    // H1: the DeviceCheck token's hash is part of what the assertion signs. The
    // token is the one input to the persistent-bit lookup; if it were not bound,
    // a valid assertion from one device could ride next to another device's
    // clean token.
    const tokenHash = toHex(await deps.sha256(utf8(att.deviceCheckToken)));
    // iOS binding (string form, string-binding.ts): clientDataHash = SHA-256(UTF-8(S)), S a canonical JSON string that
    // carries the nonce as TEXT (`req.nonce`, the very string consumeLiveChallenge just consumed) and the token hash.
    // A React Native module can only hash a string, so the raw-bytes form (still used for Android's requestHash below)
    // could not be produced by an iOS client. Same construction as key registration, purpose "reward_activation".
    const clientDataHash = await computeIosActivationBinding(deps.sha256, { rewardId, deviceId, challengeId: req.challengeId!, deviceCheckTokenSha256: tokenHash, nonce: req.nonce! });
    const device = await repo.rewards.deviceAttestState(deviceId);
    if (!device) throw Errors.internal();
    const verdict = await port.verifyAssertion({ assertionB64: att.assertion, keyId: att.keyId, clientDataHash, device });
    let grade: Grade;
    let reasons: string[];
    if (verdict.ok) {
      // Atomic, monotonic and key-bound: a replayed or racing counter does not advance, and neither does an
      // assertion whose key was replaced (by a registration that committed after `deviceAttestState` read it) —
      // `device.attestKeyId` is non-null here because the verifier only returns ok for a recorded key. Zero rows
      // is the same fail-closed outcome as a replay: `failed` (held), never `attested`.
      if (device.attestKeyId !== null && (await repo.rewards.advanceAttestCounter(deviceId, device.attestKeyId, verdict.counter))) {
        grade = "attested";
        reasons = [];
      } else {
        grade = "failed";
        // Two different reasons for the same zero rows (NIT-A): the counter was not higher (a replay, or a lost race with another
        // advance) vs the key this assertion was verified against is no longer the device's key (a registration replaced it between
        // the read and the write). The grade and the held outcome are identical; only the diagnostic differs, so an operator reading
        // the signal can tell a reinstall racing an activation from a replay. The re-read runs only on this failure path, on the
        // same transaction (READ COMMITTED sees the committed replacement), and decides nothing: it can only relabel a `failed`.
        const current = device.attestKeyId === null ? null : await repo.rewards.deviceAttestState(deviceId);
        reasons = current !== null && current.attestKeyId !== device.attestKeyId ? ["key_replaced"] : ["counter_replay"];
      }
    } else {
      grade = verdict.grade;
      reasons = [verdict.reason];
    }
    return { grade, reasons, tokenHash, readBits: () => port.readBits(att.deviceCheckToken), setBit0: (known) => port.setBit0(att.deviceCheckToken, known) };
  }

  // android
  const port = deps.ports.android;
  if (!port) throw fail503("attestation_not_configured", "Android device attestation is not configured on this deployment; the reward was not changed");
  const nonceBytes = await consumeLiveChallenge(req, deviceId, repo, deps.sha256);
  const bound: BoundBody = {
    rewardId,
    deviceId,
    platform: "android",
    challengeId: req.challengeId!,
    ...(req.installLinkId !== undefined ? { installLinkId: req.installLinkId } : {}),
  };
  const binding = await computeRequestBinding(deps.sha256, bound, nonceBytes);
  const verdict = await port.verifyIntegrity({ integrityToken: att.integrityToken, expectedRequestHash: toBase64Url(binding), nowMs: repo.now().getTime() });
  const tokenHash = toHex(await deps.sha256(utf8(att.integrityToken)));
  return {
    grade: verdict.grade,
    reasons: verdict.grade === "failed" ? verdict.reasons : [],
    tokenHash,
    readBits: null,
    setBit0: null,
  };
}

function resultOf(reward: OwnReward, state: string, replay: boolean): ActivationResult {
  return { id: reward.id, kind: reward.kind, state, held: state === "held_review", replay };
}

export async function handleActivation(rewardId: string, req: ActivationRequest, repo: Repo, deps: ActivationDeps): Promise<ActivationResult> {
  // 0. The app-review demo account has no rewards to activate (§4.7.7: 403) —
  //    refused before any reward is read, so it cannot probe for ids either.
  if (await repo.rewards.isAppReviewDemoAccount()) throw Errors.forbidden("this account cannot activate rewards");

  // 1. Ownership first. A foreign or unknown id is a 404 before anything else
  //    is read, written, rate-counted against a vendor, or revealed.
  const reward = await repo.rewards.lockOwnReward(rewardId);
  if (!reward) throw Errors.notFound("no such reward");

  // 2. Idempotent short-circuits — no verification, no writes, no vendor call.
  //    A held reward waits for a human; activation never releases it.
  if (reward.state === "held_review") return resultOf(reward, reward.state, true);
  const activeState = reward.kind === "offer_code" ? "issued" : "redeemable";
  if (reward.state === activeState && reward.activatedDeviceId === req.deviceId) return resultOf(reward, reward.state, true);

  // 3. Only `earned` (first activation) and the already-active state (a SECOND
  //    device re-runs the table, §7.5) can be activated.
  if (reward.state !== "earned" && reward.state !== activeState) {
    throw Errors.conflict("reward_not_activatable", `this reward is ${reward.state} and cannot be activated`);
  }
  if (reward.expiresAt !== null && !reward.expiryPaused && Date.parse(reward.expiresAt) <= repo.now().getTime()) {
    throw Errors.conflict("reward_expired", "this reward has expired");
  }

  // 4. Device: the same discipline as every other device-bearing endpoint —
  //    check the cap BEFORE creating the row it would reject.
  const known = await repo.device.findOwn(req.deviceId);
  if (!known && (await repo.device.countForUser()) >= MAX_DEVICES_PER_USER) {
    throw Errors.unprocessable("device_limit_exceeded", `this account already has ${MAX_DEVICES_PER_USER} devices on record`);
  }
  const device = known ?? (await repo.device.ensureOwn(req.deviceId, req.platform));
  const deviceState = await repo.rewards.deviceAttestState(device.id);
  if (!deviceState) throw Errors.internal();
  if (deviceState.platform !== req.platform) throw Errors.unprocessable("platform_mismatch", "this device is registered under a different platform");

  // 5-6. Grade the activating device, then read the bits.
  let assessment: Assessment;
  try {
    assessment = await assessActivatingDevice(reward.id, device.id, req, repo, deps);
  } catch (e) {
    throw mapVendorError(e);
  }
  let grade = assessment.grade;
  const reasons = [...assessment.reasons];

  let bits: BitsInput = { kind: "none" };
  let lastUpdateMonth: string | null = null;
  let androidSignals: AndroidInstallSignals | null = null;
  if (req.platform === "android") {
    // The §7.5 Android substitute (A20). Record the install link FIRST (this
    // install has now been seen on this account — the substitute's "write"),
    // then read the two signals back. A row with no link key at all (no install
    // id was ever sent, no attest key) can be linked to nothing: the substitute
    // has no answer and the table holds, exactly like a platform with no source.
    if (req.installLinkId !== undefined) {
      await repo.rewards.recordInstallLink(device.id, toHex(await deps.sha256(utf8(req.installLinkId))));
    }
    androidSignals = await repo.rewards.androidInstallSignals(device.id);
    if (androidSignals) {
      // "seen on > 2 accounts" ~ bit0; "an account voided for fraud used this
      // install" ~ bit1 (§7.5). Nothing is written to a vendor.
      bits = { kind: "known", bit0: androidSignals.accountsOnInstall > 2, bit1: androidSignals.voidedAccountUsedInstall };
    }
  } else if (assessment.readBits) {
    try {
      const b = await assessment.readBits();
      bits = { kind: "known", bit0: b.bit0, bit1: b.bit1 };
      lastUpdateMonth = b.lastUpdateMonth;
    } catch (e) {
      if (grade === "attested") {
        // The one grade whose outcome depends on the bits: unreadable bits must
        // never become "clean".
        if (e instanceof VendorRejectedError) {
          grade = "failed";
          reasons.push("devicecheck_token_rejected");
        } else {
          throw mapVendorError(e);
        }
      }
      // A non-attested grade is held whatever the bits say; the read was
      // best-effort (it only decides whether row 1's signal is raised).
    }
  }

  // 7. A failed verdict opens the signal AT INTAKE (security doc §3), in the same
  //    transaction that records the activation attempt.
  if (grade === "failed") {
    await repo.rewards.raiseAttestationFailedIfNone({ rewardId: reward.id, deviceId: device.id, platform: req.platform, reasons, source: "rewards-activate" });
  }

  // 8. The table. A reviewer-cleared reward (H2) has ROW 3 cleared FOR IT —
  //    `reward.restsOnUnattestable` is already the effective flag — while rows 1,
  //    2 and 4-6 run as ever: an open attestation_failed signal on the ACCOUNT is
  //    released only by the signal itself being cleared (N3).
  const decision = decideActivation({
    bits,
    activatingGrade: grade,
    accountHasOpenAttestationFailed: await repo.rewards.hasOpenAttestationFailedSignal(),
    rewardRestsOnUnattestable: reward.restsOnUnattestable,
    accountHasPriorReward: await repo.rewards.hasPriorReward(),
  });

  // N1 pre-check (advisory, no lock). The database HOLDS a code it cannot reserve
  // for instead of issuing it; asking first lets us skip the vendor bit0 write for
  // a reward that is about to be held (bit0 means "an account that RECEIVED a
  // reward used this device"). A race (room taken between this read and the
  // transition) still ends held, and leaves bit0 set: follow-up F14.
  let outcome = decision.outcome;
  let wantSetBit0 = decision.setBit0;
  let heldFor: "offer_budget" | null = null;
  if (outcome === "activate" && !(await repo.rewards.canReserveBudget(reward.id))) {
    outcome = "held_review";
    wantSetBit0 = false;
    heldFor = "offer_budget";
  }

  // 8b. Row 6 on iOS: set DeviceCheck bit0 — BEFORE the database transition (N2).
  //     The transition locks the offer row (reservation) and every lock is held to
  //     the end of the transaction; calling the vendor AFTER it meant the offer
  //     lock was held across Apple's latency, so activations on one offer queued
  //     behind each other and `lock_timeout` restarted per holder: 6 concurrent
  //     activations with a 2.4 s `update_two_bits` produced two 503s. Here the only
  //     lock held across the vendor call is the caller's own reward row. A failure
  //     here still throws and rolls the whole transaction back, so bit0 is never
  //     claimed set for a transition that did not run; the remaining failure
  //     direction (bit0 set, then the transition fails or ends held) is the
  //     accepted follow-up F14. Android has no vendor bit to set: the install link
  //     recorded above is its "write".
  if (outcome === "activate" && wantSetBit0 && req.platform === "ios") {
    if (!assessment.setBit0 || bits.kind !== "known") throw Errors.internal();
    try {
      await assessment.setBit0({ bit0: bits.bit0, bit1: bits.bit1, lastUpdateMonth });
    } catch (e) {
      throw mapVendorError(e);
    }
  }

  // M2: first match decides the outcome, EVERY matching row raises its signals.
  for (const kind of decision.signals) {
    await repo.rewards.raiseFraudSignalOnce(
      kind,
      {
        rewardId: reward.id,
        rewardKind: reward.kind,
        deviceId: device.id,
        platform: req.platform,
        priority: kind === "flagged_device_activation" ? "high" : "normal",
        tableRow: decision.row,
        matchedRows: decision.matchedRows,
        // DeviceCheck's last-update month is shown to the reviewer (§7.5).
        deviceCheckLastUpdateMonth: lastUpdateMonth,
      },
      `${reward.id}:${device.id}`,
    );
  }
  await repo.rewards.recordDeviceVerdict(device.id, { grade, tokenHash: assessment.tokenHash });

  // 9. The transition itself. A hold carries what the reviewer needs (§7.5): the
  //    bits as read, every matched row, the primary one, DeviceCheck's
  //    last-update month — stored on the reward, never returned to the client.
  const holdDetail: Record<string, unknown> | null =
    outcome === "held_review"
      ? {
          bits: bits.kind === "known" ? { bit0: bits.bit0, bit1: bits.bit1 } : null,
          bitsSource: req.platform === "ios" ? "devicecheck" : "server_substitute",
          matchedRows: decision.matchedRows,
          primaryRow: decision.row,
          deviceCheckLastUpdateMonth: lastUpdateMonth,
          ...(androidSignals ? { androidInstallSignals: { accountsOnInstall: androidSignals.accountsOnInstall, voidedAccountUsedInstall: androidSignals.voidedAccountUsedInstall } } : {}),
          ...(heldFor ? { heldFor } : {}),
          platform: req.platform,
          grade,
          at: repo.now().toISOString(),
        }
      : null;
  const applied = await repo.rewards.applyActivation({
    kind: reward.kind,
    rewardId: reward.id,
    deviceId: device.id,
    tokenHash: assessment.tokenHash,
    decision: outcome,
    holdDetail,
  });
  return resultOf(reward, applied.state, false);
}
