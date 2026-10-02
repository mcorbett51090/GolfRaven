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
//      assertion / integrity verdict against SHA-256(canonical_body ‖ challenge),
//      advance the App Attest counter atomically;
//   6. read the persistent bits (DeviceCheck / device recall);
//   7. raise fraud_signal(attestation_failed) AT INTAKE if the grade is `failed`;
//   8. run the table; raise its signals; record the verdict;
//   9. apply the transition in the database (which re-checks rows 2 and 3
//      itself, independently of this code);
//  10. only then, on row 6, set bit0 at the vendor. A failure here throws and
//      rolls the whole transaction back — the reward stays `earned`, a retry is
//      safe, and bit0 is never claimed set when it was not.
//
// A failed verification never refuses: it opens the signal and the reward goes
// to `held_review`. The only 5xx outcomes are vendor unavailability or an
// unconfigured deployment — never a silent "clean" reading.

import { Errors, HttpError } from "../http.ts";
import type { Repo } from "../types.ts";
import { computeRequestBinding, fromBase64UrlStrict, toBase64Url, toHex, type BoundBody, type Sha256Fn } from "./binding.ts";
import { decideActivation, type BitsInput } from "./decision-table.ts";
import type { ActivationRequest } from "./request-shape.ts";
import {
  type AttestationPorts,
  type DeviceBits,
  type Grade,
  type OwnReward,
  type RewardKind,
  NoPersistentSignalError,
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
  /** null: this request carries nothing a persistent-bit lookup can use. */
  readBits: (() => Promise<DeviceBits>) | null;
  setBit0: ((known: DeviceBits) => Promise<void>) | null;
}

function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

/** Single-use challenge, bound to this device and live (120 s TTL). Every
 * failure is the same 422 — which of "wrong id", "wrong device", "used",
 * "expired", "wrong nonce" it was is not something to tell a prober. */
async function consumeLiveChallenge(req: ActivationRequest, deviceId: string, repo: Repo, sha256: Sha256Fn): Promise<Uint8Array> {
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

  const bound: BoundBody = { rewardId, deviceId, platform: req.platform, challengeId: req.challengeId! };

  if (att.kind === "ios") {
    const port = deps.ports.ios;
    if (!port) throw fail503("attestation_not_configured", "iOS device attestation is not configured on this deployment; the reward was not changed");
    const nonceBytes = await consumeLiveChallenge(req, deviceId, repo, deps.sha256);
    const clientDataHash = await computeRequestBinding(deps.sha256, bound, nonceBytes);
    const device = await repo.rewards.deviceAttestState(deviceId);
    if (!device) throw Errors.internal();
    const verdict = await port.verifyAssertion({ assertionB64: att.assertion, keyId: att.keyId, clientDataHash, device });
    const tokenHash = toHex(await deps.sha256(utf8(att.deviceCheckToken)));
    let grade: Grade;
    let reasons: string[];
    if (verdict.ok) {
      // Atomic and monotonic: a replayed or racing counter does not advance.
      if (await repo.rewards.advanceAttestCounter(deviceId, verdict.counter)) {
        grade = "attested";
        reasons = [];
      } else {
        grade = "failed";
        reasons = ["counter_replay"];
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
  const binding = await computeRequestBinding(deps.sha256, bound, nonceBytes);
  const verdict = await port.verifyIntegrity({ integrityToken: att.integrityToken, expectedRequestHash: toBase64Url(binding), nowMs: repo.now().getTime() });
  const tokenHash = toHex(await deps.sha256(utf8(att.integrityToken)));
  const bits = verdict.bits;
  return {
    grade: verdict.grade,
    reasons: verdict.grade === "failed" ? verdict.reasons : [],
    tokenHash,
    readBits: async () => {
      if (!bits) throw new NoPersistentSignalError("no device-recall bits in the integrity verdict");
      return bits;
    },
    setBit0: (known) => port.setBit0(att.integrityToken, known),
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
  if (assessment.readBits) {
    try {
      const b = await assessment.readBits();
      bits = { kind: "known", bit0: b.bit0, bit1: b.bit1 };
      lastUpdateMonth = b.lastUpdateMonth;
    } catch (e) {
      if (e instanceof NoPersistentSignalError) {
        bits = { kind: "none" };
      } else if (grade === "attested") {
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

  // 8. The table.
  const decision = decideActivation({
    bits,
    activatingGrade: grade,
    accountHasOpenAttestationFailed: await repo.rewards.hasOpenAttestationFailedSignal(),
    rewardRestsOnUnattestable: reward.restsOnUnattestable,
    accountHasPriorReward: await repo.rewards.hasPriorReward(),
  });
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
        // DeviceCheck's last-update month is shown to the reviewer (§7.5).
        deviceCheckLastUpdateMonth: lastUpdateMonth,
      },
      `${reward.id}:${device.id}`,
    );
  }
  await repo.rewards.recordDeviceVerdict(device.id, { grade, tokenHash: assessment.tokenHash });

  // 9. The transition itself.
  const applied = await repo.rewards.applyActivation({
    kind: reward.kind,
    rewardId: reward.id,
    deviceId: device.id,
    tokenHash: assessment.tokenHash,
    decision: decision.outcome,
  });

  // 10. Row 6 only: mark the device. Last, so a failure rolls everything back.
  if (decision.setBit0 && applied.state !== "held_review") {
    if (!assessment.setBit0 || bits.kind !== "known") throw Errors.internal();
    try {
      await assessment.setBit0({ bit0: bits.bit0, bit1: bits.bit1, lastUpdateMonth });
    } catch (e) {
      throw mapVendorError(e);
    }
  }
  return resultOf(reward, applied.state, false);
}
