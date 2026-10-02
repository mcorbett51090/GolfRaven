// supabase/functions/_shared/rewards/string-binding.ts
//
// The CLIENT-PRODUCIBLE request binding for App Attest (iOS): `clientDataHash = SHA-256(UTF-8(S))`, where `S` is a
// canonical JSON STRING that contains the server nonce as the STRING the challenge endpoint returned.
//
// WHY A STRING. `@expo/app-integrity` (the React Native module the mobile spike recommends; its behaviour is as
// relayed by the mobile builder, `[unverified — not checked here]`) takes the challenge as a JS string and hashes
// that string with SHA-256 itself before calling App Attest, for both `attestKeyAsync(keyId, challenge)` and
// `generateAssertionAsync(keyId, challenge)`. The older construction in binding.ts —
// `SHA-256(canonical_body ‖ RAW nonce bytes)` — needs the client to hash arbitrary BYTES, which cannot be handed to
// such a module through a string (raw bytes do not survive a round trip through a JS string). Putting the nonce into
// the signed string as base64url TEXT removes the problem: the client builds one ASCII string, passes it as the
// "challenge", and the module's own SHA-256 yields exactly the hash the server recomputes.
//
// SECURITY. Nothing is weakened: the nonce string in `S` is the very string the server accepted — it is consumed
// against the stored SHA-256 of its decoded bytes (activate-handler.ts#consumeLiveChallenge) before verification —
// and every other field is a fixed-vocabulary ASCII value. S contains no value a client can choose freely except
// ids the server then checks (the device is the caller's own; the challenge is single-use, live and device-bound).
//
// `S` is canonical JSON (binding.ts#canonicalJson): keys sorted, no whitespace, `JSON.stringify` escaping. All the
// values are ASCII with no quote or backslash (UUIDs, standard base64 which JSON does not escape, base64url, fixed
// words), so a client can build it with a template literal as well as with `JSON.stringify` over sorted keys.

import { canonicalJson, type Sha256Fn } from "./binding.ts";

/** `fields` must be string-valued. UUIDs lowercase. */
export function canonicalChallengeString(fields: Record<string, string>): string {
  return canonicalJson(fields);
}

export async function computeStringBinding(sha256: Sha256Fn, fields: Record<string, string>): Promise<Uint8Array> {
  return sha256(new TextEncoder().encode(canonicalChallengeString(fields)));
}

// ---------------------------------------------------------------------------
// The iOS activation binding (same construction, `purpose: "reward_activation"`)
// ---------------------------------------------------------------------------

/** Domain separator for the iOS activation assertion; registration uses "attest_key_registration". */
export const REWARD_ACTIVATION_PURPOSE = "reward_activation";

export interface IosActivationBoundBody {
  rewardId: string;
  deviceId: string;
  challengeId: string;
  /** Lowercase hex SHA-256 of the DeviceCheck token the request carries (H1: the assertion covers the token's hash). */
  deviceCheckTokenSha256: string;
  /** The nonce STRING exactly as the challenge endpoint returned it (unpadded base64url). */
  nonce: string;
}

/** The string the app passes as the `challenge` of `generateAssertionAsync(keyId, S)`:
 * `{"challengeId":..,"deviceCheckTokenSha256":..,"deviceId":..,"nonce":..,"platform":"ios","purpose":"reward_activation","rewardId":..}`. */
export function iosActivationChallengeString(body: IosActivationBoundBody): string {
  return canonicalChallengeString({
    challengeId: body.challengeId,
    deviceCheckTokenSha256: body.deviceCheckTokenSha256,
    deviceId: body.deviceId,
    nonce: body.nonce,
    platform: "ios",
    purpose: REWARD_ACTIVATION_PURPOSE,
    rewardId: body.rewardId,
  });
}

/** iOS `clientDataHash` for an activation assertion = SHA-256(UTF-8(iosActivationChallengeString(body))). Android is
 * unchanged and keeps binding.ts#computeRequestBinding. */
export async function computeIosActivationBinding(sha256: Sha256Fn, body: IosActivationBoundBody): Promise<Uint8Array> {
  return sha256(new TextEncoder().encode(iosActivationChallengeString(body)));
}
