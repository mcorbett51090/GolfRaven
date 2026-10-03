/**
 * The device-attestation SEAM (build plan §7.5, ruling C5). The app depends on this interface only. Two implementations: `NativeAttestor`
 * (`native.ts`, P4.2b-2: the local Expo module over iOS App Attest + DeviceCheck and Android Play Integrity), used only where the module is present
 * and reports support, and `UnattestableAttestor` (`unattestable.ts`) everywhere else (Expo Go, web, tests, an iOS simulator, an Android build with
 * no Cloud project number), which says, truthfully, "this build cannot attest".
 *
 * Roles and byte layouts (all of them are what the SERVER verifies today, `supabase/functions/_shared/rewards/`; see `binding.ts`):
 *  - iOS `attestKey` (once per install, `POST devices-attest-key`): `clientDataHash` = SHA-256(UTF-8(S)), S the canonical string of
 *    `attestKeyChallengeString`;
 *  - iOS `assert` (per request, today only `POST rewards-activate`): `clientDataHash` = SHA-256(UTF-8(S)), S = `iosActivationChallengeString`;
 *  - Android `integrityToken` (per request): `requestHash` = SHA-256(canonical_body || challenge bytes), `androidRequestBinding`.
 * A caller computes the hash with `binding.ts` and hands the finished bytes in; an Attestor never builds a body itself, so it cannot sign something
 * other than what the caller bound.
 *
 * A result is typed, never thrown, never faked: `unattestable` is a value ("this device or build cannot attest"), distinct from `failed`
 * ("the platform refused / errored"), because the server grades them differently (§4.5: `unattestable` is a co-signal that routes a reward to
 * `held_review`; `failed` removes the co-signal and opens a fraud signal). Never turn one into the other.
 */
export type AttestPlatform = "ios" | "android" | "none";

export type UnattestableReason =
  | "not_implemented" // this build has no native attestation module (Expo Go, web, tests): the default reason of `UnattestableAttestor`
  | "platform_unsupported" // the platform / hardware reports it cannot attest (App Attest unsupported, no Play services)
  | "not_configured"; // attestation is supported but not set up (no Cloud project number, no App Attest entitlement)

/** Why a platform call failed, when the caller must react differently. `invalid_key`: App Attest says the key is no longer usable (`DCError.invalidKey`:
 * the app was reinstalled or the key was lost), so the caller drops it and registers a fresh one; everything else is `other`. */
export type AttestFailureCode = "invalid_key" | "other";

export type AttestResult<T> = { kind: "ok"; value: T } | { kind: "unattestable"; reason: UnattestableReason } | { kind: "failed"; message: string; code?: AttestFailureCode };

export interface Attestor {
  /** What this device can do, read before any request. This is CAPABILITY, not the wire claim: the `hardwareSupportsAttestation` field a request carries
   * is the SELF-REPORT the server's G3-08 "no token" rule takes (`false` => a token-less request is graded `unattestable`; `true` with no verified token
   * => `failed` plus a fraud signal), and it is derived PER REQUEST by `redeemer.ts` as "this request carries an attestation": never true without one. */
  readonly capability: { platform: AttestPlatform; hardwareSupportsAttestation: boolean };

  /** iOS: `DCAppAttestService.generateKey()`. The key id is part of the registration hash, so it is generated first. */
  generateKey(): Promise<AttestResult<{ keyId: string }>>;
  /** iOS: `attestKey(keyId, clientDataHash)` -> the base64 attestation object `POST devices-attest-key` takes. `clientDataHash` is 32 bytes. */
  attestKey(keyId: string, clientDataHash: Uint8Array): Promise<AttestResult<{ attestation: string }>>;
  /** iOS: `generateAssertion(keyId, clientDataHash)` -> the base64 CBOR assertion. `clientDataHash` is 32 bytes. */
  assert(keyId: string, clientDataHash: Uint8Array): Promise<AttestResult<{ assertion: string }>>;
  /** Android: a standard Play Integrity request whose `requestHash` is the 32 bytes given (base64url on the wire, the module's concern). */
  integrityToken(requestHash: Uint8Array): Promise<AttestResult<{ integrityToken: string }>>;
}
