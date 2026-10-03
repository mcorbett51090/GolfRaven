/**
 * The device-attestation SEAM (build plan §7.5, ruling C5). The app depends on this interface only; the native implementations (iOS App Attest via
 * DeviceCheck, Android Play Integrity) are P4.2b-2 and are NOT in this build: the only implementation shipped is `UnattestableAttestor`
 * (`unattestable.ts`), which says, truthfully, "this build cannot attest".
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
  | "not_implemented" // this build has no native attestation module (P4.2b-1): the only reason `UnattestableAttestor` gives
  | "platform_unsupported" // the platform / hardware reports it cannot attest (App Attest unsupported, no Play services)
  | "not_configured"; // attestation is supported but not set up (no Cloud project number, no App Attest entitlement)

export type AttestResult<T> = { kind: "ok"; value: T } | { kind: "unattestable"; reason: UnattestableReason } | { kind: "failed"; message: string };

export interface Attestor {
  /** What this device can do, read before any request. `hardwareSupportsAttestation` is the SELF-REPORT the server's G3-08 "no token" rule takes
   * (`checkin-token` / `rewards-activate` `kind: "none"`): `false` => the server grades the request `unattestable`; `true` with no verified token
   * => `failed`. An implementation that returns `true` MUST then attest every request. */
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
