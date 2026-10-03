/**
 * The surface of the LOCAL Expo module `modules/golfraven-attest` (P4.2b-2): types only, no import of `expo` or `react-native`, so everything above it
 * runs under Node against a fake. The Swift (`ios/GolfravenAttestModule.swift`) and Kotlin (`android/.../GolfravenAttestModule.kt`) sources are kept
 * minimal and declarative on purpose: they call the platform API and report its answer, nothing else (no hashing, no binding, no retry, no state).
 * All logic lives in `native.ts` / `redeemer.ts` and is tested against `FakeNativeAttestModule` (`test/support/fake-native-attest.ts`).
 *
 * Every function RESOLVES (it never rejects for a platform error): `{ ok: true, ... }` or `{ ok: false, code, message }`. A rejection (a bridge failure, a
 * module that is present but broken) is caught by `NativeAttestor` and reported as `failed`.
 *
 * Hashes cross the bridge as text so no binary type is needed: `clientDataHash` is STANDARD base64 of the 32 bytes (`DCAppAttestService` takes `Data`),
 * `requestHash` is the base64url (no padding) STRING Play Integrity is given. The module hashes nothing: JS computes the hash with `@noble/hashes`
 * (checked against the server's recorded vectors), so what is bound is verifiable here, not only on a device.
 */
export type NativeErrorCode =
  | "unsupported" // this platform / device does not do that (App Attest on an Android build, an iOS simulator)
  | "invalid_key" // App Attest `DCError.invalidKey`: the key is gone (reinstall) or was never attested
  | "unavailable" // a transient platform failure (Apple / Google service unreachable, Play services missing or updating)
  | "other";

export type NativeResult<T> = ({ ok: true } & T) | { ok: false; code: NativeErrorCode; message: string };

export interface NativeCapability {
  /** iOS: `DCAppAttestService.shared.isSupported`. Android: `true` (Play Integrity availability is only known at request time). */
  supported: boolean;
}

export interface NativeAttestModule {
  capability(): Promise<NativeCapability>;
  // ---- iOS: App Attest + DeviceCheck ----------------------------------------------------------------------------------------------------
  /** `DCAppAttestService.generateKey` -> the key id (44 characters, standard base64). */
  generateKey(): Promise<NativeResult<{ keyId: string }>>;
  /** `attestKey(keyId, clientDataHash)` -> the base64 attestation object. `clientDataHashB64` = base64 of the 32 hash bytes. */
  attestKey(keyId: string, clientDataHashB64: string): Promise<NativeResult<{ attestation: string }>>;
  /** `generateAssertion(keyId, clientDataHash)` -> the base64 assertion. Advances the key's counter on the device: callers hold ONE per key in flight. */
  generateAssertion(keyId: string, clientDataHashB64: string): Promise<NativeResult<{ assertion: string }>>;
  /** `DCDevice.current.generateToken` -> the base64 DeviceCheck token (used by reward activation, P4.2c; not by check-in). */
  deviceCheckToken(): Promise<NativeResult<{ token: string }>>;
  // ---- Android: Play Integrity (standard requests) -------------------------------------------------------------------------------------
  /** `prepareIntegrityToken(cloudProjectNumber)` (once, cached) then `request(requestHash)` -> the integrity token. */
  integrityToken(cloudProjectNumber: string, requestHash: string): Promise<NativeResult<{ token: string }>>;
}
