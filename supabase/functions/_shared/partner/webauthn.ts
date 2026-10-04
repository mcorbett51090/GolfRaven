// supabase/functions/_shared/partner/webauthn.ts
//
// The ONE module through which the partner (staff) lane touches @simplewebauthn/server. docs/security/partner-auth-design.md, 6.1 "The WebAuthn wrapper
// must (L7)" and slice S0. Pure: no database, no network, no clock, no logging. The RP ID and the origin are PARAMETERS (S1.1's `partner_rp_config` row
// feeds them; this module never reads configuration), and the challenge arrives as bytes the database issued (4.4), never generated here.
//
// What the library does NOT do, read in the 14.0.3 source (design section 14), and what this module therefore does itself:
//   (a) `crossOrigin: true` is accepted when the response carries no `topOrigin`, and the registration path never looks at `crossOrigin` at all.
//       -> any `crossOrigin` other than absent/false, and any `topOrigin`, is refused, for both ceremonies, before the library runs.
//   (b) registration branches on the attestation `fmt` the AUTHENTICATOR names (fido-u2f, packed, android-safetynet, android-key, tpm, apple, none),
//       whatever was requested, which puts its X.509 and ASN.1 parsers on client-supplied bytes.
//       -> the attestation object is decoded with the library's own `decodeAttestationObject` (a CBOR decode, nothing more) and any `fmt` other than
//          `none` is refused BEFORE `verifyRegistrationResponse` is called.
//   (c) `response.id` is never compared with the credential being verified against (the library takes the key from the `credential` argument).
//       -> sign-in: `response.id` and `rawId` must equal the looked-up credential id; registration: `response.id` must equal the id inside the
//          authenticator data the library parsed.
//   (d) the default accepted algorithms are EdDSA, ES256 and RS256, and `verifyAuthenticationResponse` has no algorithm option at all.
//       -> `supportedAlgorithmIDs: [-7, -257]` goes to `generateRegistrationOptions` and `verifyRegistrationResponse`, and at sign-in the STORED
//          key's COSE alg is checked against the same list before the library sees it.
// Beyond the four: the stored key's shape is checked (EC2/P-256 for -7; RSA, 2048 bits or more, e = 65537 for -257: the shapes the database-side
// verifier spike assumes), and at sign-in the response's `userHandle` must equal the stored one (a discoverable-credential sign-in always returns it).
//
// Error discipline: every refusal is a `WebAuthnRefusal` whose message is its closed code. The library's own message (which can quote the challenge,
// the origin and the counter) rides on `cause` for the caller's tests and never in `message`, so a handler that returns `error.message` leaks nothing.

import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialRequestOptionsJSON,
  type RegistrationResponseJSON,
} from "@simplewebauthn/server";
import { decodeAttestationObject, decodeClientDataJSON, decodeCredentialPublicKey, isoBase64URL } from "@simplewebauthn/server/helpers";

/** COSE ES256 (ECDSA P-256 with SHA-256) and RS256 (RSASSA-PKCS1-v1_5 with SHA-256). The only algorithms the partner lane accepts (L7 d). */
export const COSE_ES256 = -7;
export const COSE_RS256 = -257;
export const PARTNER_ALGORITHM_IDS: readonly number[] = Object.freeze([COSE_ES256, COSE_RS256]);

/** The ceremony timeout the design emits for both options calls (6.2 step 1). */
export const CEREMONY_TIMEOUT_MS = 120_000;

/** The closed set of refusal codes this module can raise. */
export type WebAuthnRefusalCode =
  | "malformed" // a field is missing, not the right shape, or not decodable
  | "cross_origin" // clientDataJSON.crossOrigin is anything but absent/false
  | "top_origin" // clientDataJSON.topOrigin is present
  | "attestation_format" // registration fmt other than `none`
  | "algorithm_not_allowed" // a key algorithm outside [-7, -257]
  | "key_shape" // a stored or presented public key is not the shape the lane accepts
  | "credential_id_mismatch" // response.id / rawId differs from the credential being verified against
  | "user_handle_mismatch" // the response's userHandle is absent or differs from the stored one
  | "verification_failed" // the library refused (origin, RP ID, challenge, type, UP/UV, counter, signature ...); see `cause`
  | "not_verified"; // the library returned verified: false

export class WebAuthnRefusal extends Error {
  readonly code: WebAuthnRefusalCode;
  constructor(code: WebAuthnRefusalCode, cause?: unknown) {
    super(code, cause === undefined ? undefined : { cause });
    this.name = "WebAuthnRefusal";
    this.code = code;
  }
}

/** The relying party's identity, from `partner_rp_config` (S1.1). Both are exact strings: no wildcard, no list. */
export interface RpConfig {
  /** The RP ID: a lowercase DNS name, no scheme, no port. */
  readonly rpId: string;
  /** The exact origin the PWA is served from: `https://host[:port]`, no path, no trailing slash. */
  readonly origin: string;
}

/** A programming or configuration error (not a client refusal): the RP config itself is unusable. Fails closed. */
export class RpConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RpConfigError";
  }
}

const RP_ID_RE = /^(?=.{1,253}$)[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/;

/** Throws `RpConfigError` unless `rp` is an https origin whose host is the RP ID or a subdomain of it. */
export function assertRpConfig(rp: RpConfig): void {
  if (typeof rp?.rpId !== "string" || !RP_ID_RE.test(rp.rpId)) throw new RpConfigError("rpId must be a lowercase DNS name");
  if (typeof rp.origin !== "string") throw new RpConfigError("origin must be a string");
  let url: URL;
  try {
    url = new URL(rp.origin);
  } catch {
    throw new RpConfigError("origin is not a URL");
  }
  if (url.protocol !== "https:" || url.origin !== rp.origin) throw new RpConfigError("origin must be an exact https origin (no path, no trailing slash)");
  if (url.hostname !== rp.rpId && !url.hostname.endsWith(`.${rp.rpId}`)) throw new RpConfigError("origin host must equal the rpId or be a subdomain of it");
}

function assertChallenge(challenge: Uint8Array): void {
  if (!(challenge instanceof Uint8Array) || challenge.length !== 32) throw new RpConfigError("challenge must be exactly 32 bytes");
}

// ---------------------------------------------------------------------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------------------------------------------------------------------

export interface RegistrationOptionsInput {
  rp: RpConfig;
  /** Shown by some authenticators; not an identifier. */
  rpName: string;
  /** The person's stable opaque id (the WebAuthn user handle), 1 to 64 bytes. Never an email address. */
  userHandle: Uint8Array;
  userName: string;
  userDisplayName: string;
  /** The 32 bytes the database issued (a `register` challenge, 4.4). */
  challenge: Uint8Array;
  /** Credential ids the person already holds, so the authenticator does not register a second one (6.1 step 4). */
  excludeCredentialIds?: readonly string[];
}

/** Registration options: attestation `none`, discoverable credential required, UV required, ES256 and RS256 only (L7 d). */
export function registrationOptions(input: RegistrationOptionsInput): Promise<PublicKeyCredentialCreationOptionsJSON> {
  assertRpConfig(input.rp);
  assertChallenge(input.challenge);
  if (!(input.userHandle instanceof Uint8Array) || input.userHandle.length < 1 || input.userHandle.length > 64) throw new RpConfigError("userHandle must be 1 to 64 bytes");
  return generateRegistrationOptions({
    rpName: input.rpName,
    rpID: input.rp.rpId,
    userName: input.userName,
    userDisplayName: input.userDisplayName,
    userID: input.userHandle as Uint8Array<ArrayBuffer>,
    // bytes, not a string: the library UTF-8 encodes a string challenge before base64url, which would change the value
    challenge: input.challenge as Uint8Array<ArrayBuffer>,
    timeout: CEREMONY_TIMEOUT_MS,
    attestationType: "none",
    authenticatorSelection: { residentKey: "required", userVerification: "required" },
    supportedAlgorithmIDs: [...PARTNER_ALGORITHM_IDS],
    excludeCredentials: (input.excludeCredentialIds ?? []).map((id) => ({ id })),
  });
}

export interface AuthenticationOptionsInput {
  rp: RpConfig;
  /** The 32 bytes the database issued (`partner_challenge_issue_sign_in`, 4.4). */
  challenge: Uint8Array;
}

/** Sign-in options: UV required, empty `allowCredentials` (the operating system's chooser lists the discoverable credentials, 6.2 step 2). */
export function authenticationOptions(input: AuthenticationOptionsInput): Promise<PublicKeyCredentialRequestOptionsJSON> {
  assertRpConfig(input.rp);
  assertChallenge(input.challenge);
  return generateAuthenticationOptions({
    rpID: input.rp.rpId,
    challenge: input.challenge as Uint8Array<ArrayBuffer>,
    timeout: CEREMONY_TIMEOUT_MS,
    userVerification: "required",
    allowCredentials: [],
  });
}

// ---------------------------------------------------------------------------------------------------------------------------------------
// Shared checks
// ---------------------------------------------------------------------------------------------------------------------------------------

const isB64u = (v: unknown): v is string => typeof v === "string" && v.length > 0 && isoBase64URL.isBase64URL(v);

/** Refuses `crossOrigin` (anything but absent or `false`) and any `topOrigin`. Run on BOTH ceremonies, before the library (L7 a). */
function assertNotCrossOrigin(clientDataJSON: unknown): void {
  if (!isB64u(clientDataJSON)) throw new WebAuthnRefusal("malformed");
  let cd: unknown;
  try {
    cd = decodeClientDataJSON(clientDataJSON);
  } catch (e) {
    throw new WebAuthnRefusal("malformed", e);
  }
  if (typeof cd !== "object" || cd === null || Array.isArray(cd)) throw new WebAuthnRefusal("malformed");
  const { crossOrigin, topOrigin } = cd as { crossOrigin?: unknown; topOrigin?: unknown };
  if (crossOrigin !== undefined && crossOrigin !== false) throw new WebAuthnRefusal("cross_origin");
  if (topOrigin !== undefined) throw new WebAuthnRefusal("top_origin");
}

type CoseMap = Map<number, unknown>;

/** The COSE alg of a stored public key, and its shape check. Throws `algorithm_not_allowed` or `key_shape`. */
function assertKeyAllowed(publicKey: Uint8Array): number {
  let key: CoseMap;
  try {
    key = decodeCredentialPublicKey(publicKey as Uint8Array<ArrayBuffer>) as unknown as CoseMap;
  } catch (e) {
    throw new WebAuthnRefusal("key_shape", e);
  }
  if (!(key instanceof Map)) throw new WebAuthnRefusal("key_shape"); // CBOR that decodes to something other than a map (a number, a byte string ...)
  const alg = key.get(3);
  if (typeof alg !== "number" || !PARTNER_ALGORITHM_IDS.includes(alg)) throw new WebAuthnRefusal("algorithm_not_allowed");
  const kty = key.get(1);
  if (alg === COSE_ES256) {
    // EC2, P-256, 32-byte coordinates
    const x = key.get(-2);
    const y = key.get(-3);
    if (kty !== 2 || key.get(-1) !== 1 || !(x instanceof Uint8Array) || x.length !== 32 || !(y instanceof Uint8Array) || y.length !== 32) throw new WebAuthnRefusal("key_shape");
  } else {
    // RSA, modulus of 2048 bits or more, e = 65537
    const n = key.get(-1);
    const e = key.get(-2);
    const e65537 = e instanceof Uint8Array && e.length === 3 && e[0] === 1 && e[1] === 0 && e[2] === 1;
    if (kty !== 3 || !(n instanceof Uint8Array) || n.length < 256 || n.length > 512 || n[0] === 0 || !e65537) throw new WebAuthnRefusal("key_shape");
  }
  return alg;
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i]! ^ b[i]!;
  return d === 0;
}

// ---------------------------------------------------------------------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------------------------------------------------------------------

export interface VerifyRegistrationInput {
  rp: RpConfig;
  response: RegistrationResponseJSON;
  /** The 32 challenge bytes the database bound to this enrolment. */
  expectedChallenge: Uint8Array;
}

export interface VerifiedRegistration {
  /** base64url credential id, as the authenticator reported it inside the authenticator data (and equal to `response.id`). */
  credentialId: string;
  /** The COSE public key, as sent, for storage. */
  publicKey: Uint8Array;
  /** -7 or -257. */
  alg: number;
  /** The authenticator's initial counter (0 for a synced passkey). */
  signCount: number;
  /** `true` when the authenticator flagged the credential backup-eligible (multi-device), and whether it is currently backed up (R-P3). */
  backupEligible: boolean;
  backupState: boolean;
  userVerified: boolean;
  aaguid: string;
  transports: readonly string[];
}

/**
 * Verifies a create ceremony. With `attestation: none` the ceremony carries NO signature (R4-L2): this proves only that the structural fields are the
 * ones the database issued a challenge for. Every L7 rule that applies to registration runs here, the format and cross-origin ones BEFORE the library.
 */
export async function verifyRegistration(input: VerifyRegistrationInput): Promise<VerifiedRegistration> {
  assertRpConfig(input.rp);
  assertChallenge(input.expectedChallenge);
  const { response } = input;
  if (typeof response !== "object" || response === null || typeof response.response !== "object" || response.response === null) throw new WebAuthnRefusal("malformed");
  if (!isB64u(response.id) || !isB64u(response.rawId)) throw new WebAuthnRefusal("malformed");

  assertNotCrossOrigin(response.response.clientDataJSON);

  // L7 b: the format, before the library parses anything the authenticator chose.
  if (!isB64u(response.response.attestationObject)) throw new WebAuthnRefusal("malformed");
  let fmt: unknown;
  try {
    fmt = decodeAttestationObject(isoBase64URL.toBuffer(response.response.attestationObject)).get("fmt");
  } catch (e) {
    throw new WebAuthnRefusal("malformed", e);
  }
  if (fmt !== "none") throw new WebAuthnRefusal("attestation_format");

  let result: Awaited<ReturnType<typeof verifyRegistrationResponse>>;
  try {
    result = await verifyRegistrationResponse({
      response,
      expectedChallenge: isoBase64URL.fromBuffer(input.expectedChallenge as Uint8Array<ArrayBuffer>),
      expectedOrigin: input.rp.origin,
      expectedRPID: input.rp.rpId,
      expectedType: "webauthn.create",
      requireUserPresence: true,
      requireUserVerification: true,
      supportedAlgorithmIDs: [...PARTNER_ALGORITHM_IDS],
    });
  } catch (e) {
    throw new WebAuthnRefusal("verification_failed", e);
  }
  if (!result.verified) throw new WebAuthnRefusal("not_verified");
  const info = result.registrationInfo;
  if (info.fmt !== "none") throw new WebAuthnRefusal("attestation_format");

  // L7 c: the id the browser reported must be the id the authenticator put inside the (hashed, parsed) authenticator data.
  if (response.id !== info.credential.id || response.rawId !== info.credential.id) throw new WebAuthnRefusal("credential_id_mismatch");

  const alg = assertKeyAllowed(info.credential.publicKey);
  return {
    credentialId: info.credential.id,
    publicKey: info.credential.publicKey,
    alg,
    signCount: info.credential.counter,
    backupEligible: info.credentialDeviceType === "multiDevice",
    backupState: info.credentialBackedUp,
    userVerified: info.userVerified,
    aaguid: info.aaguid,
    transports: info.credential.transports ?? [],
  };
}

// ---------------------------------------------------------------------------------------------------------------------------------------
// Sign-in (assertion)
// ---------------------------------------------------------------------------------------------------------------------------------------

/** What `partner_credential_lookup` returned (4.4). */
export interface StoredCredential {
  /** base64url credential id. */
  id: string;
  /** The COSE public key bytes. */
  publicKey: Uint8Array;
  /** The stored sign count (an integer, 0 to 2^32 - 1). */
  signCount: number;
}

export interface VerifyAssertionInput {
  rp: RpConfig;
  response: AuthenticationResponseJSON;
  /** The 32 challenge bytes of the token the request carried (after the database recomputed its HMAC, 4.4). */
  expectedChallenge: Uint8Array;
  credential: StoredCredential;
  /** The WebAuthn user handle stored for this credential's person. A response whose `userHandle` is absent or different is refused. */
  expectedUserHandle: Uint8Array;
}

export interface VerifiedAssertion {
  credentialId: string;
  /** The counter the authenticator reported. The database advances the stored one by compare-and-set (4.4); this module never writes. */
  newSignCount: number;
  userVerified: boolean;
  backupEligible: boolean;
  backupState: boolean;
}

/**
 * Verifies a get ceremony against a looked-up credential, with exact origin and RP ID, UV required, and the counter policy of 6.2 step 4: a non-zero
 * counter that does not strictly increase is refused (equal and lower both) and a 0 against a stored 0 is accepted. All L7 rules run here.
 */
export async function verifyAssertion(input: VerifyAssertionInput): Promise<VerifiedAssertion> {
  assertRpConfig(input.rp);
  assertChallenge(input.expectedChallenge);
  const { response, credential } = input;
  if (!Number.isInteger(credential?.signCount) || credential.signCount < 0 || credential.signCount > 0xffff_ffff) throw new RpConfigError("stored signCount must be an integer in [0, 2^32 - 1]");
  if (!(input.expectedUserHandle instanceof Uint8Array) || input.expectedUserHandle.length < 1) throw new RpConfigError("expectedUserHandle must be non-empty");
  if (typeof response !== "object" || response === null || typeof response.response !== "object" || response.response === null) throw new WebAuthnRefusal("malformed");
  if (!isB64u(response.id) || !isB64u(response.rawId)) throw new WebAuthnRefusal("malformed");

  // L7 c: the response must be for the credential we are about to verify against.
  if (response.id !== credential.id || response.rawId !== credential.id) throw new WebAuthnRefusal("credential_id_mismatch");

  assertNotCrossOrigin(response.response.clientDataJSON);

  // the discoverable-credential sign-in always returns the user handle; it must be the stored one
  const uh = response.response.userHandle;
  if (!isB64u(uh)) throw new WebAuthnRefusal("user_handle_mismatch");
  if (!sameBytes(isoBase64URL.toBuffer(uh), input.expectedUserHandle)) throw new WebAuthnRefusal("user_handle_mismatch");

  // L7 d: verifyAuthenticationResponse has no algorithm option, so the stored key itself is checked
  assertKeyAllowed(credential.publicKey);

  let result: Awaited<ReturnType<typeof verifyAuthenticationResponse>>;
  try {
    result = await verifyAuthenticationResponse({
      response,
      expectedChallenge: isoBase64URL.fromBuffer(input.expectedChallenge as Uint8Array<ArrayBuffer>),
      expectedOrigin: input.rp.origin,
      expectedRPID: input.rp.rpId,
      expectedType: "webauthn.get",
      requireUserVerification: true,
      credential: { id: credential.id, publicKey: credential.publicKey as Uint8Array<ArrayBuffer>, counter: credential.signCount },
    });
  } catch (e) {
    throw new WebAuthnRefusal("verification_failed", e);
  }
  if (!result.verified) throw new WebAuthnRefusal("not_verified");
  const info = result.authenticationInfo;
  if (info.credentialID !== credential.id) throw new WebAuthnRefusal("credential_id_mismatch");
  return {
    credentialId: info.credentialID,
    newSignCount: info.newCounter,
    userVerified: info.userVerified,
    backupEligible: info.credentialDeviceType === "multiDevice",
    backupState: info.credentialBackedUp,
  };
}
