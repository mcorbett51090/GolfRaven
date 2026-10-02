// supabase/functions/_shared/rewards/app-attest-registration.ts
//
// App Attest KEY REGISTRATION: verifying an attestation object and extracting the key it attests.
// (app-attest.ts verifies ASSERTIONS made later with that key; this closes follow-up F2 — until a key
// is registered here, every iOS device grades `unattestable`.)
//
// Pure and DI'd: `createAttestationVerifier(config, deps)` returns a verifier whose only inputs are
// bytes. No network (the trust anchor is pinned in code and the certificates arrive in the object),
// no database, no environment, no clock except the `nowMs` the caller passes.
//
// THE TRUST-ANCHOR SEAM. `config.trustAnchorDer` is the one thing that decides who is trusted. In
// production it is set by privileged.ts's wiring to APPLE_APP_ATTEST_ROOT_DER (apple-app-attest-root.ts)
// and by nothing else; a unit test pins that privileged.ts references the pinned constant and that no
// other module builds a verifier. Tests construct a verifier with a throw-away root.
//
// THE PROCEDURE implemented, in Apple's order. Apple's server-side validation of an attestation
// object ("Validating apps that connect to your server"), as I recall it — EVERY step below is
// `[unverified — training knowledge]`; no Apple document was fetched this session and nothing here has
// met a real attestation from a physical device. Each is a named failure reason:
//
//   0. (ours) the client-claimed key id is the canonical 44-character standard-base64 of 32 bytes.
//   1. Decode the object (CBOR map) and require `fmt` = "apple-appattest", `attStmt` = { x5c: [credCert,
//      intermediate], receipt }, `authData`.                          attestation_malformed_* / bad_*
//   2. Verify the x5c chain: credCert <- intermediate <- Apple's App Attestation Root CA (pinned), each
//      within its validity window. (x509-lite.ts)                                chain_*
//   3. nonce = SHA-256(authData ‖ clientDataHash), where clientDataHash is what the server computed
//      from ITS challenge (the string binding, string-binding.ts / below). It must equal the single OCTET STRING in the
//      credCert extension 1.2.840.113635.100.8.2.                       nonce_missing / nonce_mismatch
//   4. SHA-256 of the credCert's public key (the 65-byte uncompressed point) must equal the key id
//      the client named.                                                          key_id_mismatch
//   5. authData.rpIdHash must equal SHA-256("<TeamID>.<BundleID>").                rp_id_mismatch
//   6. authData.counter must be 0.                                                 counter_not_zero
//   7. authData.aaguid must be "appattestdevelop" (development) or "appattest" followed by seven 0x00
//      bytes (production) — 16 bytes either way.                                   aaguid_mismatch
//      (The task brief said "plus 9 zero bytes"; an AAGUID is 16 bytes, and "appattest" is 9 of them,
//      so seven zero bytes is the consistent reading.)
//   8. authData.credentialId must equal the key id.                                credential_id_mismatch
//   Extra, not on Apple's list: the COSE_Key inside authData must be the credCert's key
//   (cose_key_mismatch), and the key must be a valid P-256 point (public_key_invalid). Both only ever
//   refuse; neither can accept anything the list above would not.
//
// NOT done: the `receipt` (an opaque Apple-signed blob used with Apple's fraud-metric endpoint) is
// parsed as a byte string and ignored.
//
// FAIL CLOSED: every failure is a named `{ ok: false, reason }`; nothing throws to the caller and
// nothing unrecognised is accepted.

import { CborError, decodeCborPrefix, decodeCborStrict, type CborValue } from "./cbor-strict.ts";
import { bytesEqual, concatBytes, fromBase64Lenient, type Sha256Fn } from "./binding.ts";
import { DerError, TAG, children, readTlv, tlvContent } from "./der.ts";
import { canonicalChallengeString } from "./string-binding.ts";
import { verifyChain } from "./x509-lite.ts";

// ---------------------------------------------------------------------------
// The request binding for registration (string-form: see string-binding.ts for WHY)
// ---------------------------------------------------------------------------

/** Domain separator: a registration hash can never equal an activation hash (whose fields name a `rewardId` and no
 * `purpose`), so one challenge-bound signature cannot be moved between the two. */
export const ATTEST_KEY_PURPOSE = "attest_key_registration";

export interface AttestKeyBoundBody {
  challengeId: string;
  deviceId: string;
  /** Exactly the string the client sends as `keyId` (canonical standard base64). */
  keyId: string;
  /** The nonce STRING exactly as `POST /v1/checkin/challenge` returned it (unpadded base64url). */
  nonce: string;
}

/** The string the app passes as the `challenge` of `attestKeyAsync(keyId, challenge)`; the module (or
 * `DCAppAttestService.attestKey` over `SHA256(UTF-8(S))`) turns it into `clientDataHash`. */
export function attestKeyChallengeString(body: AttestKeyBoundBody): string {
  return canonicalChallengeString({
    challengeId: body.challengeId,
    deviceId: body.deviceId,
    keyId: body.keyId,
    nonce: body.nonce,
    platform: "ios",
    purpose: ATTEST_KEY_PURPOSE,
  });
}

/** `clientDataHash` = SHA-256(UTF-8(attestKeyChallengeString(body))). */
export async function computeAttestKeyBinding(sha256: Sha256Fn, body: AttestKeyBoundBody): Promise<Uint8Array> {
  return sha256(new TextEncoder().encode(attestKeyChallengeString(body)));
}

/** App Attest key ids are base64(SHA-256(public key)): 32 bytes, 44 characters, one `=`. Only this
 * canonical spelling is accepted, so a key has exactly one string form to bind and to store. */
const KEY_ID_RE = /^[A-Za-z0-9+/]{43}=$/;
export function parseKeyId(s: string): Uint8Array | null {
  if (!KEY_ID_RE.test(s)) return null;
  const bytes = fromBase64Lenient(s);
  return bytes && bytes.length === 32 ? bytes : null;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** The credential certificate extension that carries the nonce (Apple's arc). */
export const NONCE_EXTENSION_OID = "1.2.840.113635.100.8.2";

const MAX_ATTESTATION_BYTES = 16 * 1024;
/** Clock-skew tolerance on certificate validity: a few minutes either way. */
export const CERT_VALIDITY_SKEW_MS = 5 * 60_000;

const ENC = new TextEncoder();
const AAGUID_DEVELOPMENT = ENC.encode("appattestdevelop"); // 16 bytes
const AAGUID_PRODUCTION = concatBytes(ENC.encode("appattest"), new Uint8Array(7)); // 9 + 7 = 16 bytes

export type AppAttestEnvironment = "production" | "development";

export type RegistrationFailure =
  | "key_id_malformed"
  | "client_data_hash_malformed"
  | "attestation_malformed_base64"
  | "attestation_too_large"
  | "attestation_malformed_cbor"
  | "attestation_bad_structure"
  | "attestation_bad_fmt"
  | "authdata_malformed"
  | "chain_parse"
  | "chain_names"
  | "chain_validity"
  | "chain_not_a_ca"
  | "chain_leaf_is_ca"
  | "chain_leaf_key"
  | "chain_signature"
  | "nonce_missing"
  | "nonce_mismatch"
  | "key_id_mismatch"
  | "rp_id_mismatch"
  | "counter_not_zero"
  | "aaguid_mismatch"
  | "credential_id_mismatch"
  | "cose_key_mismatch"
  | "public_key_invalid";

export type RegistrationVerdict = { ok: true; keyId: string; publicKeyRaw: Uint8Array } | { ok: false; reason: RegistrationFailure };

export interface RegistrationVerifierConfig {
  /** `<TeamID>.<BundleID>` (the App ID whose SHA-256 is the rpIdHash). */
  appId: string;
  environment: AppAttestEnvironment;
  /** The ONE trusted root, DER. Production: APPLE_APP_ATTEST_ROOT_DER (privileged.ts only). */
  trustAnchorDer: Uint8Array;
}

export interface RegistrationInput {
  /** Base64 (standard or url-safe, padded or not) of the CBOR attestation object. */
  attestationB64: string;
  /** The key id the client names, canonical standard base64. */
  keyId: string;
  /** SHA-256(UTF-8(canonical challenge string)) — what the SERVER computed (computeAttestKeyBinding). */
  clientDataHash: Uint8Array;
  nowMs: number;
}

export interface AttestationRegistrationVerifier {
  verify(input: RegistrationInput): Promise<RegistrationVerdict>;
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

interface ParsedAttestationObject {
  authData: Uint8Array;
  x5c: [Uint8Array, Uint8Array];
}

function parseAttestationObject(bytes: Uint8Array): ParsedAttestationObject | RegistrationFailure {
  let v: CborValue;
  try {
    v = decodeCborStrict(bytes);
  } catch (e) {
    if (e instanceof CborError) return "attestation_malformed_cbor";
    throw e;
  }
  if (!(v instanceof Map) || v.size !== 3) return "attestation_bad_structure";
  const fmt = v.get("fmt");
  const attStmt = v.get("attStmt");
  const authData = v.get("authData");
  if (typeof fmt !== "string" || !(attStmt instanceof Map) || !(authData instanceof Uint8Array)) return "attestation_bad_structure";
  if (fmt !== "apple-appattest") return "attestation_bad_fmt";
  if (attStmt.size !== 2) return "attestation_bad_structure";
  const x5c = attStmt.get("x5c");
  const receipt = attStmt.get("receipt");
  if (!Array.isArray(x5c) || x5c.length !== 2 || !(receipt instanceof Uint8Array)) return "attestation_bad_structure";
  const [leaf, inter] = x5c;
  if (!(leaf instanceof Uint8Array) || !(inter instanceof Uint8Array)) return "attestation_bad_structure";
  return { authData, x5c: [leaf, inter] };
}

interface ParsedAuthData {
  rpIdHash: Uint8Array;
  counter: number;
  aaguid: Uint8Array;
  credentialId: Uint8Array;
  cose: CborValue;
}

/** authData = rpIdHash(32) ‖ flags(1) ‖ counter(4, BE) ‖ aaguid(16) ‖ credIdLen(2, BE) ‖ credId ‖ COSE_Key. */
function parseAttestedAuthData(ad: Uint8Array): ParsedAuthData | null {
  if (ad.length < 55) return null;
  const flags = ad[32]!;
  // AT (attested credential data present) set; ED (extensions) clear: nothing may follow the COSE key.
  if ((flags & 0x40) === 0 || (flags & 0x80) !== 0) return null;
  const view = new DataView(ad.buffer, ad.byteOffset, ad.byteLength);
  const counter = view.getUint32(33, false);
  const credLen = view.getUint16(53, false);
  if (55 + credLen >= ad.length) return null;
  const rest = ad.subarray(55 + credLen);
  let cose: CborValue;
  try {
    const { value, length } = decodeCborPrefix(rest);
    if (length !== rest.length) return null;
    cose = value;
  } catch {
    return null;
  }
  return { rpIdHash: ad.slice(0, 32), counter, aaguid: ad.slice(37, 53), credentialId: ad.slice(55, 55 + credLen), cose };
}

/** The nonce extension's value: `SEQUENCE { OCTET STRING }`, or `SEQUENCE { [1] { OCTET STRING } }`
 * (the form most implementations decode) `[unverified]`; the octet string is 32 bytes. */
function parseNonceExtension(value: Uint8Array): Uint8Array | null {
  try {
    const seq = readTlv(value, 0, value.length);
    if (seq.tag !== TAG.SEQUENCE || seq.end !== value.length) return null;
    const kids = children(value, seq);
    if (kids.length !== 1) return null;
    let octets = kids[0]!;
    if (octets.tag === 0xa1) {
      const inner = children(value, octets);
      if (inner.length !== 1) return null;
      octets = inner[0]!;
    }
    if (octets.tag !== TAG.OCTET_STRING) return null;
    const nonce = tlvContent(value, octets);
    return nonce.length === 32 ? nonce.slice() : null;
  } catch (e) {
    if (e instanceof DerError) return null;
    throw e;
  }
}

function coseMatchesPoint(cose: CborValue, point: Uint8Array): boolean {
  if (!(cose instanceof Map)) return false;
  for (const k of cose.keys()) if (![1, 3, -1, -2, -3].includes(k as number)) return false;
  if (cose.get(1) !== 2 || cose.get(-1) !== 1) return false;
  if (cose.has(3) && cose.get(3) !== -7) return false;
  const x = cose.get(-2);
  const y = cose.get(-3);
  if (!(x instanceof Uint8Array) || !(y instanceof Uint8Array) || x.length !== 32 || y.length !== 32) return false;
  return bytesEqual(concatBytes(new Uint8Array([0x04]), x, y), point);
}

// ---------------------------------------------------------------------------
// The verifier
// ---------------------------------------------------------------------------

export function createAttestationVerifier(config: RegistrationVerifierConfig, deps: { sha256: Sha256Fn }): AttestationRegistrationVerifier {
  const expectedAaguid = config.environment === "production" ? AAGUID_PRODUCTION : AAGUID_DEVELOPMENT;
  return {
    async verify(input: RegistrationInput): Promise<RegistrationVerdict> {
      const fail = (reason: RegistrationFailure): RegistrationVerdict => ({ ok: false, reason });

      const keyIdBytes = parseKeyId(input.keyId);
      if (!keyIdBytes) return fail("key_id_malformed");
      if (input.clientDataHash.length !== 32) return fail("client_data_hash_malformed");

      const raw = fromBase64Lenient(input.attestationB64);
      if (!raw) return fail("attestation_malformed_base64");
      if (raw.length > MAX_ATTESTATION_BYTES) return fail("attestation_too_large");

      const parsed = parseAttestationObject(raw);
      if (typeof parsed === "string") return fail(parsed);
      const auth = parseAttestedAuthData(parsed.authData);
      if (!auth) return fail("authdata_malformed");

      // 2. the chain, to the pinned anchor.
      const chain = await verifyChain({
        leafDer: parsed.x5c[0],
        intermediateDer: parsed.x5c[1],
        anchorDer: config.trustAnchorDer,
        nowMs: input.nowMs,
        skewMs: CERT_VALIDITY_SKEW_MS,
      });
      if (!chain.ok) return fail(chain.reason);
      const leaf = chain.leaf;

      // 3. the nonce.
      const ext = leaf.extensions.find((e) => e.oid === NONCE_EXTENSION_OID);
      const certNonce = ext ? parseNonceExtension(ext.value) : null;
      if (!certNonce) return fail("nonce_missing");
      const expectedNonce = await deps.sha256(concatBytes(parsed.authData, input.clientDataHash));
      if (!bytesEqual(certNonce, expectedNonce)) return fail("nonce_mismatch");

      // 4. the key id is the hash of the credCert's public key.
      const keyHash = await deps.sha256(leaf.publicKeyRaw);
      if (!bytesEqual(keyHash, keyIdBytes)) return fail("key_id_mismatch");

      // 5-8. the application, the counter, the environment, the credential id.
      const expectedRpIdHash = await deps.sha256(ENC.encode(config.appId));
      if (!bytesEqual(auth.rpIdHash, expectedRpIdHash)) return fail("rp_id_mismatch");
      if (auth.counter !== 0) return fail("counter_not_zero");
      if (!bytesEqual(auth.aaguid, expectedAaguid)) return fail("aaguid_mismatch");
      if (!bytesEqual(auth.credentialId, keyIdBytes)) return fail("credential_id_mismatch");

      // Extras (refuse-only).
      if (!coseMatchesPoint(auth.cose, leaf.publicKeyRaw)) return fail("cose_key_mismatch");
      try {
        await crypto.subtle.importKey("raw", leaf.publicKeyRaw.slice().buffer, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
      } catch {
        return fail("public_key_invalid");
      }

      return { ok: true, keyId: input.keyId, publicKeyRaw: leaf.publicKeyRaw.slice() };
    },
  };
}
