// supabase/functions/_shared/rewards/attest-key-request.ts
//
// Strict, hand-rolled validation of the CLIENT-SUBMITTED wire shape of
// `POST /v1/devices/attest-key` (same style as request-shape.ts: no schema library, unknown keys
// rejected).
//
//   POST /v1/devices/attest-key
//   {
//     "deviceId":    "<uuid>",          // the install the key belongs to (issued a challenge already)
//     "challengeId": "<uuid>",          // from POST /v1/checkin/challenge (a LIVE challenge)
//     "nonce":       "<base64url>",     // the raw challenge nonce that call returned, unpadded
//     "keyId":       "<base64>",        // DCAppAttestService.generateKey(): 44 chars, standard base64, one "="
//     "attestation": "<base64 CBOR>"    // DCAppAttestService.attestKey(keyId, clientDataHash:) result
//   }
//
// CLIENT CONTRACT for `clientDataHash` (what the app passes to `attestKey`): the app builds ONE ASCII string, S,
// and gives it as the `challenge` of `attestKeyAsync(keyId, S)` (`@expo/app-integrity`, which hashes the string with
// SHA-256 itself `[unverified]`), or hashes it itself for a native `DCAppAttestService.attestKey(keyId,
// clientDataHash:)`:
//
//   S = {"challengeId":"<uuid>","deviceId":"<uuid>","keyId":"<keyId>","nonce":"<nonce>","platform":"ios","purpose":"attest_key_registration"}
//   clientDataHash = SHA-256(UTF-8(S))
//
// Exactly that: keys in that (sorted) order, no whitespace; both UUIDs LOWERCASE (Swift's `UUID.uuidString` is
// uppercase: lowercase it first, as for activation); `keyId` the string `generateKey` returned; `nonce` the unpadded
// base64url STRING the challenge endpoint returned, NOT decoded. (The nonce travels as text so a JS client never has to
// hash raw bytes; see string-binding.ts.) `[unverified]`: no iOS client exists yet; the final contract needs a
// real-device run (docs/security/p3-money-path-requirements.md, the §7.5 interop note).

export interface ParseIssue {
  path: string;
  message: string;
}
export type ParseResult<T> = { ok: true; value: T } | { ok: false; issues: ParseIssue[] };

const UUID_RE = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
const B64URL_RE = /^[A-Za-z0-9_-]{1,512}$/;
const B64_RE = /^[A-Za-z0-9+/_-]+={0,2}$/;
const KEY_ID_RE = /^[A-Za-z0-9+/]{43}=$/;
/** A real attestation object is ~5 KB (two certificates and a receipt); 16 KiB decoded is generous. */
const MAX_ATTESTATION_CHARS = 24 * 1024;

export interface AttestKeyRequest {
  deviceId: string;
  challengeId: string;
  nonce: string;
  keyId: string;
  attestation: string;
}

const KEYS = new Set(["deviceId", "challengeId", "nonce", "keyId", "attestation"]);

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

export function parseAttestKeyBody(raw: unknown): ParseResult<AttestKeyRequest> {
  const issues: ParseIssue[] = [];
  if (!isPlainObject(raw)) return { ok: false, issues: [{ path: "", message: "body must be a JSON object" }] };
  for (const k of Object.keys(raw)) if (!KEYS.has(k)) issues.push({ path: k, message: "unrecognised field" });
  if (typeof raw.deviceId !== "string" || !UUID_RE.test(raw.deviceId)) issues.push({ path: "deviceId", message: "must be a UUID" });
  if (typeof raw.challengeId !== "string" || !UUID_RE.test(raw.challengeId)) issues.push({ path: "challengeId", message: "must be a UUID" });
  if (typeof raw.nonce !== "string" || !B64URL_RE.test(raw.nonce)) issues.push({ path: "nonce", message: "must be unpadded base64url" });
  if (typeof raw.keyId !== "string" || !KEY_ID_RE.test(raw.keyId)) issues.push({ path: "keyId", message: "must be the 44-character standard-base64 key id App Attest returned" });
  if (typeof raw.attestation !== "string" || raw.attestation.length === 0 || raw.attestation.length > MAX_ATTESTATION_CHARS || !B64_RE.test(raw.attestation)) {
    issues.push({ path: "attestation", message: "must be a base64 string" });
  }
  if (issues.length > 0) return { ok: false, issues };
  return {
    ok: true,
    value: {
      deviceId: (raw.deviceId as string).toLowerCase(),
      challengeId: (raw.challengeId as string).toLowerCase(),
      nonce: raw.nonce as string,
      keyId: raw.keyId as string,
      attestation: raw.attestation as string,
    },
  };
}
