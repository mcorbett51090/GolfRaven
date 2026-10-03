// supabase/functions/_shared/checkin/token-request-shape.ts
//
// Strict, hand-rolled validation of the CLIENT-SUBMITTED wire shape of `POST /v1/checkin/token` (Edge Function
// `checkin-token`). Same style and reasoning as rewards/request-shape.ts: no schema library, UNKNOWN KEYS REFUSED
// (at the top level and inside the attestation block), every string bounded.
//
//   POST /v1/checkin/token
//   {
//     "challengeId": "<uuid>",                    // from POST /v1/checkin/challenge
//     "nonce": "<base64url>",                     // the RAW nonce that response returned (unpadded base64url)
//     "hardwareSupportsAttestation": boolean,     // a self-report; only consulted when NO attestation is sent
//     "attestation": OPTIONAL, one of
//        { "platform": "ios",     "keyId": "<base64>", "assertion": "<base64 CBOR>" }
//        { "platform": "android", "integrityToken": "<token>" }
//   }
//
// The attestation commits to the check-in binding (rewards/binding.ts#CHECKIN_TOKEN_PURPOSE and the two compute functions
// there and in rewards/string-binding.ts): purpose, challenge id, the device the challenge was issued to, the account, and the
// raw nonce. The device id is therefore NOT a field of this request: the server reads it from the challenge row.
//
// This module deliberately imports nothing (it sits on the earning side, which may import only the verification-only
// rewards modules; see rewards-isolation.test.ts).

export interface ParseIssue {
  path: string;
  message: string;
}
export type ParseResult<T> = { ok: true; value: T } | { ok: false; issues: ParseIssue[] };

export type IosCheckinAttestation = { platform: "ios"; keyId: string; assertion: string };
export type AndroidCheckinAttestation = { platform: "android"; integrityToken: string };
export type CheckinAttestation = IosCheckinAttestation | AndroidCheckinAttestation;

export interface TokenRequest {
  challengeId: string;
  /** The RAW nonce POST /v1/checkin/challenge returned — proves
   * possession of that specific challenge, not just knowledge of its id
   * (should-fix, P3c gate round 2). */
  nonce: string;
  hardwareSupportsAttestation: boolean;
  /** Absent = the G3-08 "no token" case, graded from `hardwareSupportsAttestation` exactly as before. */
  attestation?: CheckinAttestation;
}

const UUID_RE = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
const B64_RE = /^[A-Za-z0-9+/_-]+={0,2}$/;
const TOKEN_RE = /^[A-Za-z0-9._~+/=-]+$/;
const MAX_NONCE_CHARS = 512;
const MAX_ASSERTION_CHARS = 16 * 1024;
const MAX_TOKEN_CHARS = 16 * 1024;
const MAX_KEY_ID_CHARS = 256;

const TOP_KEYS = new Set(["challengeId", "nonce", "hardwareSupportsAttestation", "attestation"]);
const IOS_KEYS = new Set(["platform", "keyId", "assertion"]);
const ANDROID_KEYS = new Set(["platform", "integrityToken"]);

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function boundedB64(v: unknown, max: number): v is string {
  return typeof v === "string" && v.length > 0 && v.length <= max && B64_RE.test(v);
}

export function parseTokenBody(raw: unknown): ParseResult<TokenRequest> {
  const issues: ParseIssue[] = [];
  if (!isPlainObject(raw)) return { ok: false, issues: [{ path: "", message: "body must be a JSON object" }] };
  for (const k of Object.keys(raw)) if (!TOP_KEYS.has(k)) issues.push({ path: k, message: "unrecognised field" });

  if (!(typeof raw.challengeId === "string" && UUID_RE.test(raw.challengeId))) issues.push({ path: "challengeId", message: "must be a UUID" });
  if (!(typeof raw.nonce === "string" && raw.nonce.length > 0 && raw.nonce.length <= MAX_NONCE_CHARS)) issues.push({ path: "nonce", message: "must be the unpadded base64url nonce the challenge returned" });
  if (typeof raw.hardwareSupportsAttestation !== "boolean") issues.push({ path: "hardwareSupportsAttestation", message: "must be a boolean" });

  let attestation: CheckinAttestation | undefined;
  if (raw.attestation !== undefined) {
    const att = raw.attestation;
    if (!isPlainObject(att)) {
      issues.push({ path: "attestation", message: "must be an object" });
    } else if (att.platform === "ios") {
      for (const k of Object.keys(att)) if (!IOS_KEYS.has(k)) issues.push({ path: `attestation.${k}`, message: "unrecognised field" });
      if (!boundedB64(att.keyId, MAX_KEY_ID_CHARS)) issues.push({ path: "attestation.keyId", message: "must be a base64 string" });
      if (!boundedB64(att.assertion, MAX_ASSERTION_CHARS)) issues.push({ path: "attestation.assertion", message: "must be a base64 string" });
      if (typeof att.keyId === "string" && typeof att.assertion === "string") attestation = { platform: "ios", keyId: att.keyId, assertion: att.assertion };
    } else if (att.platform === "android") {
      for (const k of Object.keys(att)) if (!ANDROID_KEYS.has(k)) issues.push({ path: `attestation.${k}`, message: "unrecognised field" });
      if (typeof att.integrityToken !== "string" || att.integrityToken.length === 0 || att.integrityToken.length > MAX_TOKEN_CHARS || !TOKEN_RE.test(att.integrityToken)) {
        issues.push({ path: "attestation.integrityToken", message: "must be a token string" });
      }
      if (typeof att.integrityToken === "string") attestation = { platform: "android", integrityToken: att.integrityToken };
    } else {
      issues.push({ path: "attestation.platform", message: 'must be "ios" or "android"' });
    }
  }

  if (issues.length > 0) return { ok: false, issues };
  return {
    ok: true,
    value: {
      challengeId: (raw.challengeId as string).toLowerCase(),
      nonce: raw.nonce as string,
      hardwareSupportsAttestation: raw.hardwareSupportsAttestation as boolean,
      ...(attestation !== undefined ? { attestation } : {}),
    },
  };
}
