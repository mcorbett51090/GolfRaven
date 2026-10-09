// supabase/functions/_shared/partner/session-shape.ts
//
// Strict, hand-rolled validation of the CLIENT-SUBMITTED wire shapes of `partner-session` (the same style as signin/request-shape.ts: no schema library, unknown keys REJECTED, because a field that is
// silently ignored today is one refactor away from being trusted). Pure: no environment, no database, no logging.
//
//   POST options, sign-out, lock, reauth/options    {}                                                       (no field at all)
//   POST verify                                      { challengeToken, credential, pop_jkt? }                  pop_jkt: the reserved proof-of-possession slot (N7), accepted and IGNORED
//   POST reauth                                      { challengeToken, credential }
//   POST step-up/pin                                 { derived }                                                (derived: 43 base64url characters = the 32 browser-derived bytes; never the PIN)
//   POST pin/set                                     { derived, salt, iterations }                              (salt: 22 characters = 16 bytes; iterations: an integer in the contract's range)
//   POST pin/change                                  { currentDerived, derived, salt, iterations }
//   POST otp-proof/start                             {}
//   POST otp-proof/verify                            { code }                                                   (the emailed one-time code: 6 to 10 digits)
//   POST totp/enrol                                  {}
//   POST totp/confirm                                { code }                                                   (exactly 6 digits)
//   POST step-up/totp                                { code }                                                   (exactly 6 digits)
//
//   challengeToken  `<nonce b64u, 43>.<exp, epoch seconds>.<mac b64u, 43>`: what POST options returned
//   credential      the browser's `PublicKeyCredential.toJSON()` of a `navigator.credentials.get`: { id, rawId, type: "public-key", response: { clientDataJSON, authenticatorData, signature, userHandle? },
//                   authenticatorAttachment?, clientExtensionResults? }. Every binary field is CANONICAL unpadded base64url (re-encoding must give the same string); `clientExtensionResults` is accepted and dropped
//                   (the lane uses no extension), `authenticatorAttachment` is accepted and ignored.

import { parseDerivedKey, parseIterations, parsePinSalt } from "./pin-contract.ts";
import type { AssertionJson, PinChangeInput, PinSetInput } from "./ports.ts";
import { fromB64u } from "./token.ts";

export interface ParseIssue {
  path: string;
  message: string;
}
export type ParseResult<T> = { ok: true; value: T } | { ok: false; issues: ParseIssue[] };

/** A parsed, decoded challenge token. */
export interface ChallengeToken {
  readonly nonce: Uint8Array;
  readonly exp: number;
  readonly mac: Uint8Array;
}

export interface ParsedAssertion {
  /** What the wrapper takes (strings as sent, `clientExtensionResults` replaced by `{}`). */
  readonly json: AssertionJson;
  readonly credentialId: Uint8Array;
  readonly authenticatorData: Uint8Array;
  readonly clientDataJson: Uint8Array;
  readonly signature: Uint8Array;
}

export interface VerifyRequest {
  readonly token: ChallengeToken;
  readonly assertion: ParsedAssertion;
  /** The reserved `pop_jkt` (N7): parsed so it is accepted, never used. */
  readonly popJkt: string | null;
}

const TOKEN_RE = /^([A-Za-z0-9_-]{43})\.([0-9]{1,12})\.([A-Za-z0-9_-]{43})$/;
const MAX_CLIENT_DATA = 4096;
const MAX_AUTH_DATA = 4096;
const MAX_SIGNATURE = 1024;
const MAX_CREDENTIAL_ID = 1023;
const MIN_CREDENTIAL_ID = 16;
const MAX_USER_HANDLE = 64;
const MAX_POP_JKT = 64;

function plain(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function unknownKeys(obj: Record<string, unknown>, known: ReadonlySet<string>, prefix: string, issues: ParseIssue[]): void {
  for (const k of Object.keys(obj)) if (!known.has(k)) issues.push({ path: prefix + k, message: "unknown field" });
}

/** The body of a route that takes nothing: exactly `{}`. */
export function parseEmptyBody(raw: unknown): ParseResult<Record<string, never>> {
  if (!plain(raw)) return { ok: false, issues: [{ path: "", message: "expected a JSON object" }] };
  const issues: ParseIssue[] = [];
  unknownKeys(raw, new Set(), "", issues);
  return issues.length === 0 ? { ok: true, value: {} } : { ok: false, issues };
}

/** `<nonce>.<exp>.<mac>`, or null: the nonce and the MAC are 32 bytes, the expiry is a plain integer of epoch seconds. */
export function parseChallengeToken(raw: unknown): ChallengeToken | null {
  if (typeof raw !== "string") return null;
  const m = TOKEN_RE.exec(raw);
  if (m === null) return null;
  const nonce = fromB64u(m[1]!);
  const mac = fromB64u(m[3]!);
  const exp = Number(m[2]);
  if (nonce === null || mac === null || nonce.length !== 32 || mac.length !== 32 || !Number.isSafeInteger(exp)) return null;
  return { nonce, exp, mac };
}

function parseAssertion(raw: unknown, issues: ParseIssue[]): ParsedAssertion | null {
  if (!plain(raw)) {
    issues.push({ path: "credential", message: "expected an object" });
    return null;
  }
  const before = issues.length;
  unknownKeys(raw, new Set(["id", "rawId", "type", "response", "authenticatorAttachment", "clientExtensionResults"]), "credential.", issues);
  if (raw.type !== "public-key") issues.push({ path: "credential.type", message: 'must be "public-key"' });
  if (raw.authenticatorAttachment !== undefined && raw.authenticatorAttachment !== null && typeof raw.authenticatorAttachment !== "string") issues.push({ path: "credential.authenticatorAttachment", message: "must be a string" });
  if (raw.clientExtensionResults !== undefined && !plain(raw.clientExtensionResults)) issues.push({ path: "credential.clientExtensionResults", message: "must be an object" });
  const id = typeof raw.id === "string" ? fromB64u(raw.id) : null;
  if (id === null || id.length < MIN_CREDENTIAL_ID || id.length > MAX_CREDENTIAL_ID) issues.push({ path: "credential.id", message: "must be canonical base64url of 16 to 1023 bytes" });
  if (typeof raw.rawId !== "string" || raw.rawId !== raw.id) issues.push({ path: "credential.rawId", message: "must equal id" });
  const resp = raw.response;
  if (!plain(resp)) {
    issues.push({ path: "credential.response", message: "expected an object" });
    return null;
  }
  unknownKeys(resp, new Set(["clientDataJSON", "authenticatorData", "signature", "userHandle"]), "credential.response.", issues);
  const cd = typeof resp.clientDataJSON === "string" ? fromB64u(resp.clientDataJSON) : null;
  if (cd === null || cd.length < 2 || cd.length > MAX_CLIENT_DATA) issues.push({ path: "credential.response.clientDataJSON", message: "must be canonical base64url of 2 to 4096 bytes" });
  const ad = typeof resp.authenticatorData === "string" ? fromB64u(resp.authenticatorData) : null;
  if (ad === null || ad.length < 37 || ad.length > MAX_AUTH_DATA) issues.push({ path: "credential.response.authenticatorData", message: "must be canonical base64url of 37 to 4096 bytes" });
  const sig = typeof resp.signature === "string" ? fromB64u(resp.signature) : null;
  if (sig === null || sig.length < 8 || sig.length > MAX_SIGNATURE) issues.push({ path: "credential.response.signature", message: "must be canonical base64url of 8 to 1024 bytes" });
  if (resp.userHandle !== undefined) {
    const uh = typeof resp.userHandle === "string" ? fromB64u(resp.userHandle) : null;
    if (uh === null || uh.length < 1 || uh.length > MAX_USER_HANDLE) issues.push({ path: "credential.response.userHandle", message: "must be canonical base64url of 1 to 64 bytes" });
  }
  if (issues.length > before || id === null || cd === null || ad === null || sig === null) return null;
  const response: AssertionJson["response"] = { clientDataJSON: resp.clientDataJSON as string, authenticatorData: resp.authenticatorData as string, signature: resp.signature as string };
  if (typeof resp.userHandle === "string") response.userHandle = resp.userHandle;
  return {
    json: { id: raw.id as string, rawId: raw.rawId as string, type: "public-key", response, clientExtensionResults: {} },
    credentialId: id,
    authenticatorData: ad,
    clientDataJson: cd,
    signature: sig,
  };
}

function parseAssertionBody(raw: unknown, allowPop: boolean): ParseResult<VerifyRequest> {
  if (!plain(raw)) return { ok: false, issues: [{ path: "", message: "expected a JSON object" }] };
  const issues: ParseIssue[] = [];
  unknownKeys(raw, new Set(allowPop ? ["challengeToken", "credential", "pop_jkt"] : ["challengeToken", "credential"]), "", issues);
  const token = parseChallengeToken(raw.challengeToken);
  if (token === null) issues.push({ path: "challengeToken", message: "malformed" });
  const assertion = parseAssertion(raw.credential, issues);
  let popJkt: string | null = null;
  if (allowPop && raw.pop_jkt !== undefined && raw.pop_jkt !== null) {
    if (typeof raw.pop_jkt !== "string" || raw.pop_jkt.length === 0 || raw.pop_jkt.length > MAX_POP_JKT) issues.push({ path: "pop_jkt", message: "must be a string of 1 to 64 characters" });
    else popJkt = raw.pop_jkt;
  }
  if (issues.length > 0 || token === null || assertion === null) return { ok: false, issues };
  return { ok: true, value: { token, assertion, popJkt } };
}

/** POST verify: `{ challengeToken, credential, pop_jkt? }`. */
export function parseVerifyBody(raw: unknown): ParseResult<VerifyRequest> {
  return parseAssertionBody(raw, true);
}

/** POST reauth: `{ challengeToken, credential }`. */
export function parseReauthBody(raw: unknown): ParseResult<VerifyRequest> {
  return parseAssertionBody(raw, false);
}

/** The 16 bytes of a uuid (the WebAuthn user handle of a person), or null for a string that is not a uuid. */
export function uuidToBytes(uuid: string): Uint8Array | null {
  const hex = uuid.replace(/-/g, "");
  if (!/^[0-9a-fA-F]{32}$/.test(hex) || !/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(uuid)) return null;
  return Uint8Array.from(hex.match(/../g)!, (h) => parseInt(h, 16));
}

/** POST step-up/pin: `{ derived }`. The Edge checks LENGTH and ENCODING only: it cannot see the PIN, so it cannot judge its shape (pin-contract.ts). */
export function parsePinVerifyBody(raw: unknown): ParseResult<{ readonly derived: Uint8Array }> {
  if (!plain(raw)) return { ok: false, issues: [{ path: "", message: "expected a JSON object" }] };
  const issues: ParseIssue[] = [];
  unknownKeys(raw, new Set(["derived"]), "", issues);
  const derived = parseDerivedKey(raw.derived);
  if (derived === null) issues.push({ path: "derived", message: "must be canonical base64url of 32 bytes (43 characters)" });
  if (issues.length > 0 || derived === null) return { ok: false, issues };
  return { ok: true, value: { derived } };
}

function parseNewPin(raw: Record<string, unknown>, issues: ParseIssue[]): PinSetInput | null {
  const derived = parseDerivedKey(raw.derived);
  if (derived === null) issues.push({ path: "derived", message: "must be canonical base64url of 32 bytes (43 characters)" });
  const salt = parsePinSalt(raw.salt);
  if (salt === null) issues.push({ path: "salt", message: "must be canonical base64url of 16 bytes (22 characters)" });
  const iterations = parseIterations(raw.iterations);
  if (iterations === null) issues.push({ path: "iterations", message: "must be an integer from 210000 to 1000000" });
  return derived === null || salt === null || iterations === null ? null : { derived, salt, iterations };
}

/** POST pin/set: `{ derived, salt, iterations }`. */
export function parsePinSetBody(raw: unknown): ParseResult<PinSetInput> {
  if (!plain(raw)) return { ok: false, issues: [{ path: "", message: "expected a JSON object" }] };
  const issues: ParseIssue[] = [];
  unknownKeys(raw, new Set(["derived", "salt", "iterations"]), "", issues);
  const v = parseNewPin(raw, issues);
  if (issues.length > 0 || v === null) return { ok: false, issues };
  return { ok: true, value: v };
}

/** POST pin/change: `{ currentDerived, derived, salt, iterations }`. */
export function parsePinChangeBody(raw: unknown): ParseResult<PinChangeInput> {
  if (!plain(raw)) return { ok: false, issues: [{ path: "", message: "expected a JSON object" }] };
  const issues: ParseIssue[] = [];
  unknownKeys(raw, new Set(["currentDerived", "derived", "salt", "iterations"]), "", issues);
  const current = parseDerivedKey(raw.currentDerived);
  if (current === null) issues.push({ path: "currentDerived", message: "must be canonical base64url of 32 bytes (43 characters)" });
  const v = parseNewPin(raw, issues);
  if (issues.length > 0 || v === null || current === null) return { ok: false, issues };
  return { ok: true, value: { ...v, current } };
}

const OTP_CODE_RE = /^[0-9]{6,10}$/;
const TOTP_CODE_RE = /^[0-9]{6}$/;

/** POST otp-proof/verify: `{ code }`, the emailed one-time code (6 to 10 digits). */
export function parseOtpVerifyBody(raw: unknown): ParseResult<{ readonly code: string }> {
  if (!plain(raw)) return { ok: false, issues: [{ path: "", message: "expected a JSON object" }] };
  const issues: ParseIssue[] = [];
  unknownKeys(raw, new Set(["code"]), "", issues);
  if (typeof raw.code !== "string" || !OTP_CODE_RE.test(raw.code)) issues.push({ path: "code", message: "must be 6 to 10 digits" });
  if (issues.length > 0) return { ok: false, issues };
  return { ok: true, value: { code: raw.code as string } };
}

/** POST totp/confirm and POST step-up/totp: exactly `{ code }` with 6 digits; unknown keys rejected. */
export function parseTotpCodeBody(raw: unknown): ParseResult<{ readonly code: string }> {
  if (!plain(raw)) return { ok: false, issues: [{ path: "", message: "expected a JSON object" }] };
  const issues: ParseIssue[] = [];
  unknownKeys(raw, new Set(["code"]), "", issues);
  if (typeof raw.code !== "string" || !TOTP_CODE_RE.test(raw.code)) issues.push({ path: "code", message: "must be exactly 6 digits" });
  if (issues.length > 0) return { ok: false, issues };
  return { ok: true, value: { code: raw.code as string } };
}
