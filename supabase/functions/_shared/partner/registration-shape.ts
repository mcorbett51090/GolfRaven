// supabase/functions/_shared/partner/registration-shape.ts
//
// Strict, hand-rolled validation of a create ceremony submitted to the partner lane (docs/security/partner-auth-design.md 6.1 step 4; slice S1.5), in the style of session-shape.ts: unknown keys REJECTED,
// every binary field CANONICAL unpadded base64url. Pure: no environment, no database, no logging.
//
//   credential   the browser's `PublicKeyCredential.toJSON()` of a `navigator.credentials.create`:
//                { id, rawId, type: "public-key", response: { clientDataJSON, attestationObject, transports?, authenticatorData?, publicKey?, publicKeyAlgorithm? }, authenticatorAttachment?, clientExtensionResults? }
//                The wrapper and the database read the attestation object and the client data; `authenticatorData`, `publicKey` and `publicKeyAlgorithm` are the browser's convenience copies of what is inside
//                the attestation object, accepted and DROPPED (never trusted), as are `authenticatorAttachment` and `clientExtensionResults`.
//   `{ challengeToken, credential }` is the second-credential body (a session); the enrolment body adds who and which acceptance (invites-shape.ts).

import type { RegistrationJson } from "./ports.ts";
import { type ChallengeToken, type ParseIssue, type ParseResult, parseChallengeToken, plain, unknownKeys } from "./session-shape.ts";
import { fromB64u } from "./token.ts";

export interface ParsedRegistration {
  /** What the wrapper takes. */
  readonly json: RegistrationJson;
  readonly credentialId: Uint8Array;
  readonly attestationObject: Uint8Array;
  readonly clientDataJson: Uint8Array;
}

export interface SecondCredentialRequest {
  readonly token: ChallengeToken;
  readonly registration: ParsedRegistration;
}

const MAX_CLIENT_DATA = 4096;
const MAX_ATTESTATION = 8192;
const MIN_CREDENTIAL_ID = 16;
const MAX_CREDENTIAL_ID = 1023;
const MAX_TRANSPORTS_PRESENTED = 16;

export function parseRegistration(raw: unknown, issues: ParseIssue[]): ParsedRegistration | null {
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
  unknownKeys(resp, new Set(["clientDataJSON", "attestationObject", "transports", "authenticatorData", "publicKey", "publicKeyAlgorithm"]), "credential.response.", issues);
  const cd = typeof resp.clientDataJSON === "string" ? fromB64u(resp.clientDataJSON) : null;
  if (cd === null || cd.length < 2 || cd.length > MAX_CLIENT_DATA) issues.push({ path: "credential.response.clientDataJSON", message: "must be canonical base64url of 2 to 4096 bytes" });
  const att = typeof resp.attestationObject === "string" ? fromB64u(resp.attestationObject) : null;
  if (att === null || att.length < 16 || att.length > MAX_ATTESTATION) issues.push({ path: "credential.response.attestationObject", message: "must be canonical base64url of 16 to 8192 bytes" });
  let transports: string[] | undefined;
  if (resp.transports !== undefined) {
    if (!Array.isArray(resp.transports) || resp.transports.length > MAX_TRANSPORTS_PRESENTED || !resp.transports.every((t) => typeof t === "string" && t.length <= 16)) {
      issues.push({ path: "credential.response.transports", message: "must be an array of at most 16 short strings" });
    } else transports = resp.transports as string[];
  }
  for (const k of ["authenticatorData", "publicKey"] as const) {
    if (resp[k] !== undefined && (typeof resp[k] !== "string" || fromB64u(resp[k] as string) === null)) issues.push({ path: `credential.response.${k}`, message: "must be canonical base64url" });
  }
  if (resp.publicKeyAlgorithm !== undefined && !Number.isSafeInteger(resp.publicKeyAlgorithm)) issues.push({ path: "credential.response.publicKeyAlgorithm", message: "must be an integer" });
  if (issues.length > before || id === null || cd === null || att === null) return null;
  const response: RegistrationJson["response"] = { clientDataJSON: resp.clientDataJSON as string, attestationObject: resp.attestationObject as string };
  if (transports !== undefined) response.transports = transports;
  return {
    json: { id: raw.id as string, rawId: raw.rawId as string, type: "public-key", response, clientExtensionResults: {} },
    credentialId: id,
    attestationObject: att,
    clientDataJson: cd,
  };
}

/** POST credentials with a session (a second credential): `{ challengeToken, credential }`. */
export function parseSecondCredentialBody(raw: unknown): ParseResult<SecondCredentialRequest> {
  if (!plain(raw)) return { ok: false, issues: [{ path: "", message: "expected a JSON object" }] };
  const issues: ParseIssue[] = [];
  unknownKeys(raw, new Set(["challengeToken", "credential"]), "", issues);
  const token = parseChallengeToken(raw.challengeToken);
  if (token === null) issues.push({ path: "challengeToken", message: "malformed" });
  const registration = parseRegistration(raw.credential, issues);
  if (issues.length > 0 || token === null || registration === null) return { ok: false, issues };
  return { ok: true, value: { token, registration } };
}
