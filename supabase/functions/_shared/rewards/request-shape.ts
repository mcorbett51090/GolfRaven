// supabase/functions/_shared/rewards/request-shape.ts
//
// Strict, hand-rolled validation of the CLIENT-SUBMITTED wire shape of
// `POST /v1/rewards/{id}/activate` (same style and reasoning as
// evidence/request-shape.ts: no schema library, unknown keys rejected).
//
//   POST /v1/rewards/{id}/activate
//   {
//     "deviceId":    "<uuid>",            // the activating install
//     "platform":    "ios" | "android",
//     "challengeId": "<uuid>",            // from POST /v1/checkin/challenge — required
//     "nonce":       "<base64url>",       //   whenever attestation material is sent
//     "installLinkId": "<opaque id>",     // OPTIONAL, android only: the install identifier the
//                                         //   §7.5 Android substitute (A20) links device rows on
//     "attestation": one of
//        { "kind": "ios",     "keyId": "<base64>", "assertion": "<base64 CBOR>", "deviceCheckToken": "<base64>" }
//        { "kind": "android", "integrityToken": "<token>" }
//        { "kind": "none",    "hardwareSupportsAttestation": boolean, "deviceCheckToken"?: "<base64>" }
//   }
//
// The reward id comes ONLY from the URL (never the body): there is exactly one
// place a caller names the reward, and it is the one the request binding
// (binding.ts) signs.
//
// `kind: "none"` is how an old or attestation-incapable device activates at all
// (§4.5: "A submission that carries no token is graded at intake: on hardware
// that supports attestation it is `failed`, and otherwise `unattestable`").
// `hardwareSupportsAttestation` is a client self-report (the standing gap
// recorded in docs/security/p3-money-path-requirements.md follow-up 9): the
// worst a lying client gains is `unattestable` instead of `failed`; both route
// to `held_review`, neither can reach "activate".

export interface ParseIssue {
  path: string;
  message: string;
}
export type ParseResult<T> = { ok: true; value: T } | { ok: false; issues: ParseIssue[] };

const UUID_RE = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
const B64URL_RE = /^[A-Za-z0-9_-]{1,512}$/;
const B64_RE = /^[A-Za-z0-9+/_-]+={0,2}$/;
const MAX_ASSERTION_CHARS = 16 * 1024;
const MAX_TOKEN_CHARS = 16 * 1024;
const MAX_KEY_ID_CHARS = 256;

export type IosMaterial = { kind: "ios"; keyId: string; assertion: string; deviceCheckToken: string };
export type AndroidMaterial = { kind: "android"; integrityToken: string };
export type NoneMaterial = { kind: "none"; hardwareSupportsAttestation: boolean; deviceCheckToken?: string };
export type AttestationMaterial = IosMaterial | AndroidMaterial | NoneMaterial;

export interface ActivationRequest {
  deviceId: string;
  platform: "ios" | "android";
  challengeId?: string;
  nonce?: string;
  /** Android only. Opaque, client-chosen: an UNAUTHENTICATED hint (a factory
   * reset or a fresh id evades it — §7.5 accepts that). Bound into the Android
   * request hash when present, so it cannot be altered in transit.
   *
   * CLIENT CONTRACT: send an id that SURVIVES an app reinstall on the same device
   * and is stable across accounts — the Android ID (`Settings.Secure.ANDROID_ID`,
   * the SSAID: scoped to the app signing key, the user and the device, unchanged
   * by an uninstall/reinstall of an app signed with the same key, reset by a
   * factory reset) `[unverified — training knowledge]`. NOT a per-install random
   * id, an advertising id, or anything the user resets from settings: the server
   * links device rows (and a pseudonymous tombstone that outlives account
   * deletion) by this id, and an id that changes on reinstall links nothing.
   * 16-128 characters of [A-Za-z0-9._~-] (the SSAID is 16 hex characters). The
   * server stores only its SHA-256. Omit it and the activation is held: with no
   * link the server has no substitute signal to evaluate. */
  installLinkId?: string;
  attestation: AttestationMaterial;
}

export function isUuid(v: unknown): v is string {
  return typeof v === "string" && UUID_RE.test(v);
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function boundedB64(v: unknown, max: number): v is string {
  return typeof v === "string" && v.length > 0 && v.length <= max && B64_RE.test(v);
}

/** The reward id from the request path: exactly one UUID path segment, in
 * `/v1/rewards/{id}/activate`, `/rewards/{id}/activate` or the bare function
 * route `/rewards-activate/{id}`. Anything else — no UUID, two UUIDs, a UUID
 * glued to other text — is `null` (the caller answers 404, the same answer as
 * an id that is not theirs). */
export function extractRewardId(pathname: string): string | null {
  const segments = pathname.split("/").filter((s) => s.length > 0);
  const uuids = segments.filter((s) => UUID_RE.test(s));
  if (uuids.length !== 1) return null;
  const id = uuids[0]!;
  const i = segments.indexOf(id);
  const before = i > 0 ? segments.at(i - 1) : undefined;
  const after = segments.at(i + 1);
  const ok = (before === "rewards" && after === "activate" && i + 2 === segments.length) || (before === "rewards-activate" && i + 1 === segments.length);
  return ok ? id.toLowerCase() : null;
}

const TOP_KEYS = new Set(["deviceId", "platform", "challengeId", "nonce", "installLinkId", "attestation"]);
const INSTALL_LINK_RE = /^[A-Za-z0-9._~-]{16,128}$/;

export function parseActivationBody(raw: unknown): ParseResult<ActivationRequest> {
  const issues: ParseIssue[] = [];
  if (!isPlainObject(raw)) return { ok: false, issues: [{ path: "", message: "body must be a JSON object" }] };
  for (const k of Object.keys(raw)) if (!TOP_KEYS.has(k)) issues.push({ path: k, message: "unrecognised field" });

  if (!isUuid(raw.deviceId)) issues.push({ path: "deviceId", message: "must be a UUID" });
  if (raw.platform !== "ios" && raw.platform !== "android") issues.push({ path: "platform", message: 'must be "ios" or "android"' });
  if (raw.challengeId !== undefined && !isUuid(raw.challengeId)) issues.push({ path: "challengeId", message: "must be a UUID" });
  if (raw.nonce !== undefined && !(typeof raw.nonce === "string" && B64URL_RE.test(raw.nonce))) issues.push({ path: "nonce", message: "must be unpadded base64url" });

  if (raw.installLinkId !== undefined) {
    if (!(typeof raw.installLinkId === "string" && INSTALL_LINK_RE.test(raw.installLinkId))) {
      issues.push({ path: "installLinkId", message: "must be an opaque id of 16-128 characters [A-Za-z0-9._~-]" });
    } else if (raw.platform !== "android") {
      issues.push({ path: "installLinkId", message: "Android only" });
    }
  }

  const att = raw.attestation;
  let attestation: AttestationMaterial | null = null;
  if (!isPlainObject(att)) {
    issues.push({ path: "attestation", message: "must be an object" });
  } else if (att.kind === "ios") {
    const extra = Object.keys(att).filter((k) => !["kind", "keyId", "assertion", "deviceCheckToken"].includes(k));
    for (const k of extra) issues.push({ path: `attestation.${k}`, message: "unrecognised field" });
    if (!boundedB64(att.keyId, MAX_KEY_ID_CHARS)) issues.push({ path: "attestation.keyId", message: "must be a base64 string" });
    if (!boundedB64(att.assertion, MAX_ASSERTION_CHARS)) issues.push({ path: "attestation.assertion", message: "must be a base64 string" });
    if (!boundedB64(att.deviceCheckToken, MAX_TOKEN_CHARS)) issues.push({ path: "attestation.deviceCheckToken", message: "must be a base64 string" });
    if (raw.platform !== "ios") issues.push({ path: "attestation.kind", message: 'kind "ios" requires platform "ios"' });
    if (typeof att.keyId === "string" && typeof att.assertion === "string" && typeof att.deviceCheckToken === "string") {
      attestation = { kind: "ios", keyId: att.keyId, assertion: att.assertion, deviceCheckToken: att.deviceCheckToken };
    }
  } else if (att.kind === "android") {
    const extra = Object.keys(att).filter((k) => !["kind", "integrityToken"].includes(k));
    for (const k of extra) issues.push({ path: `attestation.${k}`, message: "unrecognised field" });
    if (typeof att.integrityToken !== "string" || att.integrityToken.length === 0 || att.integrityToken.length > MAX_TOKEN_CHARS || !/^[A-Za-z0-9._~+/=-]+$/.test(att.integrityToken)) {
      issues.push({ path: "attestation.integrityToken", message: "must be a token string" });
    }
    if (raw.platform !== "android") issues.push({ path: "attestation.kind", message: 'kind "android" requires platform "android"' });
    if (typeof att.integrityToken === "string") attestation = { kind: "android", integrityToken: att.integrityToken };
  } else if (att.kind === "none") {
    const extra = Object.keys(att).filter((k) => !["kind", "hardwareSupportsAttestation", "deviceCheckToken"].includes(k));
    for (const k of extra) issues.push({ path: `attestation.${k}`, message: "unrecognised field" });
    if (typeof att.hardwareSupportsAttestation !== "boolean") issues.push({ path: "attestation.hardwareSupportsAttestation", message: "must be a boolean" });
    if (att.deviceCheckToken !== undefined && !boundedB64(att.deviceCheckToken, MAX_TOKEN_CHARS)) {
      issues.push({ path: "attestation.deviceCheckToken", message: "must be a base64 string" });
    }
    if (att.deviceCheckToken !== undefined && raw.platform !== "ios") issues.push({ path: "attestation.deviceCheckToken", message: "DeviceCheck exists on iOS only" });
    if (typeof att.hardwareSupportsAttestation === "boolean") {
      attestation = {
        kind: "none",
        hardwareSupportsAttestation: att.hardwareSupportsAttestation,
        ...(typeof att.deviceCheckToken === "string" ? { deviceCheckToken: att.deviceCheckToken } : {}),
      };
    }
  } else {
    issues.push({ path: "attestation.kind", message: 'must be "ios", "android" or "none"' });
  }

  // Attestation material is bound to a server challenge; without one there is
  // nothing for the signature to cover.
  if (attestation !== null && attestation.kind !== "none") {
    if (raw.challengeId === undefined) issues.push({ path: "challengeId", message: "required when attestation material is sent" });
    if (raw.nonce === undefined) issues.push({ path: "nonce", message: "required when attestation material is sent" });
  }

  if (issues.length > 0 || attestation === null) return { ok: false, issues };
  return {
    ok: true,
    value: {
      deviceId: (raw.deviceId as string).toLowerCase(),
      platform: raw.platform as "ios" | "android",
      ...(raw.challengeId !== undefined ? { challengeId: (raw.challengeId as string).toLowerCase() } : {}),
      ...(raw.nonce !== undefined ? { nonce: raw.nonce as string } : {}),
      ...(typeof raw.installLinkId === "string" && issues.length === 0 ? { installLinkId: raw.installLinkId } : {}),
      attestation,
    },
  };
}
