// supabase/functions/_shared/course-qr/request-shape.ts
//
// Strict, hand-rolled validation of the CLIENT-SUBMITTED wire shape of `POST /v1/marker-scan` (Edge Function `marker-scan`). Same style and reasoning as
// checkin/token-request-shape.ts and evidence/request-shape.ts: no schema library, UNKNOWN KEYS REFUSED (at the top level, inside `qr` and inside `fix`), every string bounded.
//
//   POST /v1/marker-scan
//   {
//     "facilityId": "<catalog facility id>",
//     "qr":  OPTIONAL, one of
//        { "variant": "rotating",   "token": "<the compact JWS from the course QR's #fragment>" }
//        { "variant": "static_pin", "kid": "<qr_kid>", "sig": "<signature from the printed QR's #fragment>", "pin": "<4 digits>" }
//     "deviceId": "<uuid>",          // the per-install device id; REQUIRED with a fix (the check-in token is bound to the device that redeemed it), refused without one
//     "fix": OPTIONAL { "fixId", "lat", "lng", "accuracyMeters", "capturedAt", "simulated", "foreground", "fromApp" }   // exactly the evidence endpoint's fix, minus the jti
//     "jti": "<the check-in token's jti>"   // OPTIONAL, with a fix: the token POST /v1/checkin/token issued for the challenge the fix was taken against
//   }
//
// A request is one of two things:
//   * a SCAN (`qr` present): the player scanned the shop's QR. With a fix (and its jti) the fix is the co-signal; without one the purchase is `pending` (plan §4.6(q)).
//   * a CO-SIGNAL (`qr` absent, `fix` + `jti` present): the player's queued "Buying a marker" capture (plan §7.6 G2-03) or the late fix of an earlier scan. It is tied to the
//     player's own pending purchase at that facility whose window holds the fix.
// This is exactly what the mobile capture records: `{ facilityId, fix, jti }` (apps/mobile/src/marker). Nothing that is a trust fact is ever sent: no grade, no tier, no
// challenge kind, no local date; the server derives all of them.

export interface ParseIssue {
  path: string;
  message: string;
}
export type ParseResult<T> = { ok: true; value: T } | { ok: false; issues: ParseIssue[] };

export interface MarkerScanFix {
  fixId: string;
  lat: number;
  lng: number;
  accuracyMeters: number;
  capturedAt: number;
  simulated: boolean;
  foreground: boolean;
  fromApp: boolean;
}

export type MarkerScanQr = { variant: "rotating"; token: string } | { variant: "static_pin"; kid: string; sig: string; pin: string };

export interface MarkerScanBody {
  facilityId: string;
  qr?: MarkerScanQr;
  deviceId?: string;
  fix?: MarkerScanFix;
  jti?: string;
}

const ID_LIKE_RE = /^[A-Za-z0-9_.:-]{1,128}$/;
const UUID_RE = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
const B64URL_ID_RE = /^[A-Za-z0-9_-]{1,128}$/;
const KID_RE = /^[A-Za-z0-9_-]{1,64}$/;
const SIG_RE = /^[A-Za-z0-9_-]{86}$/;
const PIN_RE = /^[0-9]{4}$/;
const MAX_TOKEN_CHARS = 640;
// the evidence endpoint's own plausibility floor / ceiling for a client timestamp (2020-01-01 .. 2100-01-01, exclusive)
const MIN_EPOCH_MS = Date.UTC(2020, 0, 1);
const MAX_EPOCH_MS = Date.UTC(2100, 0, 1);

const TOP_KEYS = new Set(["facilityId", "qr", "deviceId", "fix", "jti"]);
const FIX_KEYS = new Set(["fixId", "lat", "lng", "accuracyMeters", "capturedAt", "simulated", "foreground", "fromApp"]);
const ROTATING_KEYS = new Set(["variant", "token"]);
const STATIC_KEYS = new Set(["variant", "kid", "sig", "pin"]);

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}
const isFiniteNumber = (v: unknown): v is number => typeof v === "number" && Number.isFinite(v);

function parseFix(raw: unknown, issues: ParseIssue[]): MarkerScanFix | undefined {
  if (!isPlainObject(raw)) {
    issues.push({ path: "fix", message: "must be an object" });
    return undefined;
  }
  const before = issues.length;
  for (const k of Object.keys(raw)) if (!FIX_KEYS.has(k)) issues.push({ path: `fix.${k}`, message: "unrecognised field" });
  if (typeof raw.fixId !== "string" || !B64URL_ID_RE.test(raw.fixId)) issues.push({ path: "fix.fixId", message: "must be unpadded base64url, 1-128 chars" });
  if (!isFiniteNumber(raw.lat) || raw.lat < -90 || raw.lat > 90) issues.push({ path: "fix.lat", message: "must be a finite number in [-90, 90]" });
  if (!isFiniteNumber(raw.lng) || raw.lng < -180 || raw.lng > 180) issues.push({ path: "fix.lng", message: "must be a finite number in [-180, 180]" });
  if (!isFiniteNumber(raw.accuracyMeters) || raw.accuracyMeters < 0) issues.push({ path: "fix.accuracyMeters", message: "must be a finite number >= 0" });
  if (!isFiniteNumber(raw.capturedAt) || raw.capturedAt < MIN_EPOCH_MS || raw.capturedAt >= MAX_EPOCH_MS) issues.push({ path: "fix.capturedAt", message: "must be a plausible epoch-ms timestamp (2020-01-01..2100-01-01)" });
  for (const k of ["simulated", "foreground", "fromApp"] as const) if (typeof raw[k] !== "boolean") issues.push({ path: `fix.${k}`, message: "must be a boolean" });
  if (issues.length > before) return undefined;
  return {
    fixId: raw.fixId as string,
    lat: raw.lat as number,
    lng: raw.lng as number,
    accuracyMeters: raw.accuracyMeters as number,
    capturedAt: raw.capturedAt as number,
    simulated: raw.simulated as boolean,
    foreground: raw.foreground as boolean,
    fromApp: raw.fromApp as boolean,
  };
}

function parseQr(raw: unknown, issues: ParseIssue[]): MarkerScanQr | undefined {
  if (!isPlainObject(raw)) {
    issues.push({ path: "qr", message: "must be an object" });
    return undefined;
  }
  if (raw.variant === "rotating") {
    for (const k of Object.keys(raw)) if (!ROTATING_KEYS.has(k)) issues.push({ path: `qr.${k}`, message: "unrecognised field" });
    if (typeof raw.token !== "string" || raw.token.length === 0 || raw.token.length > MAX_TOKEN_CHARS) {
      issues.push({ path: "qr.token", message: `must be the course QR's token string (1-${MAX_TOKEN_CHARS} chars)` });
      return undefined;
    }
    return { variant: "rotating", token: raw.token };
  }
  if (raw.variant === "static_pin") {
    for (const k of Object.keys(raw)) if (!STATIC_KEYS.has(k)) issues.push({ path: `qr.${k}`, message: "unrecognised field" });
    const before = issues.length;
    if (typeof raw.kid !== "string" || !KID_RE.test(raw.kid)) issues.push({ path: "qr.kid", message: "must be the printed QR's kid" });
    if (typeof raw.sig !== "string" || !SIG_RE.test(raw.sig)) issues.push({ path: "qr.sig", message: "must be the printed QR's signature (86 base64url characters)" });
    if (typeof raw.pin !== "string" || !PIN_RE.test(raw.pin)) issues.push({ path: "qr.pin", message: "must be 4 digits" });
    if (issues.length > before) return undefined;
    return { variant: "static_pin", kid: raw.kid as string, sig: raw.sig as string, pin: raw.pin as string };
  }
  issues.push({ path: "qr.variant", message: 'must be "rotating" or "static_pin"' });
  return undefined;
}

export function parseMarkerScanBody(raw: unknown): ParseResult<MarkerScanBody> {
  const issues: ParseIssue[] = [];
  if (!isPlainObject(raw)) return { ok: false, issues: [{ path: "", message: "body must be a JSON object" }] };
  for (const k of Object.keys(raw)) if (!TOP_KEYS.has(k)) issues.push({ path: k, message: "unrecognised field" });

  if (typeof raw.facilityId !== "string" || !ID_LIKE_RE.test(raw.facilityId)) issues.push({ path: "facilityId", message: "must be a catalog facility id" });
  const qr = raw.qr === undefined ? undefined : parseQr(raw.qr, issues);
  const fix = raw.fix === undefined ? undefined : parseFix(raw.fix, issues);
  if (raw.deviceId !== undefined && (typeof raw.deviceId !== "string" || !UUID_RE.test(raw.deviceId))) issues.push({ path: "deviceId", message: "must be a UUID" });
  if (raw.jti !== undefined && (typeof raw.jti !== "string" || !B64URL_ID_RE.test(raw.jti))) issues.push({ path: "jti", message: "must be unpadded base64url, 1-128 chars" });

  if (raw.qr === undefined && raw.fix === undefined) issues.push({ path: "", message: "a request carries a qr, a fix, or both" });
  if (raw.fix !== undefined && raw.deviceId === undefined) issues.push({ path: "deviceId", message: "is required with a fix (the check-in token is bound to the device)" });
  if (raw.fix === undefined && raw.deviceId !== undefined) issues.push({ path: "deviceId", message: "is meaningful only with a fix" });
  if (raw.jti !== undefined && raw.fix === undefined) issues.push({ path: "jti", message: "is meaningful only with a fix" });
  if (raw.qr === undefined && raw.fix !== undefined && raw.jti === undefined) issues.push({ path: "jti", message: "a co-signal with no qr needs the check-in token's jti (a fix with no token is not a co-signal)" });

  if (issues.length > 0) return { ok: false, issues };
  const value: MarkerScanBody = { facilityId: raw.facilityId as string };
  if (qr !== undefined) value.qr = qr;
  if (raw.deviceId !== undefined) value.deviceId = (raw.deviceId as string).toLowerCase();
  if (fix !== undefined) value.fix = fix;
  if (raw.jti !== undefined) value.jti = raw.jti as string;
  return { ok: true, value };
}
