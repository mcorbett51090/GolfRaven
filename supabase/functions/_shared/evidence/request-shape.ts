// supabase/functions/_shared/evidence/request-shape.ts
//
// Hand-rolled (no external schema library — see this round's report for
// why: avoids a second, version-mismatched zod dependency between the
// Deno-pinned 3.23.8 import-map entry and packages/rules' own zod@4.6.5,
// which the bundled scorer already vendors) strict validation of the
// CLIENT-SUBMITTED wire shape for POST /v1/evidence and POST
// /v1/evidence/batch.
//
// This is deliberately NARROWER than `packages/rules`' own `Evidence`
// union (parse-evidence.ts): every field a client could use to forge a
// money-path fact (attestationGrade, verificationTier, geometryKind,
// insideBuffer, challenge kind, courseDisambiguatedBy) is ABSENT from
// this shape on purpose — see evidence/handler.ts for where those get
// filled in server-side before the row is ever handed to the bundled
// `scorePlay`.
//
// **Only player-submittable sources are accepted here** (security doc §2:
// "each row type comes only from its own server path" — `POST
// /v1/evidence` rejects every field in the trust-table-restricted rows).
// `staff_presence` (only from `/v1/partner/attest`), `booking` (only from
// the P7 provider webhook), `receipt_green_fee` (only from the receipt
// intake + review queue), and `arccos`/`garmin` (only from the P8
// connector) are explicitly rejected here with a clear error — none of
// those server paths are built this round (out of scope; see the P3c
// handback report). Accepted this round: `foreground_checkin`,
// `foreground_dwell`, `self_report`, `health_workout`.
//
// ⛔ FIX (P3c gate round 2, item 6: "client claims mint badge credit").
// `connect_iq`, `health_route` and `file_import` moved from accepted to
// REJECTED — each one's own client-reported "quality" field
// (`insidePolygon`/`k4bPassed`, `insideRatio`/`sourceAllowListed`,
// `matchedRoute`) was taken at FACE VALUE with no server-side matcher or
// connector verifying it, meaning a client could simply claim
// `insidePolygon: true`/`matchedRoute: true` and mint real `score_badge`
// credit for nothing. Until a real server-side matcher
// (`@golfraven/matching`, wired against the raw route/points the same way
// `Repo#catalog.matchFix` already does for a single fix) or the P8
// connector exists, these three sources have no honest server-derivable
// signal at all and are rejected the same way staff_presence/booking/
// receipt_green_fee/arccos/garmin are — recorded as a deferral in
// docs/security/p3-money-path-requirements.md.

const ID_LIKE_RE = /^[A-Za-z0-9_.:-]{1,128}$/;
const UUID_RE = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
const BASE64URL_UNPADDED_RE = /^[A-Za-z0-9_-]{1,128}$/;
const LOCAL_DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const SHA256_HEX_RE = /^[0-9a-f]{64}$/;
// Same plausibility floor/ceiling as packages/rules' own PlausibleEpochMsSchema
// (parse-evidence.ts) — 2020-01-01 to 2100-01-01 (exclusive).
const MIN_EPOCH_MS = Date.UTC(2020, 0, 1);
const MAX_EPOCH_MS = Date.UTC(2100, 0, 1);

export const REJECTED_SOURCES = new Set(["staff_presence", "booking", "receipt_green_fee", "arccos", "garmin", "ghin", "connect_iq", "health_route", "file_import"]);
export const ACCEPTED_SOURCES = new Set(["foreground_checkin", "foreground_dwell", "self_report", "health_workout"]);

export interface ParseIssue {
  path: string;
  message: string;
}

export type ParseResult<T> = { ok: true; value: T } | { ok: false; issues: ParseIssue[] };

function isRealCalendarDate(y: number, m: number, d: number): boolean {
  const dt = new Date(Date.UTC(y, m - 1, d));
  return dt.getUTCFullYear() === y && dt.getUTCMonth() === m - 1 && dt.getUTCDate() === d;
}

function isIdLike(v: unknown): v is string {
  return typeof v === "string" && ID_LIKE_RE.test(v);
}
function isUuid(v: unknown): v is string {
  return typeof v === "string" && UUID_RE.test(v);
}
function isBase64UrlId(v: unknown): v is string {
  return typeof v === "string" && BASE64URL_UNPADDED_RE.test(v);
}
function isLocalDate(v: unknown): v is string {
  if (typeof v !== "string" || !LOCAL_DATE_RE.test(v)) return false;
  const [y, m, d] = v.split("-").map(Number);
  return isRealCalendarDate(y!, m!, d!);
}
function isPlausibleEpochMs(v: unknown): v is number {
  return typeof v === "number" && Number.isFinite(v) && v >= MIN_EPOCH_MS && v < MAX_EPOCH_MS;
}
function isBoolean(v: unknown): v is boolean {
  return typeof v === "boolean";
}
function isFiniteNumber(v: unknown): v is number {
  return typeof v === "number" && Number.isFinite(v);
}
function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Client-submitted fix — deliberately not `packages/rules`' `AppFix`:
 * every trust-table field (facilityId's VERIFICATION, verificationTier,
 * geometryKind, insideBuffer, challenge, token) is derived server-side in
 * evidence/handler.ts from the checkin-token/challenge row `checkinTokenJti`
 * points at, never from these client-reported values directly. */
export interface FixSubmission {
  fixId: string;
  lat: number;
  lng: number;
  accuracyMeters: number;
  capturedAt: number;
  simulated: boolean;
  foreground: boolean;
  fromApp: boolean;
  /** If present, ties this fix to a live/prefetched checkin-token session
   * (issued by POST /v1/checkin/token) — the server looks up that
   * session's own facility/challenge-kind/attestation-grade rather than
   * trusting anything the client claims about them. Absent entirely ->
   * `challenge: "none"` (never a co-signal; §4.5's own definition). */
  checkinTokenJti?: string;
}

function parseFix(raw: unknown, path: string): ParseResult<FixSubmission> {
  const issues: ParseIssue[] = [];
  if (!isPlainObject(raw)) return { ok: false, issues: [{ path, message: "must be an object" }] };
  const allowedKeys = new Set(["fixId", "lat", "lng", "accuracyMeters", "capturedAt", "simulated", "foreground", "fromApp", "checkinTokenJti"]);
  for (const k of Object.keys(raw)) {
    if (!allowedKeys.has(k)) issues.push({ path: `${path}.${k}`, message: "unrecognized key" });
  }
  if (!isBase64UrlId(raw.fixId)) issues.push({ path: `${path}.fixId`, message: "must be unpadded base64url, 1-128 chars" });
  if (!isFiniteNumber(raw.lat) || raw.lat < -90 || raw.lat > 90) issues.push({ path: `${path}.lat`, message: "must be a finite number in [-90, 90]" });
  if (!isFiniteNumber(raw.lng) || raw.lng < -180 || raw.lng > 180) issues.push({ path: `${path}.lng`, message: "must be a finite number in [-180, 180]" });
  if (!isFiniteNumber(raw.accuracyMeters) || raw.accuracyMeters < 0) issues.push({ path: `${path}.accuracyMeters`, message: "must be a finite number >= 0" });
  if (!isPlausibleEpochMs(raw.capturedAt)) issues.push({ path: `${path}.capturedAt`, message: "must be a plausible epoch-ms timestamp (2020-01-01..2100-01-01)" });
  if (!isBoolean(raw.simulated)) issues.push({ path: `${path}.simulated`, message: "must be a boolean" });
  if (!isBoolean(raw.foreground)) issues.push({ path: `${path}.foreground`, message: "must be a boolean" });
  if (!isBoolean(raw.fromApp)) issues.push({ path: `${path}.fromApp`, message: "must be a boolean" });
  if (raw.checkinTokenJti !== undefined && !isBase64UrlId(raw.checkinTokenJti)) {
    issues.push({ path: `${path}.checkinTokenJti`, message: "must be unpadded base64url, 1-128 chars" });
  }
  if (issues.length > 0) return { ok: false, issues };
  return {
    ok: true,
    value: {
      fixId: raw.fixId as string,
      lat: raw.lat as number,
      lng: raw.lng as number,
      accuracyMeters: raw.accuracyMeters as number,
      capturedAt: raw.capturedAt as number,
      simulated: raw.simulated as boolean,
      foreground: raw.foreground as boolean,
      fromApp: raw.fromApp as boolean,
      checkinTokenJti: raw.checkinTokenJti as string | undefined,
    },
  };
}

interface CommonFields {
  deviceId: string;
  facilityId: string;
  courseId?: string;
  localDate: string;
  catalogVersion: number;
  // should-fix (P3c gate round 2): "sign a domain-tagged payload that
  // binds the version and the manifest sha256" — manifestSha256 is the
  // claimed content hash the signature is verified to also cover
  // (handler.ts builds the exact domain-tagged string), not merely the
  // bare version integer.
  manifestSig?: { kid: string; signatureB64Url: string; manifestSha256: string };
}

export type EvidenceSubmission =
  | (CommonFields & { source: "foreground_checkin"; fix: FixSubmission })
  // ⛔ FIX (P3c gate round 2, item 6): `holes` is no longer client
  // -submitted at all — evidence/handler.ts derives it from
  // `Repo#catalog.courseHoleCount`, never the client's own claim.
  | (CommonFields & { source: "foreground_dwell"; checkinFix: FixSubmission; checkoutFix: FixSubmission; apartMinutes: number })
  | (CommonFields & { source: "self_report" })
  | (CommonFields & { source: "health_workout" });

function parseCommon(raw: Record<string, unknown>, issues: ParseIssue[]): CommonFields | null {
  const ok0 = issues.length;
  // ⛔ FIX (P3c gate round 2, item 7): "validate deviceId as a UUID; a
  // non-UUID currently returns 500." app.device.id is a real Postgres
  // `uuid` column — a non-UUID string passed as a query parameter used
  // to reach the driver before failing, surfacing as an unhandled 500
  // instead of a clean 400 at the validation layer.
  if (!isUuid(raw.deviceId)) issues.push({ path: "deviceId", message: "must be a UUID" });
  if (!isIdLike(raw.facilityId)) issues.push({ path: "facilityId", message: "must be an id-like string" });
  if (raw.courseId !== undefined && !isIdLike(raw.courseId)) issues.push({ path: "courseId", message: "must be an id-like string when present" });
  if (raw.courseId === null) issues.push({ path: "courseId", message: 'must be OMITTED, not null, when absent (security doc §2: "a SQL NULL maps to an OMITTED JSON field, never a literal null")' });
  if (!isLocalDate(raw.localDate)) issues.push({ path: "localDate", message: "must be a real YYYY-MM-DD calendar date" });
  if (!(typeof raw.catalogVersion === "number" && Number.isInteger(raw.catalogVersion) && raw.catalogVersion >= 0)) {
    issues.push({ path: "catalogVersion", message: "must be a non-negative integer" });
  }
  if (raw.manifestSig !== undefined) {
    const sig = raw.manifestSig as Record<string, unknown>;
    if (
      !isPlainObject(raw.manifestSig) ||
      !isIdLike(sig.kid) ||
      !isBase64UrlId(sig.signatureB64Url) ||
      typeof sig.manifestSha256 !== "string" ||
      !SHA256_HEX_RE.test(sig.manifestSha256)
    ) {
      issues.push({ path: "manifestSig", message: "must be {kid: id-like string, signatureB64Url: base64url string, manifestSha256: 64-char lowercase hex} when present" });
    }
  }
  if (issues.length !== ok0) return null;
  return {
    deviceId: raw.deviceId as string,
    facilityId: raw.facilityId as string,
    courseId: raw.courseId as string | undefined,
    localDate: raw.localDate as string,
    catalogVersion: raw.catalogVersion as number,
    manifestSig: raw.manifestSig as { kid: string; signatureB64Url: string; manifestSha256: string } | undefined,
  };
}

const COMMON_KEYS = new Set(["source", "deviceId", "facilityId", "courseId", "localDate", "catalogVersion", "manifestSig"]);

export function parseEvidenceSubmission(raw: unknown): ParseResult<EvidenceSubmission> {
  if (!isPlainObject(raw)) return { ok: false, issues: [{ path: "", message: "must be an object" }] };
  if (typeof raw.source !== "string") return { ok: false, issues: [{ path: "source", message: "must be a string" }] };
  const source = raw.source;

  if (REJECTED_SOURCES.has(source)) {
    return {
      ok: false,
      issues: [{ path: "source", message: `"${source}" is not accepted via this endpoint — it must come from its own server path (security doc §2)` }],
    };
  }
  if (!ACCEPTED_SOURCES.has(source)) {
    return { ok: false, issues: [{ path: "source", message: `unrecognized source "${source}"` }] };
  }

  const issues: ParseIssue[] = [];
  const common = parseCommon(raw, issues);

  switch (source) {
    case "foreground_checkin": {
      const extraKeys = Object.keys(raw).filter((k) => !COMMON_KEYS.has(k) && k !== "fix");
      for (const k of extraKeys) issues.push({ path: k, message: "unrecognized key" });
      const fix = parseFix(raw.fix, "fix");
      if (!fix.ok) issues.push(...fix.issues);
      if (issues.length > 0 || !common || !fix.ok) return { ok: false, issues };
      return { ok: true, value: { ...common, source: "foreground_checkin", fix: fix.value } };
    }
    case "foreground_dwell": {
      // ⛔ FIX (P3c gate round 2, item 6): `holes` is no longer a
      // client-submitted field at all — see this file's own note above
      // EvidenceSubmission's foreground_dwell variant.
      const extraKeys = Object.keys(raw).filter((k) => !COMMON_KEYS.has(k) && !["checkinFix", "checkoutFix", "apartMinutes"].includes(k));
      for (const k of extraKeys) issues.push({ path: k, message: "unrecognized key" });
      const checkinFix = parseFix(raw.checkinFix, "checkinFix");
      const checkoutFix = parseFix(raw.checkoutFix, "checkoutFix");
      if (!checkinFix.ok) issues.push(...checkinFix.issues);
      if (!checkoutFix.ok) issues.push(...checkoutFix.issues);
      if (!isFiniteNumber(raw.apartMinutes) || raw.apartMinutes < 0) issues.push({ path: "apartMinutes", message: "must be a finite number >= 0" });
      if (issues.length > 0 || !common || !checkinFix.ok || !checkoutFix.ok) return { ok: false, issues };
      return {
        ok: true,
        value: { ...common, source: "foreground_dwell", checkinFix: checkinFix.value, checkoutFix: checkoutFix.value, apartMinutes: raw.apartMinutes as number },
      };
    }
    case "self_report":
    case "health_workout": {
      const extraKeys = Object.keys(raw).filter((k) => !COMMON_KEYS.has(k));
      for (const k of extraKeys) issues.push({ path: k, message: "unrecognized key" });
      if (issues.length > 0 || !common) return { ok: false, issues };
      return { ok: true, value: { ...common, source } as EvidenceSubmission };
    }
    default:
      return { ok: false, issues: [{ path: "source", message: `unrecognized source "${source}"` }] };
  }
}
