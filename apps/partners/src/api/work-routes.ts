/**
 * Typed wrappers for the S7b work screens: `partner-attest`, `course-qr` and `qr-print` (docs/security/partner-auth-design.md 26, 25, S7b).
 *
 * Every call goes through `PartnerApi.call`, so the bearer, the function allow-list and the closed route/query shapes apply. Response bodies are checked
 * field-by-field: a malformed answer is `malformed_response`, never trusted into the UI.
 */

import type { PartnerApi } from "./client";
import { PartnerApiError } from "./errors";

export type AttestKind = "presence" | "marker_purchase";

export interface AttestResult {
  readonly attestationId: string;
  readonly held: boolean;
}

export interface ShiftLogEntry {
  readonly id: string;
  readonly facilityId: string;
  readonly createdAt: string;
  readonly kind: string;
  readonly playerHandle: string;
  readonly staffHandle: string;
}

export interface StaffActivityRow {
  readonly staffUserId: string;
  readonly facilityId: string;
  readonly day: string;
  readonly attests: number;
  readonly activations: number;
  readonly anomalies: number;
}

export interface CoursePin {
  readonly facilityId: string;
  readonly pin: string;
  readonly localDate: string;
  readonly validUntil: string;
  readonly pinEpoch: number;
}

export interface MintedToken {
  readonly facilityId: string;
  readonly token: string;
  readonly link: string | null;
  readonly nonceHash: string;
  readonly kid: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
}

export interface TokenRefresh {
  readonly state: string;
  readonly secondsLeft: number;
}

export interface PrintedQr {
  readonly facilityId: string;
  readonly qrKid: string;
  readonly sig: string;
  readonly printedAt: string;
  readonly revoked: boolean;
  readonly revokedAt: string | null;
  readonly link?: string | null;
  readonly changed?: boolean;
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}
const isString = (v: unknown): v is string => typeof v === "string";
const isStringOrNull = (v: unknown): v is string | null => v === null || typeof v === "string";
const isBool = (v: unknown): v is boolean => typeof v === "boolean";
const isNum = (v: unknown): v is number => typeof v === "number" && Number.isFinite(v);

function malformed(): never {
  throw new PartnerApiError("malformed_response");
}

function parseAttest(data: unknown): AttestResult {
  if (!isObject(data) || !isString(data["attestationId"]) || !isBool(data["held"])) malformed();
  return { attestationId: data["attestationId"], held: data["held"] };
}

export async function postOnlineAttest(api: PartnerApi, input: { facilityId: string; kind: AttestKind; token: string }): Promise<AttestResult> {
  return parseAttest(await api.call("POST", "partner-attest", "attest", input));
}

export async function postOfflineAttest(api: PartnerApi, input: { facilityId: string; kind: AttestKind; handle: string; code: string }): Promise<AttestResult> {
  return parseAttest(await api.call("POST", "partner-attest", "attest/offline", input));
}

export async function getShiftLog(api: PartnerApi, facilityId: string): Promise<readonly ShiftLogEntry[]> {
  const data = await api.call("GET", "partner-attest", "shift-log", undefined, { facilityId });
  if (!isObject(data) || !Array.isArray(data["entries"])) malformed();
  return data["entries"].map((e) => {
    if (!isObject(e) || !isString(e["id"]) || !isString(e["facilityId"]) || !isString(e["createdAt"]) || !isString(e["kind"]) || !isString(e["playerHandle"]) || !isString(e["staffHandle"])) malformed();
    return { id: e["id"], facilityId: e["facilityId"], createdAt: e["createdAt"], kind: e["kind"], playerHandle: e["playerHandle"], staffHandle: e["staffHandle"] };
  });
}

export async function getStaffActivity(api: PartnerApi, facilityId: string, days: number): Promise<readonly StaffActivityRow[]> {
  const data = await api.call("GET", "partner-attest", "staff-activity", undefined, { facilityId, days: String(days) });
  if (!isObject(data) || !Array.isArray(data["activity"])) malformed();
  return data["activity"].map((r) => {
    if (!isObject(r) || !isString(r["staffUserId"]) || !isString(r["facilityId"]) || !isString(r["day"]) || !isNum(r["attests"]) || !isNum(r["activations"]) || !isNum(r["anomalies"])) malformed();
    return { staffUserId: r["staffUserId"], facilityId: r["facilityId"], day: r["day"], attests: r["attests"], activations: r["activations"], anomalies: r["anomalies"] };
  });
}

export async function getCoursePin(api: PartnerApi, facilityId: string): Promise<CoursePin> {
  const data = await api.call("GET", "course-qr", "pin", undefined, { facilityId });
  if (!isObject(data) || !isString(data["facilityId"]) || !isString(data["pin"]) || !isString(data["localDate"]) || !isString(data["validUntil"]) || !isNum(data["pinEpoch"])) malformed();
  return { facilityId: data["facilityId"], pin: data["pin"], localDate: data["localDate"], validUntil: data["validUntil"], pinEpoch: data["pinEpoch"] };
}

export async function postRotatePin(api: PartnerApi, facilityId: string): Promise<{ facilityId: string; pinEpoch: number }> {
  const data = await api.call("POST", "course-qr", "pin/rotate", { facilityId });
  if (!isObject(data) || !isString(data["facilityId"]) || !isNum(data["pinEpoch"])) malformed();
  return { facilityId: data["facilityId"], pinEpoch: data["pinEpoch"] };
}

export async function postMintToken(api: PartnerApi, facilityId: string): Promise<MintedToken> {
  const data = await api.call("POST", "course-qr", "tokens", { facilityId });
  if (
    !isObject(data) || !isString(data["facilityId"]) || !isString(data["token"]) || !isStringOrNull(data["link"] ?? null) ||
    !isString(data["nonceHash"]) || !isString(data["kid"]) || !isString(data["issuedAt"]) || !isString(data["expiresAt"])
  ) malformed();
  return {
    facilityId: data["facilityId"],
    token: data["token"],
    link: (data["link"] as string | null) ?? null,
    nonceHash: data["nonceHash"],
    kid: data["kid"],
    issuedAt: data["issuedAt"],
    expiresAt: data["expiresAt"],
  };
}

export async function postRefreshToken(api: PartnerApi, facilityId: string, nonceHash: string): Promise<TokenRefresh> {
  const data = await api.call("POST", "course-qr", "tokens/refresh", { facilityId, nonceHash });
  if (!isObject(data) || !isString(data["state"]) || !isNum(data["secondsLeft"])) malformed();
  return { state: data["state"], secondsLeft: data["secondsLeft"] };
}

export async function getPrintedQr(api: PartnerApi, facilityId: string): Promise<PrintedQr> {
  const data = await api.call("GET", "qr-print", "", undefined, { facilityId });
  if (
    !isObject(data) || !isString(data["facilityId"]) || !isString(data["qrKid"]) || !isString(data["sig"]) ||
    !isString(data["printedAt"]) || !isBool(data["revoked"]) || !isStringOrNull(data["revokedAt"] ?? null)
  ) malformed();
  return {
    facilityId: data["facilityId"],
    qrKid: data["qrKid"],
    sig: data["sig"],
    printedAt: data["printedAt"],
    revoked: data["revoked"],
    revokedAt: (data["revokedAt"] as string | null) ?? null,
  };
}

export async function postPrintedQr(api: PartnerApi, facilityId: string): Promise<PrintedQr> {
  const data = await api.call("POST", "qr-print", "", { facilityId });
  if (
    !isObject(data) || !isString(data["facilityId"]) || !isString(data["qrKid"]) || !isString(data["sig"]) ||
    !isString(data["printedAt"]) || !isBool(data["revoked"]) || !isStringOrNull(data["revokedAt"] ?? null)
  ) malformed();
  const out: PrintedQr = {
    facilityId: data["facilityId"],
    qrKid: data["qrKid"],
    sig: data["sig"],
    printedAt: data["printedAt"],
    revoked: data["revoked"],
    revokedAt: (data["revokedAt"] as string | null) ?? null,
  };
  if (isStringOrNull(data["link"] ?? null)) (out as { link?: string | null }).link = data["link"] as string | null;
  if (isBool(data["changed"])) (out as { changed?: boolean }).changed = data["changed"];
  return out;
}
