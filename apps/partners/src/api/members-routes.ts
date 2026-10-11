/**
 * Typed wrappers for `partner-members` credential settings (docs/security/partner-auth-design.md §65 / §67 / §74 / §75 / §81 / §82 / §84 / §85).
 *
 * List + display-note PATCH (class A0); own revoke DELETE and second-credential add (class A2).
 * Org roster GET (class A0) and credentials `?userId=` under the reach rule (§79 / §80 / §81).
 * Member PIN reset / recover / revoke under reach (class A2, §82–§84).
 * Org sessions revoke-all (stolen-iPad, class A2, §85).
 * Every call goes through `PartnerApi.call`; response bodies are checked field-by-field.
 */

import type { PartnerApi } from "./client";
import type { RegistrationJson } from "./types";
import { PartnerApiError, isPartnerApiError } from "./errors";

/** Edge `CredentialView` (GET credentials). Active rows are those with `revokedAt === null`. */
export interface PartnerCredential {
  readonly id: string;
  readonly label: string;
  readonly note: string | null;
  readonly createdAt: string;
  readonly lastUsedAt: string | null;
  readonly revokedAt: string | null;
  readonly backupEligible: boolean;
  readonly backupState: boolean;
}

/** Edge `MemberView` (GET members). Never email / token. */
export interface PartnerMember {
  readonly userId: string;
  readonly orgId: string;
  readonly role: string;
  readonly facilityId: string | null;
  readonly invitedBy: string | null;
  readonly createdAt: string;
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}
const isString = (v: unknown): v is string => typeof v === "string";
const isStringOrNull = (v: unknown): v is string | null => v === null || typeof v === "string";
const isBool = (v: unknown): v is boolean => typeof v === "boolean";

function malformed(): never {
  throw new PartnerApiError("malformed_response");
}

function parseCredential(raw: unknown): PartnerCredential {
  if (
    !isObject(raw) || !isString(raw["id"]) || !isString(raw["label"]) || !isStringOrNull(raw["note"] ?? null) ||
    !isString(raw["createdAt"]) || !isStringOrNull(raw["lastUsedAt"] ?? null) || !isStringOrNull(raw["revokedAt"] ?? null) ||
    !isBool(raw["backupEligible"]) || !isBool(raw["backupState"])
  ) malformed();
  return {
    id: raw["id"],
    label: raw["label"],
    note: (raw["note"] as string | null) ?? null,
    createdAt: raw["createdAt"],
    lastUsedAt: (raw["lastUsedAt"] as string | null) ?? null,
    revokedAt: (raw["revokedAt"] as string | null) ?? null,
    backupEligible: raw["backupEligible"],
    backupState: raw["backupState"],
  };
}

function parseMember(raw: unknown): PartnerMember {
  if (
    !isObject(raw) || !isString(raw["userId"]) || !isString(raw["orgId"]) || !isString(raw["role"]) ||
    !isStringOrNull(raw["facilityId"] ?? null) || !isStringOrNull(raw["invitedBy"] ?? null) || !isString(raw["createdAt"])
  ) malformed();
  return {
    userId: raw["userId"],
    orgId: raw["orgId"],
    role: raw["role"],
    facilityId: (raw["facilityId"] as string | null) ?? null,
    invitedBy: (raw["invitedBy"] as string | null) ?? null,
    createdAt: raw["createdAt"],
  };
}

/** GET partner-members/members?orgId= (optional). A0; empty outside manager|operator facility scope. */
export async function listMembers(api: PartnerApi, orgId?: string | null): Promise<readonly PartnerMember[]> {
  const data = await api.call(
    "GET",
    "partner-members",
    "members",
    undefined,
    orgId ? { orgId } : undefined,
  );
  if (!isObject(data) || !Array.isArray(data["members"])) malformed();
  return data["members"].map(parseMember);
}

/** GET partner-members/credentials; omit userId for own, pass uuid for a person under the reach rule (§79). */
export async function getCredentials(api: PartnerApi, userId?: string | null): Promise<readonly PartnerCredential[]> {
  const data = await api.call(
    "GET",
    "partner-members",
    "credentials",
    undefined,
    userId ? { userId } : undefined,
  );
  if (!isObject(data) || !Array.isArray(data["credentials"])) malformed();
  return data["credentials"].map(parseCredential);
}

/** PATCH credentials/{id} body `{ note }` (null / "" clears; ≤40 chars on the wire). 404 → `not_found`. */
export async function patchCredentialNote(api: PartnerApi, id: string, note: string | null): Promise<void> {
  try {
    const data = await api.call("PATCH", "partner-members", `credentials/${id}`, { note });
    if (!isObject(data) || !isStringOrNull(data["note"] ?? null)) malformed();
  } catch (e) {
    if (isPartnerApiError(e) && (e.kind === "not_found" || e.code === "not_found")) {
      throw new PartnerApiError("not_found", { status: e.status ?? 404, code: "not_found" });
    }
    throw e;
  }
}

/** DELETE credentials/{id} (class A2). 404 → `not_found`; 409 → `already_revoked`. */
export async function revokeCredential(api: PartnerApi, id: string): Promise<void> {
  try {
    const data = await api.call("DELETE", "partner-members", `credentials/${id}`);
    if (!isObject(data) || data["revoked"] !== true) malformed();
  } catch (e) {
    if (isPartnerApiError(e) && (e.kind === "not_found" || e.code === "not_found")) {
      throw new PartnerApiError("not_found", { status: e.status ?? 404, code: "not_found" });
    }
    if (isPartnerApiError(e) && (e.code === "already_revoked" || e.kind === "conflict")) {
      throw new PartnerApiError("conflict", { status: e.status ?? 409, code: "already_revoked" });
    }
    throw e;
  }
}

export interface CredentialCreateChallenge {
  readonly options: unknown;
  readonly challengeToken: string;
  readonly expiresAt: string;
}

/** POST credentials/options (class A2). 409 `too_many` when five active. */
export async function credentialOptions(api: PartnerApi): Promise<CredentialCreateChallenge> {
  try {
    const data = await api.call("POST", "partner-members", "credentials/options", {});
    if (!isObject(data) || data["options"] === undefined || !isString(data["challengeToken"]) || !isString(data["expiresAt"])) malformed();
    return { options: data["options"], challengeToken: data["challengeToken"], expiresAt: data["expiresAt"] };
  } catch (e) {
    if (isPartnerApiError(e) && (e.code === "too_many" || e.kind === "conflict")) {
      throw new PartnerApiError("conflict", { status: e.status ?? 409, code: "too_many" });
    }
    throw e;
  }
}

/** POST credentials (class A2): register a second/further passkey. */
export async function registerCredential(api: PartnerApi, challengeToken: string, credential: RegistrationJson): Promise<string> {
  try {
    const data = await api.call("POST", "partner-members", "credentials", { challengeToken, credential });
    if (!isObject(data) || !isString(data["credentialId"])) malformed();
    return data["credentialId"];
  } catch (e) {
    if (isPartnerApiError(e) && (e.code === "too_many" || e.kind === "conflict")) {
      throw new PartnerApiError("conflict", { status: e.status ?? 409, code: "too_many" });
    }
    throw e;
  }
}

/** POST members/{id}/pin-reset (class A2): clear lock/counters, set must_change. 409 `pin_not_set` when unset. */
export async function resetMemberPin(api: PartnerApi, userId: string): Promise<void> {
  try {
    const data = await api.call("POST", "partner-members", `members/${userId}/pin-reset`, {});
    if (!isObject(data) || data["reset"] !== true) malformed();
  } catch (e) {
    if (isPartnerApiError(e) && (e.code === "pin_not_set" || e.kind === "conflict")) {
      throw new PartnerApiError("conflict", { status: e.status ?? 409, code: "pin_not_set" });
    }
    throw e;
  }
}

/** One-time recovery enrolment issued by POST members/{id}/recover. Plaintext shown once; never logged. */
export interface MemberRecovered {
  readonly tokenId: string;
  readonly expiresAt: string;
  readonly token: string;
  readonly enrolUrl: string;
}

/** POST members/{id}/recover (class A2): revoke credentials/sessions, PIN must_change, return `gr_enr_` once. 409 `no_email`. */
export async function recoverMember(api: PartnerApi, userId: string): Promise<MemberRecovered> {
  try {
    const data = await api.call("POST", "partner-members", `members/${userId}/recover`, {});
    if (
      !isObject(data) || !isString(data["tokenId"]) || !isString(data["expiresAt"]) ||
      !isString(data["token"]) || !isString(data["enrolUrl"])
    ) malformed();
    return {
      tokenId: data["tokenId"],
      expiresAt: data["expiresAt"],
      token: data["token"],
      enrolUrl: data["enrolUrl"],
    };
  } catch (e) {
    if (isPartnerApiError(e) && (e.code === "no_email" || e.kind === "conflict")) {
      throw new PartnerApiError("conflict", { status: e.status ?? 409, code: "no_email" });
    }
    throw e;
  }
}

/** POST members/{id}/revoke (class A2): end ONE membership `{ orgId }`. 404 → `not_found`. */
export async function revokeMember(api: PartnerApi, userId: string, orgId: string): Promise<void> {
  try {
    const data = await api.call("POST", "partner-members", `members/${userId}/revoke`, { orgId });
    if (!isObject(data) || data["revoked"] !== true) malformed();
  } catch (e) {
    if (isPartnerApiError(e) && (e.kind === "not_found" || e.code === "not_found")) {
      throw new PartnerApiError("not_found", { status: e.status ?? 404, code: "not_found" });
    }
    throw e;
  }
}

/** Counts from POST orgs/{id}/sessions/revoke-all (class A2). */
export interface OrgRevokeAllResult {
  readonly sessions: number;
  readonly credentials: number;
}

/**
 * POST orgs/{id}/sessions/revoke-all (class A2): stolen-iPad button.
 * `createdAfter` null/absent = sessions only; otherwise a UTC instant (credentials of reach-covered members after T).
 * 404 → `not_found`.
 */
export async function revokeAllOrgSessions(
  api: PartnerApi,
  orgId: string,
  createdAfter: string | null,
): Promise<OrgRevokeAllResult> {
  try {
    const body = createdAfter === null ? {} : { createdAfter };
    const data = await api.call("POST", "partner-members", `orgs/${orgId}/sessions/revoke-all`, body);
    if (
      !isObject(data) || typeof data["revokedSessions"] !== "number" || typeof data["revokedCredentials"] !== "number" ||
      !Number.isInteger(data["revokedSessions"]) || !Number.isInteger(data["revokedCredentials"]) ||
      data["revokedSessions"] < 0 || data["revokedCredentials"] < 0
    ) malformed();
    return { sessions: data["revokedSessions"], credentials: data["revokedCredentials"] };
  } catch (e) {
    if (isPartnerApiError(e) && (e.kind === "not_found" || e.code === "not_found")) {
      throw new PartnerApiError("not_found", { status: e.status ?? 404, code: "not_found" });
    }
    throw e;
  }
}
