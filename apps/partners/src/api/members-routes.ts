/**
 * Typed wrappers for `partner-members` credential settings (docs/security/partner-auth-design.md §65 / §67 / §74 / §75).
 *
 * List + display-note PATCH (class A0); own revoke DELETE and second-credential add (class A2).
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

export async function getCredentials(api: PartnerApi): Promise<readonly PartnerCredential[]> {
  const data = await api.call("GET", "partner-members", "credentials");
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
