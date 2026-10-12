/**
 * Typed wrappers for `partner-invites` manage routes (docs/security/partner-auth-design.md §88).
 *
 * GET invites (class A0); POST invites create and DELETE invites/{id} (class A2).
 * Create returns the `gr_inv_` token and inviteUrl once; never log them.
 * Accept / enrol routes stay in `client.ts` (pre-session). Every call goes through `PartnerApi.call`.
 */

import type { PartnerApi } from "./client";
import { PartnerApiError, isPartnerApiError } from "./errors";

export type InviteRole = "staff" | "manager" | "operator";

/** Edge `InviteView` (GET invites). Never the token hash. */
export interface PartnerInvite {
  readonly id: string;
  readonly orgId: string;
  readonly role: string;
  readonly facilityId: string | null;
  readonly inviteeEmail: string;
  readonly invitedBy: string;
  readonly createdAt: string;
  readonly expiresAt: string;
  readonly acceptedAt: string | null;
  readonly revokedAt: string | null;
  readonly attempts: number;
}

/** Show-once create response (POST invites 201). */
export interface InviteCreated {
  readonly inviteId: string;
  readonly expiresAt: string;
  readonly token: string;
  readonly inviteUrl: string;
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}
const isString = (v: unknown): v is string => typeof v === "string";
const isStringOrNull = (v: unknown): v is string | null => v === null || typeof v === "string";

function malformed(): never {
  throw new PartnerApiError("malformed_response");
}

function parseInvite(raw: unknown): PartnerInvite {
  if (
    !isObject(raw) || !isString(raw["id"]) || !isString(raw["orgId"]) || !isString(raw["role"]) ||
    !isStringOrNull(raw["facilityId"] ?? null) || !isString(raw["inviteeEmail"]) || !isString(raw["invitedBy"]) ||
    !isString(raw["createdAt"]) || !isString(raw["expiresAt"]) || !isStringOrNull(raw["acceptedAt"] ?? null) ||
    !isStringOrNull(raw["revokedAt"] ?? null) || typeof raw["attempts"] !== "number" || !Number.isInteger(raw["attempts"])
  ) malformed();
  return {
    id: raw["id"],
    orgId: raw["orgId"],
    role: raw["role"],
    facilityId: (raw["facilityId"] as string | null) ?? null,
    inviteeEmail: raw["inviteeEmail"],
    invitedBy: raw["invitedBy"],
    createdAt: raw["createdAt"],
    expiresAt: raw["expiresAt"],
    acceptedAt: (raw["acceptedAt"] as string | null) ?? null,
    revokedAt: (raw["revokedAt"] as string | null) ?? null,
    attempts: raw["attempts"],
  };
}

/** GET partner-invites/invites?orgId= (optional). A0; scoped by the actor's reach. */
export async function listInvites(api: PartnerApi, orgId?: string | null): Promise<readonly PartnerInvite[]> {
  const data = await api.call(
    "GET",
    "partner-invites",
    "invites",
    undefined,
    orgId ? { orgId } : undefined,
  );
  if (!isObject(data) || !Array.isArray(data["invites"])) malformed();
  return data["invites"].map(parseInvite);
}

/**
 * POST partner-invites/invites `{ orgId, role, email }` (class A2).
 * Returns plaintext token + inviteUrl once. 409 `already_member` when the address already holds an active membership.
 */
export async function createInvite(
  api: PartnerApi,
  input: { orgId: string; role: InviteRole; email: string },
): Promise<InviteCreated> {
  try {
    const data = await api.call("POST", "partner-invites", "invites", input);
    if (
      !isObject(data) || !isString(data["inviteId"]) || !isString(data["expiresAt"]) ||
      !isString(data["token"]) || !isString(data["inviteUrl"])
    ) malformed();
    return {
      inviteId: data["inviteId"],
      expiresAt: data["expiresAt"],
      token: data["token"],
      inviteUrl: data["inviteUrl"],
    };
  } catch (e) {
    if (isPartnerApiError(e) && (e.code === "already_member" || e.kind === "conflict")) {
      throw new PartnerApiError("conflict", { status: e.status ?? 409, code: "already_member" });
    }
    throw e;
  }
}

/**
 * POST partner-invites/invites/accept `{ token }` (branch E, class A2).
 * An existing credential holder joins another org; no new passkey. 403 when refused; 409 already_member.
 */
export async function acceptInvite(
  api: PartnerApi,
  token: string,
): Promise<{ readonly orgId: string; readonly role: string }> {
  try {
    const data = await api.call("POST", "partner-invites", "invites/accept", { token });
    if (!isObject(data) || !isString(data["orgId"]) || !isString(data["role"])) malformed();
    return { orgId: data["orgId"], role: data["role"] };
  } catch (e) {
    if (isPartnerApiError(e) && (e.code === "already_member" || e.kind === "conflict")) {
      throw new PartnerApiError("conflict", { status: e.status ?? 409, code: "already_member" });
    }
    if (isPartnerApiError(e) && (e.code === "invite_refused" || e.kind === "forbidden")) {
      throw new PartnerApiError("forbidden", { status: e.status ?? 403, code: "invite_refused" });
    }
    throw e;
  }
}

/** DELETE partner-invites/invites/{id} (class A2). 409 when already accepted or already revoked. */
export async function revokeInvite(api: PartnerApi, inviteId: string): Promise<void> {
  try {
    const data = await api.call("DELETE", "partner-invites", `invites/${inviteId}`);
    if (!isObject(data) || data["revoked"] !== true) malformed();
  } catch (e) {
    if (isPartnerApiError(e) && (e.code === "invite_accepted" || e.code === "invite_revoked" || e.kind === "conflict")) {
      throw new PartnerApiError("conflict", { status: e.status ?? 409, code: e.code ?? "invite_revoked" });
    }
    if (isPartnerApiError(e) && (e.kind === "not_found" || e.code === "not_found")) {
      throw new PartnerApiError("not_found", { status: e.status ?? 404, code: "not_found" });
    }
    throw e;
  }
}
