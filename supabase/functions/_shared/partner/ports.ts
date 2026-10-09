// supabase/functions/_shared/partner/ports.ts
//
// The seams of the partner handlers (docs/security/partner-auth-design.md 4.2 / 4.4 / 4.5, slices S1.2 and S1.5): what the pure handlers ask of the database (`PartnerDb`, implemented in
// `privileged.ts`, the sole database site) and of the WebAuthn wrapper (`AssertionVerifier` and `RegistrationVerifier`, implemented in `webauthn-port.ts`). Types and the error classes only: no behaviour,
// no imports, so the handlers and their unit tests (vitest, no Deno) see the contract without pulling in a driver or a library.

/** The relying party, from `app.partner_rp_config` (the exact origin and the RP ID). */
export interface RpConfig {
  readonly rpId: string;
  readonly origin: string;
}

/** A stateless challenge (5.1): 32 random bytes, an expiry in epoch seconds and the HMAC the database computed. */
export interface ChallengeIssue {
  readonly nonce: Uint8Array;
  readonly exp: number;
  readonly mac: Uint8Array;
}

/** What the database knows of a live credential (4.4 `partner_credential_lookup`). */
export interface StoredCredentialRow {
  /** The credential row's uuid (never sent to the client). */
  readonly id: string;
  /** The person (auth.users id): its 16 bytes are the WebAuthn user handle. */
  readonly userId: string;
  readonly alg: number;
  readonly publicKey: Uint8Array;
  readonly signCount: number;
}

/** `ok` carries the credential; `unknown` (an unknown credential and a revoked one are one answer) and `cooldown` (five failed verifications in the last hour) carry nothing. */
export type CredentialLookup = { readonly status: "ok"; readonly credential: StoredCredentialRow } | { readonly status: "unknown" | "cooldown" };

export interface MintInput {
  /** sha256 hex of the opaque session token: the raw token never reaches the database. */
  readonly tokenHash: string;
  readonly credentialId: Uint8Array;
  readonly nonce: Uint8Array;
  readonly exp: number;
  readonly mac: Uint8Array;
  readonly authenticatorData: Uint8Array;
  readonly clientDataJson: Uint8Array;
  readonly signature: Uint8Array;
}

export interface MintResult {
  /** `ok` or one of the refusal statuses of `private.partner_session_mint` (never shown to a client). */
  readonly status: string;
  readonly aal: number | null;
  readonly expiresAt: string | null;
}

/** One transaction as `edge_partner_minter`: no actor is bound. It COMMITS when the callback returns, whatever status it holds (the alarm rows, the burned nonce and the failure counter are written by refusals). */
export interface PartnerMintTx {
  rpConfig(): Promise<RpConfig>;
  issueChallenge(): Promise<ChallengeIssue>;
  lookupCredential(credentialId: Uint8Array): Promise<CredentialLookup>;
  /** Counts one failed verification of a credential (design 8): `counted`, `cooldown` or `unknown`. */
  recordFailure(credentialId: Uint8Array): Promise<"counted" | "cooldown" | "unknown">;
  mint(input: MintInput): Promise<MintResult>;
}

export interface ReauthCredential extends StoredCredentialRow {
  readonly rp: RpConfig;
}

export interface ReauthInput {
  readonly credentialId: Uint8Array;
  readonly nonce: Uint8Array;
  readonly exp: number;
  readonly mac: Uint8Array;
  readonly authenticatorData: Uint8Array;
  readonly clientDataJson: Uint8Array;
  readonly signature: Uint8Array;
}

/** What `GET pin` returns: the PBKDF2 inputs the browser derives with (`ok`), or why it cannot (`unset`, `must_change`, `locked`: none of them carries a salt). */
export type PinParams =
  | { readonly state: "ok"; readonly salt: Uint8Array; readonly iterations: number; readonly retryAfterSeconds: number }
  | { readonly state: "unset" | "must_change" | "locked" };

/** The outcome of evaluating a derived key (partner_pin_verify_for_partner): every one a RETURNED status, so the failure counter commits with the refusal (the 0020 lesson). */
export type PinCheckStatus = "ok" | "wrong" | "locked" | "retry_after" | "unset" | "must_change";
export interface PinVerifyResult {
  readonly status: PinCheckStatus;
  /** Whole seconds until the next attempt is allowed (`retry_after`), or the backoff the failure just started (`wrong`); 0 otherwise. */
  readonly retryAfterSeconds: number;
  /** ISO time the single-use PIN grant expires (`ok` only). */
  readonly grantUntil: string | null;
}

export interface PinSetInput {
  /** The browser-derived key (32 bytes): never the PIN. */
  readonly derived: Uint8Array;
  /** The salt the browser chose (16 bytes). */
  readonly salt: Uint8Array;
  readonly iterations: number;
}
export interface PinChangeInput extends PinSetInput {
  /** The derived key of the CURRENT PIN (32 bytes). */
  readonly current: Uint8Array;
}
export type PinWriteStatus = "ok" | "already_set" | "no_pin" | "must_change" | "wrong" | "locked" | "retry_after" | "unset";
export interface PinWriteResult {
  readonly status: PinWriteStatus;
  readonly retryAfterSeconds: number;
}

/** POST totp/enrol (partner_totp_enrol_for_partner): the derived seed once, or a returned refusal (`already_confirmed`). */
export type TotpEnrolStatus = "ok" | "already_confirmed";
export interface TotpEnrolResult {
  readonly status: TotpEnrolStatus;
  /** The derived seed bytes (`ok` only); never stored. The handler base32-encodes them for the client. */
  readonly seed: Uint8Array | null;
  readonly seedVersion: number | null;
  readonly issuer: string | null;
  readonly period: number | null;
  readonly digits: number | null;
  readonly algo: string | null;
}

/** POST totp/confirm (partner_totp_confirm_for_partner): every refusal a RETURNED status so the failure counter commits. */
export type TotpConfirmStatus = "ok" | "wrong" | "locked" | "unset" | "already_confirmed" | "wrong_session";
export interface TotpConfirmResult {
  readonly status: TotpConfirmStatus;
  readonly retryAfterSeconds: number;
}

/** POST step-up/totp (partner_totp_verify_for_partner): on `ok` the session is aal 2 with mfa_until. */
export type TotpVerifyStatus = "ok" | "wrong" | "locked" | "unset" | "unconfirmed" | "retry_after";
export interface TotpVerifyResult {
  readonly status: TotpVerifyStatus;
  readonly retryAfterSeconds: number;
  /** ISO time the MFA window expires (`ok` only). */
  readonly mfaUntil: string | null;
}

/** POST members/{id}/totp-reset (partner_totp_reset_for_partner, under the full reach rule since 0054): served by `partner-members`. */
export type TotpResetStatus = "ok" | "unset";
export interface TotpResetResult {
  readonly status: TotpResetStatus;
}

/** One transaction as `edge_partner`, bound to the presented session. Every method is a `_for_partner` definer that begins with `partner_authorize`. */
export interface PartnerSessionTx {
  whoami(): Promise<unknown>;
  signOut(): Promise<void>;
  lock(): Promise<void>;
  reauthOptions(): Promise<ChallengeIssue & { readonly rp: RpConfig }>;
  /** The key a reauth assertion is verified against: a live credential of THE SESSION'S OWN person, or null (PA-27). */
  reauthCredential(credentialId: Uint8Array): Promise<ReauthCredential | null>;
  reauth(input: ReauthInput): Promise<{ readonly status: string; readonly reauthUntil: string | null }>;
  /** GET pin (class A0, staff or manager): the PBKDF2 inputs for this person. */
  pinParams(): Promise<PinParams>;
  /** POST step-up/pin: evaluates the derived key; on `ok` the session holds a single-use PIN grant. A returned status for every refusal: the transaction COMMITS (the counter and the audit row with it). */
  pinVerify(derived: Uint8Array): Promise<PinVerifyResult>;
  /** POST pin/set: the first PIN, or the replacement after a reset. 42501 (`PartnerAuthorityRefused`) without an enrolment window or an email proof. */
  pinSet(input: PinSetInput): Promise<PinWriteResult>;
  /** POST pin/change: replace a live PIN (needs the current one, counted like a verify). */
  pinChange(input: PinChangeInput): Promise<PinWriteResult>;
  /** The member's OWN mailbox for the email OTP of the proof, or null when the account has none. Never returned to a client. */
  otpTarget(): Promise<string | null>;
  /** Records the email proof bound to a fresh GoTrue session of this person: `refused` when the session is not fresh for this person or was already used for a proof. */
  otpProof(gotrueSessionId: string): Promise<{ readonly status: "ok" | "refused"; readonly otpProofUntil: string | null }>;
  /** POST totp/enrol: bumps seed_version, returns the derived seed once (PA-24). 42501 without an enrolment window or email proof; 55000 when the Vault key is missing. */
  totpEnrol(): Promise<TotpEnrolResult>;
  /** POST totp/confirm: confirms the unconfirmed seed in the same session that enrolled. */
  totpConfirm(code: string): Promise<TotpConfirmResult>;
  /** POST step-up/totp: evaluates a 6-digit code; on `ok` sets aal 2 and mfa_until. A returned status for every refusal: the transaction COMMITS. */
  totpVerify(code: string): Promise<TotpVerifyResult>;
  /** Reset of another person's TOTP (class A3, the reach rule): used by `partner-members` through `PartnerMembersTx`. */
  totpReset(targetUid: string): Promise<TotpResetResult>;
}

// ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// S1.5 (migration 0054): invites, enrolment and members. Statuses are the SQL's own, one for one; every one of them is a RETURNED row (PA-14), so the transaction that returned it COMMITS.
// ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

/** The roles an invite may name (`sponsor` invites are disabled until P6: the database refuses them with 22023). */
export type InviteRole = "staff" | "manager" | "operator";

/** `partner_invite_accept` (branch N). `existing_member_sign_in` and `recover_required` are reached only by the owner of the invited mailbox (the OTP was just proved). */
export type InviteAcceptStatus = "ok" | "not_found" | "locked" | "email_mismatch" | "email_unconfirmed" | "session_stale" | "existing_member_sign_in" | "recover_required";
export interface InviteAcceptResult {
  readonly status: InviteAcceptStatus;
  /** Present on `ok` only. */
  readonly accepted: { readonly userId: string; readonly inviteId: string; readonly orgId: string; readonly role: string; readonly challenge: ChallengeIssue } | null;
}

/** `partner_enrolment_token_accept` (recovery and admin enrolment tokens: a person, no org). */
export type EnrolmentAcceptStatus = "ok" | "not_found" | "locked" | "email_mismatch" | "email_unconfirmed" | "session_stale" | "existing_member_sign_in" | "refused";
export interface EnrolmentAcceptResult {
  readonly status: EnrolmentAcceptStatus;
  /** Present on `ok` only. */
  readonly accepted: { readonly userId: string; readonly tokenId: string; readonly purpose: string; readonly challenge: ChallengeIssue } | null;
}

/** Which acceptance a registration follows: the `ref_kind` of the register challenge (1 an invite, 2 an enrolment token). */
export type RegisterRefKind = 1 | 2;

export interface RegisterFirstInput {
  /** sha256 hex of the opaque session token the first session is minted with: the raw token never reaches the database. */
  readonly sessionTokenHash: string;
  readonly userId: string;
  readonly refKind: RegisterRefKind;
  readonly refId: string;
  readonly nonce: Uint8Array;
  readonly exp: number;
  readonly mac: Uint8Array;
  /** The create ceremony's raw bytes: the database parses and re-checks all of it (R4-L2). */
  readonly attestationObject: Uint8Array;
  readonly clientDataJson: Uint8Array;
  readonly credentialId: Uint8Array;
  readonly publicKey: Uint8Array;
  readonly transports: readonly string[];
}
/** `partner_credential_register_first`: `ok`, one of its own refusals (`not_accepted`, `accept_expired`, `bad_challenge`, `expired`, `credential_exists`, `other_membership`, `already_registered`) or one of the create core's. */
export interface RegisterFirstResult {
  readonly status: string;
  readonly credentialId: string | null;
  readonly aal: number | null;
  readonly expiresAt: string | null;
  readonly enrolmentUntil: string | null;
}

/** One transaction as `edge_partner_minter` for the enrolment routes: unbound, COMMITS when the callback returns (the attempt counters of the accept definers are written by their refusals). */
export interface PartnerInviteMintTx {
  rpConfig(): Promise<RpConfig>;
  /** The normalised address of a LIVE invite (unaccepted, unrevoked, unexpired, under 10 attempts), or null: unknown, expired, revoked, accepted and locked are one answer. */
  inviteEmailForToken(tokenHash: string): Promise<string | null>;
  inviteAccept(tokenHash: string, verifiedUserId: string, gotrueSessionId: string): Promise<InviteAcceptResult>;
  enrolmentEmailForToken(tokenHash: string): Promise<string | null>;
  enrolmentAccept(tokenHash: string, verifiedUserId: string, gotrueSessionId: string): Promise<EnrolmentAcceptResult>;
  registerFirst(input: RegisterFirstInput): Promise<RegisterFirstResult>;
}

export interface InviteView {
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
export type InviteCreateResult =
  | { readonly status: "ok"; readonly inviteId: string; readonly expiresAt: string }
  | { readonly status: "already_member"; readonly inviteId: null; readonly expiresAt: null };
export type InviteRevokeStatus = "ok" | "not_found" | "already_accepted" | "already_revoked";
/** Branch E (`partner_invite_accept_for_partner`): the core's statuses that a signed-in member can reach. */
export type InviteMemberAcceptStatus = "ok" | "not_found" | "locked" | "email_mismatch" | "email_unconfirmed" | "already_member";
export interface InviteMemberAcceptResult {
  readonly status: InviteMemberAcceptStatus;
  readonly orgId: string | null;
  readonly role: string | null;
}

/** One transaction as `edge_partner` for the `partner-invites` routes. Every method is a `_for_partner` definer that begins with `partner_authorize`. */
export interface PartnerInvitesTx {
  /** POST invites (class A2): only the SHA-256 of the token arrives; 42501 outside the inviter's reach, 22023 for a malformed argument. */
  inviteCreate(orgId: string, role: InviteRole, inviteeEmail: string, tokenHash: string): Promise<InviteCreateResult>;
  /** GET invites (class A0), newest first, never the token hash. */
  inviteList(orgId: string | null): Promise<InviteView[]>;
  /** DELETE invites/{id} (class A2). */
  inviteRevoke(inviteId: string): Promise<InviteRevokeStatus>;
  /** POST invites/accept, branch E (class A2): the SESSION user's confirmed email must equal the invite's. */
  inviteAcceptMember(tokenHash: string): Promise<InviteMemberAcceptResult>;
}

export type MemberRevokeStatus = "ok" | "not_found";
export type MemberRecoverResult =
  | { readonly status: "ok"; readonly tokenId: string; readonly expiresAt: string }
  | { readonly status: "no_email"; readonly tokenId: null; readonly expiresAt: null };
export type PinResetStatus = "ok" | "unset";
export interface OrgRevokeAllResult {
  readonly status: "ok" | "not_found";
  readonly sessions: number;
  readonly credentials: number;
}
export interface AdminEnrolmentResult {
  readonly tokenId: string;
  readonly expiresAt: string;
}

export type CredentialOptionsResult =
  | { readonly status: "ok"; readonly challenge: ChallengeIssue; readonly rp: RpConfig; readonly excludeCredentialIds: readonly Uint8Array[] }
  | { readonly status: "too_many" };
/** The signed-in person a second credential is created for: the WebAuthn user handle is their id (a sign-in assertion must return it), the name is only what an authenticator shows. */
export interface CredentialSubject {
  readonly userId: string;
  readonly email: string | null;
}
export interface CredentialRegisterInput {
  readonly nonce: Uint8Array;
  readonly exp: number;
  readonly mac: Uint8Array;
  readonly attestationObject: Uint8Array;
  readonly clientDataJson: Uint8Array;
  readonly credentialId: Uint8Array;
  readonly publicKey: Uint8Array;
  readonly transports: readonly string[];
}
export interface CredentialView {
  readonly id: string;
  readonly label: string;
  readonly note: string | null;
  readonly createdAt: string;
  readonly lastUsedAt: string | null;
  readonly revokedAt: string | null;
  readonly backupEligible: boolean;
  readonly backupState: boolean;
}
export type CredentialRevokeStatus = "ok" | "not_found" | "already_revoked";

/** One transaction as `edge_partner` for the `partner-members` routes. Every method is a `_for_partner` definer that begins with `partner_authorize`; the reach rule (6.5) is the database's: a target outside it is a 42501. */
export interface PartnerMembersTx extends Pick<PartnerSessionTx, "totpReset"> {
  /** POST members/{id}/revoke (class A2): ONE membership. */
  memberRevoke(targetUserId: string, orgId: string): Promise<MemberRevokeStatus>;
  /** POST members/{id}/recover (class A2): only the SHA-256 of the new enrolment token arrives. */
  memberRecover(targetUserId: string, tokenHash: string): Promise<MemberRecoverResult>;
  /** POST members/{id}/pin-reset (class A2). */
  pinReset(targetUserId: string): Promise<PinResetStatus>;
  /** POST orgs/{id}/sessions/revoke-all (class A2); `createdAfter` is an ISO time or null. */
  orgSessionsRevokeAll(orgId: string, createdAfter: string | null): Promise<OrgRevokeAllResult>;
  /** POST admin/enrolments (class A3): an admin issues an enrolment token for ANOTHER admin. */
  adminEnrolmentIssue(targetUserId: string, tokenHash: string): Promise<AdminEnrolmentResult>;
  /** POST credentials/options (class A2 + reauth). */
  credentialOptions(): Promise<CredentialOptionsResult>;
  credentialSubject(): Promise<CredentialSubject>;
  /** POST credentials (class A2 + reauth): a second credential. */
  credentialRegister(input: CredentialRegisterInput): Promise<{ readonly status: string; readonly credentialId: string | null }>;
  /** GET credentials (class A0): the person's own. */
  credentialList(): Promise<CredentialView[]>;
  /** DELETE credentials/{id} (class A2, one's own included): own, or one the reach rule covers; its sessions die with it. */
  credentialRevoke(credentialId: string): Promise<CredentialRevokeStatus>;
}

/** The kinds an attestation of this slice can have (0056). `offer_redemption` and `special_marker_handover` are other slices'. */
export type AttestKind = "presence" | "marker_purchase";
export const ATTEST_KINDS: readonly AttestKind[] = ["presence", "marker_purchase"];

/** What `partner_attest_for_partner` / `partner_offline_attest_for_partner` answer (0056). Every status except a raise is a returned value, so the failure counters commit. */
export type AttestStatus =
  | "ok"
  | "token_invalid"
  | "replayed"
  | "verification_failed"
  | "rate_limited"
  | "no_facility"
  | "no_programme"
  | "cold_start_cap";
export interface AttestResult {
  readonly status: AttestStatus;
  /** Present only on `ok`. */
  readonly attestationId: string | null;
  /** True when the same-device rule held the purchase (an `ok` attest that went to held_review). */
  readonly held: boolean;
}
/** One row of the shift log (the old `api.staff_shift_log`, a subset of its columns). */
export interface ShiftLogRow {
  readonly id: string;
  readonly facilityId: string;
  readonly createdAt: string;
  readonly kind: string;
  readonly playerHandle: string;
  readonly staffHandle: string;
}
/** One row of `staff_activity`: counts and anomaly markers, never a player id or handle. */
export interface StaffActivityRow {
  readonly staffUserId: string;
  readonly facilityId: string;
  readonly day: string;
  readonly attests: number;
  readonly activations: number;
  readonly anomalies: unknown;
}

/** One transaction as `edge_partner` for the `partner-attest` routes. Every method is a `_for_partner` definer that begins with `partner_authorize` (class A1 for the two attests, A0 for the reads). */
export interface PartnerAttestTx {
  /** POST attest (class A1): the ONLINE path; the player is the owner of the check-in token, never named by the caller. */
  attest(facilityId: string, kind: AttestKind, token: string): Promise<AttestResult>;
  /** POST attest/offline (class A1): the offline code, verified and recorded IN THE DATABASE. The handle and the six digits go in; a status comes out. */
  offlineAttest(facilityId: string, kind: AttestKind, handle: string, code: string): Promise<AttestResult>;
  /** GET shift-log (class A0, staff or manager of the facility). */
  shiftLog(facilityId: string): Promise<ShiftLogRow[]>;
  /** GET staff-activity (class A0, manager or operator of the facility). */
  staffActivity(facilityId: string, days: number): Promise<StaffActivityRow[]>;
}

/** What `partner_resolve_held_*_for_partner` answers (0057). Every status except a raise is a returned value. */
export type ResolveHeldStatus = "ok" | "not_found" | "not_held" | "budget_short";
export interface ResolveHeldResult {
  readonly status: ResolveHeldStatus;
  /** Present only on `ok`: the resulting offer_code_state or entitlement_state. */
  readonly state: string | null;
}
/** One row of the held-review queue (0057). */
export interface HeldQueueRow {
  readonly kind: "offer_code" | "entitlement" | "review_item";
  readonly id: string;
  readonly subjectTable: string;
  readonly subjectId: string;
  readonly userId: string | null;
  readonly handle: string | null;
  readonly facilityId: string | null;
  readonly trailId: string | null;
  readonly holdDetail: unknown;
  readonly reservedAmount: number | null;
  readonly heldAt: string | null;
  readonly slaBreached: boolean;
  readonly reviewKind: string | null;
}
/** The SLA summary the ops alert surface reads (0057). */
export interface ReviewSlaSummary {
  readonly heldOfferCodes: number;
  readonly heldEntitlements: number;
  readonly openReviewItems: number;
  readonly slaBreachedRewards: number;
  readonly slaBreachedReviewItems: number;
  readonly slaHours: number;
}

/** One transaction as `edge_partner` for the `partner-review` routes. Every method is a `_for_partner` definer that begins with `partner_authorize` (class A3 for resolve, A0 for the reads); ADMIN only. */
export interface PartnerReviewTx {
  /** GET queue (class A0, admin). */
  heldQueue(): Promise<HeldQueueRow[]>;
  /** GET sla (class A0, admin). */
  reviewSla(): Promise<ReviewSlaSummary>;
  /** POST resolve/offer-code (class A3, admin). */
  resolveHeldOfferCode(codeId: string, approve: boolean): Promise<ResolveHeldResult>;
  /** POST resolve/entitlement (class A3, admin). */
  resolveHeldEntitlement(entitlementId: string, approve: boolean): Promise<ResolveHeldResult>;
}

/**
 * The email OTP of the proof (6.1, 6.3), through GoTrue with the ANON key, as the player flow already does (E19): `send` mails a one-time code to the member's own address; `verify` proves the mailbox and returns the
 * GoTrue session the verification created, which the database then checks (it must exist, for THIS person, fresh) and which the caller closes AFTER the proof is recorded, on every path. A wrong or expired code is
 * `{ ok: false }`; a transport failure THROWS (it says nothing about the code).
 */
export interface EmailOtpPort {
  send(email: string): Promise<void>;
  verify(email: string, code: string): Promise<{ readonly ok: false } | { readonly ok: true; readonly userId: string; readonly sessionId: string | null; closeSession(): Promise<void> }>;
}

export interface PartnerDb {
  /** Runs `op` in one transaction as `edge_partner_minter`; COMMITS whenever `op` returns (a refusal is a returned value, never a throw). A throw rolls back. */
  withMint<T>(op: (m: PartnerMintTx) => Promise<T>): Promise<T>;
  /** The same transaction (kind `partner_mint`, no binding) with the invite and enrolment definers of 0054 (S1.5). COMMITS whenever `op` returns: the attempt counts are written by refusals (PA-14). */
  withInviteMint<T>(op: (m: PartnerInviteMintTx) => Promise<T>): Promise<T>;
  /** Runs `op` in one transaction as `edge_partner` bound to the session whose token hash this is. Throws `PartnerSessionRefused` when the binder refuses, `PartnerAuthorityRefused` on a 42501 refusal. */
  withSession<T>(tokenHash: string, op: (s: PartnerSessionTx) => Promise<T>): Promise<T>;
  /** `withSession` for the `partner-invites` routes (invite create / list / revoke, branch-E accept): the same bound transaction, the invite definers. */
  withInvites<T>(tokenHash: string, op: (s: PartnerInvitesTx) => Promise<T>): Promise<T>;
  /** `withSession` for the `partner-members` routes (member revoke / recover, PIN and TOTP reset, org revoke-all, credentials): the same bound transaction, the member definers. */
  withMembers<T>(tokenHash: string, op: (s: PartnerMembersTx) => Promise<T>): Promise<T>;
  /** `withSession` for the `partner-attest` routes (attest, offline attest, shift-log, staff-activity): the same bound transaction, the attest definers of 0056 (S3). */
  withAttest<T>(tokenHash: string, op: (s: PartnerAttestTx) => Promise<T>): Promise<T>;
  /** `withSession` for the `partner-review` routes (queue, sla, resolve): the same bound transaction, the review definers of 0057 (S4). */
  withReview<T>(tokenHash: string, op: (s: PartnerReviewTx) => Promise<T>): Promise<T>;
  /** One hit of a per-member bucket, in its OWN short transaction, committed before any request transaction opens (the pool-deadlock rule of `hitRateLimitForActor`). */
  hitRateLimit(tokenHash: string, bucket: string, windowSeconds: number, max: number): Promise<{ readonly ok: boolean; readonly retryAfterSeconds: number }>;
  /** One hit of a SYSTEM bucket (design 8: nothing is bound before authentication, so the buckets keyed on an object the caller cannot choose, the invite token and the target mailbox, are `edge_system` buckets), in its own short transaction. */
  hitSystemRateLimit(bucket: string, windowSeconds: number, max: number): Promise<{ readonly ok: boolean; readonly retryAfterSeconds: number }>;
}

/** The assertion as the browser's `PublicKeyCredential.toJSON()` hands it over (the shape `@simplewebauthn/server` takes). */
export interface AssertionJson {
  id: string;
  rawId: string;
  type: "public-key";
  response: { clientDataJSON: string; authenticatorData: string; signature: string; userHandle?: string };
  clientExtensionResults: Record<string, never>;
}

export interface VerifyAssertionRequest {
  readonly rp: RpConfig;
  readonly response: AssertionJson;
  readonly expectedChallenge: Uint8Array;
  readonly credential: { readonly id: string; readonly publicKey: Uint8Array; readonly signCount: number };
  readonly expectedUserHandle: Uint8Array;
}

/**
 * The outcome of the Edge's own verification. `counterOnly` is true when the assertion fails ONLY because the counter did not advance (re-verified with the stored counter forgotten): a clone
 * indicator, which is passed to the mint anyway so the database writes the audit_log and alarm rows (PA-12). Anything else that fails is a plain refusal.
 */
export type VerifyOutcome = { readonly ok: true } | { readonly ok: false; readonly counterOnly: boolean };

export interface AssertionVerifier {
  /** The sign-in options (UV required, empty allowCredentials) for a challenge the database issued. */
  options(rp: RpConfig, challenge: Uint8Array): Promise<unknown>;
  verify(input: VerifyAssertionRequest): Promise<VerifyOutcome>;
}

/** The create ceremony as the browser's `PublicKeyCredential.toJSON()` hands it over (the shape `@simplewebauthn/server` takes), with the fields the lane never reads dropped. */
export interface RegistrationJson {
  id: string;
  rawId: string;
  type: "public-key";
  response: { clientDataJSON: string; attestationObject: string; transports?: string[] };
  clientExtensionResults: Record<string, never>;
}

export interface CreationOptionsRequest {
  readonly rp: RpConfig;
  /** The person's id (16 bytes): the WebAuthn user handle. */
  readonly userHandle: Uint8Array;
  readonly userName: string;
  /** The 32 bytes the database issued (a `register` challenge, or the session-bound one of `credentials/options`). */
  readonly challenge: Uint8Array;
  /** Credential ids the person already holds (so the authenticator does not register a second one on the same device). */
  readonly excludeCredentialIds: readonly Uint8Array[];
}

export interface VerifyRegistrationRequest {
  readonly rp: RpConfig;
  readonly response: RegistrationJson;
  readonly expectedChallenge: Uint8Array;
}

/** `ok: true` carries what the database stores (the id and key as the library parsed them, the transports reduced to the WebAuthn enum). Any refusal is `{ ok: false }`: the reason stays in the wrapper. */
export type RegistrationOutcome = { readonly ok: true; readonly credentialId: Uint8Array; readonly publicKey: Uint8Array; readonly transports: readonly string[] } | { readonly ok: false };

export interface RegistrationVerifier {
  /** Create options: attestation `none`, discoverable credential and user verification required, ES256 and RS256 only (6.1 step 4). */
  options(req: CreationOptionsRequest): Promise<unknown>;
  verify(req: VerifyRegistrationRequest): Promise<RegistrationOutcome>;
}

/** The binder refused the presented token (28000, one message for unknown, idle, expired, revoked ...): the handler answers the ONE 401. */
export class PartnerSessionRefused extends Error {
  constructor() {
    super("partner_session_refused");
    this.name = "PartnerSessionRefused";
  }
}

/** A definer refused with 42501 (no scope, the assurance level is below the member's required one): the handler answers 403. */
export class PartnerAuthorityRefused extends Error {
  constructor() {
    super("partner_authority_refused");
    this.name = "PartnerAuthorityRefused";
  }
}

/** A deploy fault (the relying-party row or the Vault key is missing, or the configured origin disagrees with the database's): a bare 503, never a client refusal. */
export class PartnerNotConfigured extends Error {
  constructor() {
    super("partner_not_configured");
    this.name = "PartnerNotConfigured";
  }
}

/** A unique index refused the write (23505): in this lane, only a GoTrue session that already proved another proof. The handler answers a 409 (an OTP proof answers its one 403). */
export class PartnerConflict extends Error {
  constructor() {
    super("partner_conflict");
    this.name = "PartnerConflict";
  }
}

/** A definer refused a malformed argument (22023), most often an action on oneself where the rule is "a different target person": the handler answers 422. */
export class PartnerInvalidArgument extends Error {
  constructor() {
    super("partner_invalid_argument");
    this.name = "PartnerInvalidArgument";
  }
}
