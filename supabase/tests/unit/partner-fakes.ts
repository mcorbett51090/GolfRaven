// supabase/tests/unit/partner-fakes.ts
//
// In-memory fakes of the partner handler's ports (supabase/functions/_shared/partner/ports.ts), shared by the vitest suite (partner-session-handler.test.ts). They RECORD every call, and the fake
// `withMint` / `withSession` model exactly one thing the real ones are proven to do: a transaction COMMITS when its callback returns (whatever the callback returns) and ROLLS BACK when it throws. That
// is how the "commit on every status" cells state their claim: `committed` is true for every returned refusal and false for a throw.

import {
  type AdminEnrolmentResult,
  type AssertionVerifier,
  type ChallengeIssue,
  type CredentialOptionsResult,
  type CredentialRegisterInput,
  type CredentialRevokeStatus,
  type CredentialSubject,
  type CredentialView,
  type CreationOptionsRequest,
  type CredentialLookup,
  type EmailOtpPort,
  type EnrolmentAcceptResult,
  type InviteAcceptResult,
  type InviteCreateResult,
  type InviteMemberAcceptResult,
  type InviteRevokeStatus,
  type InviteRole,
  type InviteView,
  type MemberRecoverResult,
  type MemberRevokeStatus,
  type MintInput,
  type MintResult,
  type OrgRevokeAllResult,
  type PartnerDb,
  type PartnerInviteMintTx,
  type PartnerInvitesTx,
  type PartnerMembersTx,
  type PartnerMintTx,
  type PartnerSessionTx,
  PartnerAuthorityRefused,
  PartnerInvalidArgument,
  PartnerSessionRefused,
  type PinResetStatus,
  type RegisterFirstInput,
  type RegisterFirstResult,
  type RegistrationOutcome,
  type RegistrationVerifier,
  type VerifyRegistrationRequest,
  type PinChangeInput,
  type PinParams,
  type PinSetInput,
  type PinVerifyResult,
  type PinWriteResult,
  type ReauthCredential,
  type ReauthInput,
  type RpConfig,
  type TotpConfirmResult,
  type TotpEnrolResult,
  type TotpResetResult,
  type TotpVerifyResult,
  type VerifyAssertionRequest,
  type VerifyOutcome,
} from "../../functions/_shared/partner/ports.ts";
import { type PartnerInvitesDeps } from "../../functions/_shared/partner/invites-handler.ts";
import { type PartnerMembersDeps } from "../../functions/_shared/partner/members-handler.ts";
import { type PartnerSessionDeps } from "../../functions/_shared/partner/session-handler.ts";
import { fromB64u, toB64u } from "../../functions/_shared/partner/token.ts";

export const ORIGIN = "https://partners.example.test";
export const RP: RpConfig = { rpId: "partners.example.test", origin: ORIGIN };
export const USER_ID = "00000000-0000-0000-0000-1000000000a1";
export const NOW_MS = Date.UTC(2030, 0, 1, 12, 0, 0);

export const bytes = (n: number, fill = 7): Uint8Array => new Uint8Array(n).fill(fill);

/** A well-formed challenge token, `exp` seconds since the epoch. */
export function challengeToken(exp = NOW_MS / 1000 + 100, nonceFill = 1, macFill = 2): string {
  return `${toB64u(bytes(32, nonceFill))}.${exp}.${toB64u(bytes(32, macFill))}`;
}

export const CRED_ID = bytes(32, 9);

/** A well-formed `credential` body. */
export function credentialJson(over: Record<string, unknown> = {}, response: Record<string, unknown> = {}): Record<string, unknown> {
  const id = toB64u(CRED_ID);
  return {
    id,
    rawId: id,
    type: "public-key",
    response: {
      clientDataJSON: toB64u(new TextEncoder().encode('{"type":"webauthn.get"}')),
      authenticatorData: toB64u(bytes(37, 3)),
      signature: toB64u(bytes(70, 4)),
      userHandle: toB64u(bytes(16, 5)),
      ...response,
    },
    clientExtensionResults: {},
    ...over,
  };
}

export function verifyBody(over: Record<string, unknown> = {}): Record<string, unknown> {
  return { challengeToken: challengeToken(), credential: credentialJson(), ...over };
}

/** What the S1.5 ports (invites, enrolment, members) were handed, in call order. */
export interface Recorded {
  readonly systemHits: Array<{ bucket: string; windowSeconds: number; max: number }>;
  readonly emailLookups: Array<{ kind: "invite" | "enrolment"; hash: string }>;
  readonly accepts: Array<{ kind: "invite" | "enrolment"; hash: string; userId: string; gotrueSessionId: string }>;
  readonly registerFirst: RegisterFirstInput[];
  readonly registrationVerify: VerifyRegistrationRequest[];
  readonly registrationOptions: CreationOptionsRequest[];
  readonly otpSentTo: Array<{ port: "invite" | "enrolment"; email: string }>;
  readonly otpVerifiedBy: Array<{ port: "invite" | "enrolment"; email: string; code: string }>;
  readonly inviteCreate: Array<{ orgId: string; role: InviteRole; email: string; tokenHash: string }>;
  readonly inviteList: Array<string | null>;
  readonly inviteRevoke: string[];
  readonly inviteAcceptMember: string[];
  readonly memberRevoke: Array<{ target: string; org: string }>;
  readonly memberRecover: Array<{ target: string; hash: string }>;
  readonly pinReset: string[];
  readonly revokeAll: Array<{ org: string; createdAfter: string | null }>;
  readonly adminEnrol: Array<{ target: string; hash: string }>;
  readonly credentialRegister: CredentialRegisterInput[];
  readonly credentialRevoke: string[];
}

export interface Fakes {
  readonly deps: PartnerSessionDeps;
  readonly invitesDeps: PartnerInvitesDeps;
  readonly membersDeps: PartnerMembersDeps;
  readonly rec: Recorded;
  /** every call to a port, in order, as `"mint.lookupCredential"` ... */
  readonly calls: string[];
  /** the outcome of every `withMint` / `withSession` transaction */
  readonly tx: Array<{ kind: "mint" | "session"; committed: boolean }>;
  /** the session-token hashes the S1.5 deps minted, in order */
  readonly newTokens: { readonly session: string[]; readonly invite: string[]; readonly enrolment: string[] };
  readonly mintInputs: MintInput[];
  readonly reauthInputs: ReauthInput[];
  readonly verifyRequests: VerifyAssertionRequest[];
  readonly sessionHashes: string[];
  readonly rateLimitHits: Array<{ hash: string; bucket: string; windowSeconds: number; max: number }>;
  /** what the PIN and proof ports were handed (S1.3) */
  readonly pinVerifyInputs: Uint8Array[];
  readonly pinSetInputs: PinSetInput[];
  readonly pinChangeInputs: PinChangeInput[];
  readonly otpSent: string[];
  readonly otpVerified: Array<{ email: string; code: string }>;
  readonly otpProofSessionIds: string[];
  /** what the TOTP ports were handed (S1.4) */
  readonly totpConfirmCodes: string[];
  readonly totpVerifyCodes: string[];
  readonly totpResetTargets: string[];
  /** how many GoTrue sessions the fake OTP port has closed */
  readonly otpClosed: { count: number };
  /** the number of database transactions OPEN at the moment each GoTrue call was made (it must always be 0: a vendor call is never made inside a transaction) */
  readonly openTxAtOtpCall: number[];
  /** knobs */
  state: {
    rp: RpConfig;
    lookup: CredentialLookup;
    mintStatus: string;
    verify: VerifyOutcome;
    bindRefused: boolean;
    reauthCredential: ReauthCredential | null;
    reauthStatus: string;
    rateLimitOk: boolean;
    whoami: unknown;
    throwIn: string | null;
    pinParams: PinParams;
    pinVerify: PinVerifyResult;
    pinWrite: PinWriteResult;
    otpEmail: string | null;
    otpProofStatus: "ok" | "refused";
    otpVerifyOk: boolean;
    otpSessionId: string | null;
    otpProofThrows: Error | null;
    otpSendThrows: boolean;
    totpEnrol: TotpEnrolResult;
    totpConfirm: TotpConfirmResult;
    totpVerify: TotpVerifyResult;
    totpReset: TotpResetResult;
    /** S1.5 (invites, enrolment, members) */
    inviteEmail: string | null;
    enrolmentEmail: string | null;
    inviteAccept: InviteAcceptResult;
    enrolmentAccept: EnrolmentAcceptResult;
    registerFirst: RegisterFirstResult;
    registration: RegistrationOutcome;
    systemRateLimitOk: boolean;
    inviteCreate: InviteCreateResult;
    inviteList: InviteView[];
    inviteRevoke: InviteRevokeStatus;
    inviteMemberAccept: InviteMemberAcceptResult;
    memberRevoke: MemberRevokeStatus;
    memberRecover: MemberRecoverResult;
    pinReset: PinResetStatus;
    revokeAll: OrgRevokeAllResult;
    adminEnrol: AdminEnrolmentResult;
    credentialOptions: CredentialOptionsResult;
    credentialSubject: CredentialSubject;
    credentialRegister: { status: string; credentialId: string | null };
    credentialList: CredentialView[];
    credentialRevoke: CredentialRevokeStatus;
    /** a bound-transaction method (`inviteCreate`, `memberRevoke` ...) that throws `PartnerAuthorityRefused` (42501) / `PartnerInvalidArgument` (22023) */
    authorityRefusedIn: string | null;
    invalidArgumentIn: string | null;
  };
}

export const INVITE_ID = "00000000-0000-0000-0000-2000000000b1";
export const ORG_ID = "00000000-0000-0000-0000-3000000000c1";
export const TARGET_ID = "00000000-0000-0000-0000-4000000000d1";
export const CRED_ROW_ID = "00000000-0000-0000-0000-5000000000e1";
export const TOKEN_ID = "00000000-0000-0000-0000-6000000000f1";
/** well-formed invite and enrolment tokens (`gr_inv_` / `gr_enr_` + 43 base64url characters) */
export const INVITE_TOKEN = "gr_inv_" + toB64u(bytes(32, 61));
export const ENROLMENT_TOKEN = "gr_enr_" + toB64u(bytes(32, 62));
export const OTP_CODE = "123456";

/** A well-formed create-ceremony `credential` body (`PublicKeyCredential.toJSON()` of a `credentials.create`). */
export function registrationCredentialJson(over: Record<string, unknown> = {}, response: Record<string, unknown> = {}): Record<string, unknown> {
  const id = toB64u(CRED_ID);
  return {
    id,
    rawId: id,
    type: "public-key",
    response: {
      clientDataJSON: toB64u(new TextEncoder().encode('{"type":"webauthn.create"}')),
      attestationObject: toB64u(bytes(120, 8)),
      transports: ["internal", "hybrid"],
      ...response,
    },
    clientExtensionResults: {},
    ...over,
  };
}

/** The body of POST credentials in enrolment mode. */
export function enrolCredentialBody(over: Record<string, unknown> = {}): Record<string, unknown> {
  return { userId: USER_ID, refKind: "invite", refId: INVITE_ID, challengeToken: challengeToken(), credential: registrationCredentialJson(), ...over };
}

export function makeFakes(over: Partial<Fakes["state"]> = {}, allowedOrigin: string | null = ORIGIN): Fakes {
  const calls: string[] = [];
  const tx: Fakes["tx"] = [];
  const mintInputs: MintInput[] = [];
  const reauthInputs: ReauthInput[] = [];
  const verifyRequests: VerifyAssertionRequest[] = [];
  const sessionHashes: string[] = [];
  const rateLimitHits: Fakes["rateLimitHits"] = [];
  const pinVerifyInputs: Uint8Array[] = [];
  const pinSetInputs: PinSetInput[] = [];
  const pinChangeInputs: PinChangeInput[] = [];
  const otpSent: string[] = [];
  const otpVerified: Array<{ email: string; code: string }> = [];
  const otpProofSessionIds: string[] = [];
  const totpConfirmCodes: string[] = [];
  const totpVerifyCodes: string[] = [];
  const totpResetTargets: string[] = [];
  const otpClosed = { count: 0 };
  const openTxAtOtpCall: number[] = [];
  const open = { count: 0 };
  const rec: Recorded = {
    systemHits: [],
    emailLookups: [],
    accepts: [],
    registerFirst: [],
    registrationVerify: [],
    registrationOptions: [],
    otpSentTo: [],
    otpVerifiedBy: [],
    inviteCreate: [],
    inviteList: [],
    inviteRevoke: [],
    inviteAcceptMember: [],
    memberRevoke: [],
    memberRecover: [],
    pinReset: [],
    revokeAll: [],
    adminEnrol: [],
    credentialRegister: [],
    credentialRevoke: [],
  };
  const newTokens: Fakes["newTokens"] = { session: [], invite: [], enrolment: [] };
  const state: Fakes["state"] = {
    rp: RP,
    lookup: { status: "ok", credential: { id: "11111111-1111-1111-1111-111111111111", userId: USER_ID, alg: -7, publicKey: bytes(77, 6), signCount: 4 } },
    mintStatus: "ok",
    verify: { ok: true },
    bindRefused: false,
    reauthCredential: { id: "11111111-1111-1111-1111-111111111111", userId: USER_ID, alg: -7, publicKey: bytes(77, 6), signCount: 4, rp: RP },
    reauthStatus: "ok",
    rateLimitOk: true,
    whoami: { userId: USER_ID, aal: 1 },
    throwIn: null,
    pinParams: { state: "ok", salt: bytes(16, 8), iterations: 600000, retryAfterSeconds: 0 },
    pinVerify: { status: "ok", retryAfterSeconds: 0, grantUntil: "2030-01-01T12:01:00.000Z" },
    pinWrite: { status: "ok", retryAfterSeconds: 0 },
    otpEmail: "staff@example.test",
    otpProofStatus: "ok",
    otpVerifyOk: true,
    otpSessionId: "22222222-2222-2222-2222-222222222222",
    otpProofThrows: null,
    otpSendThrows: false,
    totpEnrol: {
      status: "ok",
      seed: bytes(32, 0xab),
      seedVersion: 1,
      issuer: "GolfRaven",
      period: 30,
      digits: 6,
      algo: "SHA1",
    },
    totpConfirm: { status: "ok", retryAfterSeconds: 0 },
    totpVerify: { status: "ok", retryAfterSeconds: 0, mfaUntil: "2030-01-01T12:05:00.000Z" },
    totpReset: { status: "ok" },
    inviteEmail: "invitee@example.test",
    enrolmentEmail: "staff@example.test",
    inviteAccept: {
      status: "ok",
      accepted: { userId: USER_ID, inviteId: INVITE_ID, orgId: ORG_ID, role: "staff", challenge: { nonce: bytes(32, 11), exp: NOW_MS / 1000 + 600, mac: bytes(32, 12) } },
    },
    enrolmentAccept: {
      status: "ok",
      accepted: { userId: USER_ID, tokenId: TOKEN_ID, purpose: "recover", challenge: { nonce: bytes(32, 13), exp: NOW_MS / 1000 + 600, mac: bytes(32, 14) } },
    },
    registerFirst: { status: "ok", credentialId: CRED_ROW_ID, aal: 1, expiresAt: "2030-01-01T20:00:00.000Z", enrolmentUntil: "2030-01-01T12:15:00.000Z" },
    registration: { ok: true, credentialId: CRED_ID, publicKey: bytes(77, 6), transports: ["internal"] },
    systemRateLimitOk: true,
    inviteCreate: { status: "ok", inviteId: INVITE_ID, expiresAt: "2030-01-04T12:00:00.000Z" },
    inviteList: [],
    inviteRevoke: "ok",
    inviteMemberAccept: { status: "ok", orgId: ORG_ID, role: "staff" },
    memberRevoke: "ok",
    memberRecover: { status: "ok", tokenId: TOKEN_ID, expiresAt: "2030-01-02T12:00:00.000Z" },
    pinReset: "ok",
    revokeAll: { status: "ok", sessions: 3, credentials: 1 },
    adminEnrol: { tokenId: TOKEN_ID, expiresAt: "2030-01-02T12:00:00.000Z" },
    credentialOptions: { status: "ok", challenge: { nonce: bytes(32, 15), exp: NOW_MS / 1000 + 120, mac: bytes(32, 16) }, rp: RP, excludeCredentialIds: [bytes(32, 17)] },
    credentialSubject: { userId: USER_ID, email: "staff@example.test" },
    credentialRegister: { status: "ok", credentialId: CRED_ROW_ID },
    credentialList: [],
    credentialRevoke: "ok",
    authorityRefusedIn: null,
    invalidArgumentIn: null,
    ...over,
  };
  const maybeThrow = (where: string) => {
    if (state.throwIn === where) throw new Error(`boom in ${where}: secret database text`);
    if (state.authorityRefusedIn === where) throw new PartnerAuthorityRefused();
    if (state.invalidArgumentIn === where) throw new PartnerInvalidArgument();
  };

  const mintTx: PartnerMintTx & PartnerInviteMintTx = {
    async rpConfig() {
      calls.push("mint.rpConfig");
      maybeThrow("rpConfig");
      return state.rp;
    },
    async issueChallenge(): Promise<ChallengeIssue> {
      calls.push("mint.issueChallenge");
      maybeThrow("issueChallenge");
      return { nonce: bytes(32, 1), exp: NOW_MS / 1000 + 120, mac: bytes(32, 2) };
    },
    async lookupCredential() {
      calls.push("mint.lookupCredential");
      maybeThrow("lookupCredential");
      return state.lookup;
    },
    async recordFailure() {
      calls.push("mint.recordFailure");
      return "counted";
    },
    async mint(input: MintInput): Promise<MintResult> {
      calls.push("mint.mint");
      mintInputs.push(input);
      maybeThrow("mint");
      return state.mintStatus === "ok" ? { status: "ok", aal: 1, expiresAt: "2030-01-01T20:00:00.000Z" } : { status: state.mintStatus, aal: null, expiresAt: null };
    },
    async inviteEmailForToken(hash) {
      calls.push("mint.inviteEmailForToken");
      rec.emailLookups.push({ kind: "invite", hash });
      maybeThrow("inviteEmailForToken");
      return state.inviteEmail;
    },
    async inviteAccept(hash, userId, gotrueSessionId) {
      calls.push("mint.inviteAccept");
      rec.accepts.push({ kind: "invite", hash, userId, gotrueSessionId });
      maybeThrow("inviteAccept");
      return state.inviteAccept;
    },
    async enrolmentEmailForToken(hash) {
      calls.push("mint.enrolmentEmailForToken");
      rec.emailLookups.push({ kind: "enrolment", hash });
      return state.enrolmentEmail;
    },
    async enrolmentAccept(hash, userId, gotrueSessionId) {
      calls.push("mint.enrolmentAccept");
      rec.accepts.push({ kind: "enrolment", hash, userId, gotrueSessionId });
      return state.enrolmentAccept;
    },
    async registerFirst(input: RegisterFirstInput) {
      calls.push("mint.registerFirst");
      rec.registerFirst.push(input);
      maybeThrow("registerFirst");
      return state.registerFirst;
    },
  };
  const sessionTx: PartnerSessionTx & PartnerInvitesTx & PartnerMembersTx = {
    async whoami() {
      calls.push("session.whoami");
      maybeThrow("whoami");
      return state.whoami;
    },
    async signOut() {
      calls.push("session.signOut");
    },
    async lock() {
      calls.push("session.lock");
    },
    async reauthOptions() {
      calls.push("session.reauthOptions");
      return { nonce: bytes(32, 1), exp: NOW_MS / 1000 + 120, mac: bytes(32, 2), rp: state.rp };
    },
    async reauthCredential() {
      calls.push("session.reauthCredential");
      return state.reauthCredential;
    },
    async pinParams() {
      calls.push("session.pinParams");
      return state.pinParams;
    },
    async pinVerify(derived: Uint8Array) {
      calls.push("session.pinVerify");
      pinVerifyInputs.push(derived);
      return state.pinVerify;
    },
    async pinSet(input: PinSetInput) {
      calls.push("session.pinSet");
      pinSetInputs.push(input);
      return state.pinWrite;
    },
    async pinChange(input: PinChangeInput) {
      calls.push("session.pinChange");
      pinChangeInputs.push(input);
      return state.pinWrite;
    },
    async otpTarget() {
      calls.push("session.otpTarget");
      return state.otpEmail;
    },
    async otpProof(gotrueSessionId: string) {
      calls.push("session.otpProof");
      otpProofSessionIds.push(gotrueSessionId);
      if (state.otpProofThrows !== null) throw state.otpProofThrows;
      return state.otpProofStatus === "ok" ? { status: "ok" as const, otpProofUntil: "2030-01-01T12:10:00.000Z" } : { status: "refused" as const, otpProofUntil: null };
    },
    async totpEnrol() {
      calls.push("session.totpEnrol");
      return state.totpEnrol;
    },
    async totpConfirm(code: string) {
      calls.push("session.totpConfirm");
      totpConfirmCodes.push(code);
      return state.totpConfirm;
    },
    async totpVerify(code: string) {
      calls.push("session.totpVerify");
      totpVerifyCodes.push(code);
      return state.totpVerify;
    },
    async totpReset(targetUid: string) {
      calls.push("session.totpReset");
      totpResetTargets.push(targetUid);
      return state.totpReset;
    },
    async reauth(input: ReauthInput) {
      calls.push("session.reauth");
      reauthInputs.push(input);
      return state.reauthStatus === "ok" ? { status: "ok", reauthUntil: "2030-01-01T12:05:00.000Z" } : { status: state.reauthStatus, reauthUntil: null };
    },
    async inviteCreate(orgId, role, email, tokenHash) {
      calls.push("session.inviteCreate");
      rec.inviteCreate.push({ orgId, role, email, tokenHash });
      maybeThrow("inviteCreate");
      return state.inviteCreate;
    },
    async inviteList(orgId) {
      calls.push("session.inviteList");
      rec.inviteList.push(orgId);
      maybeThrow("inviteList");
      return state.inviteList;
    },
    async inviteRevoke(id) {
      calls.push("session.inviteRevoke");
      rec.inviteRevoke.push(id);
      maybeThrow("inviteRevoke");
      return state.inviteRevoke;
    },
    async inviteAcceptMember(hash) {
      calls.push("session.inviteAcceptMember");
      rec.inviteAcceptMember.push(hash);
      maybeThrow("inviteAcceptMember");
      return state.inviteMemberAccept;
    },
    async memberRevoke(target, org) {
      calls.push("session.memberRevoke");
      rec.memberRevoke.push({ target, org });
      maybeThrow("memberRevoke");
      return state.memberRevoke;
    },
    async memberRecover(target, hash) {
      calls.push("session.memberRecover");
      rec.memberRecover.push({ target, hash });
      maybeThrow("memberRecover");
      return state.memberRecover;
    },
    async pinReset(target) {
      calls.push("session.pinReset");
      rec.pinReset.push(target);
      maybeThrow("pinReset");
      return state.pinReset;
    },
    async orgSessionsRevokeAll(org, createdAfter) {
      calls.push("session.orgSessionsRevokeAll");
      rec.revokeAll.push({ org, createdAfter });
      maybeThrow("orgSessionsRevokeAll");
      return state.revokeAll;
    },
    async adminEnrolmentIssue(target, hash) {
      calls.push("session.adminEnrolmentIssue");
      rec.adminEnrol.push({ target, hash });
      maybeThrow("adminEnrolmentIssue");
      return state.adminEnrol;
    },
    async credentialOptions() {
      calls.push("session.credentialOptions");
      maybeThrow("credentialOptions");
      return state.credentialOptions;
    },
    async credentialSubject() {
      calls.push("session.credentialSubject");
      return state.credentialSubject;
    },
    async credentialRegister(input) {
      calls.push("session.credentialRegister");
      rec.credentialRegister.push(input);
      maybeThrow("credentialRegister");
      return state.credentialRegister;
    },
    async credentialList() {
      calls.push("session.credentialList");
      maybeThrow("credentialList");
      return state.credentialList;
    },
    async credentialRevoke(id) {
      calls.push("session.credentialRevoke");
      rec.credentialRevoke.push(id);
      maybeThrow("credentialRevoke");
      return state.credentialRevoke;
    },
  };
  async function runMint<T>(op: (m: PartnerMintTx & PartnerInviteMintTx) => Promise<T>): Promise<T> {
    calls.push("db.withMint");
    let committed = false;
    try {
      const r = await op(mintTx);
      committed = true;
      return r;
    } finally {
      tx.push({ kind: "mint", committed });
    }
  }
  async function runSession<T>(hash: string, op: (s: PartnerSessionTx & PartnerInvitesTx & PartnerMembersTx) => Promise<T>): Promise<T> {
    calls.push("db.withSession");
    sessionHashes.push(hash);
    if (state.bindRefused) throw new PartnerSessionRefused();
    let committed = false;
    open.count += 1;
    try {
      const r = await op(sessionTx);
      committed = true;
      return r;
    } finally {
      open.count -= 1;
      tx.push({ kind: "session", committed });
    }
  }
  const db: PartnerDb = {
    withMint: runMint,
    withInviteMint: runMint,
    withSession: runSession,
    withInvites: runSession,
    withMembers: runSession,
    withAttest: () => Promise.reject(new Error("not used: the attest handler has its own fake (partner-attest-handler.test.ts)")),
    withReview: () => Promise.reject(new Error("not used: the review handler has its own fake (partner-review-handler.test.ts)")),
    withStock: () => Promise.reject(new Error("not used: the stock handler has its own fake (partner-stock-handler.test.ts)")),
    withEntitlements: () => Promise.reject(new Error("not used: the entitlements handler has its own fake (partner-entitlements-handler.test.ts)")),
    async hitRateLimit(hash, bucket, windowSeconds, max) {
      calls.push("db.hitRateLimit");
      rateLimitHits.push({ hash, bucket, windowSeconds, max });
      if (state.bindRefused) throw new PartnerSessionRefused();
      return state.rateLimitOk ? { ok: true, retryAfterSeconds: 0 } : { ok: false, retryAfterSeconds: 3600 };
    },
    async hitSystemRateLimit(bucket, windowSeconds, max) {
      calls.push("db.hitSystemRateLimit");
      rec.systemHits.push({ bucket, windowSeconds, max });
      return state.systemRateLimitOk ? { ok: true, retryAfterSeconds: 0 } : { ok: false, retryAfterSeconds: windowSeconds };
    },
  };
  const webauthn: AssertionVerifier = {
    async options() {
      calls.push("webauthn.options");
      return { challenge: "x", userVerification: "required", allowCredentials: [] };
    },
    async verify(input) {
      calls.push("webauthn.verify");
      verifyRequests.push(input);
      return state.verify;
    },
  };
  const makeOtp = (port: "invite" | "enrolment" | "session"): EmailOtpPort => ({
    async send(email) {
      calls.push(port === "session" ? "otp.send" : `${port}Otp.send`);
      openTxAtOtpCall.push(open.count);
      if (port === "session") otpSent.push(email);
      else rec.otpSentTo.push({ port, email });
      if (state.otpSendThrows) throw new Error("mailer down: secret provider text");
    },
    async verify(email, code) {
      calls.push(port === "session" ? "otp.verify" : `${port}Otp.verify`);
      openTxAtOtpCall.push(open.count);
      if (port === "session") otpVerified.push({ email, code });
      else rec.otpVerifiedBy.push({ port, email, code });
      if (!state.otpVerifyOk) return { ok: false as const };
      return {
        ok: true as const,
        userId: USER_ID,
        sessionId: state.otpSessionId,
        async closeSession() {
          calls.push(port === "session" ? "otp.closeSession" : `${port}Otp.closeSession`);
          openTxAtOtpCall.push(open.count);
          otpClosed.count += 1;
        },
      };
    },
  });
  const otp = makeOtp("session");
  const registration: RegistrationVerifier = {
    async options(req) {
      calls.push("registration.options");
      rec.registrationOptions.push(req);
      return { challenge: "x", attestation: "none", authenticatorSelection: { residentKey: "required", userVerification: "required" } };
    },
    async verify(req) {
      calls.push("registration.verify");
      rec.registrationVerify.push(req);
      return state.registration;
    },
  };
  let tokenCount = 0;
  const deps: PartnerSessionDeps = {
    db,
    allowedOrigin,
    webauthn,
    otp,
    nowMs: () => NOW_MS,
    newSessionToken: async () => {
      tokenCount += 1;
      const token = "gr_ps_" + toB64u(bytes(32, 100 + tokenCount));
      const hash = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token))), (b) => b.toString(16).padStart(2, "0")).join("");
      return { token, hash };
    },
  };
  const issue = (prefix: string, into: string[]) => async () => {
    const token = prefix + toB64u(bytes(32, 100 + into.length + 1));
    const hash = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token))), (b) => b.toString(16).padStart(2, "0")).join("");
    into.push(hash);
    return { token, hash };
  };
  const invitesDeps: PartnerInvitesDeps = {
    db,
    allowedOrigin,
    registration,
    inviteOtp: makeOtp("invite"),
    enrolmentOtp: makeOtp("enrolment"),
    nowMs: () => NOW_MS,
    newSessionToken: issue("gr_ps_", newTokens.session),
    newInviteToken: issue("gr_inv_", newTokens.invite),
  };
  const membersDeps: PartnerMembersDeps = {
    db,
    allowedOrigin,
    registration,
    nowMs: () => NOW_MS,
    newEnrolmentToken: issue("gr_enr_", newTokens.enrolment),
  };
  return {
    deps,
    invitesDeps,
    membersDeps,
    rec,
    newTokens,
    calls,
    tx,
    mintInputs,
    reauthInputs,
    verifyRequests,
    sessionHashes,
    rateLimitHits,
    pinVerifyInputs,
    pinSetInputs,
    pinChangeInputs,
    otpSent,
    otpVerified,
    otpProofSessionIds,
    totpConfirmCodes,
    totpVerifyCodes,
    totpResetTargets,
    otpClosed,
    openTxAtOtpCall,
    state,
  };
}

/** A partner session token (well-formed) and its sha256. */
export const SESSION_TOKEN = "gr_ps_" + toB64u(bytes(32, 50));
export async function sha256Hex(text: string): Promise<string> {
  return Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text))), (b) => b.toString(16).padStart(2, "0")).join("");
}

/** A request to one of the partner functions (`partner-session`, `partner-invites`, `partner-members`); `path` may carry a query string. */
export function fnReq(fn: string, method: string, path: string, init: { headers?: Record<string, string>; body?: unknown; raw?: string } = {}): Request {
  const headers = new Headers(init.headers ?? {});
  let body: string | undefined;
  if (init.raw !== undefined) body = init.raw;
  else if (init.body !== undefined) body = JSON.stringify(init.body);
  if (body !== undefined && !headers.has("content-type")) headers.set("content-type", "application/json");
  return new Request(`https://project.example.test/functions/v1/${fn}/${path}`, { method, headers, body });
}

export function req(method: string, path: string, init: { headers?: Record<string, string>; body?: unknown; raw?: string } = {}): Request {
  return fnReq("partner-session", method, path, init);
}

export const authed = (extra: Record<string, string> = {}) => ({ authorization: `Bearer ${SESSION_TOKEN}`, origin: ORIGIN, ...extra });

export { fromB64u, toB64u };
