/**
 * A fake partner API for tests that runs the REAL `partner-session` handler (supabase/functions/_shared/partner/session-handler.ts) over in-memory
 * ports: so the SPA's requests are judged by the server's own Origin check, media-type rule, bearer-shape rule and strict body parser, not by a
 * second opinion written for this suite. Only the two ports are fake:
 *
 *   - `PartnerDb`: a stateful in-memory store (credentials, issued challenges and their one-time nonces, sessions, a rate-limit counter);
 *   - `AssertionVerifier`: a REAL ES256 verification (ECDSA over authenticatorData || sha256(clientDataJSON)) plus the checks the S0 wrapper makes
 *     (type, challenge, exact origin, rpIdHash, UP and UV flags, user handle, the counter).
 *
 * The sign-in `options` it returns have the shape `@simplewebauthn/server@14.0.3` `generateAuthenticationOptions` returns (read from the library
 * source in the Deno cache: `{ rpId, challenge, allowCredentials, timeout, userVerification, extensions }`).
 *
 * `handler` is a `(Request) => Promise<Response>`; `httpServer()` wraps it in a node:http server for the Playwright suite.
 */
import { createHash, randomBytes, randomUUID, verify } from "node:crypto";
import { createServer, type IncomingMessage, type Server } from "node:http";
import { handlePartnerInvitesRequest } from "../../../../supabase/functions/_shared/partner/invites-handler.ts";
import { derivePinKey, newPinSalt } from "../../../../supabase/functions/_shared/partner/pin-contract.ts";
import {
  type AssertionVerifier,
  type ChallengeIssue,
  type CredentialLookup,
  type EmailOtpPort,
  type EnrolmentAcceptResult,
  type InviteAcceptResult,
  type MintInput,
  type MintResult,
  type PartnerDb,
  type PartnerInviteMintTx,
  type PartnerMintTx,
  PartnerAuthorityRefused,
  PartnerSessionRefused,
  type PartnerSessionTx,
  type PinChangeInput,
  type PinParams,
  type PinSetInput,
  type PinVerifyResult,
  type PinWriteResult,
  type ReauthCredential,
  type ReauthInput,
  type RegisterFirstInput,
  type RegisterFirstResult,
  type RegistrationVerifier,
  type RpConfig,
  type TotpConfirmResult,
  type TotpEnrolResult,
  type TotpVerifyResult,
  type VerifyAssertionRequest,
  type VerifyOutcome,
} from "../../../../supabase/functions/_shared/partner/ports.ts";
import { handlePartnerSessionRequest } from "../../../../supabase/functions/_shared/partner/session-handler.ts";
import { fromB64u, sha256Hex, toB64u } from "../../../../supabase/functions/_shared/partner/token.ts";
import { hotpSha1, partnerTotpStep } from "../../../../supabase/functions/_shared/partner/totp-contract.ts";
import { type Cbor, cborDecode } from "./cbor";
import { publicKeyFromSpki, type SoftCredential } from "./soft-authenticator";

export const USER_ID = "00000000-0000-4000-8000-0000000000a1";

export interface LoggedRequest {
  readonly method: string;
  readonly path: string;
  readonly contentType: string | null;
  readonly authorization: string | null;
  readonly cookie: string | null;
  readonly origin: string | null;
  readonly referer: string | null;
  readonly body: string;
}

export interface FakeServerOptions {
  /** The page's origin: what CORS allows and what a signed `clientDataJSON.origin` must equal. */
  readonly pageOrigin: string;
  readonly rpId: string;
  readonly credential: SoftCredential;
  readonly whoami?: Partial<{ aal: number; requiredAal: number; isAdmin: boolean; memberships: unknown[] }>;
}

export interface FakeServer {
  readonly handler: (req: Request) => Promise<Response>;
  readonly log: LoggedRequest[];
  /** every raw token the server issued (only for assertions that the client never leaks them) */
  readonly issuedTokens: string[];
  readonly state: {
    revokedSessions: Set<string>;
    lockCalls: number;
    signOutCalls: number;
    /** after this many reauth hits, answer 429 with Retry-After */
    reauthLimit: number;
    reauthHits: number;
    /** answer every `options` call with 503 */
    unavailable: boolean;
    reauthUntil: string | null;
    /** routes (the part after `/partner-session/`, e.g. "sign-out", "session") whose non-preflight requests are received, logged and then NEVER ANSWERED until reset() */
    hang: Set<string>;
    /** route -> ms: the handler runs (the server's state changes) and the RESPONSE is held back this long */
    delayAfter: Record<string, number>;
    /** when set, every `options` call is answered 429 with this Retry-After (seconds) */
    optionsRetryAfter: number | null;
    /** the one-time code the fake mailbox accepts (the email proof and the invite / enrolment code) */
    otpCode: string;
    /** every address the fake "emailed" a code to, in order */
    mailed: string[];
    /** when set, the next invite or enrolment acceptance answers this status instead of `ok` (consumed once) */
    acceptOutcome: "existing_member_sign_in" | "recover_required" | null;
    /** the PIN grants the server has issued and the sessions that spent them: a grant is single-use */
    pinGrantsIssued: number;
  };
  /** Gives a user a PIN, derived here exactly as the browser derives it (pin-contract.ts). Default user: the signed-in one. */
  seedPin(pin: string, opts?: { userId?: string; iterations?: number; mustChange?: boolean; locked?: boolean }): Promise<void>;
  /** What the server stores of a user's PIN (never the digits), or null. */
  pinRecord(userId?: string): { derived: string; salt: string; iterations: number; failures: number; locked: boolean; mustChange: boolean } | null;
  /** A new invite (branch N) for an address: the token the invite link would carry. */
  addInvite(input: { email: string; orgId?: string; role?: string }): { token: string; inviteId: string };
  /** A new enrolment token (recovery) for an address that already has an account. */
  addEnrolment(input: { email: string }): { token: string };
  /** The credentials the server holds for a user, as `{ credentialId, publicKeySpki }`. */
  credentialsOf(userId: string): Array<{ credentialId: string; publicKeySpki: Uint8Array }>;
  /** The user the fake created for an address (by an accepted invite), or undefined. */
  userByEmail(email: string): { id: string } | undefined;
  /** The TOTP seed enrolled for a user, or null. */
  totpSeed(userId?: string): Uint8Array | null;
  /** A currently valid TOTP code for the seed (what an authenticator app would show). */
  totpCodeNow(userId?: string): Promise<string>;
  /** the sha256 hex of every LIVE (not revoked) session token */
  sessions(): string[];
  /** kills a live session on the server (as an idle expiry would) without the client knowing */
  killAllSessions(): void;
  /** back to the state of a freshly created server: no sessions, no challenges, no log, counters and knobs at their defaults */
  reset(): void;
  httpServer(): Server;
}

const sha256 = (d: Uint8Array | string): Buffer => createHash("sha256").update(d).digest();

interface PinRecord {
  salt: Uint8Array;
  iterations: number;
  derived: Uint8Array;
  failures: number;
  locked: boolean;
  mustChange: boolean;
  backoffUntil: number;
}
interface FakeUser {
  id: string;
  email: string;
  memberships: unknown[];
  pin: PinRecord | null;
  totp: { seed: Uint8Array; confirmed: boolean; enrolSession: string | null } | null;
}
interface FakeSession {
  userId: string;
  createdAt: Date;
  aal: number;
  enrolmentUntil: number | null;
  otpProofUntil: number | null;
  pinGrantUntil: number | null;
  mfaUntil: number | null;
}
interface FakeCredential {
  id: string;
  userId: string;
  alg: number;
  publicKey: Uint8Array;
  signCount: number;
}
interface FakeInvite {
  id: string;
  email: string;
  orgId: string;
  role: string;
  kind: "invite" | "enrolment";
  accepted: boolean;
}

const SPKI_P256_PREFIX = Buffer.from("3059301306072a8648ce3d020106082a8648ce3d030107034200", "hex");
const equalBytes = (a: Uint8Array, b: Uint8Array): boolean => Buffer.from(a).equals(Buffer.from(b));
const ISO = (ms: number): string => new Date(ms).toISOString();

export function createFakePartnerServer(opts: FakeServerOptions): FakeServer {
  const rp: RpConfig = { rpId: opts.rpId, origin: opts.pageOrigin };
  const challenges = new Map<string, { mac: string; exp: number; used: boolean; sessionHash: string | null; binding: string | null }>();
  const sessions = new Map<string, FakeSession>();
  const users = new Map<string, FakeUser>();
  const credentials = new Map<string, FakeCredential>();
  const invites = new Map<string, FakeInvite>();
  const usedGotrueSessions = new Set<string>();
  const log: LoggedRequest[] = [];
  const issuedTokens: string[] = [];
  const state: FakeServer["state"] = {
    revokedSessions: new Set(),
    lockCalls: 0,
    signOutCalls: 0,
    reauthLimit: Number.POSITIVE_INFINITY,
    reauthHits: 0,
    unavailable: false,
    reauthUntil: null,
    hang: new Set(),
    delayAfter: {},
    optionsRetryAfter: null,
    otpCode: "123456",
    mailed: [],
    acceptOutcome: null,
    pinGrantsIssued: 0,
  };
  const held: Array<() => void> = [];
  let signCount = 0;
  let gotrueCounter = 0;

  const defaultMemberships = () => opts.whoami?.memberships ?? [{ orgId: "33333333-3333-4333-8333-333333333333", role: "staff", facilityIds: ["44444444-4444-4444-8444-444444444444"], trailIds: [] }];
  /** The signed-in test user and the credential the virtual authenticators hold. */
  function seed(): void {
    users.set(USER_ID, { id: USER_ID, email: "staff@partners.example.test", memberships: defaultMemberships(), pin: null, totp: null });
    credentials.set(toB64u(opts.credential.credentialId), { id: "11111111-1111-4111-8111-111111111111", userId: USER_ID, alg: -7, publicKey: opts.credential.publicKeySpki, signCount: 0 });
  }
  seed();
  const userOf = (hash: string): FakeUser => users.get(sessions.get(hash)!.userId)!;

  const issue = (sessionHash: string | null, binding: string | null = null): ChallengeIssue => {
    const nonce = randomBytes(32);
    const mac = randomBytes(32);
    const exp = Math.floor(Date.now() / 1000) + 120;
    challenges.set(toB64u(nonce), { mac: toB64u(mac), exp, used: false, sessionHash, binding });
    return { nonce, exp, mac };
  };
  const consume = (nonce: Uint8Array, exp: number, mac: Uint8Array, sessionHash: string | null, binding: string | null = null): boolean => {
    const c = challenges.get(toB64u(nonce));
    if (c === undefined || c.used || c.exp !== exp || c.mac !== toB64u(mac) || c.sessionHash !== sessionHash || c.binding !== binding || c.exp * 1000 <= Date.now()) return false;
    c.used = true;
    return true;
  };

  const verifier: AssertionVerifier = {
    async options(_rp: RpConfig, challenge: Uint8Array) {
      return { rpId: _rp.rpId, challenge: toB64u(challenge), allowCredentials: [], timeout: 60000, userVerification: "required" };
    },
    async verify(input: VerifyAssertionRequest): Promise<VerifyOutcome> {
      const refuse: VerifyOutcome = { ok: false, counterOnly: false };
      const cd = fromB64u(input.response.response.clientDataJSON);
      const ad = fromB64u(input.response.response.authenticatorData);
      const sig = fromB64u(input.response.response.signature);
      if (cd === null || ad === null || sig === null || ad.length < 37) return refuse;
      let client: { type?: unknown; challenge?: unknown; origin?: unknown; crossOrigin?: unknown };
      try {
        client = JSON.parse(new TextDecoder().decode(cd));
      } catch {
        return refuse;
      }
      if (client.type !== "webauthn.get" || client.challenge !== toB64u(input.expectedChallenge) || client.origin !== input.rp.origin || client.crossOrigin === true) return refuse;
      if (!Buffer.from(ad.subarray(0, 32)).equals(sha256(input.rp.rpId))) return refuse;
      const flags = ad[32] ?? 0;
      if ((flags & 0x01) === 0 || (flags & 0x04) === 0) return refuse; // user present and user verified
      const uh = input.response.response.userHandle;
      if (uh !== undefined) {
        const got = fromB64u(uh);
        if (got === null || !Buffer.from(got).equals(Buffer.from(input.expectedUserHandle))) return refuse;
      }
      const ok = verify("sha256", Buffer.concat([Buffer.from(ad), sha256(cd)]), { key: publicKeyFromSpki(input.credential.publicKey), dsaEncoding: "der" }, Buffer.from(sig));
      if (!ok) return refuse;
      const counter = Buffer.from(ad).readUInt32BE(33);
      if ((counter !== 0 || input.credential.signCount !== 0) && counter <= input.credential.signCount) return { ok: false, counterOnly: true };
      return { ok: true };
    },
  };

  const whoamiPayload = (sessionHash: string) => {
    const s = sessions.get(sessionHash)!;
    const user = users.get(s.userId)!;
    const now = Date.now();
    const live = (ms: number | null): string | null => (ms !== null && ms > now ? ISO(ms) : null);
    return {
      userId: s.userId,
      sessionId: "22222222-2222-4222-8222-222222222222",
      aal: s.aal,
      requiredAal: opts.whoami?.requiredAal ?? 1,
      createdAt: ISO(s.createdAt.getTime()),
      lastSeenAt: ISO(now),
      idleExpiresAt: ISO(now + 30 * 60_000),
      expiresAt: ISO(s.createdAt.getTime() + 8 * 3_600_000),
      isAdmin: opts.whoami?.isAdmin ?? false,
      stepUp: { pinGrantActive: s.pinGrantUntil !== null && s.pinGrantUntil > now, reauthUntil: state.reauthUntil, mfaUntil: live(s.mfaUntil), otpProofUntil: live(s.otpProofUntil), enrolmentUntil: live(s.enrolmentUntil) },
      memberships: user.memberships,
    };
  };

  /** The session may set a PIN or enrol TOTP: an unexpired enrolment window or email proof (design 6.3). */
  const hasProof = (s: FakeSession): boolean => Date.now() < Math.max(s.enrolmentUntil ?? 0, s.otpProofUntil ?? 0);

  const pinStatus = (pin: PinRecord | null): "unset" | "must_change" | "locked" | "ok" => (pin === null ? "unset" : pin.locked ? "locked" : pin.mustChange ? "must_change" : "ok");

  /** One consecutive failure: counts, locks at 5, and starts the back-off (3rd: 30 s, 4th: 5 min). */
  function recordPinFailure(pin: PinRecord): number {
    pin.failures += 1;
    if (pin.failures >= 5) pin.locked = true;
    else if (pin.failures === 3) pin.backoffUntil = Date.now() + 30_000;
    else if (pin.failures === 4) pin.backoffUntil = Date.now() + 300_000;
    return Math.max(0, Math.ceil((pin.backoffUntil - Date.now()) / 1000));
  }

  const db: PartnerDb = {
    async withMint(op) {
      const tx: PartnerMintTx = {
        async rpConfig() {
          return rp;
        },
        async issueChallenge() {
          return issue(null);
        },
        async lookupCredential(id: Uint8Array): Promise<CredentialLookup> {
          const c = credentials.get(toB64u(id));
          return c === undefined ? { status: "unknown" } : { status: "ok", credential: { ...c, signCount } };
        },
        async recordFailure() {
          return "counted";
        },
        async mint(input: MintInput): Promise<MintResult> {
          if (!consume(input.nonce, input.exp, input.mac, null)) return { status: "challenge_invalid", aal: null, expiresAt: null };
          const c = credentials.get(toB64u(input.credentialId));
          if (c === undefined) return { status: "unknown_credential", aal: null, expiresAt: null };
          signCount = Buffer.from(input.authenticatorData).readUInt32BE(33);
          const aal = opts.whoami?.aal ?? 1;
          sessions.set(input.tokenHash, { userId: c.userId, createdAt: new Date(), aal, enrolmentUntil: null, otpProofUntil: null, pinGrantUntil: null, mfaUntil: null });
          return { status: "ok", aal, expiresAt: new Date(Date.now() + 8 * 3_600_000).toISOString() };
        },
      };
      return await op(tx);
    },
    async withSession(hash, op) {
      if (!sessions.has(hash) || state.revokedSessions.has(hash)) throw new PartnerSessionRefused();
      const session = sessions.get(hash)!;
      const tx: PartnerSessionTx = {
        async whoami() {
          return whoamiPayload(hash);
        },
        async signOut() {
          state.signOutCalls += 1;
          state.revokedSessions.add(hash);
        },
        async lock() {
          state.lockCalls += 1;
          state.reauthUntil = null;
          session.pinGrantUntil = null;
          session.otpProofUntil = null;
        },
        async reauthOptions() {
          return { ...issue(hash), rp };
        },
        async reauthCredential(id: Uint8Array): Promise<ReauthCredential | null> {
          const c = credentials.get(toB64u(id));
          return c !== undefined && c.userId === session.userId ? { ...c, signCount, rp } : null;
        },
        async pinParams(): Promise<PinParams> {
          const pin = userOf(hash).pin;
          const st = pinStatus(pin);
          if (st !== "ok" || pin === null) return { state: st === "ok" ? "unset" : st };
          return { state: "ok", salt: pin.salt, iterations: pin.iterations, retryAfterSeconds: Math.max(0, Math.ceil((pin.backoffUntil - Date.now()) / 1000)) };
        },
        async pinVerify(derived: Uint8Array): Promise<PinVerifyResult> {
          const pin = userOf(hash).pin;
          const st = pinStatus(pin);
          if (pin === null || st === "unset") return { status: "unset", retryAfterSeconds: 0, grantUntil: null };
          if (st === "locked") return { status: "locked", retryAfterSeconds: 0, grantUntil: null };
          if (st === "must_change") return { status: "must_change", retryAfterSeconds: 0, grantUntil: null };
          if (pin.backoffUntil > Date.now()) return { status: "retry_after", retryAfterSeconds: Math.ceil((pin.backoffUntil - Date.now()) / 1000), grantUntil: null };
          if (!equalBytes(derived, pin.derived)) {
            const wait = recordPinFailure(pin);
            return { status: pin.locked ? "locked" : "wrong", retryAfterSeconds: wait, grantUntil: null };
          }
          pin.failures = 0;
          session.pinGrantUntil = Date.now() + 60_000;
          state.pinGrantsIssued += 1;
          return { status: "ok", retryAfterSeconds: 0, grantUntil: ISO(session.pinGrantUntil) };
        },
        async pinSet(input: PinSetInput): Promise<PinWriteResult> {
          if (!hasProof(session)) throw new PartnerAuthorityRefused();
          const user = userOf(hash);
          if (user.pin !== null && !user.pin.mustChange && !user.pin.locked) return { status: "already_set", retryAfterSeconds: 0 };
          user.pin = { salt: input.salt, iterations: input.iterations, derived: input.derived, failures: 0, locked: false, mustChange: false, backoffUntil: 0 };
          return { status: "ok", retryAfterSeconds: 0 };
        },
        async pinChange(input: PinChangeInput): Promise<PinWriteResult> {
          if (!hasProof(session)) throw new PartnerAuthorityRefused();
          const user = userOf(hash);
          const pin = user.pin;
          if (pin === null) return { status: "no_pin", retryAfterSeconds: 0 };
          if (pin.locked) return { status: "locked", retryAfterSeconds: 0 };
          if (pin.mustChange) return { status: "must_change", retryAfterSeconds: 0 };
          if (pin.backoffUntil > Date.now()) return { status: "retry_after", retryAfterSeconds: Math.ceil((pin.backoffUntil - Date.now()) / 1000) };
          if (!equalBytes(input.current, pin.derived)) {
            const wait = recordPinFailure(pin);
            return { status: pin.locked ? "locked" : "wrong", retryAfterSeconds: wait };
          }
          user.pin = { salt: input.salt, iterations: input.iterations, derived: input.derived, failures: 0, locked: false, mustChange: false, backoffUntil: 0 };
          return { status: "ok", retryAfterSeconds: 0 };
        },
        async totpEnrol(): Promise<TotpEnrolResult> {
          if (!hasProof(session)) throw new PartnerAuthorityRefused();
          const user = userOf(hash);
          if (user.totp?.confirmed === true) return { status: "already_confirmed", seed: null, seedVersion: null, issuer: null, period: null, digits: null, algo: null };
          user.totp = { seed: new Uint8Array(randomBytes(20)), confirmed: false, enrolSession: hash };
          return { status: "ok", seed: user.totp.seed, seedVersion: 1, issuer: "GolfRaven", period: 30, digits: 6, algo: "SHA1" };
        },
        async totpConfirm(code: string): Promise<TotpConfirmResult> {
          const t = userOf(hash).totp;
          if (t === null) return { status: "unset", retryAfterSeconds: 0 };
          if (t.confirmed) return { status: "already_confirmed", retryAfterSeconds: 0 };
          if (t.enrolSession !== hash) return { status: "wrong_session", retryAfterSeconds: 0 };
          if (!(await totpAccepts(t.seed, code))) return { status: "wrong", retryAfterSeconds: 0 };
          t.confirmed = true;
          return { status: "ok", retryAfterSeconds: 0 };
        },
        async totpVerify(code: string): Promise<TotpVerifyResult> {
          const t = userOf(hash).totp;
          if (t === null) return { status: "unset", retryAfterSeconds: 0, mfaUntil: null };
          if (!t.confirmed) return { status: "unconfirmed", retryAfterSeconds: 0, mfaUntil: null };
          if (!(await totpAccepts(t.seed, code))) return { status: "wrong", retryAfterSeconds: 0, mfaUntil: null };
          session.aal = 2;
          session.mfaUntil = Date.now() + 5 * 60_000;
          return { status: "ok", retryAfterSeconds: 0, mfaUntil: ISO(session.mfaUntil) };
        },
        async totpReset(): Promise<never> {
          throw new Error("fake partner server: totp-reset is a partner-members route (not implemented)");
        },
        async otpTarget() {
          return userOf(hash).email;
        },
        async otpProof(gotrueSessionId: string) {
          if (usedGotrueSessions.has(gotrueSessionId)) return { status: "refused" as const, otpProofUntil: null };
          usedGotrueSessions.add(gotrueSessionId);
          session.otpProofUntil = Date.now() + 10 * 60_000;
          return { status: "ok" as const, otpProofUntil: ISO(session.otpProofUntil) };
        },
        async reauth(input: ReauthInput) {
          if (!consume(input.nonce, input.exp, input.mac, hash)) return { status: "challenge_invalid", reauthUntil: null };
          signCount = Buffer.from(input.authenticatorData).readUInt32BE(33);
          state.reauthUntil = new Date(Date.now() + 5 * 60_000).toISOString();
          return { status: "ok", reauthUntil: state.reauthUntil };
        },
      };
      return await op(tx);
    },
    async hitRateLimit(hash, bucket) {
      if (!sessions.has(hash) || state.revokedSessions.has(hash)) throw new PartnerSessionRefused();
      if (bucket !== "partner-reauth:member") return { ok: true, retryAfterSeconds: 0 };
      state.reauthHits += 1;
      return state.reauthHits > state.reauthLimit ? { ok: false, retryAfterSeconds: 1800 } : { ok: true, retryAfterSeconds: 0 };
    },
    // S1.5: the pre-session invite and enrolment routes run the REAL partner-invites handler over this fake; the member routes stay closed
    async withInviteMint(op) {
      const emailOf = (hashHex: string, kind: FakeInvite["kind"]): string | null => {
        const inv = invites.get(hashHex);
        return inv !== undefined && inv.kind === kind && !inv.accepted ? inv.email : null;
      };
      const accept = (hashHex: string, userId: string, kind: FakeInvite["kind"]) => {
        const inv = invites.get(hashHex);
        if (inv === undefined || inv.kind !== kind || inv.accepted) return null;
        const forced = state.acceptOutcome;
        if (forced !== null) {
          state.acceptOutcome = null;
          return { status: forced, inv };
        }
        inv.accepted = true;
        const user = users.get(userId)!;
        if (kind === "invite") user.memberships = [{ orgId: inv.orgId, role: inv.role, facilityIds: ["44444444-4444-4444-8444-444444444444"], trailIds: [] }];
        return { status: "ok", inv, challenge: issue(null, `${userId}:${kind}:${inv.id}`) };
      };
      const tx: PartnerInviteMintTx = {
        async rpConfig() {
          return rp;
        },
        async inviteEmailForToken(h) {
          return emailOf(h, "invite");
        },
        async enrolmentEmailForToken(h) {
          return emailOf(h, "enrolment");
        },
        async inviteAccept(h, userId): Promise<InviteAcceptResult> {
          const r = accept(h, userId, "invite");
          if (r === null) return { status: "not_found", accepted: null };
          if (r.status !== "ok" || r.challenge === undefined) return { status: r.status as "existing_member_sign_in", accepted: null };
          return { status: "ok", accepted: { userId, inviteId: r.inv.id, orgId: r.inv.orgId, role: r.inv.role, challenge: r.challenge } };
        },
        async enrolmentAccept(h, userId): Promise<EnrolmentAcceptResult> {
          const r = accept(h, userId, "enrolment");
          if (r === null) return { status: "not_found", accepted: null };
          if (r.status !== "ok" || r.challenge === undefined) return { status: r.status as "existing_member_sign_in", accepted: null };
          return { status: "ok", accepted: { userId, tokenId: r.inv.id, purpose: "recovery", challenge: r.challenge } };
        },
        async registerFirst(input: RegisterFirstInput): Promise<RegisterFirstResult> {
          const refuse = (status: string): RegisterFirstResult => ({ status, credentialId: null, aal: null, expiresAt: null, enrolmentUntil: null });
          const kind = input.refKind === 1 ? "invite" : "enrolment";
          if (!consume(input.nonce, input.exp, input.mac, null, `${input.userId}:${kind}:${input.refId}`)) return refuse("bad_challenge");
          const id = toB64u(input.credentialId);
          if (credentials.has(id)) return refuse("credential_in_use");
          credentials.set(id, { id: randomUUID(), userId: input.userId, alg: -7, publicKey: input.publicKey, signCount: 0 });
          const now = Date.now();
          const aal = opts.whoami?.aal ?? 1;
          sessions.set(input.sessionTokenHash, { userId: input.userId, createdAt: new Date(now), aal, enrolmentUntil: now + 15 * 60_000, otpProofUntil: null, pinGrantUntil: null, mfaUntil: null });
          return { status: "ok", credentialId: id, aal, expiresAt: ISO(now + 8 * 3_600_000), enrolmentUntil: ISO(now + 15 * 60_000) };
        },
      };
      return await op(tx);
    },
    withInvites() {
      return Promise.reject(new Error("fake partner server: invite create / list / branch E are not implemented"));
    },
    withMembers() {
      return Promise.reject(new Error("fake partner server: members are not implemented"));
    },
    async hitSystemRateLimit() {
      return { ok: true, retryAfterSeconds: 0 };
    },
  };

  async function totpAccepts(seedBytes: Uint8Array, code: string): Promise<boolean> {
    const step = partnerTotpStep(Math.floor(Date.now() / 1000));
    for (const d of [-1, 0, 1]) if ((await hotpSha1(seedBytes, step + d)) === code) return true;
    return false;
  }

  const mailbox = (): EmailOtpPort => ({
    async send(email) {
      state.mailed.push(email);
    },
    async verify(email, code) {
      if (code !== state.otpCode) return { ok: false as const };
      let user = [...users.values()].find((u) => u.email === email);
      if (user === undefined) {
        user = { id: randomUUID(), email, memberships: [], pin: null, totp: null };
        users.set(user.id, user);
      }
      gotrueCounter += 1;
      return { ok: true as const, userId: user.id, sessionId: `gotrue-session-${gotrueCounter}`, closeSession: async () => undefined };
    },
  });

  /** The registration wrapper of the real Edge, in miniature: the checks it makes on the create ceremony, and the key it hands the database (here an SPKI the fake sign-in verifies against). */
  const registration: RegistrationVerifier = {
    async options(req) {
      return {
        rp: { name: "GolfRaven Partners", id: req.rp.rpId },
        user: { id: toB64u(req.userHandle), name: req.userName, displayName: req.userName },
        challenge: toB64u(req.challenge),
        pubKeyCredParams: [{ alg: -7, type: "public-key" }, { alg: -257, type: "public-key" }],
        timeout: 60000,
        attestation: "none",
        excludeCredentials: req.excludeCredentialIds.map((id) => ({ id: toB64u(id), type: "public-key" })),
        authenticatorSelection: { residentKey: "required", userVerification: "required", requireResidentKey: true },
      };
    },
    async verify(req) {
      const refuse = { ok: false as const };
      const cd = fromB64u(req.response.response.clientDataJSON);
      const att = fromB64u(req.response.response.attestationObject);
      if (cd === null || att === null) return refuse;
      let client: { type?: unknown; challenge?: unknown; origin?: unknown; crossOrigin?: unknown };
      try {
        client = JSON.parse(new TextDecoder().decode(cd));
      } catch {
        return refuse;
      }
      if (client.type !== "webauthn.create" || client.challenge !== toB64u(req.expectedChallenge) || client.origin !== req.rp.origin || client.crossOrigin === true) return refuse;
      let obj: Cbor;
      try {
        obj = cborDecode(att);
      } catch {
        return refuse;
      }
      if (!(obj instanceof Map) || obj.get("fmt") !== "none") return refuse;
      const authData = obj.get("authData");
      if (!(authData instanceof Uint8Array) || authData.length < 55 || !equalBytes(authData.subarray(0, 32), sha256(req.rp.rpId))) return refuse;
      const flags = authData[32] ?? 0;
      if ((flags & 0x01) === 0 || (flags & 0x04) === 0 || (flags & 0x40) === 0) return refuse;
      const idLen = (authData[53]! << 8) | authData[54]!;
      const credentialId = authData.slice(55, 55 + idLen);
      let cose: Cbor;
      try {
        cose = cborDecode(authData.slice(55 + idLen));
      } catch {
        return refuse;
      }
      if (!(cose instanceof Map)) return refuse;
      const x = cose.get(-2);
      const y = cose.get(-3);
      if (!(x instanceof Uint8Array) || !(y instanceof Uint8Array) || cose.get(3) !== -7) return refuse;
      if (toB64u(credentialId) !== req.response.id) return refuse;
      return { ok: true as const, credentialId, publicKey: new Uint8Array(Buffer.concat([SPKI_P256_PREFIX, Buffer.from([0x04]), Buffer.from(x), Buffer.from(y)])), transports: req.response.response.transports ?? [] };
    },
  };

  const newSessionToken = async () => {
    const token = "gr_ps_" + toB64u(randomBytes(32));
    issuedTokens.push(token);
    return { token, hash: await sha256Hex(token) };
  };
  const sessionHandler = (req: Request) =>
    handlePartnerSessionRequest(req, { db, allowedOrigin: opts.pageOrigin, webauthn: verifier, otp: mailbox(), nowMs: () => Date.now(), newSessionToken });
  const invitesHandler = (req: Request) =>
    handlePartnerInvitesRequest(req, {
      db,
      allowedOrigin: opts.pageOrigin,
      registration,
      inviteOtp: mailbox(),
      enrolmentOtp: mailbox(),
      nowMs: () => Date.now(),
      newSessionToken,
      newInviteToken: async () => {
        const token = "gr_inv_" + toB64u(randomBytes(32));
        return { token, hash: await sha256Hex(token) };
      },
    });
  const innerHandler = (req: Request) => (new URL(req.url).pathname.includes("/partner-invites/") ? invitesHandler(req) : sessionHandler(req));

  const handler = async (req: Request): Promise<Response> => {
    const body = req.method === "GET" || req.method === "OPTIONS" ? "" : await req.clone().text();
    log.push({
      method: req.method,
      path: new URL(req.url).pathname,
      contentType: req.headers.get("content-type"),
      authorization: req.headers.get("authorization"),
      cookie: req.headers.get("cookie"),
      origin: req.headers.get("origin"),
      referer: req.headers.get("referer"),
      body,
    });
    const route = new URL(req.url).pathname.split("/partner-session/")[1] ?? "";
    if (req.method !== "OPTIONS" && state.hang.has(route)) {
      return await new Promise<Response>((resolve) => {
        held.push(() => resolve(new Response(null, { status: 503 })));
      });
    }
    if (state.optionsRetryAfter !== null && route === "options" && req.method === "POST") {
      return new Response(JSON.stringify({ error: { code: "rate_limited", message: "too many attempts" } }), {
        status: 429,
        headers: { "content-type": "application/json", "access-control-allow-origin": opts.pageOrigin, "access-control-expose-headers": "Retry-After", "retry-after": String(state.optionsRetryAfter), vary: "Origin" },
      });
    }
    if (state.unavailable && new URL(req.url).pathname.endsWith("/options") && req.method === "POST") {
      return new Response(JSON.stringify({ error: { code: "service_unavailable", message: "partner sign-in is not available" } }), { status: 503, headers: { "content-type": "application/json", "access-control-allow-origin": opts.pageOrigin, vary: "Origin" } });
    }
    const res = await innerHandler(req);
    const delay = req.method === "OPTIONS" ? undefined : state.delayAfter[route];
    if (delay !== undefined) await new Promise((r) => setTimeout(r, delay));
    return res;
  };

  return {
    handler,
    log,
    issuedTokens,
    state,
    sessions: () => [...sessions.keys()].filter((h) => !state.revokedSessions.has(h)),
    reset() {
      sessions.clear();
      challenges.clear();
      log.length = 0;
      issuedTokens.length = 0;
      signCount = 0;
      gotrueCounter = 0;
      users.clear();
      credentials.clear();
      invites.clear();
      usedGotrueSessions.clear();
      seed();
      for (const release of held.splice(0)) release();
      Object.assign(state, { revokedSessions: new Set<string>(), lockCalls: 0, signOutCalls: 0, reauthLimit: Number.POSITIVE_INFINITY, reauthHits: 0, unavailable: false, reauthUntil: null, hang: new Set<string>(), delayAfter: {}, optionsRetryAfter: null, otpCode: "123456", mailed: [], acceptOutcome: null, pinGrantsIssued: 0 });
    },
    async seedPin(pin, o = {}) {
      const user = users.get(o.userId ?? USER_ID);
      if (user === undefined) throw new Error("fake partner server: no such user");
      const salt = newPinSalt();
      const iterations = o.iterations ?? 210_000;
      user.pin = { salt, iterations, derived: await derivePinKey(pin, salt, iterations), failures: 0, locked: o.locked === true, mustChange: o.mustChange === true, backoffUntil: 0 };
    },
    pinRecord(userId = USER_ID) {
      const pin = users.get(userId)?.pin ?? null;
      return pin === null ? null : { derived: toB64u(pin.derived), salt: toB64u(pin.salt), iterations: pin.iterations, failures: pin.failures, locked: pin.locked, mustChange: pin.mustChange };
    },
    addInvite({ email, orgId = "55555555-5555-4555-8555-555555555555", role = "staff" }) {
      const token = "gr_inv_" + toB64u(randomBytes(32));
      const id = randomUUID();
      invites.set(createHash("sha256").update(token).digest("hex"), { id, email, orgId, role, kind: "invite", accepted: false });
      return { token, inviteId: id };
    },
    addEnrolment({ email }) {
      const token = "gr_enr_" + toB64u(randomBytes(32));
      invites.set(createHash("sha256").update(token).digest("hex"), { id: randomUUID(), email, orgId: "", role: "", kind: "enrolment", accepted: false });
      return { token };
    },
    credentialsOf: (userId) => [...credentials].filter(([, c]) => c.userId === userId).map(([credentialId, c]) => ({ credentialId, publicKeySpki: c.publicKey })),
    userByEmail: (email) => {
      const u = [...users.values()].find((x) => x.email === email);
      return u === undefined ? undefined : { id: u.id };
    },
    totpSeed: (userId = USER_ID) => users.get(userId)?.totp?.seed ?? null,
    async totpCodeNow(userId = USER_ID) {
      const t = users.get(userId)?.totp;
      if (t === undefined || t === null) throw new Error("fake partner server: no TOTP seed");
      return await hotpSha1(t.seed, partnerTotpStep(Math.floor(Date.now() / 1000)));
    },
    killAllSessions: () => {
      for (const h of sessions.keys()) state.revokedSessions.add(h);
    },
    httpServer() {
      return createServer((nodeReq: IncomingMessage, nodeRes) => {
        const chunks: Buffer[] = [];
        nodeReq.on("data", (c: Buffer) => chunks.push(c));
        nodeReq.on("end", () => {
          void (async () => {
            const host = nodeReq.headers.host ?? "localhost";
            const method = nodeReq.method ?? "GET";
            const headers = new Headers();
            for (const [k, v] of Object.entries(nodeReq.headers)) if (v !== undefined) headers.set(k, Array.isArray(v) ? v.join(", ") : v);
            const hasBody = method !== "GET" && method !== "HEAD" && method !== "OPTIONS";
            const init: RequestInit = { method, headers };
            if (hasBody) init.body = Buffer.concat(chunks);
            const res = await handler(new Request(`http://${host}${nodeReq.url ?? "/"}`, init));
            const out: Record<string, string> = {};
            res.headers.forEach((v, k) => {
              out[k] = v;
            });
            nodeRes.writeHead(res.status, out);
            nodeRes.end(Buffer.from(await res.arrayBuffer()));
          })();
        });
      });
    },
  };
}

/**
 * A `fetch` that behaves like a browser's CORS enforcement for a page at `pageOrigin`: it adds the `Origin` header, runs the preflight a JSON or
 * Authorization request needs, and (like a browser) turns a response without the right `Access-Control-Allow-Origin` into a network error. It is a
 * SIMPLIFIED model (the real thing is the Playwright suite), enough to prove the client's requests pass the real handler's Origin and preflight rules.
 */
export function browserLikeFetch(handler: (req: Request) => Promise<Response>, pageOrigin: string, apiBase: string): typeof fetch {
  return (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = String(input);
    const method = (init?.method ?? "GET").toUpperCase();
    const headers = new Headers(init?.headers);
    const sendsAuth = headers.has("authorization");
    const preflightNeeded = !["GET", "HEAD", "POST"].includes(method) || sendsAuth || (headers.get("content-type") ?? "") !== "text/plain";
    if (new URL(url).origin !== new URL(apiBase).origin) throw new TypeError("blocked: not the API origin");
    if (preflightNeeded) {
      const pre = await handler(new Request(url, { method: "OPTIONS", headers: { origin: pageOrigin, "access-control-request-method": method, "access-control-request-headers": [...headers.keys()].sort().join(",") } }));
      const allowOrigin = pre.headers.get("access-control-allow-origin");
      const allowMethods = (pre.headers.get("access-control-allow-methods") ?? "").split(",").map((s) => s.trim());
      const allowHeaders = (pre.headers.get("access-control-allow-headers") ?? "").split(",").map((s) => s.trim().toLowerCase());
      if (pre.status !== 204 || allowOrigin !== pageOrigin || !allowMethods.includes(method) || ![...headers.keys()].every((k) => allowHeaders.includes(k.toLowerCase()))) throw new TypeError("CORS preflight failed");
    }
    headers.set("origin", pageOrigin);
    const reqInit: RequestInit = { method, headers };
    if (init?.body !== undefined && init.body !== null) reqInit.body = init.body;
    const res = await handler(new Request(url, reqInit));
    if (res.headers.get("access-control-allow-origin") !== pageOrigin) throw new TypeError("CORS: response not allowed for this origin");
    // like a browser, a cross-origin page sees only the CORS-safelisted response headers plus those named in Access-Control-Expose-Headers (the S1.2 server names none: Retry-After is hidden)
    const visible = new Set(["cache-control", "content-language", "content-length", "content-type", "expires", "last-modified", "pragma", ...(res.headers.get("access-control-expose-headers") ?? "").split(",").map((h) => h.trim().toLowerCase()).filter((h) => h !== "")]);
    const filtered = new Headers();
    res.headers.forEach((v, k) => {
      if (visible.has(k)) filtered.set(k, v);
    });
    return new Response(res.body, { status: res.status, headers: filtered });
  }) as typeof fetch;
}
