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
    /** routes (the part after `/partner-session/` or `/partner-invites/`, e.g. "sign-out", "session", "credentials") whose non-preflight requests are received, logged and then NEVER ANSWERED until reset() */
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
  seedPin(pin: string, opts?: { userId?: string; iterations?: number; mustChange?: boolean; locked?: boolean; failures?: number }): Promise<void>;
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
          // Sessions that already start at aal 2 (operator/admin fixtures) carry a fresh MFA window so A3 routes can be exercised without a TOTP round-trip.
          sessions.set(input.tokenHash, {
            userId: c.userId,
            createdAt: new Date(),
            aal,
            enrolmentUntil: null,
            otpProofUntil: null,
            pinGrantUntil: null,
            mfaUntil: aal >= 2 ? Date.now() + 3_600_000 : null,
          });
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
    withAttest() {
      return Promise.reject(new Error("fake partner server: attest is not implemented (S7b)"));
    },
    withReview() {
      return Promise.reject(new Error("fake partner server: review is not implemented (S7d)"));
    },
    withStock() {
      return Promise.reject(new Error("fake partner server: stock is not implemented (S7c)"));
    },
    withEntitlements() {
      return Promise.reject(new Error("fake partner server: entitlements are not implemented (S7c)"));
    },
    withProgramme() {
      return Promise.reject(new Error("fake partner server: programme is not implemented (S7d)"));
    },
    withOffersAdmin() {
      return Promise.reject(new Error("fake partner server: offers-admin is not implemented (S7d)"));
    },
    withSponsorships() {
      return Promise.reject(new Error("fake partner server: sponsorships are not implemented (S7d)"));
    },
    withOffersRedeem() {
      return Promise.reject(new Error("fake partner server: offers-redeem is not implemented (P5.1b)"));
    },
    withSettlementExport() {
      return Promise.reject(new Error("fake partner server: settlement-export is not implemented (P5.1b)"));
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
  const cors = { "content-type": "application/json", "access-control-allow-origin": opts.pageOrigin, "access-control-expose-headers": "Retry-After", vary: "Origin" };
  const ok = (status: number, data: unknown) => new Response(JSON.stringify({ data }), { status, headers: cors });
  const err = (status: number, code: string) => new Response(JSON.stringify({ error: { code, message: code } }), { status, headers: cors });

  /** Bearer → live session, or null. */
  async function sessionOf(req: Request): Promise<FakeSession | null> {
    const h = req.headers.get("authorization");
    if (h === null || !h.startsWith("Bearer ")) return null;
    const hash = await sha256Hex(h.slice("Bearer ".length));
    if (state.revokedSessions.has(hash)) return null;
    return sessions.get(hash) ?? null;
  }

  /** A1: consume a live PIN grant, or 403. */
  function takePinGrant(session: FakeSession): Response | null {
    if (session.pinGrantUntil === null || session.pinGrantUntil <= Date.now()) return err(403, "pin_grant_required");
    session.pinGrantUntil = null;
    return null;
  }

  const workState = {
    pinEpoch: 1,
    minted: new Map<string, { facilityId: string; nonceHash: string; expiresAt: number }>(),
    printed: new Map<string, { qrKid: string; sig: string; printedAt: string }>(),
    usedTokens: new Set<string>(),
    usedCodes: new Set<string>(),
    /** on_hand by facilityId for stock-admin / redeem (S7c). */
    stock: new Map<string, number>(),
  };

  type FakeOffer = {
    id: string;
    termsId: string;
    trailId: string;
    facilityId: string;
    eligibility: unknown;
    funder: string;
    sponsorshipId: string | null;
    budgetCap: number;
    budgetUsed: number;
    budgetReserved: number;
    maxRedemptions: number | null;
    faceValue: number;
    validFrom: string;
    validTo: string;
    status: string;
  };
  type FakeSponsorship = {
    id: string;
    sponsorOrgId: string;
    trailId: string;
    category: string;
    scope: string;
    attributionName: string;
    attributionAsset: string | null;
    placementFee: number | null;
    startsOn: string | null;
    endsOn: string | null;
    operatorApprovedAt: string | null;
    status: string;
  };

  const adminState = {
    trails: new Map<string, Record<string, unknown>>(),
    facilities: new Map<string, Record<string, unknown>[]>(),
    offers: new Map<string, FakeOffer>(),
    sponsorships: new Map<string, FakeSponsorship>(),
    reviewOpen: true,
  };

  function needA3(session: FakeSession): Response | null {
    if (session.aal < 2 || session.mfaUntil === null || session.mfaUntil <= Date.now()) return err(403, "aal_required");
    return null;
  }

  async function workHandler(req: Request): Promise<Response> {
    if (req.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "access-control-allow-origin": opts.pageOrigin,
          "access-control-allow-methods": "GET, POST, OPTIONS",
          "access-control-allow-headers": "authorization, content-type",
          "access-control-max-age": "600",
          vary: "Origin",
        },
      });
    }
    const url = new URL(req.url);
    const parts = url.pathname.split("/").filter((p) => p.length > 0);
    const fnIdx = parts.findIndex((p) =>
      p === "partner-attest" || p === "course-qr" || p === "qr-print" || p === "stock-admin" || p === "partner-entitlements" ||
      p === "programme-config" || p === "offers-admin" || p === "sponsorships-admin" || p === "partner-review"
    );
    if (fnIdx < 0) return err(404, "not_found");
    const fn = parts[fnIdx]!;
    const route = parts.slice(fnIdx + 1).join("/");
    const session = await sessionOf(req);
    if (session === null) return err(401, "unauthenticated");

    if (fn === "partner-attest") {
      if (route === "attest" && req.method === "POST") {
        const refused = takePinGrant(session);
        if (refused !== null) return refused;
        const body = (await req.json()) as { token?: string; facilityId?: string; kind?: string };
        if (typeof body.token !== "string" || workState.usedTokens.has(body.token)) return err(409, "replayed");
        workState.usedTokens.add(body.token);
        return ok(201, { attestationId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", held: false });
      }
      if (route === "attest/offline" && req.method === "POST") {
        const refused = takePinGrant(session);
        if (refused !== null) return refused;
        const body = (await req.json()) as { handle?: string; code?: string };
        const key = `${body.handle}:${body.code}`;
        if (workState.usedCodes.has(key)) return err(409, "replayed");
        if (body.code === "000000") return err(422, "verification_failed");
        workState.usedCodes.add(key);
        return ok(201, { attestationId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", held: false });
      }
      if (route === "shift-log" && req.method === "GET") {
        const facilityId = url.searchParams.get("facilityId") ?? "";
        return ok(200, { entries: [{ id: "1", facilityId, createdAt: new Date().toISOString(), kind: "presence", playerHandle: "player_one", staffHandle: "staff_one" }] });
      }
      if (route === "staff-activity" && req.method === "GET") {
        const facilityId = url.searchParams.get("facilityId") ?? "";
        return ok(200, { activity: [{ staffUserId: USER_ID, facilityId, day: "2026-10-09", attests: 1, activations: 0, anomalies: 0 }] });
      }
      return err(404, "not_found");
    }

    if (fn === "course-qr") {
      if (route === "pin" && req.method === "GET") {
        const facilityId = url.searchParams.get("facilityId") ?? "";
        return ok(200, { facilityId, pin: "4242", localDate: "2026-10-09", validUntil: new Date(Date.now() + 86_400_000).toISOString(), pinEpoch: workState.pinEpoch });
      }
      if (route === "pin/rotate" && req.method === "POST") {
        // A2: need reauth window and a PIN grant
        if (state.reauthUntil === null || Date.parse(state.reauthUntil) <= Date.now()) return err(403, "reauth_required");
        const refused = takePinGrant(session);
        if (refused !== null) return refused;
        const body = (await req.json()) as { facilityId?: string };
        workState.pinEpoch += 1;
        return ok(200, { facilityId: body.facilityId ?? "", pinEpoch: workState.pinEpoch });
      }
      if (route === "tokens" && req.method === "POST") {
        const refused = takePinGrant(session);
        if (refused !== null) return refused;
        const body = (await req.json()) as { facilityId?: string };
        const facilityId = body.facilityId ?? "";
        const nonceHash = "a".repeat(64);
        const issuedAt = new Date().toISOString();
        const expiresAt = new Date(Date.now() + 120_000).toISOString();
        workState.minted.set(nonceHash, { facilityId, nonceHash, expiresAt: Date.now() + 120_000 });
        return ok(201, { facilityId, token: "rotating.token.example", link: `https://golfraven.example/q/m#rotating.token.example`, nonceHash, kid: "kid1", issuedAt, expiresAt });
      }
      if (route === "tokens/refresh" && req.method === "POST") {
        const body = (await req.json()) as { nonceHash?: string };
        const row = body.nonceHash !== undefined ? workState.minted.get(body.nonceHash) : undefined;
        if (row === undefined) return err(404, "not_found");
        return ok(200, { state: "live", secondsLeft: Math.max(0, Math.floor((row.expiresAt - Date.now()) / 1000)) });
      }
      return err(404, "not_found");
    }

    if (fn === "qr-print") {
      if (req.method === "GET") {
        const facilityId = url.searchParams.get("facilityId") ?? "";
        const row = workState.printed.get(facilityId);
        if (row === undefined) return err(404, "not_printed");
        return ok(200, { facilityId, qrKid: row.qrKid, sig: row.sig, printedAt: row.printedAt, revoked: false, revokedAt: null });
      }
      if (req.method === "POST") {
        if (session.aal < 2 || session.mfaUntil === null || session.mfaUntil <= Date.now()) return err(403, "aal_required");
        const body = (await req.json()) as { facilityId?: string };
        const facilityId = body.facilityId ?? "";
        const printedAt = new Date().toISOString();
        const row = { qrKid: "printkid", sig: "f".repeat(128), printedAt };
        workState.printed.set(facilityId, row);
        return ok(201, { facilityId, qrKid: row.qrKid, sig: row.sig, printedAt, revoked: false, revokedAt: null, link: null, changed: true });
      }
    }

    if (fn === "stock-admin") {
      if (route === "stock" && req.method === "GET") {
        const facilityId = url.searchParams.get("facilityId") ?? "";
        const onHand = workState.stock.get(facilityId) ?? 5;
        return ok(200, {
          stock: [{ trailId: "trl_demo", onHand, lowThreshold: 3, status: onHand <= 0 ? "out" : onHand <= 3 ? "low" : "in_stock", lastCountedAt: null }],
        });
      }
      if (route === "stock/move" && req.method === "POST") {
        const refused = takePinGrant(session);
        if (refused !== null) return refused;
        const body = (await req.json()) as { facilityId?: string; trailId?: string; kind?: string; qty?: number };
        const facilityId = body.facilityId ?? "";
        const qty = typeof body.qty === "number" ? body.qty : 0;
        const prev = workState.stock.get(facilityId) ?? 5;
        const next = body.kind === "count_adjustment" ? prev + qty : body.kind === "transfer_out" || body.kind === "damaged" ? prev - Math.abs(qty) : prev + Math.abs(qty);
        if (next < 0) return err(422, "short");
        workState.stock.set(facilityId, next);
        return ok(200, { onHand: next, availability: next <= 0 ? "out" : next <= 3 ? "low" : "in_stock" });
      }
      return err(404, "not_found");
    }

    if (fn === "partner-entitlements") {
      if (route === "collect" && req.method === "GET") {
        return ok(200, {
          entitlements: [{
            entitlementId: "51000000-0000-0000-0000-000000003601",
            trailId: "trl_demo",
            state: "redeemable",
            playerHandle: "player_one",
            activatedAt: new Date().toISOString(),
            voucherIssuedAt: null,
          }],
        });
      }
      if (route === "handover/mint" && req.method === "POST") {
        const refused = takePinGrant(session);
        if (refused !== null) return refused;
        const token = "gr_ho_" + "c".repeat(43);
        return ok(201, { token, expiresAt: new Date(Date.now() + 15 * 60_000).toISOString() });
      }
      if (route === "redeem" && req.method === "POST") {
        const refused = takePinGrant(session);
        if (refused !== null) return refused;
        const body = (await req.json()) as { facilityId?: string; method?: string; credential?: string };
        if (body.credential === "replayed") return err(409, "replayed");
        if (workState.stock.get(body.facilityId ?? "") === 0) return err(409, "out_of_stock");
        const facilityId = body.facilityId ?? "";
        const prev = workState.stock.get(facilityId) ?? 5;
        workState.stock.set(facilityId, Math.max(0, prev - 1));
        return ok(201, { attestationId: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", movement: "redeemed", availability: "low" });
      }
      if (route === "voucher" && req.method === "POST") {
        const refused = takePinGrant(session);
        if (refused !== null) return refused;
        return ok(200, { voucherIssuedAt: new Date().toISOString() });
      }
      return err(404, "not_found");
    }

    if (fn === "programme-config") {
      if (route === "programme" && req.method === "GET") {
        const trailId = url.searchParams.get("trailId") ?? "";
        const trail = adminState.trails.get(trailId) ?? {
          trailId,
          status: "pilot",
          markerSource: "any_purchase",
          markerRequiresCompletion: false,
          specialMarkerFundedBy: null,
          specialMarkerLowThreshold: 3,
          webPlayerFlow: true,
          specialMarkerSku: null,
          specialMarkerSponsorshipId: null,
          feeModel: null,
          feeAmount: null,
          startsOn: null,
          endsOn: null,
        };
        const facilities = adminState.facilities.get(trailId) ?? [{
          facilityId: "44444444-4444-4444-8444-444444444444",
          participation: "accepted",
          stocksMarkers: true,
          holdsSpecialMarker: false,
          connectivity: "ok",
          staffNetwork: true,
          wifiNote: null,
          qrMode: "rotating",
          pinEpoch: 1,
        }];
        return ok(200, { trail, facilities });
      }
      if (route === "programme/trail" && req.method === "POST") {
        const refused = needA3(session);
        if (refused !== null) return refused;
        const body = (await req.json()) as { trailId?: string };
        const trailId = body.trailId ?? "";
        adminState.trails.set(trailId, { ...body, trailId });
        return ok(200, { ok: true });
      }
      if (route === "programme/facility" && req.method === "POST") {
        const refused = needA3(session);
        if (refused !== null) return refused;
        const body = (await req.json()) as { trailId?: string; facilityId?: string };
        const trailId = body.trailId ?? "";
        if (!adminState.trails.has(trailId) && trailId !== "trl_demo") return err(422, "no_trail");
        const list = adminState.facilities.get(trailId) ?? [];
        const row = {
          facilityId: body.facilityId ?? "",
          participation: (body as { participation?: string }).participation ?? "invited",
          stocksMarkers: (body as { stocksMarkers?: boolean | null }).stocksMarkers ?? null,
          holdsSpecialMarker: (body as { holdsSpecialMarker?: boolean | null }).holdsSpecialMarker ?? null,
          connectivity: (body as { connectivity?: string | null }).connectivity ?? null,
          staffNetwork: (body as { staffNetwork?: boolean | null }).staffNetwork ?? null,
          wifiNote: (body as { wifiNote?: string | null }).wifiNote ?? null,
          qrMode: (body as { qrMode?: string }).qrMode ?? "rotating",
          pinEpoch: 1,
        };
        adminState.facilities.set(trailId, [...list.filter((f) => f["facilityId"] !== row.facilityId), row]);
        return ok(200, { ok: true });
      }
      if (route === "rollups/operator" && req.method === "GET") {
        const trailId = url.searchParams.get("trailId") ?? "";
        return ok(200, { rollups: [{ trailId, month: "2026-10", metric: "redemptions", value: 12, cohortN: 40 }] });
      }
      if (route === "rollups/sponsor" && req.method === "GET") {
        const sponsorshipId = url.searchParams.get("sponsorshipId") ?? "";
        return ok(200, { rollups: [{ sponsorshipId, month: "2026-10", metric: "impressions", value: 90, cohortN: 40 }] });
      }
      return err(404, "not_found");
    }

    if (fn === "offers-admin") {
      if (route === "offers" && req.method === "GET") {
        const trailId = url.searchParams.get("trailId") ?? "";
        const offers = [...adminState.offers.values()].filter((o) => o.trailId === trailId);
        if (offers.length === 0) {
          return ok(200, {
            offers: [{
              id: "61000000-0000-0000-0000-000000006101",
              termsId: "61000000-0000-0000-0000-000000006102",
              trailId,
              facilityId: "44444444-4444-4444-8444-444444444444",
              eligibility: { all: true },
              funder: "course",
              sponsorshipId: null,
              budgetCap: 100,
              budgetUsed: 0,
              budgetReserved: 0,
              maxRedemptions: null,
              faceValue: 10,
              validFrom: "2026-01-01",
              validTo: "2026-12-31",
              status: "draft",
            }],
          });
        }
        return ok(200, { offers });
      }
      if (route === "offers" && req.method === "POST") {
        const refused = needA3(session);
        if (refused !== null) return refused;
        const body = (await req.json()) as Partial<FakeOffer> & { id?: string | null };
        const id = typeof body.id === "string" && body.id.length > 0 ? body.id : randomUUID();
        const existing = adminState.offers.get(id);
        if (existing !== undefined && existing.status !== "draft") return err(422, "not_draft");
        if (body.funder === "sponsor" && (body.sponsorshipId === null || body.sponsorshipId === undefined)) return err(422, "bad_funder");
        const row: FakeOffer = {
          id,
          termsId: existing?.termsId ?? randomUUID(),
          trailId: body.trailId ?? "",
          facilityId: body.facilityId ?? "",
          eligibility: body.eligibility ?? {},
          funder: body.funder ?? "course",
          sponsorshipId: body.sponsorshipId ?? null,
          budgetCap: body.budgetCap ?? 0,
          budgetUsed: existing?.budgetUsed ?? 0,
          budgetReserved: existing?.budgetReserved ?? 0,
          maxRedemptions: body.maxRedemptions ?? null,
          faceValue: body.faceValue ?? 0,
          validFrom: body.validFrom ?? "2026-01-01",
          validTo: body.validTo ?? "2026-12-31",
          status: "draft",
        };
        adminState.offers.set(id, row);
        return ok(200, { id });
      }
      if (route === "offers/approve" && req.method === "POST") {
        const refused = needA3(session);
        if (refused !== null) return refused;
        const body = (await req.json()) as { id?: string };
        const row = adminState.offers.get(body.id ?? "");
        if (row === undefined) {
          // seed default draft if approving the canned id
          if (body.id === "61000000-0000-0000-0000-000000006101") {
            adminState.offers.set(body.id, {
              id: body.id,
              termsId: "61000000-0000-0000-0000-000000006102",
              trailId: "trl_demo",
              facilityId: "44444444-4444-4444-8444-444444444444",
              eligibility: { all: true },
              funder: "course",
              sponsorshipId: null,
              budgetCap: 100,
              budgetUsed: 0,
              budgetReserved: 0,
              maxRedemptions: null,
              faceValue: 10,
              validFrom: "2026-01-01",
              validTo: "2026-12-31",
              status: "live",
            });
            return ok(200, { ok: true });
          }
          return err(422, "not_found");
        }
        if (row.status !== "draft") return err(422, "not_draft");
        row.status = "live";
        return ok(200, { ok: true });
      }
      if (route === "offers/end" && req.method === "POST") {
        const refused = needA3(session);
        if (refused !== null) return refused;
        const body = (await req.json()) as { id?: string };
        const row = adminState.offers.get(body.id ?? "");
        if (row === undefined) return err(422, "not_found");
        if (row.status !== "live") return err(422, "not_live");
        row.status = "ended";
        return ok(200, { ok: true });
      }
      return err(404, "not_found");
    }

    if (fn === "sponsorships-admin") {
      if (route === "sponsorships" && req.method === "GET") {
        const trailId = url.searchParams.get("trailId") ?? "";
        const sponsorships = [...adminState.sponsorships.values()].filter((s) => s.trailId === trailId);
        if (sponsorships.length === 0) {
          return ok(200, {
            sponsorships: [{
              id: "71000000-0000-0000-0000-000000007101",
              sponsorOrgId: "71000000-0000-0000-0000-000000007199",
              trailId,
              category: "equipment",
              scope: "offers",
              attributionName: "Demo Sponsor",
              attributionAsset: null,
              placementFee: null,
              startsOn: null,
              endsOn: null,
              operatorApprovedAt: null,
              status: "draft",
            }],
          });
        }
        return ok(200, { sponsorships });
      }
      if (route === "sponsorships" && req.method === "POST") {
        const refused = needA3(session);
        if (refused !== null) return refused;
        const body = (await req.json()) as Partial<FakeSponsorship> & { id?: string | null };
        const id = typeof body.id === "string" && body.id.length > 0 ? body.id : randomUUID();
        const existing = adminState.sponsorships.get(id);
        if (existing !== undefined && existing.status !== "draft") return err(422, "not_draft");
        const row: FakeSponsorship = {
          id,
          sponsorOrgId: body.sponsorOrgId ?? "",
          trailId: body.trailId ?? "",
          category: body.category ?? "equipment",
          scope: body.scope ?? "offers",
          attributionName: body.attributionName ?? "Sponsor",
          attributionAsset: body.attributionAsset ?? null,
          placementFee: body.placementFee ?? null,
          startsOn: body.startsOn ?? null,
          endsOn: body.endsOn ?? null,
          operatorApprovedAt: null,
          status: "draft",
        };
        adminState.sponsorships.set(id, row);
        return ok(200, { id });
      }
      if (route === "sponsorships/approve" && req.method === "POST") {
        const refused = needA3(session);
        if (refused !== null) return refused;
        const body = (await req.json()) as { id?: string };
        const id = body.id ?? "";
        let row = adminState.sponsorships.get(id);
        if (row === undefined && id === "71000000-0000-0000-0000-000000007101") {
          row = {
            id,
            sponsorOrgId: "71000000-0000-0000-0000-000000007199",
            trailId: "trl_demo",
            category: "equipment",
            scope: "offers",
            attributionName: "Demo Sponsor",
            attributionAsset: null,
            placementFee: null,
            startsOn: null,
            endsOn: null,
            operatorApprovedAt: null,
            status: "draft",
          };
          adminState.sponsorships.set(id, row);
        }
        if (row === undefined) return err(422, "not_found");
        if (row.status !== "draft") return err(422, "not_draft");
        if (row.scope === "special_marker" || row.scope === "both") {
          // AT(20) stub: stock_short when scope needs markers and on_hand is zero
          const onHand = [...workState.stock.values()][0];
          if (onHand === 0) return err(422, "stock_short");
        }
        row.status = "live";
        row.operatorApprovedAt = new Date().toISOString();
        return ok(200, { ok: true });
      }
      return err(404, "not_found");
    }

    if (fn === "partner-review") {
      if (route === "queue" && req.method === "GET") {
        return ok(200, {
          items: adminState.reviewOpen
            ? [{
                kind: "offer_code",
                id: "81000000-0000-0000-0000-000000008101",
                subjectTable: "offer_codes",
                subjectId: "81000000-0000-0000-0000-000000008102",
                userId: USER_ID,
                handle: "player_one",
                facilityId: "44444444-4444-4444-8444-444444444444",
                trailId: "trl_demo",
                holdDetail: "held_review",
                reservedAmount: 10,
                heldAt: new Date().toISOString(),
                slaBreached: false,
                reviewKind: "offer_code",
              }]
            : [],
        });
      }
      if (route === "sla" && req.method === "GET") {
        return ok(200, {
          heldOfferCodes: adminState.reviewOpen ? 1 : 0,
          heldEntitlements: 0,
          openReviewItems: adminState.reviewOpen ? 1 : 0,
          slaBreachedRewards: 0,
          slaBreachedReviewItems: 0,
          slaHours: 48,
        });
      }
      if ((route === "resolve/offer-code" || route === "resolve/entitlement") && req.method === "POST") {
        const refused = needA3(session);
        if (refused !== null) return refused;
        const body = (await req.json()) as { id?: string; approve?: boolean };
        if (typeof body.id !== "string" || typeof body.approve !== "boolean") return err(400, "bad_request");
        if (body.id === "budget-short") return err(422, "budget_short");
        if (!adminState.reviewOpen && body.id !== "81000000-0000-0000-0000-000000008101") return err(409, "not_held");
        adminState.reviewOpen = false;
        return ok(200, { state: body.approve ? "approved" : "rejected" });
      }
      return err(404, "not_found");
    }

    return err(404, "not_found");
  }

  const innerHandler = (req: Request) => {
    const path = new URL(req.url).pathname;
    if (path.includes("/partner-invites/")) return invitesHandler(req);
    if (
      path.includes("/partner-attest/") || path.includes("/course-qr/") || path.includes("/qr-print") ||
      path.includes("/stock-admin/") || path.includes("/partner-entitlements/") ||
      path.includes("/programme-config/") || path.includes("/offers-admin/") || path.includes("/sponsorships-admin/") ||
      path.includes("/partner-review/")
    ) return workHandler(req);
    return sessionHandler(req);
  };

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
    const route = new URL(req.url).pathname.split(/\/(?:partner-(?:session|invites|attest)|course-qr|qr-print)\//)[1] ?? "";
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
      workState.pinEpoch = 1;
      workState.minted.clear();
      workState.printed.clear();
      workState.usedTokens.clear();
      workState.usedCodes.clear();
      workState.stock.clear();
      adminState.trails.clear();
      adminState.facilities.clear();
      adminState.offers.clear();
      adminState.sponsorships.clear();
      adminState.reviewOpen = true;
    },
    async seedPin(pin, o = {}) {
      const user = users.get(o.userId ?? USER_ID);
      if (user === undefined) throw new Error("fake partner server: no such user");
      const salt = newPinSalt();
      const iterations = o.iterations ?? 210_000;
      user.pin = { salt, iterations, derived: await derivePinKey(pin, salt, iterations), failures: o.failures ?? 0, locked: o.locked === true, mustChange: o.mustChange === true, backoffUntil: 0 };
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
