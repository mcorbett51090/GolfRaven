// supabase/tests/unit/partner-fakes.ts
//
// In-memory fakes of the partner handler's ports (supabase/functions/_shared/partner/ports.ts), shared by the vitest suite (partner-session-handler.test.ts). They RECORD every call, and the fake
// `withMint` / `withSession` model exactly one thing the real ones are proven to do: a transaction COMMITS when its callback returns (whatever the callback returns) and ROLLS BACK when it throws. That
// is how the "commit on every status" cells state their claim: `committed` is true for every returned refusal and false for a throw.

import {
  type AssertionVerifier,
  type ChallengeIssue,
  type CredentialLookup,
  type EmailOtpPort,
  type MintInput,
  type MintResult,
  type PartnerDb,
  type PartnerMintTx,
  type PartnerSessionTx,
  PartnerSessionRefused,
  type PinChangeInput,
  type PinParams,
  type PinSetInput,
  type PinVerifyResult,
  type PinWriteResult,
  type ReauthCredential,
  type ReauthInput,
  type RpConfig,
  type VerifyAssertionRequest,
  type VerifyOutcome,
} from "../../functions/_shared/partner/ports.ts";
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

export interface Fakes {
  readonly deps: PartnerSessionDeps;
  /** every call to a port, in order, as `"mint.lookupCredential"` ... */
  readonly calls: string[];
  /** the outcome of every `withMint` / `withSession` transaction */
  readonly tx: Array<{ kind: "mint" | "session"; committed: boolean }>;
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
  };
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
  const otpClosed = { count: 0 };
  const openTxAtOtpCall: number[] = [];
  const open = { count: 0 };
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
    ...over,
  };
  const maybeThrow = (where: string) => {
    if (state.throwIn === where) throw new Error(`boom in ${where}: secret database text`);
  };

  const mintTx: PartnerMintTx = {
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
  };
  const sessionTx: PartnerSessionTx = {
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
    async reauth(input: ReauthInput) {
      calls.push("session.reauth");
      reauthInputs.push(input);
      return state.reauthStatus === "ok" ? { status: "ok", reauthUntil: "2030-01-01T12:05:00.000Z" } : { status: state.reauthStatus, reauthUntil: null };
    },
  };
  const db: PartnerDb = {
    async withMint(op) {
      calls.push("db.withMint");
      let committed = false;
      try {
        const r = await op(mintTx);
        committed = true;
        return r;
      } finally {
        tx.push({ kind: "mint", committed });
      }
    },
    async withSession(hash, op) {
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
    },
    async hitRateLimit(hash, bucket, windowSeconds, max) {
      calls.push("db.hitRateLimit");
      rateLimitHits.push({ hash, bucket, windowSeconds, max });
      if (state.bindRefused) throw new PartnerSessionRefused();
      return state.rateLimitOk ? { ok: true, retryAfterSeconds: 0 } : { ok: false, retryAfterSeconds: 3600 };
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
  const otp: EmailOtpPort = {
    async send(email) {
      calls.push("otp.send");
      openTxAtOtpCall.push(open.count);
      otpSent.push(email);
      if (state.otpSendThrows) throw new Error("mailer down: secret provider text");
    },
    async verify(email, code) {
      calls.push("otp.verify");
      openTxAtOtpCall.push(open.count);
      otpVerified.push({ email, code });
      if (!state.otpVerifyOk) return { ok: false as const };
      return {
        ok: true as const,
        userId: USER_ID,
        sessionId: state.otpSessionId,
        async closeSession() {
          calls.push("otp.closeSession");
          openTxAtOtpCall.push(open.count);
          otpClosed.count += 1;
        },
      };
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
  return { deps, calls, tx, mintInputs, reauthInputs, verifyRequests, sessionHashes, rateLimitHits, pinVerifyInputs, pinSetInputs, pinChangeInputs, otpSent, otpVerified, otpProofSessionIds, otpClosed, openTxAtOtpCall, state };
}

/** A partner session token (well-formed) and its sha256. */
export const SESSION_TOKEN = "gr_ps_" + toB64u(bytes(32, 50));
export async function sha256Hex(text: string): Promise<string> {
  return Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text))), (b) => b.toString(16).padStart(2, "0")).join("");
}

export function req(method: string, path: string, init: { headers?: Record<string, string>; body?: unknown; raw?: string } = {}): Request {
  const headers = new Headers(init.headers ?? {});
  let body: string | undefined;
  if (init.raw !== undefined) body = init.raw;
  else if (init.body !== undefined) body = JSON.stringify(init.body);
  if (body !== undefined && !headers.has("content-type")) headers.set("content-type", "application/json");
  return new Request(`https://project.example.test/functions/v1/partner-session/${path}`, { method, headers, body });
}

export const authed = (extra: Record<string, string> = {}) => ({ authorization: `Bearer ${SESSION_TOKEN}`, origin: ORIGIN, ...extra });

export { fromB64u, toB64u };
