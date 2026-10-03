// supabase/functions/_shared/signin/types.ts
//
// The seams of the sign-in feature. Handlers (methods-handler.ts, revocation.ts) are pure and take everything that touches the
// outside world through these interfaces: the database through `SigninRepo` / `RevocationDb` (built by privileged.ts, the only
// file allowed to), the providers through the `*Port`s (built by production.ts from a parsed configuration), and the clock.

import type { Envelope, Kek } from "./envelope.ts";
import type { VerifiedAppleIdentity } from "./apple-id-token.ts";

export interface SigninMethodRow {
  provider: string; // 'email' | 'apple' | 'google'
  /** The provider's stable user id. Used server-side only (compared with a verified token's `sub`); never sent to a client. */
  subject: string;
  email: string | null;
  isPrivateRelay: boolean;
  linkedAt: string;
  /** A refresh token is stored for this method, so it can be revoked at the provider. */
  hasToken: boolean;
}

export interface LinkIdentityInput {
  provider: "apple" | "google";
  subject: string;
  email: string | null;
  emailVerified: boolean;
  isPrivateRelay: boolean;
}

export interface RevocationJob {
  queueId: string;
  provider: string;
}

/** The database half of `me-signin-methods` and of the DELETE /v1/me revocation. Built per transaction by privileged.ts
 * (`Repo#signin`); every method is one of the private.signin_* definers of 0035. Errors are already mapped to HttpErrors:
 * 409 identity_conflict / provider_already_linked, 404 not_linked, 422 last_sign_in_method, 503 on a timeout. */
export interface SigninRepo {
  /** The caller's own sign-in methods. */
  listMethods(): Promise<SigninMethodRow[]>;
  /** The account holding an email, or null (§3.4 rule 1). Cross-user by design; returns only an id. */
  findAccountByEmail(email: string): Promise<string | null>;
  /** Links an identity to the CALLER's own account (`targetUserId` must be the caller's uid; any other account is a 403: the OTP-proven link to
   * another account is `linkIdentityWithProof`). true = created, false = this account already held that identity. */
  linkIdentity(targetUserId: string, input: LinkIdentityInput): Promise<boolean>;
  storeToken(targetUserId: string, provider: "apple" | "google", envelope: Envelope): Promise<void>;
  /** Redeems the proof ATOMICALLY and links the identity AND stores its token for the PROOF's target account (never the
   * caller's): one definer call, so the proof is consumed exactly once. true = created, false = that account already held that identity. A
   * proof that is expired, already used, issued to another caller, or for another identity / address is 409 `email_proof_refused`. */
  linkIdentityWithProof(proofId: string, input: LinkIdentityInput, envelope: Envelope): Promise<boolean>;
  /** Unlinks one method (only while another remains) and queues its provider-grant revocation. Returns the queue ids. */
  unlinkIdentity(provider: string): Promise<string[]>;
  /** DELETE /v1/me: queue every grant of the caller for revocation, before the rows are deleted. Idempotent. */
  enqueueRevocations(): Promise<RevocationJob[]>;
  /** The newest KEK (wraps a new DEK) / a named one (unwraps a stored DEK). */
  currentKek(): Promise<Kek>;
  kekById(kekId: string): Promise<Kek>;
  /** System operations that act on no particular account (the queue, the KEK, the OTP-failure counter). They are methods of this
   * repository only so that every database access in this feature runs through `withOwnership` and its one set of timeouts; they
   * never read the caller's uid. See privileged.ts (the O12 section) for what an edge-role flip does with them. */
  system: SigninSystemOps;
}

export interface SigninSystemOps {
  claim(ids: string[] | null, limit: number, leaseSeconds: number): Promise<ClaimedRevocation[]>;
  complete(id: string, outcome: "revoked" | "retry", errorCode: string | null, backoffSeconds: number): Promise<string>;
  purge(olderThanDays: number): Promise<number>;
  kekById(kekId: string): Promise<Kek>;
  peekOtpFailures(emailHash: string): Promise<number>;
  /** Atomic: takes one attempt (cap check + increment in one statement). `attempts` is the number used including this one, or -1 at the cap;
   * `windowStart` is the hour window the attempt was charged to (ISO 8601), to be handed to `releaseOtpAttempt` (L2). */
  reserveOtpAttempt(emailHash: string): Promise<OtpReservation>;
  /** Gives one reserved attempt back, in EXACTLY the window it was reserved in (never the current one by itself; never below zero). */
  releaseOtpAttempt(emailHash: string, windowStart: string): Promise<void>;
  /** Deletes email-OTP link proofs an hour past their expiry (0039); system work. */
  purgeEmailProofs(): Promise<number>;
}

export interface ClaimedRevocation {
  id: string;
  provider: string;
  envelope: Envelope;
  attempts: number;
  expiresAt: string;
}

/** The queue operations the revocation runner needs. Each call is its own short database transaction (privileged.ts), so a
 * vendor call is never made while a transaction is open. */
export interface RevocationDb {
  claim(ids: string[] | null, limit: number, leaseSeconds: number): Promise<ClaimedRevocation[]>;
  complete(id: string, outcome: "revoked" | "retry", errorCode: string | null, backoffSeconds: number): Promise<string>;
  kekById(kekId: string): Promise<Kek>;
  purge(olderThanDays: number): Promise<number>;
}

/** What a reservation hands back: the attempts used (-1 at the cap) and the hour window the attempt was charged to. */
export interface OtpReservation {
  attempts: number;
  windowStart: string;
}

export interface OtpFailureCounter {
  /** Failed-or-in-flight OTP proofs recorded for this target-email hash in the current hour (read only; the handler does not decide on it). */
  peek(emailHash: string): Promise<number>;
  /** Takes one attempt BEFORE the proof is verified, atomically (the cap check and the increment are one statement, so parallel proofs cannot all
   * pass a read of the count). Returns the attempts used including this one and the window it was charged to, or null when the cap is already
   * reached (nothing was taken). Commits on its own: a proof that fails, or a request that dies, still counts. */
  reserve(emailHash: string): Promise<{ used: number; windowStart: string } | null>;
  /** Gives one reserved attempt back: the proof SUCCEEDED, or never reached a verdict (a transport failure says nothing about the code).
   * `windowStart` is the window `reserve` returned: a release after the hour rolled over must not refund the new window (L2). */
  release(emailHash: string, windowStart: string): Promise<void>;
}

export interface AppleSigninPort {
  verifyIdentityToken(token: string, rawNonce: string): Promise<VerifiedAppleIdentity>;
  exchangeAuthorizationCode(code: string): Promise<{ refreshToken: string; subject: string }>;
  revokeRefreshToken(refreshToken: string): Promise<void>;
}

export interface GoogleRevokePort {
  revokeToken(token: string): Promise<void>;
}

/** What the handler hands the minter after an OTP verified (0039). The minter hashes the address and the subject; the database re-derives both. */
export interface EmailProofInput {
  /** The signed-in caller: the only account that may redeem the proof. */
  callerUserId: string;
  /** The account whose mailbox was proven: the only account the proof can link to. */
  targetUserId: string;
  email: string;
  provider: "apple" | "google";
  /** The provider's stable subject (the Apple `sub`) of the identity that triggered the proof. */
  subject: string;
  /** The id of the GoTrue session the OTP verification created for the target (0041, (b)): the database refuses unless that session exists, for the
   * target, fresh. The id is the one secret the minter's statement carries that no other edge path can know. */
  sessionId: string;
}

/** Mints the single-use, short-lived proof of a verified email OTP (`private.signin_record_email_proof`, 0039 / 0041). Runs in its OWN transaction as
 * `edge_signin_minter` (the one role with EXECUTE on it), never as the per-user actor or `edge_system`, and the database refuses unless the target's own
 * address, GoTrue's sign-in stamp and a fresh session of the target with the given id agree. The address and the subject go in RAW: the database
 * normalises and hashes them (one rule, 0041 L2); nothing here hashes either. Returns the proof id (a random uuid that never leaves the server). */
export interface EmailProofMinter {
  record(input: EmailProofInput): Promise<string>;
}

export type EmailOtpResult =
  | {
      ok: true;
      userId: string;
      /** The id of the session verifyOtp created (the `session_id` claim of its access token), or null when the response carried none (the handler then
       * refuses: a proof cannot be bound to a session it cannot name). */
      sessionId: string | null;
      /** Signs out exactly that session (scope local, on the client that holds it). The CALLER runs it after the mint, whatever the outcome: until then the
       * session must exist, because the database checks it. Never throws; a failed sign-out is logged and the session is in memory only (security gate F5). */
      closeSession(): Promise<void>;
    }
  | { ok: false };

/** Proves control of a mailbox by an email OTP (Supabase Auth's verifyOtp). Resolves `{ ok: false }` for a wrong or expired code
 * (counted against the 5-per-target-per-hour limit); THROWS for a transport failure (not counted: it says nothing about the code). A SUCCESS leaves the
 * GoTrue session it created OPEN and hands the caller `closeSession`: the proof is bound to that session, so it is signed out after the mint, not before. */
export interface EmailOtpVerifier {
  verify(email: string, code: string): Promise<EmailOtpResult>;
}

export const OTP_FAILURES_PER_EMAIL_PER_HOUR = 5;
export const SIGNIN_LINKING_PER_USER_PER_HOUR = 10;
