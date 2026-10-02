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
  /** false when this transaction has no way to link an identity to ANOTHER account (the OTP-proven link): `edge` mode, by design (no
   * edge definer attaches an identity to an arbitrary account). The handler answers 501 before it spends an OTP or a code. */
  readonly crossAccountLink: boolean;
  /** The caller's own sign-in methods. */
  listMethods(): Promise<SigninMethodRow[]>;
  /** The account holding an email, or null (§3.4 rule 1). Cross-user by design; returns only an id. */
  findAccountByEmail(email: string): Promise<string | null>;
  /** Links an identity to `targetUserId` (the caller, or, on the OTP-proven path, the account whose mailbox the caller proved).
   * true = created, false = this account already held that identity. */
  linkIdentity(targetUserId: string, input: LinkIdentityInput): Promise<boolean>;
  storeToken(targetUserId: string, provider: "apple" | "google", envelope: Envelope): Promise<void>;
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
  /** Atomic: takes one attempt (cap check + increment in one statement). Returns attempts used including this one, or -1 at the cap. */
  reserveOtpAttempt(emailHash: string): Promise<number>;
  /** Gives one reserved attempt back (never below zero). */
  releaseOtpAttempt(emailHash: string): Promise<void>;
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

export interface OtpFailureCounter {
  /** Failed-or-in-flight OTP proofs recorded for this target-email hash in the current hour (read only; the handler does not decide on it). */
  peek(emailHash: string): Promise<number>;
  /** Takes one attempt BEFORE the proof is verified, atomically (the cap check and the increment are one statement, so parallel proofs cannot all
   * pass a read of the count). Returns the attempts used including this one, or null when the cap is already reached (nothing was taken).
   * Commits on its own: a proof that fails, or a request that dies, still counts. */
  reserve(emailHash: string): Promise<number | null>;
  /** Gives one reserved attempt back: the proof SUCCEEDED, or never reached a verdict (a transport failure says nothing about the code). */
  release(emailHash: string): Promise<void>;
}

export interface AppleSigninPort {
  verifyIdentityToken(token: string, rawNonce: string): Promise<VerifiedAppleIdentity>;
  exchangeAuthorizationCode(code: string): Promise<{ refreshToken: string; subject: string }>;
  revokeRefreshToken(refreshToken: string): Promise<void>;
}

export interface GoogleRevokePort {
  revokeToken(token: string): Promise<void>;
}

export type EmailOtpResult = { ok: true; userId: string } | { ok: false };

/** Proves control of a mailbox by an email OTP (Supabase Auth's verifyOtp). Resolves `{ ok: false }` for a wrong or expired code
 * (counted against the 5-per-email-per-hour limit); THROWS for a transport failure (not counted: it says nothing about the code). */
export interface EmailOtpVerifier {
  verify(email: string, code: string): Promise<EmailOtpResult>;
}

export const OTP_FAILURES_PER_EMAIL_PER_HOUR = 5;
export const SIGNIN_LINKING_PER_USER_PER_HOUR = 10;
