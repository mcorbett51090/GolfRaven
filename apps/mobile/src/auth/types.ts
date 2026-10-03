/**
 * The app's auth seam: everything the screens and the API client need from "the Supabase session", behind an interface so the sign-in state
 * machines and the HTTP client are tested without the auth library. The real implementation is `supabase-auth.ts` (`@supabase/auth-js` 2.65.0, the one bundled by the
 * supabase-js 2.45.4 the Edge Functions are pinned to); `mock-auth.ts` is the dev-only stand-in.
 */
import type { Session } from "../api/types";

export type AuthFailureKind =
  /** A wrong or expired code, or a token the auth server refused. */
  | "invalid_credentials"
  /** 429 from Auth (too many codes requested / too many attempts). */
  | "rate_limited"
  /** `shouldCreateUser: false` for an address with no account. */
  | "unknown_user"
  /** No connection, a timeout, a 5xx: says nothing about the credentials. */
  | "network"
  | "other";

export class AuthError extends Error {
  readonly kind: AuthFailureKind;
  readonly status: number | null;
  readonly code: string | null;
  constructor(kind: AuthFailureKind, init: { status?: number | null; code?: string | null; message?: string } = {}) {
    super(init.message ?? kind);
    this.name = "AuthError";
    this.kind = kind;
    this.status = init.status ?? null;
    this.code = init.code ?? null;
  }
}

export interface IdTokenCredential {
  provider: "apple" | "google";
  idToken: string;
  /** The RAW nonce. (The hash went to the provider; the auth server re-hashes this and compares with the token's claim.) */
  nonce: string;
}

export interface AuthService {
  /** Loads the persisted session from the secure store (refreshing it if it has expired). `null` = signed out. Never throws for "no session". */
  restore(): Promise<Session | null>;
  /** The session as last known (no I/O). */
  current(): Session | null;
  /** The access token to send as a bearer, refreshed if it is about to expire (`forceRefresh`: refresh regardless, after a 401).
   * `null` = signed out. Throws `AuthError("network")` if a needed refresh could not reach the server. */
  getAccessToken(opts?: { forceRefresh?: boolean }): Promise<string | null>;
  /** Sends a one-time code to `email`. `createUser: true` is a sign-in (creates the account on first use); `false` sends only to an
   * existing account (the cross-account proof of the linking flow). */
  requestEmailCode(email: string, opts: { createUser: boolean }): Promise<void>;
  /** Verifies the code and starts the session. */
  verifyEmailCode(email: string, code: string): Promise<Session>;
  /** Native Apple / Google sign-in: exchanges the provider's id token for a Supabase session. */
  signInWithIdToken(credential: IdTokenCredential): Promise<Session>;
  /** Ends the session: revokes it at the server best-effort, and ALWAYS removes it from the secure store. */
  signOut(): Promise<void>;
  /** Removes the session from the secure store with no network call (after account deletion the server session no longer exists). */
  clearLocalSession(): Promise<void>;
  /** Called with the new session (or `null`) whenever it changes. Returns an unsubscribe. */
  subscribe(listener: (session: Session | null) => void): () => void;
}
