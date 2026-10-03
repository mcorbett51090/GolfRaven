/**
 * `AuthService` over `@supabase/auth-js` 2.65.0 (`GoTrueClient`): the exact auth-js that `@supabase/supabase-js` 2.45.4 pins, and
 * supabase-js 2.45.4 is the version `supabase/functions/_shared/privileged.ts` imports, so the client and the server speak with the same library.
 * **Why auth-js and not supabase-js itself:** only the Auth client is used, and `@supabase/supabase-js` also pulls in `realtime-js`, which requires
 * Node's `ws` (and through it `stream`): Metro cannot resolve it and `expo export` fails for both platforms (observed, 2026-10-03). auth-js alone
 * bundles, and is a fraction of the size.
 *
 * The session (access + REFRESH token) is persisted through `storage`, which is the secure store (`sessionStorageAdapter`), under the one key
 * `SESSION_STORAGE_KEY`. Nothing else is ever given to the library to persist: not SQLite, not `AsyncStorage` (`test/supabase-auth.test.ts` runs
 * the real library against a fake GoTrue and asserts where the session landed).
 *
 * Settings, and why:
 *  - `autoRefreshToken: false`: no background timer. The token is refreshed ON DEMAND (`getAccessToken`: early, within `expiryMarginMs` of expiry, or
 *    forced after a 401), bounded by `refreshBudgetMs`; no background work, nothing to start/stop on app state.
 *  - `detectSessionInUrl: false`: there is no browser URL; the OTP is typed in, never a magic link (§3.4: codes, not links).
 *  - `flowType: "implicit"`: the library's default for OTP and id-token sign-in; PKCE is for redirect (OAuth) flows this app does not use.
 *
 * `[unverified]` on a device: auth-js on React Native 0.86/Hermes. Read from source: it uses `URLSearchParams` (RN ships one that accepts an object
 * and has `toString`) and `new URL(...)` only for browser OAuth-redirect parsing, which this app never reaches. `expo export` bundles it for both
 * platforms (recorded in the README); nothing has run on a device.
 * `[GoTrue's wire behaviour (`/otp`, `/verify`, `/token?grant_type=id_token|refresh_token`, `/logout`) is the library's, not re-implemented here;
 * whether a real GoTrue accepts a native id token with a raw nonce for Apple/Google is Supabase behaviour this repo has not verified.]`
 */
import { GoTrueClient, type Session as SupabaseSession } from "@supabase/auth-js";
import type { Session } from "../api/types";
import type { SignInProviderId } from "../signin/providers";
import { SESSION_STORAGE_KEY, type SecureStore } from "../secure";
import { AuthError, type AuthService, type IdTokenCredential } from "./types";

export interface SupabaseAuthOptions {
  /** `https://<ref>.supabase.co` (`parseSupabaseUrl`). */
  url: string;
  /** The PUBLIC anon/publishable key (`parseSupabaseAnonKey`). */
  anonKey: string;
  /** Where the session is persisted: the secure store. */
  storage: SecureStore;
  /** Defaults to the global `fetch`. */
  fetch?: typeof fetch;
  /** Per-request timeout for every call auth-js makes (default 15 s). */
  fetchTimeoutMs?: number;
  /** Overall budget for refreshing the session before `getAccessToken` gives up with a network error (default 10 s). auth-js retries a
   * failed refresh with backoff for up to ~30 s on its own; a person waiting on a request must not wait that long. */
  refreshBudgetMs?: number;
  /** A token expiring within this many ms is refreshed before use (default 60 s). auth-js 2.65.0's `getSession()` only refreshes a token
   * that has ALREADY expired (its 10 s margin is for its background timer, which is off here). */
  expiryMarginMs?: number;
}

export const DEFAULTS = { fetchTimeoutMs: 15_000, refreshBudgetMs: 10_000, expiryMarginMs: 60_000 } as const;

/** Wraps `fetch` so no auth request can hang forever (RN's `fetch` has no timeout of its own). */
export function withFetchTimeout(base: typeof fetch, ms: number): typeof fetch {
  return ((input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const controller = new AbortController();
    const outer = init?.signal;
    if (outer) {
      if (outer.aborted) controller.abort();
      else outer.addEventListener("abort", () => controller.abort(), { once: true });
    }
    const timer = setTimeout(() => controller.abort(), ms);
    return base(input, { ...init, signal: controller.signal }).finally(() => clearTimeout(timer));
  }) as typeof fetch;
}

function raceBudget<T>(p: Promise<T>, ms: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const budget = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new AuthError("network", { message: `session refresh did not finish in ${ms} ms` })), ms);
  });
  return Promise.race([p, budget]).finally(() => clearTimeout(timer));
}

/** auth-js's `SupportedStorage`, over a `SecureStore`. A READ that fails answers "no session" (the app is signed out until the player signs
 * in again, which overwrites it): auth-js reads the store from its own initialisation, where a rejection would be an unhandled one. Writes and
 * deletes are not swallowed. (This is for the session only: the age flag's store lets read errors surface, `age/secure-flags.ts`.) */
export function sessionStorageAdapter(secure: SecureStore): { getItem(key: string): Promise<string | null>; setItem(key: string, value: string): Promise<void>; removeItem(key: string): Promise<void> } {
  return {
    getItem: (key) => secure.get(key).catch(() => null),
    setItem: (key, value) => secure.set(key, value),
    removeItem: (key) => secure.delete(key),
  };
}

function providerOf(s: SupabaseSession): SignInProviderId {
  const p = (s.user.app_metadata as { provider?: unknown } | undefined)?.provider;
  return p === "apple" || p === "google" || p === "email" ? p : "email";
}

function toSession(s: SupabaseSession | null): Session | null {
  return s ? { userId: s.user.id, provider: providerOf(s), stub: false } : null;
}

/** Maps a auth-js error to ours. Status 0/undefined with a retryable name is a transport failure; 429 is rate limiting. */
export function mapAuthError(e: unknown): AuthError {
  if (e instanceof AuthError) return e;
  const err = e as { name?: unknown; status?: unknown; code?: unknown; message?: unknown } | null;
  const status = typeof err?.status === "number" ? err.status : null;
  const code = typeof err?.code === "string" ? err.code : null;
  const message = typeof err?.message === "string" ? err.message : "auth error";
  const name = typeof err?.name === "string" ? err.name : "";
  if (status === 429 || code === "over_email_send_rate_limit" || code === "over_request_rate_limit") return new AuthError("rate_limited", { status, code, message });
  if (name === "AuthRetryableFetchError" || (status !== null && status >= 500) || (status === null && name !== "AuthApiError" && name !== "AuthInvalidTokenResponseError" && /fetch|network|timeout|abort/i.test(message))) {
    return new AuthError("network", { status, code, message });
  }
  if (code === "otp_disabled" || code === "signup_disabled" || code === "user_not_found") return new AuthError("unknown_user", { status, code, message });
  if (status === 400 || status === 401 || status === 403 || status === 422) return new AuthError("invalid_credentials", { status, code, message });
  return new AuthError("other", { status, code, message });
}

export function createSupabaseAuth(opts: SupabaseAuthOptions): AuthService {
  const fetchTimeoutMs = opts.fetchTimeoutMs ?? DEFAULTS.fetchTimeoutMs;
  const refreshBudgetMs = opts.refreshBudgetMs ?? DEFAULTS.refreshBudgetMs;
  const expiryMarginMs = opts.expiryMarginMs ?? DEFAULTS.expiryMarginMs;
  const baseFetch: typeof fetch = opts.fetch ?? ((input, init) => fetch(input, init));
  // The same construction supabase-js's own `createClient` does for `.auth`: the Auth base URL, and the PUBLIC key as `apikey` and as the
  // anonymous bearer (an authenticated call replaces the bearer with the access token itself).
  const client = new GoTrueClient({
    url: `${opts.url}/auth/v1`,
    headers: { apikey: opts.anonKey, Authorization: `Bearer ${opts.anonKey}`, "X-Client-Info": "golfraven-mobile" },
    storage: sessionStorageAdapter(opts.storage),
    storageKey: SESSION_STORAGE_KEY,
    persistSession: true,
    autoRefreshToken: false,
    detectSessionInUrl: false,
    flowType: "implicit",
    fetch: withFetchTimeout(baseFetch, fetchTimeoutMs),
  });
  let current: Session | null = null;
  const listeners = new Set<(s: Session | null) => void>();
  const publish = (s: Session | null): void => {
    const changed = current?.userId !== s?.userId || current?.provider !== s?.provider;
    current = s;
    if (changed) for (const l of [...listeners]) l(s);
  };

  // A refresh that the server refuses (revoked / reused refresh token) makes auth-js drop the session and emit SIGNED_OUT: mirror it.
  // ONLY that event is acted on: INITIAL_SESSION / SIGNED_IN / TOKEN_REFRESHED can be delivered after the session they describe was already
  // replaced or cleared, and every operation here publishes its own result. The callback never calls back into the client (the library warns
  // that doing so can deadlock).
  client.onAuthStateChange((event) => {
    if (event === "SIGNED_OUT") publish(null);
  });

  async function ok<T extends { error: unknown }>(p: Promise<T>): Promise<T> {
    let r: T;
    try {
      r = await p;
    } catch (e) {
      throw mapAuthError(e);
    }
    if (r.error) throw mapAuthError(r.error);
    return r;
  }

  const requireSession = (s: SupabaseSession | null | undefined): Session => {
    const mapped = toSession(s ?? null);
    if (!mapped) throw new AuthError("other", { message: "no session returned" });
    publish(mapped);
    return mapped;
  };

  return {
    async restore() {
      try {
        const { data } = await client.getSession();
        publish(toSession(data.session));
      } catch {
        // unreadable storage or a transport failure on refresh: treat as signed out for now; the stored session (if any) is left alone
      }
      return current;
    },
    current: () => current,
    async getAccessToken(o) {
      // Reads the stored session (auth-js refreshes it itself if it has already expired), then refreshes early when it is about to expire
      // or the caller says a 401 proved it stale. Each library call that may refresh is bounded by `refreshBudgetMs`.
      const bounded = async <T extends { error: unknown }>(p: Promise<T>): Promise<T | AuthError> => {
        try {
          return await raceBudget(p, refreshBudgetMs);
        } catch (e) {
          return mapAuthError(e);
        }
      };
      const first = await bounded(client.getSession());
      if (first instanceof AuthError) throw first;
      if (first.error) {
        const mapped = mapAuthError(first.error);
        if (mapped.kind === "network") throw mapped;
        return null;
      }
      const s = first.data.session;
      if (!s) return null;
      const stale = o?.forceRefresh === true || (s.expires_at !== undefined && s.expires_at * 1000 - Date.now() < expiryMarginMs);
      if (!stale) return s.access_token;
      const refreshed = await bounded(client.refreshSession());
      const failure = refreshed instanceof AuthError ? refreshed : refreshed.error ? mapAuthError(refreshed.error) : null;
      if (failure === null && !(refreshed instanceof AuthError)) return refreshed.data.session?.access_token ?? null;
      if (failure?.kind === "network") {
        // Offline with a token that has not expired yet: use it (the server decides; a 401 comes back through the forced refresh).
        if (o?.forceRefresh !== true && s.expires_at !== undefined && s.expires_at * 1000 > Date.now()) return s.access_token;
        throw failure;
      }
      return null; // the server refused the refresh token: the library has dropped the session
    },
    async requestEmailCode(email, o) {
      await ok(client.signInWithOtp({ email, options: { shouldCreateUser: o.createUser } }));
    },
    async verifyEmailCode(email, code) {
      const r = await ok(client.verifyOtp({ email, token: code, type: "email" }));
      return requireSession(r.data.session);
    },
    async signInWithIdToken(c: IdTokenCredential) {
      const r = await ok(client.signInWithIdToken({ provider: c.provider, token: c.idToken, nonce: c.nonce }));
      return requireSession(r.data.session);
    },
    async signOut() {
      try {
        await client.signOut({ scope: "local" });
      } catch {
        // best effort: the local removal below is what matters
      }
      await opts.storage.delete(SESSION_STORAGE_KEY);
      publish(null);
    },
    async clearLocalSession() {
      await opts.storage.delete(SESSION_STORAGE_KEY);
      publish(null);
    },
    subscribe(listener) {
      listeners.add(listener);
      return () => void listeners.delete(listener);
    },
  };
}
