/**
 * A stand-in `AuthService` for the `__DEV__` demo and tests: no server, nothing persisted, "sessions" are marked `stub`. Needs a `DevOnly`
 * token (`dev-guard.ts`) like `api/mock.ts`: never constructed in a release build. The demo accepts the code `123456`.
 */
import { assertDevOnly, type DevOnly } from "../dev-guard";
import type { Session } from "../api/types";
import { AuthError, type AuthService } from "./types";

export const MOCK_OTP_CODE = "123456";

export interface MockAuth extends AuthService {
  readonly emailCodesRequested: readonly { email: string; createUser: boolean }[];
}

export function createMockAuth(guard: DevOnly): MockAuth {
  assertDevOnly(guard);
  let session: Session | null = null;
  const listeners = new Set<(s: Session | null) => void>();
  const requested: { email: string; createUser: boolean }[] = [];
  const set = (s: Session | null): void => {
    session = s;
    for (const l of [...listeners]) l(s);
  };
  return {
    emailCodesRequested: requested,
    restore: () => Promise.resolve(session),
    current: () => session,
    getAccessToken: (o) => Promise.resolve(session && (o?.forUserId === undefined || o.forUserId === session.userId) ? "mock-access-token" : null),
    requestEmailCode(email, o) {
      requested.push({ email, createUser: o.createUser });
      return Promise.resolve();
    },
    verifyEmailCode(_email, code) {
      if (code !== MOCK_OTP_CODE) return Promise.reject(new AuthError("invalid_credentials", { status: 403 }));
      const s: Session = { userId: "mock-user-email", provider: "email", stub: true };
      set(s);
      return Promise.resolve(s);
    },
    signInWithIdToken(c) {
      const s: Session = { userId: `mock-user-${c.provider}`, provider: c.provider, stub: true };
      set(s);
      return Promise.resolve(s);
    },
    signOut() {
      set(null);
      return Promise.resolve();
    },
    clearLocalSession() {
      set(null);
      return Promise.resolve();
    },
    subscribe(l) {
      listeners.add(l);
      return () => void listeners.delete(l);
    },
  };
}
