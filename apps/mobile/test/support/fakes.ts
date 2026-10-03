/** Test doubles for the sign-in and account flows: a spy age gate, native-module adapters that record what they were given, an auth service
 * and an API that record calls and can be scripted to fail. */
import { AgeGate, MemoryDeviceFlagStore } from "../../src/age";
import { ApiError, type ApiClient, type LinkSignInRequest, type LinkSignInResult, type Session } from "../../src/api";
import { AuthError, type AuthService, type IdTokenCredential } from "../../src/auth";
import type { AppleAdapter, AppleAuthResult, GoogleAdapter, GoogleAuthResult } from "../../src/signin";

export const NOW = () => new Date("2026-10-02T12:00:00.000Z");

export async function gateIn(state: "unknown" | "eligible" | "ineligible"): Promise<AgeGate> {
  const gate = new AgeGate(new MemoryDeviceFlagStore(), NOW);
  if (state === "eligible") await gate.submitBirthYear(1990, 16);
  if (state === "ineligible") await gate.submitBirthYear(2015, 16);
  return gate;
}

/** A fixed, non-zero "CSPRNG": byte i = (seed + i) mod 256. Different seeds, different nonces. */
export const fixedRandom = (seed = 7) => (n: number): Uint8Array => Uint8Array.from({ length: n }, (_, i) => (seed + i * 5 + 1) % 256);

export function b64url(text: string): string {
  return Buffer.from(text, "utf8").toString("base64url");
}
export function jwt(payload: Record<string, unknown>): string {
  return `${b64url(JSON.stringify({ alg: "RS256", kid: "k" }))}.${b64url(JSON.stringify(payload))}.${b64url("sig")}`;
}

export class FakeApple implements AppleAdapter {
  availabilityResult: "available" | "unsupported_platform" = "available";
  result: AppleAuthResult = { status: "ok", identityToken: jwt({ email: "alice@example.test", email_verified: "true" }), authorizationCode: "auth-code-1" };
  throws: Error | null = null;
  readonly hashedNonces: string[] = [];
  availabilityCalls = 0;
  availability() {
    this.availabilityCalls += 1;
    return Promise.resolve(this.availabilityResult);
  }
  authenticate(hashedNonce: string): Promise<AppleAuthResult> {
    this.hashedNonces.push(hashedNonce);
    return this.throws ? Promise.reject(this.throws) : Promise.resolve(this.result);
  }
}

export class FakeGoogle implements GoogleAdapter {
  availabilityResult: "available" | "not_configured" = "not_configured";
  result: GoogleAuthResult = { status: "ok", idToken: jwt({ email: "g@example.test" }) };
  readonly hashedNonces: string[] = [];
  availabilityCalls = 0;
  availability() {
    this.availabilityCalls += 1;
    return Promise.resolve(this.availabilityResult);
  }
  authenticate(hashedNonce: string): Promise<GoogleAuthResult> {
    this.hashedNonces.push(hashedNonce);
    return Promise.resolve(this.result);
  }
}

export class FakeAuth implements AuthService {
  session: Session | null = null;
  readonly idTokenCalls: IdTokenCredential[] = [];
  readonly emailCodeRequests: { email: string; createUser: boolean }[] = [];
  readonly verifyCalls: { email: string; code: string }[] = [];
  failWith: AuthError | null = null;
  clearedLocal = 0;
  signedOut = 0;
  restore = () => Promise.resolve(this.session);
  current = () => this.session;
  getAccessToken = () => Promise.resolve(this.session ? "access" : null);
  requestEmailCode(email: string, o: { createUser: boolean }): Promise<void> {
    this.emailCodeRequests.push({ email, createUser: o.createUser });
    return this.failWith ? Promise.reject(this.failWith) : Promise.resolve();
  }
  verifyEmailCode(email: string, code: string): Promise<Session> {
    this.verifyCalls.push({ email, code });
    if (this.failWith) return Promise.reject(this.failWith);
    this.session = { userId: "user-1", provider: "email", stub: false };
    return Promise.resolve(this.session);
  }
  signInWithIdToken(c: IdTokenCredential): Promise<Session> {
    this.idTokenCalls.push(c);
    if (this.failWith) return Promise.reject(this.failWith);
    this.session = { userId: "user-1", provider: c.provider, stub: false };
    return Promise.resolve(this.session);
  }
  signOut = () => {
    this.signedOut += 1;
    this.session = null;
    return Promise.resolve();
  };
  clearLocalSession = () => {
    this.clearedLocal += 1;
    this.session = null;
    return Promise.resolve();
  };
  subscribe = () => () => undefined;
}

/** Only the `link` call, recording every request and answering from a script (each entry is a result or an error to throw). */
export class FakeLinkApi implements Pick<ApiClient, "linkSignInMethod"> {
  readonly calls: LinkSignInRequest[] = [];
  script: (LinkSignInResult | ApiError)[] = [];
  fallback: LinkSignInResult | ApiError = { linked: { provider: "apple", created: false, isPrivateRelay: false }, linkedTo: "self", methods: [] };
  linkSignInMethod(req: LinkSignInRequest): Promise<LinkSignInResult> {
    this.calls.push(req);
    const next = this.script.shift() ?? this.fallback;
    return next instanceof ApiError ? Promise.reject(next) : Promise.resolve(next);
  }
}

export const apiError = (kind: ApiError["kind"], status: number, code: string | null, details?: unknown, retryAfterSeconds: number | null = null): ApiError =>
  new ApiError({ kind, status, code, details, retryAfterSeconds });
