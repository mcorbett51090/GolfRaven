/**
 * The sign-in state machines (build plan §3.4, §7.8; P4 AT 17, 20). Pure orchestration over injected seams (age gate, auth service, the
 * native adapters, the API client, a CSPRNG), so every rule below is tested without a device.
 *
 * THE RULES, and where each is enforced:
 *  1. **Age first (O18, AT 20).** Every entry point starts with `checkEligible(gate)`. A provider adapter (`apple.authenticate`,
 *     `google.authenticate`), the auth service and the API are not touched unless the gate says `eligible`: for `unknown` the result is
 *     `age_required` (the screen sends the player to the age screen), for `ineligible` it is `blocked` and nothing is called, on any retry.
 *  2. **Nonce (server F1).** The adapter receives `nonce.hashed`; Supabase Auth and our server receive `nonce.raw`.
 *  3. **Grant capture (server O12 "honest gap").** A native Apple sign-in creates the Apple identity inside Supabase Auth without going through
 *     `me-signin-methods`, so no refresh token would be stored and the grant could not be revoked on deletion. Right after the session starts,
 *     the flow calls `link` (idempotent: `created: false`) with the same token, authorization code and raw nonce. It is the caller's OWN account,
 *     it carries NO `emailProof`, and a failure does not undo the sign-in: it is reported (`grantCaptured: false`).
 *  4. **No auto-linking.** Nothing in this file ever sends `emailProof`; that exists only in `account/link-flow.ts`, behind two explicit player
 *     actions. `[Supabase Auth's own automatic linking of same-email identities at sign-in is outside the app's reach: see the README.]`
 */
import type { AgeGate } from "../age";
import { ApiError } from "../api/errors";
import type { ApiClient, Session } from "../api/types";
import { AuthError, type AuthService } from "../auth/types";
import type { AppleAdapter, GoogleAdapter } from "./adapters";
import { EMAIL_RE } from "./jwt";
import { createNonce, type RandomBytes } from "./nonce";
import type { SignInProviderId } from "./providers";

export interface SignInDeps {
  gate: AgeGate;
  auth: AuthService;
  api: Pick<ApiClient, "linkSignInMethod">;
  apple: AppleAdapter;
  google: GoogleAdapter;
  random: RandomBytes;
}

export type SignInFailure = "invalid_code" | "invalid_email" | "rate_limited" | "network" | "unknown";

export type SignInOutcome =
  | {
      status: "signed_in";
      session: Session;
      /** Apple only: whether the provider grant was stored for revocation. `null` = not applicable. */
      grantCaptured: boolean | null;
    }
  | { status: "age_required" } // the gate has not been passed yet: show the age screen
  | { status: "blocked" } // this install already failed the gate
  | { status: "cancelled" }
  | { status: "not_configured" } // Google: no native module / client id in this build
  | { status: "unsupported_platform" } // Apple on Android
  | { status: "failed"; reason: SignInFailure; retryAfterSeconds?: number };

export type Eligibility = { ok: true } | { ok: false; status: "age_required" | "blocked" };

/** O18 / AT 20: "a neutral age screen runs before any sign-in provider is called". The ONLY thing that lets a flow proceed. */
export async function checkEligible(gate: AgeGate): Promise<Eligibility> {
  const state = await gate.state();
  if (state === "ineligible") return { ok: false, status: "blocked" };
  if (state !== "eligible") return { ok: false, status: "age_required" };
  return { ok: true };
}

export function failureFrom(e: unknown): SignInOutcome {
  if (e instanceof AuthError) {
    if (e.kind === "invalid_credentials") return { status: "failed", reason: "invalid_code" };
    if (e.kind === "rate_limited") return { status: "failed", reason: "rate_limited" };
    if (e.kind === "network") return { status: "failed", reason: "network" };
    return { status: "failed", reason: "unknown" };
  }
  if (e instanceof ApiError) {
    if (e.kind === "network") return { status: "failed", reason: "network" };
    if (e.kind === "rate_limited") return { status: "failed", reason: "rate_limited", ...(e.retryAfterSeconds !== null ? { retryAfterSeconds: e.retryAfterSeconds } : {}) };
  }
  return { status: "failed", reason: "unknown" };
}

/** Apple: age gate, availability, nonce, Apple's sheet (hash only), Supabase sign-in (raw nonce), grant capture (raw nonce). */
export async function signInWithApple(deps: SignInDeps): Promise<SignInOutcome> {
  const eligible = await checkEligible(deps.gate);
  if (!eligible.ok) return { status: eligible.status };
  if ((await deps.apple.availability()) !== "available") return { status: "unsupported_platform" };
  const nonce = createNonce(deps.random);
  let result;
  try {
    result = await deps.apple.authenticate(nonce.hashed);
  } catch {
    return { status: "failed", reason: "unknown" };
  }
  if (result.status === "cancelled") return { status: "cancelled" };
  let session: Session;
  try {
    session = await deps.auth.signInWithIdToken({ provider: "apple", idToken: result.identityToken, nonce: nonce.raw });
  } catch (e) {
    return failureFrom(e);
  }
  let grantCaptured = false;
  try {
    await deps.api.linkSignInMethod({ provider: "apple", identityToken: result.identityToken, authorizationCode: result.authorizationCode, nonce: nonce.raw });
    grantCaptured = true;
  } catch {
    // Signed in, but the grant is not stored: reported, not hidden. The authorization code is single-use, so it cannot be replayed later.
  }
  return { status: "signed_in", session, grantCaptured };
}

/** Google: age gate, then "not configured" in a build with no native SDK; otherwise the same nonce discipline as Apple. No grant capture
 * (the server's Google `link` is a 501 today, so there is nothing to capture). */
export async function signInWithGoogle(deps: SignInDeps): Promise<SignInOutcome> {
  const eligible = await checkEligible(deps.gate);
  if (!eligible.ok) return { status: eligible.status };
  if ((await deps.google.availability()) !== "available") return { status: "not_configured" };
  const nonce = createNonce(deps.random);
  let result;
  try {
    result = await deps.google.authenticate(nonce.hashed);
  } catch {
    return { status: "failed", reason: "unknown" };
  }
  if (result.status === "cancelled") return { status: "cancelled" };
  try {
    const session = await deps.auth.signInWithIdToken({ provider: "google", idToken: result.idToken, nonce: nonce.raw });
    return { status: "signed_in", session, grantCaptured: null };
  } catch (e) {
    return failureFrom(e);
  }
}

/** The single entry point for the two native providers (what the screen calls). Email is two steps below. */
export function startSignIn(id: Exclude<SignInProviderId, "email">, deps: SignInDeps): Promise<SignInOutcome> {
  return id === "apple" ? signInWithApple(deps) : signInWithGoogle(deps);
}

export type EmailCodeRequestOutcome = { status: "sent" } | { status: "age_required" } | { status: "blocked" } | { status: "failed"; reason: SignInFailure };

/** Email OTP step 1: age gate, then Supabase Auth sends the code (`shouldCreateUser: true`: first use creates the account). */
export async function requestEmailSignInCode(email: string, deps: Pick<SignInDeps, "gate" | "auth">): Promise<EmailCodeRequestOutcome> {
  const eligible = await checkEligible(deps.gate);
  if (!eligible.ok) return { status: eligible.status };
  const address = email.trim();
  if (!EMAIL_RE.test(address)) return { status: "failed", reason: "invalid_email" };
  try {
    await deps.auth.requestEmailCode(address, { createUser: true });
    return { status: "sent" };
  } catch (e) {
    const f = failureFrom(e);
    return { status: "failed", reason: f.status === "failed" ? f.reason : "unknown" };
  }
}

/** Email OTP step 2: age gate AGAIN (a session is never created for an ineligible install, whatever state the screen was in), then verify. */
export async function verifyEmailSignInCode(email: string, code: string, deps: Pick<SignInDeps, "gate" | "auth">): Promise<SignInOutcome> {
  const eligible = await checkEligible(deps.gate);
  if (!eligible.ok) return { status: eligible.status };
  const token = code.trim();
  if (!/^[0-9]{6,10}$/.test(token)) return { status: "failed", reason: "invalid_code" };
  try {
    const session = await deps.auth.verifyEmailCode(email.trim(), token);
    return { status: "signed_in", session, grantCaptured: null };
  } catch (e) {
    return failureFrom(e);
  }
}
