/**
 * Sign-in provider registry (build plan §3.4 Auth, §7.8 Apple 4.8; P4 ACs
 * 17 and 20). **Stubs only in P4.1**: real Sign in with Apple, Google and
 * email OTP are P4.2. What this slice fixes is the SHAPE and the one
 * invariant that must hold from day one: no provider is ever called before
 * the age gate says `eligible` (`start.ts`).
 */
export type SignInProviderId = "apple" | "google" | "email";

export interface SignInResult {
  ok: true;
  provider: SignInProviderId;
  /** True for every provider in this slice: no real account exists. */
  stub: boolean;
}

export interface SignInProvider {
  id: SignInProviderId;
  signIn(): Promise<SignInResult>;
}

/** Apple 4.8 (O12): offering Google makes Sign in with Apple mandatory, with
 * equal prominence — so Apple is listed FIRST and is always present
 * whenever Google is. (Whether Android shows the Apple button via a web flow
 * is a P4.2 call `[unverified — training knowledge]`; the plan's AT 17 says
 * the button is present in every build that offers Google.) */
export function offeredProviders(): SignInProviderId[] {
  return ["apple", "google", "email"];
}

export function stubProvider(id: SignInProviderId): SignInProvider {
  return { id, signIn: () => Promise.resolve({ ok: true, provider: id, stub: true }) };
}

export function stubProviders(): Record<SignInProviderId, SignInProvider> {
  return { apple: stubProvider("apple"), google: stubProvider("google"), email: stubProvider("email") };
}
