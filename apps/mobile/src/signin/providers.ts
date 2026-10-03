/**
 * Sign-in providers (build plan §3.4 Auth, §7.8 Apple 4.8; P4 ACs 17 and 20).
 *
 * The invariant that must hold: no provider is ever called before the age gate says `eligible` (`flow.ts` is the only path to one).
 */
export type SignInProviderId = "apple" | "google" | "email";

export const SIGN_IN_PROVIDER_IDS: readonly SignInProviderId[] = ["apple", "google", "email"];

export interface OfferedProvidersInput {
  /** `Platform.OS`. */
  platform: string;
  /** True only when a native Google sign-in is built into this binary AND configured (it is not, today: `google.ts`). */
  googleConfigured: boolean;
}

/**
 * The buttons the sign-in screen shows, in order.
 *
 * Apple 4.8 / P4 AT 17: offering Google makes Sign in with Apple mandatory, with equal prominence, in EVERY build that offers Google. So Apple
 * is present whenever Google is (`googleConfigured`), listed before it, and is always present on iOS, where it is native. A build that
 * does not offer Google (today: every build, until the owner's Google client and a native package exist) and is not iOS shows email only,
 * because a dead Apple button on Android would only mislead; the moment Google is offered there, Apple appears with it.
 * `[Apple on Android needs a web flow and a Services ID (server-side O3); until then the Apple button on Android reports "unavailable"]`
 */
export function offeredProviders(input: OfferedProvidersInput): SignInProviderId[] {
  const out: SignInProviderId[] = [];
  if (input.platform === "ios" || input.googleConfigured) out.push("apple");
  if (input.googleConfigured) out.push("google");
  out.push("email");
  return out;
}
