import type { AgeGate } from "../age";
import type { SignInProvider, SignInProviderId, SignInResult } from "./providers";

export type StartSignInResult =
  | { status: "signed_in"; result: SignInResult }
  | { status: "age_required" } // the gate has not been passed yet: show the age screen
  | { status: "blocked" }; // this install already failed the gate

/**
 * The ONLY path to a provider. O18 / AT 20: "a neutral age screen runs
 * before any sign-in provider is called". A provider's `signIn` is invoked
 * only when the gate state is `eligible`; for `unknown` the caller must show
 * the age screen, for `ineligible` nothing is called and no account is made.
 */
export async function startSignIn(
  id: SignInProviderId,
  deps: { gate: AgeGate; providers: Readonly<Record<SignInProviderId, SignInProvider>> },
): Promise<StartSignInResult> {
  const state = await deps.gate.state();
  if (state === "ineligible") return { status: "blocked" };
  if (state !== "eligible") return { status: "age_required" };
  return { status: "signed_in", result: await deps.providers[id].signIn() };
}
