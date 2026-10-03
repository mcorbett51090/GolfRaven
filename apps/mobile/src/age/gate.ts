/**
 * The neutral age screen (build plan §7.8 "Health data … minimum age 16+",
 * O18 DECIDED 2026-09-23, pending counsel L7; P4 AT 20).
 *
 * - Asks for a BIRTH YEAR only, and the screen never says what the cutoff is.
 * - Runs BEFORE any sign-in provider is called (`signin/start.ts` enforces
 *   it: a provider is unreachable unless this gate says `eligible`).
 * - Under the minimum: no account is created and ONLY a device-local "not
 *   eligible" flag is kept, so an immediate retry with another year is
 *   refused on that install `[inference: a common neutral-age-gate practice]`.
 *   The flag lives in the SECURE STORE (Keychain / Keystore), written with a `…ThisDeviceOnly` accessibility class, so it is excluded from
 *   iCloud/iTunes backups and device migration on iOS (`age/secure-flags.ts`, `secure/expo-secure-store.ts`; a flag the old SQLite file held is
 *   moved across once and deleted from SQLite). Android backup is OFF (`android.allowBackup: false` in app.json, asserted by
 *   `test/policy.test.ts`). An uninstall removes it on Android and (Keychain items survive an uninstall on iOS
 *   `[iOS Keychain-survives-reinstall: from the Keychain's documented behaviour, not observed on a device]`, which only strengthens
 *   the "on that install" retry refusal). Account deletion keeps the flag on purpose (`account/delete.ts`).
 *   `[unverified: never run on a device; Android 12+ device-to-device transfer also unverified]`
 * - The birth year itself is never stored or sent.
 * - `minAge` is NOT a constant here: it comes from the server policy
 *   (`MIN_AGE`, "one server constant, so counsel can raise it without a
 *   release", §7.8). `DEFAULT_MIN_AGE` is only the offline fallback.
 *
 * **Year-only boundary — an open decision, taken conservatively.** A birth
 * year alone cannot say whether someone born `currentYear - minAge` has had
 * their birthday. This gate treats that cohort as NOT eligible (it only
 * admits someone who is certainly at least `minAge`), because the harm to
 * avoid is admitting a minor and the cost is that some people who are
 * exactly `minAge` are told to try again in a year. Asking for the month
 * would remove the ambiguity but would hint at the cutoff, which §7.8
 * rules out. `[owner/counsel L7 decision: keep, or admit the boundary cohort]`
 */
import type { DeviceFlagStore } from "./flags";

export const DEFAULT_MIN_AGE = 16;
/** Oldest birth year the form accepts; anything earlier is a typo. */
export const EARLIEST_BIRTH_YEAR = 1900;

export type BirthYearVerdict = "eligible" | "ineligible" | "invalid";

export function evaluateBirthYear(birthYear: number, currentYear: number, minAge: number): BirthYearVerdict {
  if (!Number.isInteger(birthYear) || birthYear < EARLIEST_BIRTH_YEAR || birthYear > currentYear) return "invalid";
  // Youngest possible age this calendar year is (currentYear - birthYear - 1).
  return currentYear - birthYear - 1 >= minAge ? "eligible" : "ineligible";
}

export type AgeGateState = "unknown" | "eligible" | "ineligible";

export type SubmitResult =
  | { status: "eligible" }
  | { status: "ineligible" } // newly under the minimum; flag now set
  | { status: "blocked" } // already ineligible on this install: no retry
  | { status: "invalid" }; // not a plausible year; nothing recorded

/** The key the gate keeps its verdict under, in whichever `DeviceFlagStore` it is given (the secure store in the app). */
export const AGE_FLAG_KEY = "age_gate";
const FLAG = AGE_FLAG_KEY;

export class AgeGate {
  constructor(
    private readonly flags: DeviceFlagStore,
    private readonly now: () => Date = () => new Date(),
  ) {}

  async state(): Promise<AgeGateState> {
    const v = await this.flags.get(FLAG);
    return v === "eligible" || v === "ineligible" ? v : "unknown";
  }

  async submitBirthYear(birthYear: number, minAge: number): Promise<SubmitResult> {
    if ((await this.state()) === "ineligible") return { status: "blocked" };
    const verdict = evaluateBirthYear(birthYear, this.now().getUTCFullYear(), minAge);
    if (verdict === "invalid") return { status: "invalid" };
    await this.flags.set(FLAG, verdict);
    return { status: verdict };
  }
}
