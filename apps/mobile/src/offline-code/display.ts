/**
 * What the offline-code card keeps in React state, and when it must forget it (PR #44 gate NIT). Pure: no React, no clock of its own, no secure store.
 *
 * The card holds only what is DERIVED from the seed and shown anyway: the six digits, the version, the clock-offset estimate and the end of the 600 s step the digits belong to.
 * The countdown is computed from the device clock alone (`countdownSeconds`), so it needs no seed. The seed itself is read from the secure store inside `OfflineCodeManager.view()`
 * only when the digits have to be (re)computed (the screen appears, the step ends, the user resets), used there and dropped there: it never reaches a component, so it cannot sit in
 * a state hook, a React DevTools tree or a heap snapshot while the tab stays mounted (tabs do: `app/(tabs)/_layout.tsx`).
 *
 * The derived digits are dropped as soon as the card is not on screen: the tab loses focus (`mayShowCode`'s `focused`) or the app leaves the foreground (`appState` is not `active`: `inactive`
 * is the app switcher / a system sheet, `background` is gone). They are recomputed from the secure store when it comes back.
 */
import { OFFLINE_CODE_STEP_SECONDS } from "./params";
import type { ClockSkew, CodeView } from "./manager";
import { secondsToNextStep } from "./totp";

const STEP_MS = OFFLINE_CODE_STEP_SECONDS * 1000;

/** What the card keeps. No seed bytes, nothing from which they could be recovered (a TOTP code is a one-way function of the seed and the step). */
export interface ShownCode {
  /** Six digits, leading zeros kept. */
  code: string;
  seedVersion: number;
  clock: ClockSkew;
  resyncNeeded: boolean;
  /** Epoch ms at which `code` stops being the current one (the end of its step). */
  validUntilMs: number;
}

/** The end of the step `nowMs` falls in (epoch ms). */
export function stepEndMs(nowMs: number): number {
  return (Math.floor(nowMs / STEP_MS) + 1) * STEP_MS;
}

/** What the card keeps from a `view()` answer taken at `nowMs`. */
export function shownFrom(view: CodeView & { status: "ready" }, nowMs: number): ShownCode {
  return { code: view.code, seedVersion: view.seedVersion, clock: view.clock, resyncNeeded: view.resyncNeeded, validUntilMs: stepEndMs(nowMs) };
}

/** True when `shown` is no longer the code for `nowMs`: its step ended, or the device clock moved back past the start of that step (a manual clock change). The card then asks the
 * manager again. */
export function isStale(shown: ShownCode, nowMs: number): boolean {
  return nowMs >= shown.validUntilMs || nowMs < shown.validUntilMs - STEP_MS;
}

/** Whole seconds until the code changes (1 to 600), from the device clock alone. */
export function countdownSeconds(nowMs: number): number {
  return secondsToNextStep(nowMs);
}

/** React Native's `AppState`: `active`, `inactive` (iOS: the app switcher, a system sheet), `background`, or `unknown` / `extension`. Anything but `active` is "not on screen". */
export function appIsForeground(appState: string): boolean {
  return appState === "active";
}

/** The code may be kept (and shown) only while the Me tab is focused AND the app is in the foreground. */
export function mayShowCode(input: { focused: boolean; appState: string }): boolean {
  return input.focused && appIsForeground(input.appState);
}
