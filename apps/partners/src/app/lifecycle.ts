/**
 * Page lifecycle (threat model: a shared shop iPad; the browser must never hold a live bearer, or show a signed-in screen, when the user believes the
 * page is gone).
 *
 * A page that is navigated away from can be kept whole in the browser's back/forward cache and restored by Back with every variable and every node
 * as it was: a signed-in screen and a live token. So:
 *
 *   - `pagehide` ends the session: the token is wiped and the listeners are told at once, then a keepalive `sign-out` (best effort: a request that
 *     is allowed to outlive the page) revokes it on the server. This runs whether or not the page is about to enter the bfcache.
 *   - `pageshow` with `persisted` (a restore from the bfcache) forces the signed-out state: nothing a restored page shows or holds is trusted.
 *
 * The page itself is also served `Cache-Control: no-store` on `/*` (scripts/lib/csp.mjs; assets detach it), which keeps HTML paths out of the HTTP
 * cache and, in Chromium, out of the bfcache; this module is the part that does not depend on the browser honouring that.
 *
 * A page that stays open but HIDDEN (another app in front, another tab, the screen locked) is not a page that was left, so neither handler above runs and
 * a signed-in page would keep its token until the server's idle expiry. `installAutoLock` closes that: after AUTO_LOCK_HIDDEN_MS hidden, the page LOCKS
 * (the same lock the Lock button does: token wiped and listeners told first, then `POST lock` revokes the session). Two paths, because a hidden page's
 * timers can be throttled or the page frozen outright (iOS suspends a backgrounded page):
 *
 *   - on `visibilitychange` to visible, the time since it went hidden is compared with the limit. This is the path that is reliable: it needs no timer to
 *     have run. TWO clocks are read, and the page locks if EITHER says the limit has passed (or if either is not a sensible number): the wall clock
 *     (`Date.now()`: it keeps counting while a frozen page's monotonic clock may stand still, e.g. device asleep) and the monotonic clock
 *     (`performance.now()`: it cannot be set, so someone who sets the device's date back into the window cannot make an awake, away device look as if it
 *     had been away briefly). A monotonic clock never runs faster than real time and a wall clock that jumps forward only locks early, which costs one
 *     passkey tap; neither can make the page lock late;
 *   - a timer set when the page went hidden locks it the moment the limit passes, if the page is still running. Best effort, and the only one that can act
 *     while the page is still hidden (so the revoke can reach the server before the device sleeps).
 *
 * Only continuous hidden time counts: a visible page is never locked by this (that is the server's idle expiry), and two short hides do not add up.
 * What it does in each state: signed in, lock; signing in, nothing for a short hide and Cancel (a session already opened is revoked) for a long one;
 * an enrolment at the passkey step, nothing for a short hide and Cancel for a long one; anything else (signed out, the earlier enrolment steps), nothing. The decision and the reasoning: docs/security/partner-auth-design.md, the auto-lock section.
 */

import type { PartnerApi } from "../api/client";
import type { AppController } from "./controller";

export interface PageEvents {
  addEventListener(type: "pagehide" | "pageshow", listener: (ev: Event) => void): void;
}

export function installPageLifecycle(target: PageEvents, api: PartnerApi, controller: AppController): void {
  target.addEventListener("pagehide", () => {
    controller.reset({ keepalive: true });
    api.forgetSession();
  });
  target.addEventListener("pageshow", (ev) => {
    if ((ev as Event & { persisted?: boolean }).persisted === true) {
      controller.reset(); // wipes, shows signed-out and revokes what the restored page was holding
      api.forgetSession(); // a no-op once reset() has run; kept so the token cannot survive a controller that did not
    }
  });
}

/** The owner's decision: a page hidden this long locks itself. Two minutes. */
export const AUTO_LOCK_HIDDEN_MS = 120_000;

/** What the auto-lock reads from `document`. */
export interface VisibilitySource {
  readonly visibilityState: string;
  addEventListener(type: "visibilitychange", listener: (ev: Event) => void): void;
}

export interface AutoLockDeps {
  /** The page's `document`. */
  readonly document: VisibilitySource;
  /** Wall-clock milliseconds. Default: `Date.now()`, looked up at call time. Injected for tests. */
  readonly nowMs?: () => number;
  /** Monotonic milliseconds. Default: `performance.now()`, looked up at call time (NaN, which locks, where there is no `performance`). Injected for tests. */
  readonly monoMs?: () => number;
  /** Default: `setTimeout`. Injected for tests. */
  readonly setTimer?: (fn: () => void, ms: number) => unknown;
  /** Default: `clearTimeout`. Injected for tests. */
  readonly clearTimer?: (handle: unknown) => void;
}

export function installAutoLock(controller: AppController, deps: AutoLockDeps): void {
  const doc = deps.document;
  const now = deps.nowMs ?? (() => Date.now());
  const mono = deps.monoMs ?? (() => (typeof performance === "undefined" ? Number.NaN : performance.now()));
  const setTimer = deps.setTimer ?? ((fn: () => void, ms: number): unknown => setTimeout(fn, ms));
  const clearTimer = deps.clearTimer ?? ((handle: unknown): void => clearTimeout(handle as ReturnType<typeof setTimeout>));
  /** When the current hidden stretch began, on the wall clock and on the monotonic clock; null while the page is visible (or before the first `hidden`). */
  let hiddenAt: number | null = null;
  let hiddenMono = Number.NaN;
  let timer: unknown = null;

  /** The page has been away long enough. `stillHidden`: this runs from the timer, so the page may be about to be frozen and the revoke must be able to outlive it. */
  function awayTooLong(stillHidden: boolean): void {
    const state = controller.getState();
    if (state.screen === "signed-in") void controller.lock({ away: true, keepalive: stillHidden });
    // the same as pressing Cancel: the screen leaves signing-in now, a session already opened is revoked (as a keepalive request when the page is hidden)
    else if (state.screen === "signing-in") controller.cancelSignIn({ keepalive: stillHidden });
    // An enrolment at the PASSKEY step holds a verified registration challenge (good for minutes): whoever picked the iPad up could press "Create passkey" and
    // be signed in as the invitee. Cancel drops the challenge and aborts a ceremony in progress, and the screen says why: the invite was accepted at the code
    // step and an acceptance is final, so the person cannot reopen the same link and needs a new one from a manager (140.8). The earlier steps hold only a
    // one-time token that still needs a code mailed to the invitee, so there is nothing for a bystander to complete.
    else if (state.screen === "enrol" && state.step === "passkey") controller.cancelEnrol({ away: true });
    // signed out, or an enrolment before the passkey step: nothing completable is held
  }

  function stopTimer(): void {
    if (timer !== null) clearTimer(timer);
    timer = null;
  }

  doc.addEventListener("visibilitychange", () => {
    if (doc.visibilityState === "hidden") {
      if (hiddenAt !== null) return; // already hidden: the stretch keeps its start (a repeated event must not buy more time)
      hiddenAt = now();
      hiddenMono = mono();
      timer = setTimer(() => {
        timer = null;
        if (hiddenAt !== null) awayTooLong(true);
      }, AUTO_LOCK_HIDDEN_MS);
      return;
    }
    stopTimer();
    const since = hiddenAt;
    hiddenAt = null;
    if (since === null) return; // visible without a preceding hidden: nothing is known about any time away
    const wallAway = now() - since;
    const monoAway = mono() - hiddenMono;
    // Fail closed, on both clocks: only an elapsed time that is a sensible number BELOW the limit on BOTH of them lets the page stay. A clock that went
    // backwards (or is not a number) cannot prove the page was away briefly, and a wall clock that someone set back into the window is outvoted by the
    // monotonic clock, which cannot be set.
    const brief = (ms: number) => ms >= 0 && ms < AUTO_LOCK_HIDDEN_MS;
    if (!(brief(wallAway) && brief(monoAway))) awayTooLong(false);
  });
}
