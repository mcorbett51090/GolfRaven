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
 *   - on `visibilitychange` to visible, the wall-clock time since it went hidden is compared with the limit. This is the path that is reliable: it needs no
 *     timer to have run. `Date.now()` is used because a frozen page's monotonic clock may not advance while the wall clock does;
 *   - a timer set when the page went hidden locks it the moment the limit passes, if the page is still running. Best effort, and the only one that can act
 *     while the page is still hidden (so the revoke can reach the server before the device sleeps).
 *
 * Only continuous hidden time counts: a visible page is never locked by this (that is the server's idle expiry), and two short hides do not add up.
 * What it does in each state: signed in, lock; signing in, nothing for a short hide and Cancel (a session already opened is revoked) for a long one;
 * anything else (signed out, an enrolment in progress), nothing. The decision and the reasoning: docs/security/partner-auth-design.md, the auto-lock section.
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
  /** Default: `setTimeout`. Injected for tests. */
  readonly setTimer?: (fn: () => void, ms: number) => unknown;
  /** Default: `clearTimeout`. Injected for tests. */
  readonly clearTimer?: (handle: unknown) => void;
}

export function installAutoLock(controller: AppController, deps: AutoLockDeps): void {
  const doc = deps.document;
  const now = deps.nowMs ?? (() => Date.now());
  const setTimer = deps.setTimer ?? ((fn: () => void, ms: number): unknown => setTimeout(fn, ms));
  const clearTimer = deps.clearTimer ?? ((handle: unknown): void => clearTimeout(handle as ReturnType<typeof setTimeout>));
  /** When the current hidden stretch began; null while the page is visible (or before the first `hidden`). */
  let hiddenAt: number | null = null;
  let timer: unknown = null;

  /** The page has been away long enough. `stillHidden`: this runs from the timer, so the page may be about to be frozen and the revoke must be able to outlive it. */
  function awayTooLong(stillHidden: boolean): void {
    const screen = controller.getState().screen;
    if (screen === "signed-in") void controller.lock({ away: true, keepalive: stillHidden });
    else if (screen === "signing-in") controller.cancelSignIn(); // the same as pressing Cancel: the screen leaves signing-in now, a session already opened is revoked
    // signed-out, or the enrolment screens: nothing holds a session, so there is nothing to lock
  }

  function stopTimer(): void {
    if (timer !== null) clearTimer(timer);
    timer = null;
  }

  doc.addEventListener("visibilitychange", () => {
    if (doc.visibilityState === "hidden") {
      if (hiddenAt !== null) return; // already hidden: the stretch keeps its start (a repeated event must not buy more time)
      hiddenAt = now();
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
    const away = now() - since;
    // Fail closed: a clock that went backwards (or a value that is not a number) cannot prove the page was away for less than the limit, so it locks.
    if (!(away >= 0 && away < AUTO_LOCK_HIDDEN_MS)) awayTooLong(false);
  });
}
