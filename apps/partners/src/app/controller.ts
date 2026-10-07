/**
 * The app's state machine. DOM-free, so the whole sign-in, lock and sign-out behaviour is unit-tested without a browser; `ui/render.ts` draws
 * whatever state this holds and calls these methods, and nothing else changes state.
 *
 *   signed-out --signIn()--> signing-in --ok--> signed-in
 *        ^                        |                 |
 *        |                        +--error/cancel---+--signOut() / lock() / a 401 / forgetSession() / reset()
 *        +----------------------------------------- the API client has ALREADY wiped the token when this state is entered
 *
 * Lock and sign-out take effect AT ONCE: the client wipes the token and notifies before it sends anything, so the screen is signed-out while the
 * revoking request is still on the wire (and stays so if it never answers). The request's outcome only decides whether an honest "the server could
 * not be told" notice replaces the plain one. Lock and sign-out are never disabled by a busy refresh.
 *
 * State lives in memory only. A reload is a fresh `signed-out` (design 4.6: a reload needs a fresh passkey tap). The session token is not here at all:
 * it is inside the API client's closure, and this module never receives it.
 */

import type { PartnerApi, SessionEndReason } from "../api/client";
import { isPartnerApiError } from "../api/errors";
import type { SessionGrant, WhoAmI } from "../api/types";
import { signInWithPasskey } from "../auth/sign-in";
import type { GetAssertionDeps } from "../webauthn/assertion";
import { messageForError, type UiMessage } from "./messages";

export type Notice =
  | { readonly kind: "locked" | "signed-out" | "expired" | "sign-out-offline" | "lock-offline" }
  | { readonly kind: "error"; readonly message: UiMessage };

export type AppState =
  /** `retryUntilMs`: after a 429 with a readable Retry-After, the sign-in button stays disabled until this time (epoch ms). */
  | { readonly screen: "signed-out"; readonly notice: Notice | null; readonly retryUntilMs?: number }
  | { readonly screen: "signing-in" }
  | { readonly screen: "signed-in"; readonly grant: SessionGrant; readonly session: WhoAmI; readonly busy: "refresh" | null; readonly notice: Notice | null };

export interface AppController {
  getState(): AppState;
  subscribe(listener: (state: AppState) => void): () => void;
  signIn(): Promise<void>;
  cancelSignIn(): void;
  refresh(): Promise<void>;
  signOut(): Promise<void>;
  lock(): Promise<void>;
  /** The page went away (pagehide) or came back from the back/forward cache (pageshow persisted): signed-out, nothing held, no matter what the state was. */
  reset(opts?: { keepalive?: boolean }): void;
}

export interface ControllerDeps {
  readonly api: PartnerApi;
  readonly webauthn: GetAssertionDeps;
  /** Injected for tests. */
  readonly nowMs?: () => number;
}

const NOTICE_FOR_REASON: Record<SessionEndReason, Notice> = {
  "signed-out": { kind: "signed-out" },
  locked: { kind: "locked" },
  expired: { kind: "expired" },
  forgotten: { kind: "expired" },
};

const CANCELLED: Notice = { kind: "error", message: { key: "error.cancelled" } };
/** A Retry-After longer than a day is not honoured as a button lock (and `setTimeout` overflows near 25 days). */
const MAX_RETRY_LOCK_SECONDS = 86_400;

export function createController(deps: ControllerDeps): AppController {
  const { api } = deps;
  const nowMs = deps.nowMs ?? (() => Date.now());
  let state: AppState = { screen: "signed-out", notice: null };
  /** The sign-in in progress; null when none, or once it was cancelled (the flow then drops whatever it produces). */
  let abort: AbortController | null = null;
  let retryTimer: ReturnType<typeof setTimeout> | null = null;
  const listeners = new Set<(s: AppState) => void>();

  function set(next: AppState): void {
    state = next;
    for (const l of [...listeners]) l(state);
  }

  function clearRetryTimer(): void {
    if (retryTimer !== null) clearTimeout(retryTimer);
    retryTimer = null;
  }

  // Every way a session ends (sign-out, lock, a 401 anywhere, an explicit forget) arrives here AFTER the token has been wiped.
  api.onSessionEnded((reason) => {
    if (state.screen === "signed-in") set({ screen: "signed-out", notice: NOTICE_FOR_REASON[reason] });
  });

  /** After a 429 the sign-in button is disabled for the server's Retry-After. */
  function lockSignInFor(seconds: number | null): { retryUntilMs?: number } {
    clearRetryTimer();
    if (seconds === null || seconds <= 0) return {};
    const secs = Math.min(seconds, MAX_RETRY_LOCK_SECONDS);
    const until = nowMs() + secs * 1000;
    retryTimer = setTimeout(() => {
      retryTimer = null;
      if (state.screen === "signed-out" && state.retryUntilMs === until) set({ screen: "signed-out", notice: state.notice });
    }, secs * 1000);
    return { retryUntilMs: until };
  }

  /** The end of a lock or sign-out request: the screen is ALREADY signed-out; a failed request only changes the wording, and only if nothing newer happened. */
  function endedWith(failed: boolean, offline: Notice["kind"], plain: Notice["kind"]): void {
    if (!failed || state.screen !== "signed-out" || state.notice?.kind !== plain) return;
    set({ screen: "signed-out", notice: { kind: offline } as Notice });
  }

  async function end(op: () => Promise<void>, offline: Notice["kind"], plain: Notice["kind"]): Promise<void> {
    if (state.screen !== "signed-in") return;
    let failed = false;
    // `op` wipes the token and notifies BEFORE it sends (client.ts): the listener above has moved the screen to signed-out by the time it returns its promise
    const pending = op();
    if (state.screen === "signed-in") set({ screen: "signed-out", notice: { kind: plain } as Notice });
    try {
      await pending;
    } catch (e) {
      // an unreachable server (or a session the server already forgot) does not keep the token: the client wiped it before sending
      failed = isPartnerApiError(e) && e.kind !== "unauthenticated";
    }
    endedWith(failed, offline, plain);
  }

  return {
    getState: () => state,

    subscribe(listener) {
      listeners.add(listener);
      return () => {
        listeners.delete(listener);
      };
    },

    async signIn() {
      if (state.screen !== "signed-out") return;
      if (state.retryUntilMs !== undefined && nowMs() < state.retryUntilMs) return;
      clearRetryTimer();
      const mine = new AbortController();
      abort = mine;
      const live = () => abort === mine;
      set({ screen: "signing-in" });
      try {
        // verify() holds no token for a sign-in that was cancelled while it was on the wire (it revokes the session it just opened instead)
        const grant = await signInWithPasskey(api, deps.webauthn, mine.signal);
        if (!live()) {
          await dropSession();
          return;
        }
        const session = await api.session(mine.signal);
        if (!live()) {
          await dropSession();
          return;
        }
        abort = null;
        set({ screen: "signed-in", grant, session, busy: null, notice: null });
      } catch (e) {
        if (!live()) {
          // cancelled: cancelSignIn() already showed signed-out; make sure nothing is held
          await dropSession();
          return;
        }
        abort = null;
        // every failure on the way in, including a session that cannot even be read right after a successful verify, leaves no token behind: it is
        // wiped at once and the server is told (best effort) so the session it opened does not linger until its idle expiry
        const revoking = dropSession();
        const lock = isPartnerApiError(e) && e.kind === "rate_limited" ? lockSignInFor(e.retryAfterSeconds) : {};
        set({ screen: "signed-out", notice: { kind: "error", message: messageForError(e, "sign-in") }, ...lock });
        await revoking;
      }
    },

    cancelSignIn() {
      if (state.screen !== "signing-in" || abort === null) return;
      abort.abort();
      abort = null;
      // the screen leaves "signing-in" at once, whatever the request on the wire is doing; a token that already exists is revoked now, and one that is
      // still on its way is revoked on arrival (api.verify)
      void dropSession();
      set({ screen: "signed-out", notice: CANCELLED });
    },

    async refresh() {
      if (state.screen !== "signed-in" || state.busy !== null) return;
      const before = state;
      set({ ...before, busy: "refresh", notice: null });
      const stillThis = () => state.screen === "signed-in" && state.grant === before.grant;
      try {
        const session = await api.session();
        if (state.screen === "signed-in" && stillThis()) set({ ...state, session, busy: null });
      } catch (e) {
        // a 401 has already moved the app to signed-out through onSessionEnded; anything else is shown and the session stays
        if (state.screen === "signed-in" && stillThis()) set({ ...state, busy: null, notice: { kind: "error", message: messageForError(e, "session") } });
      }
    },

    signOut: () => end(() => api.signOut(), "sign-out-offline", "signed-out"),

    lock: () => end(() => api.lock(), "lock-offline", "locked"),

    reset(opts = {}) {
      abort?.abort();
      abort = null;
      clearRetryTimer();
      void dropSession(opts.keepalive === true);
      set({ screen: "signed-out", notice: { kind: "expired" } });
    },
  };

  /** Ends whatever session the client holds, best effort: the token is wiped synchronously, the server is told afterwards. */
  async function dropSession(keepalive = false): Promise<void> {
    if (!api.hasSession()) return;
    try {
      await api.signOut({ keepalive });
    } catch {
      // nothing is held any more; the server's idle timer ends the session if the request could not be sent
    }
  }
}
