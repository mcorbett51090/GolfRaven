/**
 * The app's state machine. DOM-free, so the whole sign-in, lock and sign-out behaviour is unit-tested without a browser; `ui/render.ts` draws
 * whatever state this holds and calls these methods, and nothing else changes state.
 *
 *   signed-out --signIn()--> signing-in --ok--> signed-in
 *        ^                        |                 |
 *        |                        +--error/cancel---+--signOut() / lock() / a 401 / forgetSession()
 *        +----------------------------------------- the API client has ALREADY wiped the token when this state is entered
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
  | { readonly screen: "signed-out"; readonly notice: Notice | null }
  | { readonly screen: "signing-in" }
  | { readonly screen: "signed-in"; readonly grant: SessionGrant; readonly session: WhoAmI; readonly busy: "refresh" | "lock" | "sign-out" | null; readonly notice: Notice | null };

export interface AppController {
  getState(): AppState;
  subscribe(listener: (state: AppState) => void): () => void;
  signIn(): Promise<void>;
  cancelSignIn(): void;
  refresh(): Promise<void>;
  signOut(): Promise<void>;
  lock(): Promise<void>;
}

export interface ControllerDeps {
  readonly api: PartnerApi;
  readonly webauthn: GetAssertionDeps;
}

const NOTICE_FOR_REASON: Record<SessionEndReason, Notice> = {
  "signed-out": { kind: "signed-out" },
  locked: { kind: "locked" },
  expired: { kind: "expired" },
  forgotten: { kind: "expired" },
};

export function createController(deps: ControllerDeps): AppController {
  const { api } = deps;
  let state: AppState = { screen: "signed-out", notice: null };
  let abort: AbortController | null = null;
  const listeners = new Set<(s: AppState) => void>();

  function set(next: AppState): void {
    state = next;
    for (const l of [...listeners]) l(state);
  }

  // Every way a session ends (sign-out, lock, a 401 anywhere, an explicit forget) arrives here AFTER the token has been wiped.
  api.onSessionEnded((reason) => {
    if (state.screen === "signed-in") set({ screen: "signed-out", notice: NOTICE_FOR_REASON[reason] });
  });

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
      abort = new AbortController();
      set({ screen: "signing-in" });
      try {
        const grant = await signInWithPasskey(api, deps.webauthn, abort.signal);
        const session = await api.session();
        set({ screen: "signed-in", grant, session, busy: null, notice: null });
      } catch (e) {
        // every failure on the way in, including a session that cannot even be read right after a successful verify, leaves no token behind
        if (api.hasSession()) api.forgetSession();
        set({ screen: "signed-out", notice: { kind: "error", message: messageForError(e, "sign-in") } });
      } finally {
        abort = null;
      }
    },

    cancelSignIn() {
      abort?.abort();
    },

    async refresh() {
      if (state.screen !== "signed-in" || state.busy !== null) return;
      const before = state;
      set({ ...before, busy: "refresh", notice: null });
      try {
        const session = await api.session();
        if (state.screen === "signed-in") set({ ...state, session, busy: null });
      } catch (e) {
        // a 401 has already moved the app to signed-out through onSessionEnded; anything else is shown and the session stays
        if (state.screen === "signed-in") set({ ...state, busy: null, notice: { kind: "error", message: messageForError(e, "session") } });
      }
    },

    async signOut() {
      if (state.screen !== "signed-in" || state.busy === "sign-out") return;
      set({ ...state, busy: "sign-out", notice: null });
      let failed = false;
      try {
        await api.signOut();
      } catch (e) {
        // an unreachable server (or a session the server already forgot) does not keep the token: the client wiped it in its `finally`
        failed = isPartnerApiError(e) && e.kind !== "unauthenticated";
      }
      if (failed) set({ screen: "signed-out", notice: { kind: "sign-out-offline" } });
      else if (state.screen === "signed-in") set({ screen: "signed-out", notice: { kind: "signed-out" } });
    },

    async lock() {
      if (state.screen !== "signed-in" || state.busy === "lock") return;
      set({ ...state, busy: "lock", notice: null });
      let failed = false;
      try {
        await api.lock();
      } catch (e) {
        failed = isPartnerApiError(e) && e.kind !== "unauthenticated";
      }
      if (failed) set({ screen: "signed-out", notice: { kind: "lock-offline" } });
      else if (state.screen === "signed-in") set({ screen: "signed-out", notice: { kind: "locked" } });
    },
  };
}
