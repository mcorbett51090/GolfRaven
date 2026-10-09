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
import type { AttestKind } from "../api/work-routes";
import type { SessionGrant } from "../api/types";
import { pinSetupMode } from "../auth/pin-setup";
import { signInWithPasskey } from "../auth/sign-in";
import type { StepUp } from "../auth/step-up";
import type { GetAssertionDeps } from "../webauthn/assertion";
import type { CreateCredentialDeps } from "../webauthn/registration";
import { createEnrolFlow } from "./enrol-flow";
import { messageForError } from "./messages";
import { createPanels, type PinSetupInput } from "./panels";
import type { AppState, Notice } from "./state";
import { createWorkScreens } from "./work";

export type { AppState, EnrolState, Notice, Panel, SignedInState, WorkView } from "./state";

export interface AppController extends StepUp {
  getState(): AppState;
  subscribe(listener: (state: AppState) => void): () => void;
  signIn(): Promise<void>;
  cancelSignIn(): void;
  refresh(): Promise<void>;
  signOut(): Promise<void>;
  lock(): Promise<void>;
  /** The page went away (pagehide) or came back from the back/forward cache (pageshow persisted): signed-out, nothing held, no matter what the state was. */
  reset(opts?: { keepalive?: boolean }): void;

  /** Invite and enrolment acceptance (pre-session; see enrol-flow.ts). `startEnrol({ token })` is what an invite link calls. */
  startEnrol(opts?: { token?: string }): void;
  cancelEnrol(): void;
  requestEnrolCode(pasted?: string): Promise<void>;
  submitEnrolCode(code: string): Promise<void>;
  createPasskey(): Promise<void>;

  /** The PIN prompt (`requirePin` opens it) and the PIN, email-proof and second-factor panels (see panels.ts). */
  submitPin(pin: string): void;
  cancelPin(): void;
  openPinSetup(): Promise<void>;
  submitPinSetup(input: PinSetupInput): Promise<void>;
  startEmailProof(): Promise<void>;
  submitEmailProof(code: string): Promise<void>;
  openTotp(mode: "verify" | "enrol"): Promise<void>;
  startTotpEnrol(): Promise<void>;
  submitTotp(code: string): Promise<void>;
  closePanel(): void;

  /** S7b work screens (attest and course-QR; see work.ts). */
  openAttest(facilityId: string): void;
  openCourseQr(facilityId: string): void;
  closeWork(): void;
  setWorkFacility(facilityId: string): void;
  setAttestMode(mode: "online" | "offline"): void;
  setAttestKind(kind: AttestKind): void;
  submitOnlineAttest(token: string): Promise<void>;
  submitOfflineAttest(handle: string, code: string): Promise<void>;
  loadShiftLog(): Promise<void>;
  loadStaffActivity(days: number): Promise<void>;
  loadCoursePin(): Promise<void>;
  rotatePin(): Promise<void>;
  mintToken(): Promise<void>;
  refreshSale(): Promise<void>;
  loadPrintedQr(): Promise<void>;
  printQr(): Promise<void>;
}

export interface ControllerWebAuthn {
  /** `navigator.credentials`: sign-in needs `get`, an enrolment needs `create`. */
  readonly credentials: (Pick<CredentialsContainer, "get"> & Partial<Pick<CredentialsContainer, "create">>) | undefined;
  readonly supported?: boolean;
}

export interface ControllerDeps {
  readonly api: PartnerApi;
  readonly webauthn: ControllerWebAuthn;
  /** Injected for tests. */
  readonly nowMs?: () => number;
}

function assertionDeps(w: ControllerWebAuthn): GetAssertionDeps {
  return w.supported === undefined ? { credentials: w.credentials } : { credentials: w.credentials, supported: w.supported };
}

function creationDeps(w: ControllerWebAuthn): CreateCredentialDeps {
  const c = w.credentials;
  const credentials = c?.create === undefined ? undefined : { create: c.create.bind(c) };
  return w.supported === undefined ? { credentials } : { credentials, supported: w.supported };
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
  const host = {
    getState: () => state,
    set: (next: AppState) => set(next),
  };
  const panels = createPanels({ api, host, nowMs });
  const work = createWorkScreens({ api, host, stepUp: panels, webauthn: assertionDeps(deps.webauthn) });
  const enrol = createEnrolFlow({
    api,
    webauthn: creationDeps(deps.webauthn),
    host,
    // the first session is open: show it, and ask for the first PIN before anything else (design 6.1 step 5). A person who already has one (a recovery) goes home.
    async onSession(grant: SessionGrant, signal: AbortSignal) {
      const session = await api.session(signal);
      let mode: "set" | "change" | "locked" = "set";
      try {
        mode = await pinSetupMode(api);
      } catch {
        // unknown: ask for a PIN, the safe side
      }
      const panel = mode === "set" ? ({ kind: "pin-setup", mode: "set", forced: true, canSkip: false, busy: false, notice: null } as const) : null;
      set({ screen: "signed-in", grant, session, busy: null, notice: null, panel, work: null });
    },
  });
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
    panels.sessionEnded();
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
        const grant = await signInWithPasskey(api, assertionDeps(deps.webauthn), mine.signal);
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
        set({ screen: "signed-in", grant, session, busy: null, notice: null, panel: null, work: null });
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

    startEnrol: (opts) => enrol.start(opts),
    cancelEnrol: () => enrol.cancel(),
    requestEnrolCode: (pasted) => enrol.requestCode(pasted),
    submitEnrolCode: (code) => enrol.submitCode(code),
    createPasskey: () => enrol.createPasskey(),

    requirePin: (actionClass, signal) => panels.requirePin(actionClass, signal),
    submitPin: (pin) => panels.submitPin(pin),
    cancelPin: () => panels.cancelPin(),
    openPinSetup: () => panels.openPinSetup(),
    submitPinSetup: (input) => panels.submitPinSetup(input),
    startEmailProof: () => panels.startEmailProof(),
    submitEmailProof: (code) => panels.submitEmailProof(code),
    openTotp: (mode) => panels.openTotp(mode),
    startTotpEnrol: () => panels.startTotpEnrol(),
    submitTotp: (code) => panels.submitTotp(code),
    closePanel: () => panels.closePanel(),

    openAttest: (facilityId) => work.openAttest(facilityId),
    openCourseQr: (facilityId) => work.openCourseQr(facilityId),
    closeWork: () => work.closeWork(),
    setWorkFacility: (facilityId) => work.setFacility(facilityId),
    setAttestMode: (mode) => work.setAttestMode(mode),
    setAttestKind: (kind) => work.setAttestKind(kind),
    submitOnlineAttest: (token) => work.submitOnlineAttest(token),
    submitOfflineAttest: (handle, code) => work.submitOfflineAttest(handle, code),
    loadShiftLog: () => work.loadShiftLog(),
    loadStaffActivity: (days) => work.loadStaffActivity(days),
    loadCoursePin: () => work.loadCoursePin(),
    rotatePin: () => work.rotatePin(),
    mintToken: () => work.mintToken(),
    refreshSale: () => work.refreshSale(),
    loadPrintedQr: () => work.loadPrintedQr(),
    printQr: () => work.printQr(),

    signOut: () => end(() => api.signOut(), "sign-out-offline", "signed-out"),

    lock: () => end(() => api.lock(), "lock-offline", "locked"),

    reset(opts = {}) {
      abort?.abort();
      abort = null;
      enrol.reset();
      panels.sessionEnded();
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
