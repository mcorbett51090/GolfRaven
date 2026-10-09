/**
 * The signed-in panels (docs/security/partner-auth-design.md 6.3, 6.4): the PIN prompt that an A1 or A2 action opens, setting and changing the PIN, the
 * email proof they may need, and the operator / admin second factor. DOM-free: the renderer draws `state.panel`, and this module is the only thing that
 * changes it.
 *
 * NOTHING SECRET IS KEPT. The digits of a PIN, an emailed code and a TOTP code arrive as arguments of one call, are derived or sent, and are dropped; the
 * state holds "which panel, busy or not, which notice". The one exception is the TOTP seed while its panel is open (it has to be shown so the person can
 * add it to an authenticator app); closing the panel, or the session ending, drops it.
 *
 * `requirePin` is the controller's `StepUp`: a screen that needs a PIN calls it and gets a `PinGrant`, with the prompt drawn and torn down for it.
 */

import type { PartnerApi } from "../api/client";
import { isPartnerApiError, PartnerApiError } from "../api/errors";
import { postTotpConfirm, postTotpEnrol, postTotpVerify } from "../api/session-routes";
import type { SessionGrant } from "../api/types";
import { PinError, rejectionOf } from "../auth/pin";
import { changePin, pinSetupMode, proofActive, setPin, startEmailProof, verifyEmailProof } from "../auth/pin-setup";
import { type ActionClass, createStepUp, type PinGrant, type PinPrompter, StepUpError } from "../auth/step-up";
import { type ErrorContext, messageForError, messageForPinRejection } from "./messages";
import type { Host, Notice, Panel, SignedInState } from "./state";

export interface PinSetupInput {
  /** The current PIN (only read when changing). */
  readonly current: string;
  readonly pin: string;
  readonly confirm: string;
}

export interface Panels {
  /** The controller's `StepUp.requirePin`: opens the PIN prompt, resolves with a grant or rejects with `StepUpError` (cancelled, unset, must_change, locked, busy ...). */
  requirePin(actionClass: ActionClass, signal?: AbortSignal): Promise<PinGrant>;
  /** The prompt's submit: hands the digits to the waiting `requirePin`. */
  submitPin(pin: string): void;
  cancelPin(): void;
  openPinSetup(): Promise<void>;
  submitPinSetup(input: PinSetupInput): Promise<void>;
  startEmailProof(): Promise<void>;
  submitEmailProof(code: string): Promise<void>;
  /** `verify`: enter the current code. `enrol`: add an authenticator (needs the email proof unless the enrolment window is open). */
  openTotp(mode: "verify" | "enrol"): Promise<void>;
  startTotpEnrol(): Promise<void>;
  submitTotp(code: string): Promise<void>;
  /** Back to the home screen. The forced first PIN of an enrolment cannot be closed (until the server refuses it for this role). */
  closePanel(): void;
  /** The session ended (or the page is going away): nothing may be left waiting for a PIN. */
  sessionEnded(): void;
}

export interface PanelDeps {
  readonly api: PartnerApi;
  readonly host: Host;
  readonly nowMs: () => number;
}

const CODE_RE = /^[0-9]{6,10}$/;
const TOTP_RE = /^[0-9]{6}$/;
const PIN_RE = /^[0-9]{4}$/;

export function createPanels(deps: PanelDeps): Panels {
  const { api, host, nowMs } = deps;
  /** The waiting `ask` of a `requirePin` call: settling it with a string submits it, with null cancels. */
  let waiting: ((pin: string | null) => void) | null = null;

  function signedIn(): SignedInState | null {
    const s = host.getState();
    return s.screen === "signed-in" ? s : null;
  }
  /** The signed-in state, only if it is still the session this operation began under (a sign-out and a new sign-in in between make it a different one). */
  function live(grant: SessionGrant): SignedInState | null {
    const s = signedIn();
    return s !== null && s.grant === grant ? s : null;
  }
  const err = (e: unknown, context: ErrorContext): Notice => ({ kind: "error", message: messageForError(e, context) });

  const prompter: PinPrompter = {
    ask(req, signal) {
      return new Promise<string | null>((resolve) => {
        const s = signedIn();
        if (s === null) {
          resolve(null);
          return;
        }
        const settle = (pin: string | null) => {
          if (waiting === settle) waiting = null;
          signal?.removeEventListener("abort", onAbort);
          resolve(pin);
        };
        const onAbort = () => settle(null);
        signal?.addEventListener("abort", onAbort, { once: true });
        waiting = settle;
        host.set({ ...s, panel: { kind: "pin-prompt", actionClass: req.actionClass, problem: req.problem, retryAfterSeconds: req.retryAfterSeconds, busy: false } });
      });
    },
  };
  const stepUp = createStepUp({ api, prompter });

  function closePromptIfOpen(): void {
    const s = signedIn();
    if (s !== null && s.panel?.kind === "pin-prompt") host.set({ ...s, panel: null });
  }

  /** The PIN-setup panel for this session, or the email proof first when the session has neither window. Throws what `GET pin` / `GET session` throw. */
  async function openSetupOrProof(grant: SessionGrant, purpose: "pin" | "totp", forcedNotice: Notice | null): Promise<void> {
    const session = await api.session();
    const mode = purpose === "pin" ? await pinSetupMode(api) : "set";
    const s = live(grant);
    if (s === null) return;
    if (mode === "locked") {
      host.set({ ...s, session, busy: null, panel: null, notice: err(new PartnerApiError("forbidden", { status: 403, code: "pin_locked" }), "pin") });
      return;
    }
    if (proofActive(session, nowMs())) {
      const panel: Panel = purpose === "pin" ? { kind: "pin-setup", mode, forced: false, busy: false, notice: forcedNotice, canSkip: false } : { kind: "totp", step: "enrol-start", enrolment: null, busy: false, notice: forcedNotice };
      host.set({ ...s, session, busy: null, panel });
    } else {
      host.set({ ...s, session, busy: null, panel: { kind: "email-proof", step: "send", purpose, busy: false, notice: forcedNotice } });
    }
  }

  return {
    async requirePin(actionClass, signal) {
      const s = signedIn();
      if (s === null) throw new PartnerApiError("unauthenticated");
      if (s.panel !== null || waiting !== null) throw new StepUpError("busy");
      try {
        return await stepUp.requirePin(actionClass, signal);
      } finally {
        closePromptIfOpen();
      }
    },

    submitPin(pin) {
      const s = signedIn();
      const settle = waiting;
      if (s === null || settle === null || s.panel?.kind !== "pin-prompt" || s.panel.busy) return;
      host.set({ ...s, panel: { ...s.panel, busy: true } });
      settle(pin);
    },

    cancelPin() {
      waiting?.(null);
    },

    async openPinSetup() {
      const s = signedIn();
      if (s === null || s.busy !== null || s.panel !== null) return;
      const grant = s.grant;
      host.set({ ...s, busy: "panel", notice: null });
      try {
        await openSetupOrProof(grant, "pin", null);
      } catch (e) {
        const cur = live(grant);
        if (cur !== null) host.set({ ...cur, busy: null, notice: err(e, "pin") });
      }
    },

    async submitPinSetup(input) {
      const s = signedIn();
      const panel = s?.panel;
      if (s === null || panel?.kind !== "pin-setup" || panel.busy) return;
      const grant = s.grant;
      const show = (patch: Partial<Extract<Panel, { kind: "pin-setup" }>>) => {
        const cur = live(grant);
        if (cur !== null && cur.panel?.kind === "pin-setup") host.set({ ...cur, panel: { ...cur.panel, ...patch } });
      };
      const refuse = (key: "pin.mismatch" | "pin.currentInvalid"): void => show({ notice: { kind: "error", message: { key } } });
      if (input.pin !== input.confirm) return refuse("pin.mismatch");
      if (panel.mode === "change" && !PIN_RE.test(input.current)) return refuse("pin.currentInvalid");
      const reason = rejectionOf(input.pin);
      if (reason !== null) {
        show({ notice: { kind: "error", message: messageForPinRejection(reason) } });
        return;
      }
      show({ busy: true, notice: null });
      try {
        if (panel.mode === "set") await setPin(api, input.pin);
        else await changePin(api, input.current, input.pin);
      } catch (e) {
        if (e instanceof PinError) {
          show({ busy: false, notice: e.kind === "rejected" && e.reason !== null ? { kind: "error", message: messageForPinRejection(e.reason) } : err(e, "pin") });
          return;
        }
        if (isPartnerApiError(e)) {
          // 403 with no pin_* code: the session has neither the enrolment window nor an email proof (it lapsed): prove the mailbox, then set
          if (e.kind === "forbidden" && e.code === "forbidden" && !panel.forced) {
            const cur = live(grant);
            if (cur !== null) host.set({ ...cur, panel: { kind: "email-proof", step: "send", purpose: "pin", busy: false, notice: err(e, "pin") } });
            return;
          }
          if (e.kind === "conflict" && e.code === "pin_already_set") return show({ mode: "change", busy: false, notice: err(e, "pin") });
          if (e.kind === "conflict" && e.code === "pin_must_change") return show({ mode: "set", busy: false, notice: err(e, "pin") });
          // the server will not give THIS person a PIN (an operator or admin has none) or already has one: the forced first PIN may then be left
          const refused = e.kind === "forbidden" || e.kind === "conflict";
          show({ busy: false, notice: err(e, "pin"), ...(panel.forced && refused ? { canSkip: true } : {}) });
          return;
        }
        show({ busy: false, notice: err(e, "pin") });
        return;
      }
      const cur = live(grant);
      if (cur === null) return;
      let session = cur.session;
      try {
        session = await api.session();
      } catch {
        // the PIN is saved either way; the next refresh shows the rest
      }
      const after = live(grant);
      if (after !== null) host.set({ ...after, session, panel: null, notice: { kind: panel.mode === "set" ? "pin-set" : "pin-changed" } });
    },

    async startEmailProof() {
      const s = signedIn();
      const panel = s?.panel;
      if (s === null || panel?.kind !== "email-proof" || panel.busy || panel.step !== "send") return;
      const grant = s.grant;
      const show = (patch: Partial<Extract<Panel, { kind: "email-proof" }>>) => {
        const cur = live(grant);
        if (cur !== null && cur.panel?.kind === "email-proof") host.set({ ...cur, panel: { ...cur.panel, ...patch } });
      };
      show({ busy: true, notice: null });
      try {
        await startEmailProof(api);
        show({ step: "code", busy: false, notice: { kind: "enrol-code-sent" } });
      } catch (e) {
        show({ busy: false, notice: err(e, "proof") });
      }
    },

    async submitEmailProof(code) {
      const s = signedIn();
      const panel = s?.panel;
      if (s === null || panel?.kind !== "email-proof" || panel.busy || panel.step !== "code") return;
      const grant = s.grant;
      const show = (patch: Partial<Extract<Panel, { kind: "email-proof" }>>) => {
        const cur = live(grant);
        if (cur !== null && cur.panel?.kind === "email-proof") host.set({ ...cur, panel: { ...cur.panel, ...patch } });
      };
      const clean = code.trim();
      if (!CODE_RE.test(clean)) {
        show({ notice: { kind: "error", message: { key: "enrol.codeInvalid" } } });
        return;
      }
      show({ busy: true, notice: null });
      try {
        await verifyEmailProof(api, clean);
        // the proof is on the session: go on to what it was for
        await openSetupOrProof(grant, panel.purpose, null);
      } catch (e) {
        show({ busy: false, notice: err(e, "proof") });
      }
    },

    async openTotp(mode) {
      const s = signedIn();
      if (s === null || s.busy !== null || s.panel !== null) return;
      const grant = s.grant;
      if (mode === "verify") {
        host.set({ ...s, notice: null, panel: { kind: "totp", step: "verify", enrolment: null, busy: false, notice: null } });
        return;
      }
      host.set({ ...s, busy: "panel", notice: null });
      try {
        await openSetupOrProof(grant, "totp", null);
      } catch (e) {
        const cur = live(grant);
        if (cur !== null) host.set({ ...cur, busy: null, notice: err(e, "totp") });
      }
    },

    async startTotpEnrol() {
      const s = signedIn();
      const panel = s?.panel;
      if (s === null || panel?.kind !== "totp" || panel.busy || panel.step !== "enrol-start") return;
      const grant = s.grant;
      const show = (patch: Partial<Extract<Panel, { kind: "totp" }>>) => {
        const cur = live(grant);
        if (cur !== null && cur.panel?.kind === "totp") host.set({ ...cur, panel: { ...cur.panel, ...patch } });
      };
      show({ busy: true, notice: null });
      try {
        const enrolment = await postTotpEnrol(api);
        show({ step: "enrol-confirm", enrolment, busy: false, notice: null });
      } catch (e) {
        if (isPartnerApiError(e) && e.kind === "forbidden" && e.code === "forbidden") {
          const cur = live(grant);
          if (cur !== null) host.set({ ...cur, panel: { kind: "email-proof", step: "send", purpose: "totp", busy: false, notice: err(e, "totp") } });
          return;
        }
        show({ busy: false, notice: err(e, "totp") });
      }
    },

    async submitTotp(code) {
      const s = signedIn();
      const panel = s?.panel;
      if (s === null || panel?.kind !== "totp" || panel.busy || panel.step === "enrol-start") return;
      const grant = s.grant;
      const show = (patch: Partial<Extract<Panel, { kind: "totp" }>>) => {
        const cur = live(grant);
        if (cur !== null && cur.panel?.kind === "totp") host.set({ ...cur, panel: { ...cur.panel, ...patch } });
      };
      const clean = code.trim();
      if (!TOTP_RE.test(clean)) {
        show({ notice: { kind: "error", message: { key: "totp.codeInvalid" } } });
        return;
      }
      show({ busy: true, notice: null });
      try {
        if (panel.step === "enrol-confirm") {
          await postTotpConfirm(api, clean);
          show({ step: "verify", enrolment: null, busy: false, notice: { kind: "totp-confirmed" } });
          return;
        }
        await postTotpVerify(api, clean);
      } catch (e) {
        show({ busy: false, notice: err(e, "totp") });
        return;
      }
      const cur = live(grant);
      if (cur === null) return;
      let session = cur.session;
      try {
        session = await api.session();
      } catch {
        // the second factor is accepted either way; the next refresh shows the new level
      }
      const after = live(grant);
      if (after !== null) host.set({ ...after, session, panel: null, notice: { kind: "totp-verified" } });
    },

    closePanel() {
      const s = signedIn();
      if (s === null || s.panel === null) return;
      if (s.panel.kind === "pin-prompt") {
        waiting?.(null);
        return;
      }
      if (s.panel.kind === "pin-setup" && s.panel.forced && !s.panel.canSkip) return;
      if (s.panel.busy) return;
      host.set({ ...s, panel: null });
    },

    sessionEnded() {
      waiting?.(null);
    },
  };
}
