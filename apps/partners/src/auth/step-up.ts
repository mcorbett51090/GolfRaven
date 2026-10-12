/**
 * Step-up by PIN (docs/security/partner-auth-design.md 6.3, 19.4). Section 6.3 puts a PIN in front of every A1 action and a PIN plus a fresh passkey in
 * front of every A2 action. The PIN is derived IN THE BROWSER and only the derived bytes are sent: the PIN never leaves the page.
 *
 *   - `StepUp.requirePin(actionClass)` resolves to a `PinGrant` once the person has typed their PIN and the server has accepted the derived value. The
 *     grant is single-use and short (60 s, 30 s for A2): the screen that asked then makes its action call, and the action's own transaction consumes it.
 *   - `createStepUp` is the real implementation. One call to `requirePin` is the whole conversation: it reads the member's PIN state (`GET pin`), asks the
 *     `PinPrompter` for the digits (the DOM prompt lives behind that interface, so this file is DOM-free and unit-tested), refuses a PIN the rules reject
 *     BEFORE deriving anything, derives with the stored salt and iteration count, and posts `{ derived }`. A wrong PIN or a back-off asks again (the server
 *     counts and locks: 5 consecutive failures); a locked, unset or must-change PIN ends the call with a `StepUpError` the screen routes on.
 *   - `unavailableStepUp` stays exported: a screen wired with it fails closed (a test of that wiring, and a safe default for a build with no prompter).
 *
 * The digits exist in this file only as the string the prompter returns, for the length of one call; they are never put in a request, a log or an error.
 */

import { isPartnerApiError } from "../api/errors";
import type { PartnerApi } from "../api/client";
import { getPinParams, postPinVerify } from "../api/session-routes";
import { deriveForVerify, PinError, type PinRejection, rejectionOf } from "./pin";

export type ActionClass = "A1" | "A2";

/** The server's acceptance of a derived PIN: a single-use grant that expires quickly (design 6.3: 60 s, or 30 s for A2). Carries no secret. */
export interface PinGrant {
  readonly actionClass: ActionClass;
  readonly expiresAt: string;
}

export interface StepUp {
  requirePin(actionClass: ActionClass, signal?: AbortSignal): Promise<PinGrant>;
}

export class StepUpUnavailable extends Error {
  constructor() {
    super("step-up is not available in this build");
    this.name = "StepUpUnavailable";
  }
}

export const unavailableStepUp: StepUp = {
  requirePin(): Promise<PinGrant> {
    return Promise.reject(new StepUpUnavailable());
  },
};

/** Why `requirePin` ended without a grant. */
export type StepUpFailure =
  /** The person closed the prompt (or the caller aborted). */
  | "cancelled"
  /** No PIN is set yet: send the person to set one. */
  | "unset"
  /** A reset made the PIN `must_change`: send the person to set a new one (it needs an email proof). */
  | "must_change"
  /** Five failures locked the PIN: a manager's reset is the only way out. */
  | "locked"
  /** The server's salt or iteration count is outside the contract (a server or deployment fault). */
  | "bad_params"
  /** Another PIN prompt is already open. */
  | "busy";

export class StepUpError extends Error {
  readonly kind: StepUpFailure;
  constructor(kind: StepUpFailure) {
    super(`step-up: ${kind}`);
    this.name = "StepUpError";
    this.kind = kind;
  }
}

/** What the last attempt of this call got, shown above the PIN field. */
export type PinProblem =
  | { readonly kind: "wrong" }
  | { readonly kind: "rejected"; readonly reason: PinRejection }
  | { readonly kind: "backoff"; readonly retryAfterSeconds: number | null };

export interface PinPromptRequest {
  readonly actionClass: ActionClass;
  /** null on the first ask of a call; the reason the previous PIN did not work on the later ones. */
  readonly problem: PinProblem | null;
  /** The back-off the server reported with the PIN's state, in seconds (0: none). */
  readonly retryAfterSeconds: number;
}

/** Asks the person for their PIN. Resolves to the four digits, or null if they cancel. The implementation owns the prompt's whole life (open, close, wipe the field). */
export interface PinPrompter {
  ask(req: PinPromptRequest, signal?: AbortSignal): Promise<string | null>;
}

export interface StepUpDeps {
  readonly api: PartnerApi;
  readonly prompter: PinPrompter;
}

export function createStepUp(deps: StepUpDeps): StepUp {
  const { api, prompter } = deps;
  return {
    async requirePin(actionClass, signal) {
      let problem: PinProblem | null = null;
      const aborted = () => signal?.aborted === true;
      for (;;) {
        if (aborted()) throw new StepUpError("cancelled");
        const params = await getPinParams(api);
        if (params.state !== "ok") throw new StepUpError(params.state);
        let pin = await prompter.ask({ actionClass, problem, retryAfterSeconds: params.retryAfterSeconds }, signal);
        if (pin === null || aborted()) throw new StepUpError("cancelled");
        let derived: string;
        try {
          derived = await deriveForVerify(pin, params);
        } catch (e) {
          if (e instanceof PinError && e.kind === "rejected") {
            // a PIN the rules refuse is not a PIN this page ever set: nothing was derived or sent, and nothing counts against the member's lockout
            problem = { kind: "rejected", reason: e.reason ?? rejectionOf(pin) ?? "format" };
            continue;
          }
          if (e instanceof PinError) throw new StepUpError("bad_params");
          throw e;
        } finally {
          pin = null;
        }
        try {
          const grant = await postPinVerify(api, derived);
          return { actionClass, expiresAt: grant.grantExpiresAt };
        } catch (e) {
          if (!isPartnerApiError(e)) throw e;
          if (e.code === "pin_wrong") problem = { kind: "wrong" };
          else if (e.code === "pin_backoff") problem = { kind: "backoff", retryAfterSeconds: e.retryAfterSeconds };
          else if (e.code === "pin_locked") throw new StepUpError("locked");
          else if (e.code === "pin_not_set") throw new StepUpError("unset");
          else if (e.code === "pin_must_change") throw new StepUpError("must_change");
          else throw e;
        }
      }
    },
  };
}
