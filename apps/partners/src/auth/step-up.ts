/**
 * The step-up seam (docs/security/partner-auth-design.md 6.3). This file is an INTERFACE and a fail-closed placeholder, not an implementation.
 *
 * Section 6.3 puts a PIN in front of every A1 action and a PIN plus a fresh passkey in front of every A2 action. The PIN is derived IN THE BROWSER
 * (PBKDF2 with the salt and iteration count the server hands out) and only the derived value is sent: the PIN itself never leaves the page. The
 * derivation contract (the KDF parameters, the encoding of `derived`, the route that serves the salt) belongs to slice S1.3 and is not fixed yet,
 * so S7a ships only the shape a later screen programs against:
 *
 *   - `StepUp.requirePin(actionClass)` resolves to a `PinGrant` once the person has entered their PIN and the server has accepted the derived value;
 *   - `unavailableStepUp` is what the app is wired with today: every request rejects with `StepUpUnavailable`, so a screen that needs a PIN
 *     before S1.3 lands fails closed instead of sending an action without one.
 */

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
