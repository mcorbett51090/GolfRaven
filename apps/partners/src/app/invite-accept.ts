/**
 * Branch E invite accept (docs/security/partner-auth-design.md 6.1 / §89): a signed-in person with an
 * existing passkey joins another org via `POST partner-invites/invites/accept` under class A2.
 *
 * The `gr_inv_` token is held in this closure only (never in AppState, never logged). Enrolment tokens
 * (`gr_enr_`) are not accepted here — recovery / admin enrolment stay on the pre-session enrol flow.
 */

import type { PartnerApi } from "../api/client";
import { acceptInvite as postAcceptInvite } from "../api/invites-routes";
import { reauthWithPasskey } from "../auth/reauth";
import type { StepUp } from "../auth/step-up";
import { StepUpError } from "../auth/step-up";
import type { GetAssertionDeps } from "../webauthn/assertion";
import { extractToken } from "./enrol-flow";
import { type ErrorContext, messageForError } from "./messages";
import type { Host, Notice, SignedInState } from "./state";

export interface InviteAcceptFlow {
  /** True when a live invite token is held for branch E. */
  hasPending(): boolean;
  /**
   * Hold a `gr_inv_` token for later accept. Returns true when held.
   * Enrolment tokens and garbage are refused (return false).
   */
  hold(raw: string): boolean;
  /** Drop the held token without calling the server. */
  dismiss(): void;
  /** Drop on page reset / session end. */
  reset(): void;
  /** Class A2: reauth + PIN, then POST invites/accept. Requires signed-in. */
  accept(): Promise<void>;
}

export interface InviteAcceptDeps {
  readonly api: PartnerApi;
  readonly host: Host;
  readonly stepUp: StepUp;
  readonly webauthn: GetAssertionDeps;
  /** Re-draw after hold/dismiss so the home join section appears/disappears. */
  readonly onPendingChange: (pending: boolean) => void;
}

function signedIn(host: Host): SignedInState | null {
  const s = host.getState();
  return s.screen === "signed-in" ? s : null;
}

function err(e: unknown, context: ErrorContext): Notice {
  if (e instanceof StepUpError) {
    if (e.kind === "cancelled") return { kind: "error", message: { key: "error.cancelled" } };
    if (e.kind === "busy") return { kind: "error", message: { key: "error.generic" } };
    return { kind: "error", message: { key: "error.generic" } };
  }
  return { kind: "error", message: messageForError(e, context) };
}

export function createInviteAccept(deps: InviteAcceptDeps): InviteAcceptFlow {
  const { api, host, stepUp, webauthn, onPendingChange } = deps;
  let token: string | null = null;

  function setPending(next: string | null): void {
    const was = token !== null;
    token = next;
    const now = token !== null;
    if (was !== now) onPendingChange(now);
  }

  return {
    hasPending() {
      return token !== null;
    },

    hold(raw) {
      const found = extractToken(raw);
      if (found === null || found.kind !== "invite") return false;
      setPending(found.token);
      return true;
    },

    dismiss() {
      if (token === null) return;
      setPending(null);
    },

    reset() {
      token = null;
    },

    async accept() {
      const s = signedIn(host);
      if (s === null || s.busy !== null || s.panel !== null || token === null) return;
      const held = token;
      const grant = s.grant;
      host.set({ ...s, busy: "work", notice: null });
      try {
        await reauthWithPasskey(api, webauthn);
        await stepUp.requirePin("A2");
        const joined = await postAcceptInvite(api, held);
        setPending(null);
        const cur = host.getState();
        if (cur.screen !== "signed-in" || cur.grant !== grant) return;
        // memberships changed: refresh whoami so roles update
        let session = cur.session;
        try {
          session = await api.session();
        } catch {
          // keep prior session; join already succeeded
        }
        const still = host.getState();
        if (still.screen !== "signed-in" || still.grant !== grant) return;
        host.set({
          ...still,
          busy: null,
          session,
          pendingInviteAccept: false,
          notice: { kind: "invite-accepted" },
        });
        // joined.orgId / role available if a future notice wants them; Edge already activated the membership
        void joined.orgId;
      } catch (e) {
        const cur = host.getState();
        if (cur.screen === "signed-in" && cur.grant === grant) {
          host.set({ ...cur, busy: null, notice: err(e, "invites") });
        }
      }
    },
  };
}
