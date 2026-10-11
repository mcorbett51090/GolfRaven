/**
 * U1 credential-add blocking interstitial (§93 / design §802): after sign-in (and after a forced first PIN),
 * unacked `GET credentials/notices` rows replace the home screen until each is acknowledged. Revoke is A2
 * (reauth + PIN) then ack; Lock / Sign out remain the only other exits.
 */

import type { PartnerApi } from "../api/client";
import {
  ackCredentialAddNotice,
  listCredentialAddNotices,
  revokeCredential as deleteCredential,
  type CredentialAddNotice,
} from "../api/members-routes";
import type { SessionGrant } from "../api/types";
import { reauthWithPasskey } from "../auth/reauth";
import type { GetAssertionDeps } from "../webauthn/assertion";
import { type ErrorContext, messageForError } from "./messages";
import type { Host, Notice, SignedInState } from "./state";
import { StepUpError, type StepUp } from "../auth/step-up";

export interface CredentialNoticeGate {
  /** When home is free (no panel), fetch unacked notices and open the first as a forced panel. */
  maybeOpen(grant: SessionGrant): Promise<void>;
  ack(): Promise<void>;
  revoke(): Promise<void>;
}

export interface CredentialNoticeDeps {
  readonly api: PartnerApi;
  readonly host: Host;
  readonly stepUp: StepUp;
  readonly webauthn: GetAssertionDeps;
}

function signedIn(host: Host): SignedInState | null {
  const s = host.getState();
  return s.screen === "signed-in" ? s : null;
}

function live(host: Host, grant: SessionGrant): SignedInState | null {
  const s = signedIn(host);
  return s !== null && s.grant === grant ? s : null;
}

function err(e: unknown, context: ErrorContext): Notice {
  if (e instanceof StepUpError) {
    if (e.kind === "cancelled") return { kind: "error", message: { key: "error.cancelled" } };
    if (e.kind === "unset") return { kind: "error", message: { key: "pin.notSet" } };
    if (e.kind === "must_change") return { kind: "error", message: { key: "pin.mustChange" } };
    if (e.kind === "locked") return { kind: "error", message: { key: "pin.locked" } };
    if (e.kind === "busy") return { kind: "error", message: { key: "error.generic" } };
    return { kind: "error", message: { key: "error.generic" } };
  }
  return { kind: "error", message: messageForError(e, context) };
}

function panelFor(notice: CredentialAddNotice, panelNotice: Notice | null = null, busy = false) {
  return {
    kind: "credential-add-notice" as const,
    notice,
    busy,
    panelNotice,
  };
}

export function createCredentialNoticeGate(deps: CredentialNoticeDeps): CredentialNoticeGate {
  const { api, host, stepUp, webauthn } = deps;

  async function showNext(grant: SessionGrant, success: Notice | null): Promise<void> {
    const s = live(host, grant);
    if (s === null) return;
    if (s.panel !== null && s.panel.kind !== "credential-add-notice") return;
    try {
      const notices = await listCredentialAddNotices(api);
      const cur = live(host, grant);
      if (cur === null) return;
      if (cur.panel !== null && cur.panel.kind !== "credential-add-notice") return;
      const first = notices[0];
      if (first === undefined) {
        // No-op when home is already clear (avoids a second signed-in emit after every sign-in).
        if (cur.panel?.kind === "credential-add-notice" || cur.busy !== null || success !== cur.notice) {
          host.set({ ...cur, busy: null, panel: null, notice: success });
        }
        return;
      }
      host.set({ ...cur, busy: null, notice: success, panel: panelFor(first) });
    } catch (e) {
      const cur = live(host, grant);
      // Fetch failure must not invent a permanent block (shop iPad offline).
      if (cur !== null) host.set({ ...cur, busy: null, panel: null, notice: err(e, "credentials") });
    }
  }

  return {
    async maybeOpen(grant) {
      const s = live(host, grant);
      if (s === null || s.panel !== null) return;
      await showNext(grant, s.notice);
    },

    async ack() {
      const s = signedIn(host);
      const panel = s?.panel;
      if (s === null || panel?.kind !== "credential-add-notice" || panel.busy) return;
      const grant = s.grant;
      const notice = panel.notice;
      host.set({ ...s, panel: panelFor(notice, null, true) });
      try {
        await ackCredentialAddNotice(api, notice.noticeId);
      } catch (e) {
        const cur = live(host, grant);
        if (cur !== null && cur.panel?.kind === "credential-add-notice") {
          host.set({ ...cur, panel: panelFor(notice, err(e, "credentials"), false) });
        }
        return;
      }
      await showNext(grant, { kind: "credential-notice-acked" });
    },

    async revoke() {
      const s = signedIn(host);
      const panel = s?.panel;
      if (s === null || panel?.kind !== "credential-add-notice" || panel.busy) return;
      if (panel.notice.credentialRevokedAt !== null) return;
      const grant = s.grant;
      const notice = panel.notice;
      // requirePin refuses when any panel is open: clear first, restore on cancel/failure.
      host.set({ ...s, panel: null, busy: "panel", notice: null });
      try {
        await reauthWithPasskey(api, webauthn);
        await stepUp.requirePin("A2");
        await deleteCredential(api, notice.credentialId);
        await ackCredentialAddNotice(api, notice.noticeId);
      } catch (e) {
        const cur = live(host, grant);
        if (cur !== null) {
          host.set({
            ...cur,
            busy: null,
            panel: panelFor(notice, err(e, "credentials"), false),
            notice: null,
          });
        }
        return;
      }
      await showNext(grant, { kind: "credential-revoked" });
    },
  };
}
