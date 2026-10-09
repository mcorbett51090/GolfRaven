/**
 * The S7b work screens: attest (online token and offline code) and course-QR (today's PIN, rotate, marker sold, printed QR).
 *
 * DOM-free. Every A1 action calls `requirePin("A1")` then the action in the same turn (design 6.3 / 24.3: the grant is single-use; nothing may sit between
 * the grant and the call). Rotate PIN is A2: passkey reauth then `requirePin("A2")` then the rotate. Printed-QR write is A3: the person must already hold
 * `aal` 2 with a fresh TOTP (`mfaUntil`); the screen refuses before calling when they do not.
 *
 * The PIN's digits never appear here: only `requirePin` touches them, behind the panel.
 */

import type { PartnerApi } from "../api/client";
import { isPartnerApiError } from "../api/errors";
import {
  getCoursePin,
  getPrintedQr,
  getShiftLog,
  getStaffActivity,
  postMintToken,
  postOfflineAttest,
  postOnlineAttest,
  postPrintedQr,
  postRefreshToken,
  postRotatePin,
  type AttestKind,
} from "../api/work-routes";
import { reauthWithPasskey } from "../auth/reauth";
import type { StepUp } from "../auth/step-up";
import { StepUpError } from "../auth/step-up";
import type { GetAssertionDeps } from "../webauthn/assertion";
import { type ErrorContext, messageForError } from "./messages";
import type { Host, Notice, SignedInState, WorkView } from "./state";

export interface WorkScreens {
  openAttest(facilityId: string): void;
  openCourseQr(facilityId: string): void;
  closeWork(): void;
  setFacility(facilityId: string): void;
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

export interface WorkDeps {
  readonly api: PartnerApi;
  readonly host: Host;
  readonly stepUp: StepUp;
  readonly webauthn: GetAssertionDeps;
}

const FACILITY_RE = /^[A-Za-z0-9_.:-]{1,128}$/;
const HANDLE_RE = /^[a-z0-9_]{3,20}$/;
const CODE_RE = /^[0-9]{6}$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function signedIn(host: Host): SignedInState | null {
  const s = host.getState();
  return s.screen === "signed-in" ? s : null;
}

function live(host: Host, grant: SignedInState["grant"]): SignedInState | null {
  const s = signedIn(host);
  return s !== null && s.grant === grant ? s : null;
}

function facilitiesOf(s: SignedInState): string[] {
  const out = new Set<string>();
  for (const m of s.session.memberships) for (const f of m.facilityIds) if (FACILITY_RE.test(f)) out.add(f);
  return [...out].sort();
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

export function createWorkScreens(deps: WorkDeps): WorkScreens {
  const { api, host, stepUp, webauthn } = deps;

  function withWork(s: SignedInState, work: WorkView | null, notice: Notice | null = null, busy: SignedInState["busy"] = null): void {
    host.set({ ...s, work, notice, busy, panel: s.panel });
  }

  async function runA1<T>(grant: SignedInState["grant"], context: ErrorContext, action: () => Promise<T>, apply: (s: SignedInState, result: T) => SignedInState): Promise<void> {
    const start = live(host, grant);
    if (start === null || start.busy !== null || start.panel !== null) return;
    host.set({ ...start, busy: "work", notice: null });
    try {
      await stepUp.requirePin("A1");
      const result = await action();
      const cur = live(host, grant);
      if (cur !== null) host.set(apply(cur, result));
    } catch (e) {
      const cur = live(host, grant);
      if (cur !== null) host.set({ ...cur, busy: null, notice: err(e, context) });
    }
  }

  return {
    openAttest(facilityId) {
      const s = signedIn(host);
      if (s === null || s.busy !== null || s.panel !== null) return;
      const facilities = facilitiesOf(s);
      const id = FACILITY_RE.test(facilityId) && facilities.includes(facilityId) ? facilityId : facilities[0];
      if (id === undefined) {
        host.set({ ...s, notice: { kind: "error", message: { key: "work.noFacility" } } });
        return;
      }
      withWork(s, { kind: "attest", facilityId: id, mode: "online", attestKind: "presence", busy: false, lastResult: null, shiftLog: null, staffActivity: null }, null);
    },

    openCourseQr(facilityId) {
      const s = signedIn(host);
      if (s === null || s.busy !== null || s.panel !== null) return;
      const facilities = facilitiesOf(s);
      const id = FACILITY_RE.test(facilityId) && facilities.includes(facilityId) ? facilityId : facilities[0];
      if (id === undefined) {
        host.set({ ...s, notice: { kind: "error", message: { key: "work.noFacility" } } });
        return;
      }
      withWork(s, { kind: "course-qr", facilityId: id, busy: false, pin: null, sale: null, refreshLeft: null, printed: null }, null);
    },

    closeWork() {
      const s = signedIn(host);
      if (s === null || s.busy !== null || s.panel !== null) return;
      withWork(s, null, null);
    },

    setFacility(facilityId) {
      const s = signedIn(host);
      if (s === null || s.work === null || s.busy !== null || s.panel !== null || !FACILITY_RE.test(facilityId)) return;
      if (s.work.kind === "attest") withWork(s, { ...s.work, facilityId, lastResult: null, shiftLog: null, staffActivity: null });
      else withWork(s, { ...s.work, facilityId, pin: null, sale: null, refreshLeft: null, printed: null });
    },

    setAttestMode(mode) {
      const s = signedIn(host);
      if (s === null || s.work?.kind !== "attest" || s.busy !== null || s.panel !== null) return;
      withWork(s, { ...s.work, mode });
    },

    setAttestKind(kind) {
      const s = signedIn(host);
      if (s === null || s.work?.kind !== "attest" || s.busy !== null || s.panel !== null) return;
      withWork(s, { ...s.work, attestKind: kind });
    },

    async submitOnlineAttest(token) {
      const s = signedIn(host);
      if (s === null || s.work?.kind !== "attest" || s.work.mode !== "online") return;
      const trimmed = token.trim();
      if (!UUID_RE.test(trimmed)) {
        host.set({ ...s, notice: { kind: "error", message: { key: "attest.tokenInvalid" } } });
        return;
      }
      const { facilityId, attestKind } = s.work;
      const grant = s.grant;
      await runA1(grant, "attest", () => postOnlineAttest(api, { facilityId, kind: attestKind, token: trimmed.toLowerCase() }), (cur, result) => {
        const work = cur.work?.kind === "attest" ? { ...cur.work, busy: false, lastResult: result } : cur.work;
        return { ...cur, busy: null, work, notice: { kind: "attest-ok" } };
      });
    },

    async submitOfflineAttest(handle, code) {
      const s = signedIn(host);
      if (s === null || s.work?.kind !== "attest" || s.work.mode !== "offline") return;
      const h = handle.trim().toLowerCase();
      if (!HANDLE_RE.test(h) || !CODE_RE.test(code)) {
        host.set({ ...s, notice: { kind: "error", message: { key: "attest.offlineInvalid" } } });
        return;
      }
      const { facilityId, attestKind } = s.work;
      const grant = s.grant;
      await runA1(grant, "attest", () => postOfflineAttest(api, { facilityId, kind: attestKind, handle: h, code }), (cur, result) => {
        const work = cur.work?.kind === "attest" ? { ...cur.work, busy: false, lastResult: result } : cur.work;
        return { ...cur, busy: null, work, notice: { kind: "attest-ok" } };
      });
    },

    async loadShiftLog() {
      const s = signedIn(host);
      if (s === null || s.work?.kind !== "attest" || s.busy !== null || s.panel !== null) return;
      const grant = s.grant;
      const facilityId = s.work.facilityId;
      host.set({ ...s, busy: "work", notice: null });
      try {
        const entries = await getShiftLog(api, facilityId);
        const cur = live(host, grant);
        if (cur !== null && cur.work?.kind === "attest") host.set({ ...cur, busy: null, work: { ...cur.work, shiftLog: entries } });
      } catch (e) {
        const cur = live(host, grant);
        if (cur !== null) host.set({ ...cur, busy: null, notice: err(e, "attest") });
      }
    },

    async loadStaffActivity(days) {
      const s = signedIn(host);
      if (s === null || s.work?.kind !== "attest" || s.busy !== null || s.panel !== null) return;
      const d = Number.isInteger(days) && days >= 1 && days <= 90 ? days : 7;
      const grant = s.grant;
      const facilityId = s.work.facilityId;
      host.set({ ...s, busy: "work", notice: null });
      try {
        const activity = await getStaffActivity(api, facilityId, d);
        const cur = live(host, grant);
        if (cur !== null && cur.work?.kind === "attest") host.set({ ...cur, busy: null, work: { ...cur.work, staffActivity: activity } });
      } catch (e) {
        const cur = live(host, grant);
        if (cur !== null) host.set({ ...cur, busy: null, notice: err(e, "attest") });
      }
    },

    async loadCoursePin() {
      const s = signedIn(host);
      if (s === null || s.work?.kind !== "course-qr" || s.busy !== null || s.panel !== null) return;
      const grant = s.grant;
      const facilityId = s.work.facilityId;
      host.set({ ...s, busy: "work", notice: null });
      try {
        const pin = await getCoursePin(api, facilityId);
        const cur = live(host, grant);
        if (cur !== null && cur.work?.kind === "course-qr") host.set({ ...cur, busy: null, work: { ...cur.work, pin } });
      } catch (e) {
        const cur = live(host, grant);
        if (cur !== null) host.set({ ...cur, busy: null, notice: err(e, "course-qr") });
      }
    },

    async rotatePin() {
      const s = signedIn(host);
      if (s === null || s.work?.kind !== "course-qr" || s.busy !== null || s.panel !== null) return;
      const grant = s.grant;
      const facilityId = s.work.facilityId;
      host.set({ ...s, busy: "work", notice: null });
      try {
        await reauthWithPasskey(api, webauthn);
        await stepUp.requirePin("A2");
        const rotated = await postRotatePin(api, facilityId);
        const pin = await getCoursePin(api, facilityId);
        const cur = live(host, grant);
        if (cur !== null && cur.work?.kind === "course-qr") {
          host.set({ ...cur, busy: null, work: { ...cur.work, pin: { ...pin, pinEpoch: rotated.pinEpoch } }, notice: { kind: "pin-rotated" } });
        }
      } catch (e) {
        const cur = live(host, grant);
        if (cur !== null) host.set({ ...cur, busy: null, notice: err(e, "course-qr") });
      }
    },

    async mintToken() {
      const s = signedIn(host);
      if (s === null || s.work?.kind !== "course-qr") return;
      const facilityId = s.work.facilityId;
      const grant = s.grant;
      await runA1(grant, "course-qr", () => postMintToken(api, facilityId), (cur, sale) => {
        const work = cur.work?.kind === "course-qr" ? { ...cur.work, busy: false, sale, refreshLeft: null } : cur.work;
        return { ...cur, busy: null, work, notice: { kind: "token-minted" } };
      });
    },

    async refreshSale() {
      const s = signedIn(host);
      if (s === null || s.work?.kind !== "course-qr" || s.work.sale === null || s.busy !== null || s.panel !== null) return;
      const grant = s.grant;
      const { facilityId, sale } = s.work;
      host.set({ ...s, busy: "work", notice: null });
      try {
        const r = await postRefreshToken(api, facilityId, sale.nonceHash);
        const cur = live(host, grant);
        if (cur !== null && cur.work?.kind === "course-qr") host.set({ ...cur, busy: null, work: { ...cur.work, refreshLeft: r.secondsLeft } });
      } catch (e) {
        const cur = live(host, grant);
        if (cur !== null) host.set({ ...cur, busy: null, notice: err(e, "course-qr") });
      }
    },

    async loadPrintedQr() {
      const s = signedIn(host);
      if (s === null || s.work?.kind !== "course-qr" || s.busy !== null || s.panel !== null) return;
      const grant = s.grant;
      const facilityId = s.work.facilityId;
      host.set({ ...s, busy: "work", notice: null });
      try {
        const printed = await getPrintedQr(api, facilityId);
        const cur = live(host, grant);
        if (cur !== null && cur.work?.kind === "course-qr") host.set({ ...cur, busy: null, work: { ...cur.work, printed } });
      } catch (e) {
        const cur = live(host, grant);
        if (cur !== null) {
          // 404 not_printed is an empty state, not an error strip
          if (isPartnerApiError(e) && (e.code === "not_printed" || e.kind === "not_found")) {
            host.set({ ...cur, busy: null, work: cur.work?.kind === "course-qr" ? { ...cur.work, printed: null } : cur.work, notice: { kind: "error", message: { key: "courseQr.notPrinted" } } });
          } else host.set({ ...cur, busy: null, notice: err(e, "course-qr") });
        }
      }
    },

    async printQr() {
      const s = signedIn(host);
      if (s === null || s.work?.kind !== "course-qr" || s.busy !== null || s.panel !== null) return;
      if (s.session.aal < s.session.requiredAal || s.session.aal < 2) {
        host.set({ ...s, notice: { kind: "error", message: { key: "courseQr.needTotp" } } });
        return;
      }
      const grant = s.grant;
      const facilityId = s.work.facilityId;
      host.set({ ...s, busy: "work", notice: null });
      try {
        const printed = await postPrintedQr(api, facilityId);
        const cur = live(host, grant);
        if (cur !== null && cur.work?.kind === "course-qr") host.set({ ...cur, busy: null, work: { ...cur.work, printed }, notice: { kind: "printed-ok" } });
      } catch (e) {
        const cur = live(host, grant);
        if (cur !== null) host.set({ ...cur, busy: null, notice: err(e, "course-qr") });
      }
    },
  };
}

/** Facility ids the signed-in person may act at (union of membership scopes), for the UI picker. */
export function facilityChoices(session: SignedInState["session"]): readonly string[] {
  const out = new Set<string>();
  for (const m of session.memberships) for (const f of m.facilityIds) if (FACILITY_RE.test(f)) out.add(f);
  return [...out].sort();
}
