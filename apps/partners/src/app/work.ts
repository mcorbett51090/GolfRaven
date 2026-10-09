/**
 * The S7b/S7c work screens: attest, course-QR, stock and special-marker hand-over.
 *
 * DOM-free. Every A1 action calls `requirePin("A1")` then the action in the same turn (design 6.3 / 24.3: the grant is single-use; nothing may sit between
 * the grant and the call). Rotate PIN is A2: passkey reauth then `requirePin("A2")` then the rotate. Printed-QR write is A3: the person must already hold
 * `aal` 2 with a fresh TOTP (`mfaUntil`); the screen refuses before calling when they do not.
 *
 * The PIN's digits never appear here: only `requirePin` touches them, behind the panel. A hand-over token plaintext is held only in `work.minted` until
 * dismissed or the screen closes; it is never logged.
 */

import type { PartnerApi } from "../api/client";
import { isPartnerApiError } from "../api/errors";
import {
  getCollectQueue,
  getCoursePin,
  getPrintedQr,
  getShiftLog,
  getStaffActivity,
  getStock,
  postHandoverMint,
  postMintToken,
  postOfflineAttest,
  postOnlineAttest,
  postPrintedQr,
  postRedeem,
  postRefreshToken,
  postRotatePin,
  postStockMove,
  postVoucher,
  STOCK_MOVE_KINDS,
  type AttestKind,
  type RedeemMethod,
  type StockMoveKind,
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
  openStock(facilityId: string): void;
  openHandover(facilityId: string): void;
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
  loadStock(): Promise<void>;
  submitStockMove(trailId: string, kind: StockMoveKind, qty: number, note: string | null): Promise<void>;
  loadCollectQueue(): Promise<void>;
  setRedeemMethod(method: RedeemMethod): void;
  mintHandover(entitlementId: string): Promise<void>;
  dismissHandoverMint(): void;
  submitRedeem(entitlementId: string, credential: string): Promise<void>;
  submitVoucher(entitlementId: string): Promise<void>;
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
const HANDOVER_PREFIX = "gr_ho_";

/** Shape check without a regexp (same reason as the session token: V8 last-match retention). */
function isHandoverToken(v: string): boolean {
  if (v.length !== HANDOVER_PREFIX.length + 43 || !v.startsWith(HANDOVER_PREFIX)) return false;
  for (let i = HANDOVER_PREFIX.length; i < v.length; i += 1) {
    const c = v.charCodeAt(i);
    const ok = (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c === 45 || c === 95;
    if (!ok) return false;
  }
  return true;
}

function pickFacility(s: SignedInState, facilityId: string): string | undefined {
  const facilities = facilitiesOf(s);
  const id = FACILITY_RE.test(facilityId) && facilities.includes(facilityId) ? facilityId : facilities[0];
  return id;
}

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
      const id = pickFacility(s, facilityId);
      if (id === undefined) {
        host.set({ ...s, notice: { kind: "error", message: { key: "work.noFacility" } } });
        return;
      }
      withWork(s, { kind: "attest", facilityId: id, mode: "online", attestKind: "presence", busy: false, lastResult: null, shiftLog: null, staffActivity: null }, null);
    },

    openCourseQr(facilityId) {
      const s = signedIn(host);
      if (s === null || s.busy !== null || s.panel !== null) return;
      const id = pickFacility(s, facilityId);
      if (id === undefined) {
        host.set({ ...s, notice: { kind: "error", message: { key: "work.noFacility" } } });
        return;
      }
      withWork(s, { kind: "course-qr", facilityId: id, busy: false, pin: null, sale: null, refreshLeft: null, printed: null }, null);
    },

    openStock(facilityId) {
      const s = signedIn(host);
      if (s === null || s.busy !== null || s.panel !== null) return;
      const id = pickFacility(s, facilityId);
      if (id === undefined) {
        host.set({ ...s, notice: { kind: "error", message: { key: "work.noFacility" } } });
        return;
      }
      withWork(s, { kind: "stock", facilityId: id, busy: false, rows: null, lastOnHand: null }, null);
    },

    openHandover(facilityId) {
      const s = signedIn(host);
      if (s === null || s.busy !== null || s.panel !== null) return;
      const id = pickFacility(s, facilityId);
      if (id === undefined) {
        host.set({ ...s, notice: { kind: "error", message: { key: "work.noFacility" } } });
        return;
      }
      withWork(s, { kind: "handover", facilityId: id, busy: false, queue: null, minted: null, redeemMethod: "staff_scan", lastRedeem: null }, null);
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
      else if (s.work.kind === "course-qr") withWork(s, { ...s.work, facilityId, pin: null, sale: null, refreshLeft: null, printed: null });
      else if (s.work.kind === "stock") withWork(s, { ...s.work, facilityId, rows: null, lastOnHand: null });
      else if (s.work.kind === "handover") withWork(s, { ...s.work, facilityId, queue: null, minted: null, lastRedeem: null });
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

    async loadStock() {
      const s = signedIn(host);
      if (s === null || s.work?.kind !== "stock" || s.busy !== null || s.panel !== null) return;
      const grant = s.grant;
      const facilityId = s.work.facilityId;
      host.set({ ...s, busy: "work", notice: null });
      try {
        const rows = await getStock(api, facilityId);
        const cur = live(host, grant);
        if (cur !== null && cur.work?.kind === "stock") host.set({ ...cur, busy: null, work: { ...cur.work, rows } });
      } catch (e) {
        const cur = live(host, grant);
        if (cur !== null) host.set({ ...cur, busy: null, notice: err(e, "stock") });
      }
    },

    async submitStockMove(trailId, kind, qty, note) {
      const s = signedIn(host);
      if (s === null || s.work?.kind !== "stock") return;
      if (!FACILITY_RE.test(trailId) || !(STOCK_MOVE_KINDS as readonly string[]).includes(kind) || !Number.isSafeInteger(qty) || qty === 0) {
        host.set({ ...s, notice: { kind: "error", message: { key: "stock.moveInvalid" } } });
        return;
      }
      if (kind !== "count_adjustment" && qty < 0) {
        host.set({ ...s, notice: { kind: "error", message: { key: "stock.moveInvalid" } } });
        return;
      }
      const { facilityId } = s.work;
      const grant = s.grant;
      await runA1(
        grant,
        "stock",
        () => postStockMove(api, { facilityId, trailId, kind, qty, note }),
        (cur, result) => {
          const work = cur.work?.kind === "stock" ? { ...cur.work, busy: false, lastOnHand: result.onHand, rows: null } : cur.work;
          return { ...cur, busy: null, work, notice: { kind: "stock-moved" } };
        },
      );
    },

    async loadCollectQueue() {
      const s = signedIn(host);
      if (s === null || s.work?.kind !== "handover" || s.busy !== null || s.panel !== null) return;
      const grant = s.grant;
      const facilityId = s.work.facilityId;
      host.set({ ...s, busy: "work", notice: null });
      try {
        const queue = await getCollectQueue(api, facilityId);
        const cur = live(host, grant);
        if (cur !== null && cur.work?.kind === "handover") host.set({ ...cur, busy: null, work: { ...cur.work, queue } });
      } catch (e) {
        const cur = live(host, grant);
        if (cur !== null) host.set({ ...cur, busy: null, notice: err(e, "handover") });
      }
    },

    setRedeemMethod(method) {
      const s = signedIn(host);
      if (s === null || s.work?.kind !== "handover" || s.busy !== null || s.panel !== null) return;
      withWork(s, { ...s.work, redeemMethod: method });
    },

    async mintHandover(entitlementId) {
      const s = signedIn(host);
      if (s === null || s.work?.kind !== "handover") return;
      if (!UUID_RE.test(entitlementId)) {
        host.set({ ...s, notice: { kind: "error", message: { key: "handover.entitlementInvalid" } } });
        return;
      }
      const { facilityId } = s.work;
      const grant = s.grant;
      const id = entitlementId.toLowerCase();
      await runA1(grant, "handover", () => postHandoverMint(api, facilityId, id), (cur, minted) => {
        const work = cur.work?.kind === "handover" ? { ...cur.work, busy: false, minted } : cur.work;
        return { ...cur, busy: null, work, notice: { kind: "handover-minted" } };
      });
    },

    dismissHandoverMint() {
      const s = signedIn(host);
      if (s === null || s.work?.kind !== "handover" || s.busy !== null || s.panel !== null) return;
      withWork(s, { ...s.work, minted: null }, s.notice?.kind === "handover-minted" ? null : s.notice);
    },

    async submitRedeem(entitlementId, credential) {
      const s = signedIn(host);
      if (s === null || s.work?.kind !== "handover") return;
      if (!UUID_RE.test(entitlementId)) {
        host.set({ ...s, notice: { kind: "error", message: { key: "handover.entitlementInvalid" } } });
        return;
      }
      const method = s.work.redeemMethod;
      const cred = credential.trim();
      if (method === "staff_scan" && !UUID_RE.test(cred)) {
        host.set({ ...s, notice: { kind: "error", message: { key: "handover.credentialInvalid" } } });
        return;
      }
      if (method === "hand_over_token" && !isHandoverToken(cred)) {
        host.set({ ...s, notice: { kind: "error", message: { key: "handover.credentialInvalid" } } });
        return;
      }
      const { facilityId } = s.work;
      const grant = s.grant;
      const id = entitlementId.toLowerCase();
      const wireCred = method === "staff_scan" ? cred.toLowerCase() : cred;
      await runA1(
        grant,
        "handover",
        () => postRedeem(api, { facilityId, entitlementId: id, method, credential: wireCred }),
        (cur, lastRedeem) => {
          const work = cur.work?.kind === "handover"
            ? { ...cur.work, busy: false, lastRedeem, minted: null, queue: null }
            : cur.work;
          return { ...cur, busy: null, work, notice: { kind: "redeem-ok" } };
        },
      );
    },

    async submitVoucher(entitlementId) {
      const s = signedIn(host);
      if (s === null || s.work?.kind !== "handover") return;
      if (!UUID_RE.test(entitlementId)) {
        host.set({ ...s, notice: { kind: "error", message: { key: "handover.entitlementInvalid" } } });
        return;
      }
      const { facilityId } = s.work;
      const grant = s.grant;
      const id = entitlementId.toLowerCase();
      await runA1(grant, "handover", () => postVoucher(api, facilityId, id), (cur) => {
        const work = cur.work?.kind === "handover" ? { ...cur.work, busy: false, queue: null } : cur.work;
        return { ...cur, busy: null, work, notice: { kind: "voucher-ok" } };
      });
    },
  };
}

/** Facility ids the signed-in person may act at (union of membership scopes), for the UI picker. */
export function facilityChoices(session: SignedInState["session"]): readonly string[] {
  const out = new Set<string>();
  for (const m of session.memberships) for (const f of m.facilityIds) if (FACILITY_RE.test(f)) out.add(f);
  return [...out].sort();
}
