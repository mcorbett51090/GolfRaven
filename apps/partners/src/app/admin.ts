/**
 * The S7d/S7 manager/operator/admin screens: programme, offers, sponsorships, review queue, rollups
 * and settlement export.
 *
 * DOM-free. A0 reads call the Edge routes directly. A3 writes (upsert, approve, end, resolve, settlement
 * export) refuse on the client unless the person already holds `aal` 2 with a fresh TOTP window — the
 * same gate as printed-QR write in work.ts (design 6.3 / 31 / 33). No PIN grant is used for A3.
 * Settlement signed URLs are held only in `work.export` for display; never logged.
 */

import type {
  FacilityProgrammeUpsert,
  OfferUpsert,
  SponsorshipUpsert,
  TrailProgrammeUpsert,
} from "../api/admin-routes";
import {
  getOffers,
  getOperatorRollups,
  getProgramme,
  getReceiptCrossUserPreview,
  getReviewQueue,
  getReviewSla,
  getSponsorRollups,
  getSponsorships,
  postFacilityProgramme,
  postOffer,
  postOfferApprove,
  postOfferEnd,
  postResolveEntitlement,
  postResolveOfferCode,
  postResolveReceiptCrossUser,
  postSettlementExport,
  postSponsorship,
  postSponsorshipApprove,
  postTrailProgramme,
} from "../api/admin-routes";
import type { PartnerApi } from "../api/client";
import type { WhoAmI } from "../api/types";
import { type ErrorContext, messageForError } from "./messages";
import type { Host, Notice, SignedInState, WorkView } from "./state";

export interface AdminScreens {
  openProgramme(trailId: string): void;
  openOffers(trailId: string): void;
  openSponsorships(trailId: string): void;
  openReview(): void;
  openRollups(trailId: string): void;
  openSettlement(trailId: string): void;
  setTrail(trailId: string): void;
  setSponsorshipId(sponsorshipId: string): void;
  setSettlementMonth(month: string): void;
  loadProgramme(): Promise<void>;
  saveTrail(body: TrailProgrammeUpsert): Promise<void>;
  saveFacility(body: FacilityProgrammeUpsert): Promise<void>;
  loadOffers(): Promise<void>;
  saveOffer(body: OfferUpsert): Promise<void>;
  approveOffer(id: string): Promise<void>;
  endOffer(id: string): Promise<void>;
  loadSponsorships(): Promise<void>;
  saveSponsorship(body: SponsorshipUpsert): Promise<void>;
  approveSponsorship(id: string): Promise<void>;
  loadReview(): Promise<void>;
  loadReceiptCrossUserPreview(id: string): Promise<void>;
  resolveOfferCode(id: string, approve: boolean): Promise<void>;
  resolveEntitlement(id: string, approve: boolean): Promise<void>;
  resolveReceiptCrossUser(id: string, approve: boolean): Promise<void>;
  loadOperatorRollups(): Promise<void>;
  loadSponsorRollups(): Promise<void>;
  exportSettlement(month?: string): Promise<void>;
  dismissSettlementExport(): void;
}

export interface AdminDeps {
  readonly api: PartnerApi;
  readonly host: Host;
}

const TRAIL_RE = /^[A-Za-z0-9_.:-]{1,128}$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const MONTH_RE = /^\d{4}-\d{2}-\d{2}$/;

/** Normalize a month field to YYYY-MM-01 (type=month yields YYYY-MM; Edge accepts any day in the month). */
export function normalizeSettlementMonth(raw: string): string | null {
  const v = raw.trim();
  if (/^\d{4}-\d{2}$/.test(v)) return `${v}-01`;
  if (MONTH_RE.test(v)) return `${v.slice(0, 7)}-01`;
  return null;
}

function signedIn(host: Host): SignedInState | null {
  const s = host.getState();
  return s.screen === "signed-in" ? s : null;
}

function live(host: Host, grant: SignedInState["grant"]): SignedInState | null {
  const s = signedIn(host);
  return s !== null && s.grant === grant ? s : null;
}

function err(e: unknown, context: ErrorContext): Notice {
  return { kind: "error", message: messageForError(e, context) };
}

function withWork(host: Host, s: SignedInState, work: WorkView | null, notice: Notice | null = null, busy: SignedInState["busy"] = null): void {
  host.set({ ...s, work, notice, busy, panel: s.panel });
}

/** Operator or platform admin may open programme / offers / sponsorships / rollups (server still enforces). */
export function canOpenAdminOps(session: WhoAmI): boolean {
  if (session.isAdmin) return true;
  return session.memberships.some((m) => m.role === "operator");
}

/** Review queue is admin-only on the home surface. */
export function canOpenReview(session: WhoAmI): boolean {
  return session.isAdmin;
}

export function trailChoices(session: WhoAmI): readonly string[] {
  const out = new Set<string>();
  for (const m of session.memberships) for (const t of m.trailIds) if (TRAIL_RE.test(t)) out.add(t);
  return [...out].sort();
}

function pickTrail(s: SignedInState, trailId: string): string | undefined {
  const trails = trailChoices(s.session);
  if (TRAIL_RE.test(trailId) && (trails.length === 0 || trails.includes(trailId))) return trailId;
  return trails[0];
}

/** Same client gate as printed-QR write: aal 2 (and meeting requiredAal). Fresh MFA is the server's. */
function needA3(s: SignedInState): Notice | null {
  if (s.session.aal < s.session.requiredAal || s.session.aal < 2) {
    return { kind: "error", message: { key: "admin.needTotp" } };
  }
  return null;
}

export function createAdminScreens(deps: AdminDeps): AdminScreens {
  const { api, host } = deps;

  async function runA0(
    grant: SignedInState["grant"],
    context: ErrorContext,
    action: () => Promise<void>,
  ): Promise<void> {
    const start = live(host, grant);
    if (start === null || start.busy !== null || start.panel !== null) return;
    host.set({ ...start, busy: "work", notice: null });
    try {
      await action();
    } catch (e) {
      const cur = live(host, grant);
      if (cur !== null) host.set({ ...cur, busy: null, notice: err(e, context) });
    }
  }

  async function runA3(
    grant: SignedInState["grant"],
    context: ErrorContext,
    action: () => Promise<void>,
  ): Promise<void> {
    const start = live(host, grant);
    if (start === null || start.busy !== null || start.panel !== null) return;
    const refused = needA3(start);
    if (refused !== null) {
      host.set({ ...start, notice: refused });
      return;
    }
    host.set({ ...start, busy: "work", notice: null });
    try {
      await action();
    } catch (e) {
      const cur = live(host, grant);
      if (cur !== null) host.set({ ...cur, busy: null, notice: err(e, context) });
    }
  }

  return {
    openProgramme(trailId) {
      const s = signedIn(host);
      if (s === null || s.busy !== null || s.panel !== null || !canOpenAdminOps(s.session)) return;
      const id = pickTrail(s, trailId);
      if (id === undefined) {
        host.set({ ...s, notice: { kind: "error", message: { key: "admin.noTrail" } } });
        return;
      }
      withWork(host, s, { kind: "programme", trailId: id, busy: false, trail: null, facilities: null }, null);
    },

    openOffers(trailId) {
      const s = signedIn(host);
      if (s === null || s.busy !== null || s.panel !== null || !canOpenAdminOps(s.session)) return;
      const id = pickTrail(s, trailId);
      if (id === undefined) {
        host.set({ ...s, notice: { kind: "error", message: { key: "admin.noTrail" } } });
        return;
      }
      withWork(host, s, { kind: "offers", trailId: id, busy: false, offers: null, lastId: null }, null);
    },

    openSponsorships(trailId) {
      const s = signedIn(host);
      if (s === null || s.busy !== null || s.panel !== null || !canOpenAdminOps(s.session)) return;
      const id = pickTrail(s, trailId);
      if (id === undefined) {
        host.set({ ...s, notice: { kind: "error", message: { key: "admin.noTrail" } } });
        return;
      }
      withWork(host, s, { kind: "sponsorships", trailId: id, busy: false, sponsorships: null, lastId: null }, null);
    },

    openReview() {
      const s = signedIn(host);
      if (s === null || s.busy !== null || s.panel !== null || !canOpenReview(s.session)) return;
      withWork(host, s, { kind: "review", busy: false, items: null, sla: null, lastState: null, previews: {} }, null);
    },

    openRollups(trailId) {
      const s = signedIn(host);
      if (s === null || s.busy !== null || s.panel !== null || !canOpenAdminOps(s.session)) return;
      const id = pickTrail(s, trailId);
      if (id === undefined) {
        host.set({ ...s, notice: { kind: "error", message: { key: "admin.noTrail" } } });
        return;
      }
      withWork(host, s, { kind: "rollups", trailId: id, sponsorshipId: "", busy: false, operator: null, sponsor: null }, null);
    },

    openSettlement(trailId) {
      const s = signedIn(host);
      if (s === null || s.busy !== null || s.panel !== null || !canOpenAdminOps(s.session)) return;
      const id = pickTrail(s, trailId);
      if (id === undefined) {
        host.set({ ...s, notice: { kind: "error", message: { key: "admin.noTrail" } } });
        return;
      }
      const now = new Date();
      const month = `${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, "0")}-01`;
      withWork(host, s, { kind: "settlement", trailId: id, month, busy: false, export: null }, null);
    },

    setTrail(trailId) {
      const s = signedIn(host);
      if (s === null || s.work === null || s.busy !== null || s.panel !== null || !TRAIL_RE.test(trailId)) return;
      if (s.work.kind === "programme") withWork(host, s, { ...s.work, trailId, trail: null, facilities: null });
      else if (s.work.kind === "offers") withWork(host, s, { ...s.work, trailId, offers: null, lastId: null });
      else if (s.work.kind === "sponsorships") withWork(host, s, { ...s.work, trailId, sponsorships: null, lastId: null });
      else if (s.work.kind === "rollups") withWork(host, s, { ...s.work, trailId, operator: null });
      else if (s.work.kind === "settlement") withWork(host, s, { ...s.work, trailId, export: null });
    },

    setSponsorshipId(sponsorshipId) {
      const s = signedIn(host);
      if (s === null || s.work?.kind !== "rollups" || s.busy !== null || s.panel !== null) return;
      withWork(host, s, { ...s.work, sponsorshipId: sponsorshipId.trim(), sponsor: null });
    },

    setSettlementMonth(month) {
      const s = signedIn(host);
      if (s === null || s.work?.kind !== "settlement" || s.busy !== null || s.panel !== null) return;
      const normalized = normalizeSettlementMonth(month);
      if (normalized === null) {
        host.set({ ...s, notice: { kind: "error", message: { key: "settlement.monthInvalid" } } });
        return;
      }
      withWork(host, s, { ...s.work, month: normalized, export: null }, s.notice?.kind === "error" ? null : s.notice);
    },

    async loadProgramme() {
      const s = signedIn(host);
      if (s === null || s.work?.kind !== "programme") return;
      const grant = s.grant;
      const trailId = s.work.trailId;
      await runA0(grant, "programme", async () => {
        const { trail, facilities } = await getProgramme(api, trailId);
        const cur = live(host, grant);
        if (cur !== null && cur.work?.kind === "programme") {
          host.set({ ...cur, busy: null, work: { ...cur.work, trail, facilities } });
        }
      });
    },

    async saveTrail(body) {
      const s = signedIn(host);
      if (s === null || s.work?.kind !== "programme") return;
      const grant = s.grant;
      await runA3(grant, "programme", async () => {
        await postTrailProgramme(api, body);
        const cur = live(host, grant);
        if (cur !== null && cur.work?.kind === "programme") {
          host.set({ ...cur, busy: null, work: { ...cur.work, trail: null, facilities: null }, notice: { kind: "programme-saved" } });
        }
      });
    },

    async saveFacility(body) {
      const s = signedIn(host);
      if (s === null || s.work?.kind !== "programme") return;
      const grant = s.grant;
      await runA3(grant, "programme", async () => {
        await postFacilityProgramme(api, body);
        const cur = live(host, grant);
        if (cur !== null && cur.work?.kind === "programme") {
          host.set({ ...cur, busy: null, work: { ...cur.work, facilities: null }, notice: { kind: "programme-saved" } });
        }
      });
    },

    async loadOffers() {
      const s = signedIn(host);
      if (s === null || s.work?.kind !== "offers") return;
      const grant = s.grant;
      const trailId = s.work.trailId;
      await runA0(grant, "offers", async () => {
        const offers = await getOffers(api, trailId);
        const cur = live(host, grant);
        if (cur !== null && cur.work?.kind === "offers") host.set({ ...cur, busy: null, work: { ...cur.work, offers } });
      });
    },

    async saveOffer(body) {
      const s = signedIn(host);
      if (s === null || s.work?.kind !== "offers") return;
      const grant = s.grant;
      await runA3(grant, "offers", async () => {
        const id = await postOffer(api, body);
        const cur = live(host, grant);
        if (cur !== null && cur.work?.kind === "offers") {
          host.set({ ...cur, busy: null, work: { ...cur.work, lastId: id, offers: null }, notice: { kind: "offer-saved" } });
        }
      });
    },

    async approveOffer(id) {
      const s = signedIn(host);
      if (s === null || s.work?.kind !== "offers" || !UUID_RE.test(id)) return;
      const grant = s.grant;
      await runA3(grant, "offers", async () => {
        await postOfferApprove(api, id.toLowerCase());
        const cur = live(host, grant);
        if (cur !== null && cur.work?.kind === "offers") {
          host.set({ ...cur, busy: null, work: { ...cur.work, offers: null }, notice: { kind: "offer-approved" } });
        }
      });
    },

    async endOffer(id) {
      const s = signedIn(host);
      if (s === null || s.work?.kind !== "offers" || !UUID_RE.test(id)) return;
      const grant = s.grant;
      await runA3(grant, "offers", async () => {
        await postOfferEnd(api, id.toLowerCase());
        const cur = live(host, grant);
        if (cur !== null && cur.work?.kind === "offers") {
          host.set({ ...cur, busy: null, work: { ...cur.work, offers: null }, notice: { kind: "offer-ended" } });
        }
      });
    },

    async loadSponsorships() {
      const s = signedIn(host);
      if (s === null || s.work?.kind !== "sponsorships") return;
      const grant = s.grant;
      const trailId = s.work.trailId;
      await runA0(grant, "sponsorships", async () => {
        const sponsorships = await getSponsorships(api, trailId);
        const cur = live(host, grant);
        if (cur !== null && cur.work?.kind === "sponsorships") host.set({ ...cur, busy: null, work: { ...cur.work, sponsorships } });
      });
    },

    async saveSponsorship(body) {
      const s = signedIn(host);
      if (s === null || s.work?.kind !== "sponsorships") return;
      const grant = s.grant;
      await runA3(grant, "sponsorships", async () => {
        const id = await postSponsorship(api, body);
        const cur = live(host, grant);
        if (cur !== null && cur.work?.kind === "sponsorships") {
          host.set({ ...cur, busy: null, work: { ...cur.work, lastId: id, sponsorships: null }, notice: { kind: "sponsorship-saved" } });
        }
      });
    },

    async approveSponsorship(id) {
      const s = signedIn(host);
      if (s === null || s.work?.kind !== "sponsorships" || !UUID_RE.test(id)) return;
      const grant = s.grant;
      await runA3(grant, "sponsorships", async () => {
        await postSponsorshipApprove(api, id.toLowerCase());
        const cur = live(host, grant);
        if (cur !== null && cur.work?.kind === "sponsorships") {
          host.set({ ...cur, busy: null, work: { ...cur.work, sponsorships: null }, notice: { kind: "sponsorship-approved" } });
        }
      });
    },

    async loadReview() {
      const s = signedIn(host);
      if (s === null || s.work?.kind !== "review") return;
      const grant = s.grant;
      await runA0(grant, "review", async () => {
        const [items, sla] = await Promise.all([getReviewQueue(api), getReviewSla(api)]);
        const rxuIds = items.filter((i) => i.kind === "review_item" && i.reviewKind === "receipt_cross_user_match").map((i) => i.id);
        const previewEntries = await Promise.all(
          rxuIds.map(async (id) => {
            try {
              return [id, await getReceiptCrossUserPreview(api, id)] as const;
            } catch {
              return null;
            }
          }),
        );
        const previews: Record<string, Awaited<ReturnType<typeof getReceiptCrossUserPreview>>> = {};
        for (const entry of previewEntries) {
          if (entry !== null) previews[entry[0]] = entry[1];
        }
        const cur = live(host, grant);
        if (cur !== null && cur.work?.kind === "review") host.set({ ...cur, busy: null, work: { ...cur.work, items, sla, previews } });
      });
    },

    async loadReceiptCrossUserPreview(id) {
      const s = signedIn(host);
      if (s === null || s.work?.kind !== "review" || !UUID_RE.test(id)) return;
      const grant = s.grant;
      const reviewId = id.toLowerCase();
      await runA0(grant, "review", async () => {
        const preview = await getReceiptCrossUserPreview(api, reviewId);
        const cur = live(host, grant);
        if (cur !== null && cur.work?.kind === "review") {
          host.set({ ...cur, busy: null, work: { ...cur.work, previews: { ...cur.work.previews, [reviewId]: preview } } });
        }
      });
    },

    async resolveOfferCode(id, approve) {
      const s = signedIn(host);
      if (s === null || s.work?.kind !== "review" || !UUID_RE.test(id)) return;
      const grant = s.grant;
      await runA3(grant, "review", async () => {
        const { state } = await postResolveOfferCode(api, id.toLowerCase(), approve);
        const cur = live(host, grant);
        if (cur !== null && cur.work?.kind === "review") {
          host.set({ ...cur, busy: null, work: { ...cur.work, items: null, lastState: state, previews: {} }, notice: { kind: "review-resolved" } });
        }
      });
    },

    async resolveEntitlement(id, approve) {
      const s = signedIn(host);
      if (s === null || s.work?.kind !== "review" || !UUID_RE.test(id)) return;
      const grant = s.grant;
      await runA3(grant, "review", async () => {
        const { state } = await postResolveEntitlement(api, id.toLowerCase(), approve);
        const cur = live(host, grant);
        if (cur !== null && cur.work?.kind === "review") {
          host.set({ ...cur, busy: null, work: { ...cur.work, items: null, lastState: state, previews: {} }, notice: { kind: "review-resolved" } });
        }
      });
    },

    async resolveReceiptCrossUser(id, approve) {
      const s = signedIn(host);
      if (s === null || s.work?.kind !== "review" || !UUID_RE.test(id)) return;
      const grant = s.grant;
      await runA3(grant, "review", async () => {
        const { state } = await postResolveReceiptCrossUser(api, id.toLowerCase(), approve);
        const cur = live(host, grant);
        if (cur !== null && cur.work?.kind === "review") {
          host.set({ ...cur, busy: null, work: { ...cur.work, items: null, lastState: state, previews: {} }, notice: { kind: "review-resolved" } });
        }
      });
    },

    async loadOperatorRollups() {
      const s = signedIn(host);
      if (s === null || s.work?.kind !== "rollups") return;
      const grant = s.grant;
      const trailId = s.work.trailId;
      await runA0(grant, "rollups", async () => {
        const operator = await getOperatorRollups(api, trailId);
        const cur = live(host, grant);
        if (cur !== null && cur.work?.kind === "rollups") host.set({ ...cur, busy: null, work: { ...cur.work, operator } });
      });
    },

    async loadSponsorRollups() {
      const s = signedIn(host);
      if (s === null || s.work?.kind !== "rollups" || !UUID_RE.test(s.work.sponsorshipId)) {
        if (s !== null && s.work?.kind === "rollups") {
          host.set({ ...s, notice: { kind: "error", message: { key: "rollups.sponsorshipInvalid" } } });
        }
        return;
      }
      const grant = s.grant;
      const sponsorshipId = s.work.sponsorshipId.toLowerCase();
      await runA0(grant, "rollups", async () => {
        const sponsor = await getSponsorRollups(api, sponsorshipId);
        const cur = live(host, grant);
        if (cur !== null && cur.work?.kind === "rollups") host.set({ ...cur, busy: null, work: { ...cur.work, sponsor } });
      });
    },

    async exportSettlement(monthInput) {
      const s = signedIn(host);
      if (s === null || s.work?.kind !== "settlement") return;
      const month = normalizeSettlementMonth(monthInput ?? s.work.month);
      if (month === null) {
        host.set({ ...s, notice: { kind: "error", message: { key: "settlement.monthInvalid" } } });
        return;
      }
      const grant = s.grant;
      const trailId = s.work.trailId;
      await runA3(grant, "settlement", async () => {
        const exported = await postSettlementExport(api, trailId, month);
        const cur = live(host, grant);
        if (cur !== null && cur.work?.kind === "settlement") {
          host.set({
            ...cur,
            busy: null,
            work: { ...cur.work, month, export: exported },
            notice: { kind: "settlement-exported" },
          });
        }
      });
    },

    dismissSettlementExport() {
      const s = signedIn(host);
      if (s === null || s.work?.kind !== "settlement" || s.busy !== null || s.panel !== null) return;
      withWork(host, s, { ...s.work, export: null }, s.notice?.kind === "settlement-exported" ? null : s.notice);
    },
  };
}
