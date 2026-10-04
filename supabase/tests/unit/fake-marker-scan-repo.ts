// supabase/tests/unit/fake-marker-scan-repo.ts
//
// An in-memory `Repo["markerScan"]` (migration 0046): the same OBSERVABLE contract as the four player-lane definers (private.course_qr_public_key_for_actor,
// course_pin_attempt_for_actor, marker_scan_for_actor, marker_cosignal_attach_for_actor), small enough to read and faithful where the Edge handler depends on it: the order of the
// token checks, single use, the 120 s rule against the fix time, the PIN counters, the pending window and the 7-day deadline. It is NOT the database: the database-side truth (FORCE RLS,
// the policies, concurrency, the Vault pepper, the real SQL) is the pgTAP matrix 24_* and the Deno integration suite supabase/tests/integration/marker-scan.deno.test.ts.
//
// The state also records every call (`calls`), so a test can prove ORDER: e.g. that a wrong PIN never reaches `record`, or that a forged QR never reaches `attemptPin`.

import type { MarkerPurchaseView, MarkerScanRecordInput, MarkerScanRecordResult, MarkerCosignalAttachInput, MarkerCosignalAttachResult, PinAttemptResult, Repo, CourseQrPublicKey } from "../../functions/_shared/types.ts";
import { HttpError } from "../../functions/_shared/http.ts";
import type { FakeState } from "./fake-repo.ts";

export interface FakeToken {
  facilityId: string;
  issuedAtMs: number;
  used: boolean;
}

export interface FakePurchase {
  id: string;
  userId: string;
  facilityId: string;
  trailId: string;
  method: "course_qr" | "staff_scan";
  qrVariant: "rotating" | "static_pin" | null;
  refId: string;
  localDate: string;
  status: "valid" | "pending" | "held_review";
  creditId: string;
  creditStatus: "credited" | "pending" | "held_review" | "void";
  cosignal: { grade: "attested" | "unattestable"; fixId: string; evidenceId: string } | null;
  awaiting: { fromMs: number; toMs: number; untilMs: number } | null;
}

export interface FakeMarkerScanState {
  /** `${purpose}:${kid}` -> key. */
  keys: Map<string, CourseQrPublicKey>;
  /** nonce hash -> token row (what `course-qr` / S2b writes). */
  tokens: Map<string, FakeToken>;
  /** facility -> the registered printed QR's current kid. */
  facilityQr: Map<string, string>;
  /** facility -> today's PIN (the fake has one: the real one is derived under a Vault pepper). */
  pins: Map<string, string>;
  /** facility -> the trails an `any_purchase` programme runs there. Empty / absent: no programme. */
  programme: Map<string, string[]>;
  /** facility -> `rotating` | `static_pin` | `both`. Default `both`. */
  qrMode: Map<string, "rotating" | "static_pin" | "both">;
  /** `${uid}:${facility}` -> wrong PINs so far today. */
  pinFailures: Map<string, number>;
  /** The scan's purchases and credits. */
  purchases: FakePurchase[];
  /** Every call, in order, for assertions. */
  calls: string[];
  /** Per-user PIN-attempt override (e.g. force `locked`). */
  pinOverride: PinAttemptResult | null;
  /** `false` simulates "the PIN pepper is not provisioned in Vault" (a 503 `course_pin_unavailable`). */
  pepperProvisioned: boolean;
}

const states = new WeakMap<FakeState, FakeMarkerScanState>();

export function markerScanState(state: FakeState): FakeMarkerScanState {
  let s = states.get(state);
  if (!s) {
    s = { keys: new Map(), tokens: new Map(), facilityQr: new Map(), pins: new Map(), programme: new Map(), qrMode: new Map(), pinFailures: new Map(), purchases: [], calls: [], pinOverride: null, pepperProvisioned: true };
    states.set(state, s);
  }
  return s;
}

const iso = (ms: number) => new Date(ms).toISOString();

export function makeFakeMarkerScanRepo(state: FakeState, uid: string): Repo["markerScan"] {
  const m = markerScanState(state);
  let n = 0;
  const id = (p: string) => `${p}-${uid}-${m.purchases.length + 1}-${(n += 1)}`;
  const view = (p: FakePurchase): MarkerPurchaseView => ({ purchaseId: p.id, trailId: p.trailId, purchaseStatus: p.status, creditId: p.creditId, creditStatus: p.creditStatus });
  const localDateOf = (ms: number, tz: string) => new Intl.DateTimeFormat("en-CA", { timeZone: tz, year: "numeric", month: "2-digit", day: "2-digit" }).format(new Date(ms));

  return {
    async publicKey(kid, purpose) {
      m.calls.push(`publicKey:${purpose}:${kid}`);
      return m.keys.get(`${purpose}:${kid}`) ?? null;
    },

    async attemptPin(input): Promise<PinAttemptResult> {
      m.calls.push("attemptPin");
      if (!m.pepperProvisioned) throw new HttpError(503, "course_pin_unavailable", "marker purchases by printed QR are not available right now");
      if (m.pinOverride) return m.pinOverride;
      if (!state.facilityTz.has(input.facilityId)) return { result: "no_facility", retryAfterSeconds: null };
      const mode = m.qrMode.get(input.facilityId) ?? "both";
      if (!m.programme.get(input.facilityId)?.length || mode === "rotating") return { result: "no_programme", retryAfterSeconds: null };
      const key = `${uid}:${input.facilityId}`;
      const fails = m.pinFailures.get(key) ?? 0;
      if (fails >= 5) return { result: "locked", retryAfterSeconds: 3600 };
      if (m.pins.get(input.facilityId) === input.pin) return { result: "ok", retryAfterSeconds: null };
      m.pinFailures.set(key, fails + 1);
      return { result: "wrong", retryAfterSeconds: null };
    },

    async record(input: MarkerScanRecordInput): Promise<MarkerScanRecordResult> {
      m.calls.push("record");
      const tz = state.facilityTz.get(input.facilityId);
      if (!tz) return { status: "no_facility" };
      const trails = m.programme.get(input.facilityId) ?? [];
      if (trails.length === 0) return { status: "no_programme" };
      const mode = m.qrMode.get(input.facilityId) ?? "both";
      if (mode !== "both" && mode !== input.variant) return { status: "variant_disabled" };
      const atMs = input.at.getTime();
      let ref: string;
      let awaiting: { fromMs: number; toMs: number };
      if (input.variant === "rotating") {
        const t = input.nonceHash ? m.tokens.get(input.nonceHash) : undefined;
        if (!t) return { status: "qr_unknown" };
        if (t.facilityId !== input.facilityId) return { status: "qr_wrong_facility" };
        if (t.used) return { status: "qr_used" };
        if (Math.abs(atMs - t.issuedAtMs) > 120_000) return { status: "qr_expired" };
        t.used = true;
        ref = input.nonceHash!;
        awaiting = { fromMs: t.issuedAtMs - 120_000, toMs: t.issuedAtMs + 120_000 };
      } else {
        const kid = m.facilityQr.get(input.facilityId);
        if (!kid) return { status: "qr_unknown" };
        if (kid !== input.qrKid) return { status: "qr_revoked" };
        if (m.pins.get(input.facilityId) !== input.pin) return { status: "pin_wrong" };
        ref = `pin:${input.facilityId}:${localDateOf(atMs, tz)}:0`;
        if (m.purchases.some((p) => p.userId === uid && p.method === "course_qr" && p.refId === ref)) return { status: "duplicate" };
        awaiting = { fromMs: atMs - 12 * 3_600_000, toMs: atMs + 12 * 3_600_000 };
      }
      const pstatus = input.cosignal === null ? "pending" : input.cosignal.grade === "attested" ? "valid" : "held_review";
      const cstatus = pstatus === "valid" ? "credited" : pstatus;
      const rows: MarkerPurchaseView[] = [];
      for (const trailId of trails) {
        const p: FakePurchase = {
          id: id("pe"),
          userId: uid,
          facilityId: input.facilityId,
          trailId,
          method: "course_qr",
          qrVariant: input.variant,
          refId: ref,
          localDate: localDateOf(atMs, tz),
          status: pstatus,
          creditId: id("mc"),
          creditStatus: cstatus,
          cosignal: input.cosignal,
          awaiting: input.cosignal === null ? { ...awaiting, untilMs: state.now.getTime() + 7 * 86_400_000 } : null,
        };
        m.purchases.push(p);
        rows.push(view(p));
      }
      return { status: "accepted", localDate: localDateOf(atMs, tz), purchases: rows };
    },

    async attachCosignal(input: MarkerCosignalAttachInput): Promise<MarkerCosignalAttachResult> {
      m.calls.push("attachCosignal");
      const atMs = input.at.getTime();
      const match = m.purchases
        .filter((p) => p.userId === uid && p.facilityId === input.facilityId && p.status === "pending" && p.awaiting !== null && p.awaiting.fromMs <= atMs && atMs <= p.awaiting.toMs && state.now.getTime() <= p.awaiting.untilMs)
        .sort((a, b) => (a.id < b.id ? -1 : 1))[0];
      if (!match) return { status: "no_pending_purchase" };
      const group = m.purchases.filter((p) => p.userId === uid && p.refId === match.refId && p.method === match.method && p.status === "pending");
      for (const p of group) {
        p.status = input.cosignal.grade === "attested" ? "valid" : "held_review";
        p.creditStatus = input.cosignal.grade === "attested" ? "credited" : "held_review";
        p.cosignal = input.cosignal;
        p.awaiting = null;
      }
      return { status: "attached", purchases: group.map(view) };
    },
  };
}

export function isoOf(ms: number): string {
  return iso(ms);
}
