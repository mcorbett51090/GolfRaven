// supabase/tests/unit/partner-review-handler.test.ts
//
// The `partner-review` handler and its strict shapes (docs/security/partner-auth-design.md 27, 51; slice S4 / §51, the Edge half of 0057 / 0070), against an in-memory `PartnerDb`. What is the DATABASE's (admin gate, A3,
// resolve state machine, SLA, preview refs): supabase/tests/matrix/35_partner_review_queue.sql and 48_partner_receipt_preview.sql.

import { describe, expect, it } from "vitest";
import { handlePartnerReviewRequest, RECEIPT_PREVIEW_SIGNED_URL_SECONDS, REVIEW_BUCKET } from "../../functions/_shared/partner/review-handler.ts";
import { parsePreviewQuery, parseResolveBody } from "../../functions/_shared/partner/review-shape.ts";
import {
  PartnerAuthorityRefused,
  PartnerInvalidArgument,
  PartnerSessionRefused,
  type HeldQueueRow,
  type PartnerDb,
  type PartnerReviewTx,
  type ReceiptCrossUserPreviewRefs,
  type ResolveHeldResult,
  type ReviewSlaSummary,
} from "../../functions/_shared/partner/ports.ts";
import { sha256Hex } from "../../functions/_shared/partner/token.ts";

const ORIGIN = "https://partners.example.test";
const FN = "partner-review";
const TOKEN = "gr_ps_" + "a".repeat(43);
let TOKEN_HASH = "";

async function hash(): Promise<string> {
  if (!TOKEN_HASH) TOKEN_HASH = await sha256Hex(TOKEN);
  return TOKEN_HASH;
}

function jsonResponse(status: number, body: unknown): void {
  // placeholder for type symmetry with other suites
  void status;
  void body;
}

interface FakeReview {
  readonly db: PartnerDb;
  readonly storage: { createSignedUrl: (path: string, expiresInSeconds: number) => Promise<{ signedUrl: string; expiresAt: string }> };
  readonly calls: string[];
  readonly signedPaths: string[];
  queue: HeldQueueRow[];
  sla: ReviewSlaSummary;
  preview: ReceiptCrossUserPreviewRefs;
  resolveOc: ResolveHeldResult;
  resolveEnt: ResolveHeldResult;
  resolveXu: ResolveHeldResult;
  throwOn?: "session" | "authority" | "invalid";
}

function makeFake(overrides: Partial<FakeReview> = {}): FakeReview {
  const calls: string[] = [];
  const signedPaths: string[] = [];
  const state: FakeReview = {
    calls,
    signedPaths,
    queue: overrides.queue ?? [],
    sla: overrides.sla ?? {
      heldOfferCodes: 0,
      heldEntitlements: 0,
      openReviewItems: 0,
      slaBreachedRewards: 0,
      slaBreachedReviewItems: 0,
      slaHours: 48,
    },
    preview: overrides.preview ?? { status: "ok", subjectRef: "receipts/u/a.jpg", matchedRef: "receipts/v/b.jpg" },
    resolveOc: overrides.resolveOc ?? { status: "ok", state: "issued" },
    resolveEnt: overrides.resolveEnt ?? { status: "ok", state: "redeemable" },
    resolveXu: overrides.resolveXu ?? { status: "ok", state: "approved" },
    throwOn: overrides.throwOn,
    db: null as unknown as PartnerDb,
    storage: {
      async createSignedUrl(path, expiresInSeconds) {
        signedPaths.push(`${path}:${expiresInSeconds}`);
        calls.push(`createSignedUrl:${path}`);
        return {
          signedUrl: `https://storage.example.test/sign/${encodeURIComponent(path)}?token=fake-preview-token-not-for-logs`,
          expiresAt: new Date(Date.now() + expiresInSeconds * 1000).toISOString(),
        };
      },
    },
  };
  const tx: PartnerReviewTx = {
    async heldQueue() {
      calls.push("heldQueue");
      return state.queue;
    },
    async reviewSla() {
      calls.push("reviewSla");
      return state.sla;
    },
    async receiptCrossUserPreview(id) {
      calls.push(`preview:${id}`);
      return state.preview;
    },
    async resolveHeldOfferCode(id, approve) {
      calls.push(`resolveOc:${id}:${approve}`);
      return state.resolveOc;
    },
    async resolveHeldEntitlement(id, approve) {
      calls.push(`resolveEnt:${id}:${approve}`);
      return state.resolveEnt;
    },
    async resolveReceiptCrossUserMatch(id, approve) {
      calls.push(`resolveXu:${id}:${approve}`);
      return state.resolveXu;
    },
  };
  state.db = {
    withMint: () => Promise.reject(new Error("unused")),
    withInviteMint: () => Promise.reject(new Error("unused")),
    withSession: () => Promise.reject(new Error("unused")),
    withInvites: () => Promise.reject(new Error("unused")),
    withMembers: () => Promise.reject(new Error("unused")),
    withAttest: () => Promise.reject(new Error("unused")),
    withStock: () => Promise.reject(new Error("unused")),
    withEntitlements: () => Promise.reject(new Error("unused")),
    withProgramme: () => Promise.reject(new Error("unused")),
    withOffersAdmin: () => Promise.reject(new Error("unused")),
    withSponsorships: () => Promise.reject(new Error("unused")),
    withOffersRedeem: () => Promise.reject(new Error("unused")),
    withSettlementExport: () => Promise.reject(new Error("unused")),
    async withReview(_hash, op) {
      calls.push("withReview");
      if (state.throwOn === "session") throw new PartnerSessionRefused();
      if (state.throwOn === "authority") throw new PartnerAuthorityRefused();
      if (state.throwOn === "invalid") throw new PartnerInvalidArgument();
      return await op(tx);
    },
    async hitRateLimit(_hash, bucket, _window, _max) {
      calls.push(`hitRateLimit:${bucket}`);
      return { ok: true, retryAfterSeconds: 0 };
    },
    async hitSystemRateLimit() {
      return { ok: true, retryAfterSeconds: 0 };
    },
  };
  return state;
}

async function call(fake: FakeReview, method: string, path: string, body?: unknown): Promise<Response> {
  const headers = new Headers({ origin: ORIGIN, authorization: `Bearer ${TOKEN}` });
  let init: RequestInit = { method, headers };
  if (body !== undefined) {
    headers.set("content-type", "application/json");
    init = { method, headers, body: JSON.stringify(body) };
  }
  return await handlePartnerReviewRequest(new Request(`https://project.example.test/functions/v1/${FN}/${path}`, init), {
    db: fake.db,
    storage: fake.storage,
    allowedOrigin: ORIGIN,
  });
}

describe("parseResolveBody", () => {
  it("accepts exactly { id, approve }", () => {
    const r = parseResolveBody({ id: "70000000-0000-0000-0000-000000003501", approve: true });
    expect(r).toEqual({ ok: true, value: { id: "70000000-0000-0000-0000-000000003501", approve: true } });
  });
  it("refuses unknown keys, a non-uuid id, and a non-boolean approve", () => {
    expect(parseResolveBody({ id: "70000000-0000-0000-0000-000000003501", approve: true, x: 1 }).ok).toBe(false);
    expect(parseResolveBody({ id: "not-a-uuid", approve: true }).ok).toBe(false);
    expect(parseResolveBody({ id: "70000000-0000-0000-0000-000000003501", approve: "yes" }).ok).toBe(false);
  });
});

describe("parsePreviewQuery", () => {
  it("accepts exactly ?id=<uuid>", () => {
    const r = parsePreviewQuery("https://x.test/preview/receipt-cross-user?id=91000000-0000-0000-0000-000000004701");
    expect(r).toEqual({ ok: true, value: { id: "91000000-0000-0000-0000-000000004701" } });
  });
  it("refuses missing id, bad uuid, and unknown keys", () => {
    expect(parsePreviewQuery("https://x.test/preview/receipt-cross-user").ok).toBe(false);
    expect(parsePreviewQuery("https://x.test/preview/receipt-cross-user?id=nope").ok).toBe(false);
    expect(parsePreviewQuery("https://x.test/preview/receipt-cross-user?id=91000000-0000-0000-0000-000000004701&x=1").ok).toBe(false);
  });
});

describe("handlePartnerReviewRequest", () => {
  it("refuses a foreign Origin before routing", async () => {
    const fake = makeFake();
    const res = await handlePartnerReviewRequest(
      new Request(`https://project.example.test/functions/v1/${FN}/queue`, { method: "GET", headers: { origin: "https://evil.test", authorization: `Bearer ${TOKEN}` } }),
      { db: fake.db, storage: fake.storage, allowedOrigin: ORIGIN },
    );
    expect(res.status).toBe(403);
    expect(fake.calls).toEqual([]);
  });

  it("answers OPTIONS with no port touched", async () => {
    const fake = makeFake();
    const res = await handlePartnerReviewRequest(
      new Request(`https://project.example.test/functions/v1/${FN}/queue`, { method: "OPTIONS", headers: { origin: ORIGIN } }),
      { db: fake.db, storage: fake.storage, allowedOrigin: ORIGIN },
    );
    expect(res.status).toBe(204);
    expect(fake.calls).toEqual([]);
  });

  it("404s an unknown route and 401s a missing bearer with no port touched", async () => {
    const fake = makeFake();
    expect((await call(fake, "GET", "nope")).status).toBe(404);
    const res = await handlePartnerReviewRequest(new Request(`https://project.example.test/functions/v1/${FN}/queue`, { method: "GET", headers: { origin: ORIGIN } }), {
      db: fake.db,
      storage: fake.storage,
      allowedOrigin: ORIGIN,
    });
    expect(res.status).toBe(401);
    expect(fake.calls).toEqual([]);
  });

  it("GET queue returns items and hits the per-member bucket", async () => {
    await hash();
    const fake = makeFake({
      queue: [
        {
          kind: "offer_code",
          id: "70000000-0000-0000-0000-000000003501",
          subjectTable: "offer_code",
          subjectId: "70000000-0000-0000-0000-000000003501",
          userId: "00000000-0000-0000-0000-00000000000a",
          handle: "player_a",
          facilityId: "fac_x",
          trailId: null,
          holdDetail: { heldFor: "test" },
          reservedAmount: 10,
          heldAt: "2026-01-01T00:00:00.000Z",
          slaBreached: false,
          reviewKind: null,
        },
      ],
    });
    const res = await call(fake, "GET", "queue");
    expect(res.status).toBe(200);
    const body = (await res.json()) as { data: { items: unknown[] } };
    expect(body.data.items).toHaveLength(1);
    expect(fake.calls[0]).toBe(`hitRateLimit:${REVIEW_BUCKET}`);
    expect(fake.calls).toContain("heldQueue");
  });

  it("GET sla returns the summary", async () => {
    const fake = makeFake({ sla: { heldOfferCodes: 2, heldEntitlements: 1, openReviewItems: 3, slaBreachedRewards: 1, slaBreachedReviewItems: 0, slaHours: 48 } });
    const res = await call(fake, "GET", "sla");
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      data: { heldOfferCodes: 2, heldEntitlements: 1, openReviewItems: 3, slaBreachedRewards: 1, slaBreachedReviewItems: 0, slaHours: 48 },
    });
  });

  it("GET preview/receipt-cross-user returns opaque labels and signed URLs (never storage paths)", async () => {
    const id = "91000000-0000-0000-0000-000000004701";
    const fake = makeFake({
      preview: { status: "ok", subjectRef: "receipts/uid-a/subj.jpg", matchedRef: "receipts/uid-b/match.jpg" },
    });
    const res = await call(fake, "GET", `preview/receipt-cross-user?id=${id}`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { data: { images: Array<{ label: string; signedUrl: string }>; expiresAt: string } };
    expect(body.data.images.map((i) => i.label)).toEqual(["subject", "matched"]);
    expect(body.data.images.every((i) => i.signedUrl.includes("token="))).toBe(true);
    expect(JSON.stringify(body)).not.toContain("receipts/uid");
    expect(fake.signedPaths).toEqual([
      `receipts/uid-a/subj.jpg:${RECEIPT_PREVIEW_SIGNED_URL_SECONDS}`,
      `receipts/uid-b/match.jpg:${RECEIPT_PREVIEW_SIGNED_URL_SECONDS}`,
    ]);
    expect(fake.calls).toContain(`preview:${id}`);
  });

  it("GET preview/receipt-cross-user maps not_open and no_image", async () => {
    const id = "91000000-0000-0000-0000-000000004701";
    const closed = makeFake({ preview: { status: "not_open", subjectRef: null, matchedRef: null } });
    expect((await call(closed, "GET", `preview/receipt-cross-user?id=${id}`)).status).toBe(409);
    const empty = makeFake({ preview: { status: "no_image", subjectRef: null, matchedRef: null } });
    const res = await call(empty, "GET", `preview/receipt-cross-user?id=${id}`);
    expect(res.status).toBe(404);
    expect(((await res.json()) as { error: { code: string } }).error.code).toBe("no_image");
  });

  it("POST resolve/offer-code maps statuses", async () => {
    const id = "70000000-0000-0000-0000-000000003501";
    for (const [status, code, http] of [
      ["ok", "issued", 200],
      ["not_found", null, 404],
      ["not_held", null, 409],
      ["budget_short", null, 422],
    ] as const) {
      const fake = makeFake({ resolveOc: { status, state: code } });
      const res = await call(fake, "POST", "resolve/offer-code", { id, approve: true });
      expect(res.status).toBe(http);
      if (status === "ok") expect(await res.json()).toEqual({ data: { state: "issued" } });
      else expect(((await res.json()) as { error: { code: string } }).error.code).toBe(status === "not_found" ? "not_found" : status);
    }
  });

  it("POST resolve/entitlement maps ok and not_held", async () => {
    const id = "51000000-0000-0000-0000-000000003501";
    const ok = makeFake({ resolveEnt: { status: "ok", state: "redeemable" } });
    expect((await call(ok, "POST", "resolve/entitlement", { id, approve: true })).status).toBe(200);
    const held = makeFake({ resolveEnt: { status: "not_held", state: null } });
    expect((await call(held, "POST", "resolve/entitlement", { id, approve: false })).status).toBe(409);
  });

  it("POST resolve/receipt-cross-user maps approve and not_open", async () => {
    const id = "91000000-0000-0000-0000-000000004701";
    const ok = makeFake({ resolveXu: { status: "ok", state: "approved" } });
    const res = await call(ok, "POST", "resolve/receipt-cross-user", { id, approve: true });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ data: { state: "approved" } });
    expect(ok.calls).toContain(`resolveXu:${id}:true`);
    const closed = makeFake({ resolveXu: { status: "not_open", state: null } });
    expect((await call(closed, "POST", "resolve/receipt-cross-user", { id, approve: false })).status).toBe(409);
  });

  it("maps PartnerAuthorityRefused to 403 and PartnerSessionRefused to 401", async () => {
    const auth = makeFake({ throwOn: "authority" });
    expect((await call(auth, "GET", "queue")).status).toBe(403);
    const sess = makeFake({ throwOn: "session" });
    expect((await call(sess, "GET", "queue")).status).toBe(401);
  });

  it("415s a non-exact JSON media type on POST before the port is touched", async () => {
    const fake = makeFake();
    const headers = new Headers({ origin: ORIGIN, authorization: `Bearer ${TOKEN}`, "content-type": "text/plain; x=application/json" });
    const res = await handlePartnerReviewRequest(
      new Request(`https://project.example.test/functions/v1/${FN}/resolve/offer-code`, {
        method: "POST",
        headers,
        body: JSON.stringify({ id: "70000000-0000-0000-0000-000000003501", approve: true }),
      }),
      { db: fake.db, storage: fake.storage, allowedOrigin: ORIGIN },
    );
    expect(res.status).toBe(415);
    expect(fake.calls).toEqual([]);
  });
});

void jsonResponse;
