// supabase/functions/_shared/partner/review-handler.ts
//
// The `partner-review` handler (docs/security/partner-auth-design.md 4.5, 6.3, 12, 27, 51; slice S4, the Edge half of migration 0057 / 0070). Pure and unit-testable like attest-handler.ts: the database
// (`PartnerDb`) is a PORT (`ports.ts`); this file reads no environment, opens no connection, imports no library and writes no log line (PA-11). Signed URLs are never logged.
//
// ROUTES (relative to the function; `GET queue` is `/partner-review/queue`):
//   GET  queue                         class A0 (admin): the open held_review rewards and open review_items, with an SLA-breach flag
//   GET  sla                           class A0 (admin): counts for the ops alert surface (48 h SLA, [inference])
//   GET  preview/receipt-cross-user    class A0 (admin): `?id=<reviewUuid>` — short-lived signed URLs for subject (+ matched) receipt images (0070)
//   POST resolve/offer-code            class A3 (admin): `{ id, approve }` — wraps app.resolve_held_offer_code (E20)
//   POST resolve/entitlement           class A3 (admin): `{ id, approve }` — wraps app.resolve_held_entitlement
//   POST resolve/receipt-cross-user    class A3 (admin): `{ id, approve }` — 0069 receipt_cross_user_match resolve
// Every route is a session route. Scope, class, the admin gate and the resolve state machine are the DATABASE's.
//
// THE ORDER, for every request: (1) the Origin check; (2) OPTIONS with no port touched; (3) route and method; (4) the bearer; (5) exact JSON media type and strict body (POST) or empty/strict query (GET);
// (6) the per-member bucket; (7) the work.

import { Errors } from "../http.ts";
import type { ReceiptsStoragePort } from "../receipts/ports.ts";
import { decideOrigin, preflightResponse } from "./cors.ts";
import { bearerHash, type Decision, mapPartnerError, matchRoute, methodRefusal, rateLimited, routeOfFunction, type RouteSpec } from "./handler-kit.ts";
import { partnerError, partnerOk, readPartnerJsonBody, runPartnerHandler, unauthenticated } from "./http.ts";
import type { HeldQueueRow, PartnerDb, ResolveHeldResult, ReviewSlaSummary } from "./ports.ts";
import { parsePreviewQuery, parseResolveBody } from "./review-shape.ts";

export const PARTNER_REVIEW_FUNCTION = "partner-review";
/** A per-member bucket over every review read and resolve. `[inference]`: 120 an hour is plenty for a reviewer dashboard. */
export const REVIEW_PER_MEMBER_PER_HOUR = 120;
export const REVIEW_BUCKET = "partner-review:member";
/** Short TTL for receipt image preview signed URLs (120–300s band; never log the URL). */
export const RECEIPT_PREVIEW_SIGNED_URL_SECONDS = 180;

export interface PartnerReviewDeps {
  readonly db: PartnerDb;
  readonly storage: Pick<ReceiptsStoragePort, "createSignedUrl">;
  readonly allowedOrigin: string | null;
  readonly timeoutMs?: number;
}

const ROUTES: readonly RouteSpec[] = [
  { name: "queue", path: "queue", methods: ["GET"], session: true },
  { name: "sla", path: "sla", methods: ["GET"], session: true },
  { name: "preview-receipt-cross-user", path: "preview/receipt-cross-user", methods: ["GET"], session: true },
  { name: "resolve-offer-code", path: "resolve/offer-code", methods: ["POST"], session: true },
  { name: "resolve-entitlement", path: "resolve/entitlement", methods: ["POST"], session: true },
  { name: "resolve-receipt-cross-user", path: "resolve/receipt-cross-user", methods: ["POST"], session: true },
];

export async function handlePartnerReviewRequest(req: Request, deps: PartnerReviewDeps): Promise<Response> {
  const decision = decideOrigin(req.headers, deps.allowedOrigin);
  if (decision.kind === "refused") return partnerError({ kind: "none" }, 403, "forbidden", "origin not allowed");
  if (req.method === "OPTIONS") return preflightResponse(decision);

  return await runPartnerHandler(
    decision,
    async () => {
      try {
        const matched = matchRoute(ROUTES, routeOfFunction(req.url, PARTNER_REVIEW_FUNCTION));
        if (matched === null) return partnerError(decision, 404, "not_found", "not found");
        const refusal = methodRefusal(decision, matched, req.method);
        if (refusal !== null) return refusal;
        const tokenHash = await bearerHash(req.headers);
        if (tokenHash === null) return unauthenticated(decision);

        switch (matched.spec.name) {
          case "queue":
            return await handleQueue(deps, decision, tokenHash);
          case "sla":
            return await handleSla(deps, decision, tokenHash);
          case "preview-receipt-cross-user":
            return await handlePreviewReceiptCrossUser(req, deps, decision, tokenHash);
          case "resolve-offer-code":
            return await handleResolveOfferCode(req, deps, decision, tokenHash);
          case "resolve-entitlement":
            return await handleResolveEntitlement(req, deps, decision, tokenHash);
          case "resolve-receipt-cross-user":
            return await handleResolveReceiptCrossUser(req, deps, decision, tokenHash);
          default:
            return partnerError(decision, 404, "not_found", "not found");
        }
      } catch (err) {
        return mapPartnerError(decision, err);
      }
    },
    deps.timeoutMs,
  );
}

async function memberLimit(deps: PartnerReviewDeps, decision: Decision, tokenHash: string): Promise<Response | null> {
  const limit = await deps.db.hitRateLimit(tokenHash, REVIEW_BUCKET, 3600, REVIEW_PER_MEMBER_PER_HOUR);
  return limit.ok ? null : rateLimited(decision, "too many requests", limit.retryAfterSeconds);
}

function queueRowBody(r: HeldQueueRow): Record<string, unknown> {
  return {
    kind: r.kind,
    id: r.id,
    subjectTable: r.subjectTable,
    subjectId: r.subjectId,
    userId: r.userId,
    handle: r.handle,
    facilityId: r.facilityId,
    trailId: r.trailId,
    holdDetail: r.holdDetail,
    reservedAmount: r.reservedAmount,
    heldAt: r.heldAt,
    slaBreached: r.slaBreached,
    reviewKind: r.reviewKind,
  };
}

function slaBody(s: ReviewSlaSummary): Record<string, unknown> {
  return {
    heldOfferCodes: s.heldOfferCodes,
    heldEntitlements: s.heldEntitlements,
    openReviewItems: s.openReviewItems,
    slaBreachedRewards: s.slaBreachedRewards,
    slaBreachedReviewItems: s.slaBreachedReviewItems,
    slaHours: s.slaHours,
  };
}

function resolveResponse(decision: Decision, r: ResolveHeldResult): Response {
  switch (r.status) {
    case "ok":
      return partnerOk(decision, 200, { state: r.state });
    case "not_found":
      return partnerError(decision, 404, "not_found", "not found");
    case "not_held":
      return partnerError(decision, 409, "not_held", "this reward is not awaiting review");
    case "not_open":
      return partnerError(decision, 409, "not_open", "this review item is not open");
    case "budget_short":
      return partnerError(decision, 422, "budget_short", "the offer cannot cover this code: raise its budget or reject the code");
  }
}

async function handleQueue(deps: PartnerReviewDeps, decision: Decision, tokenHash: string): Promise<Response> {
  const limited = await memberLimit(deps, decision, tokenHash);
  if (limited !== null) return limited;
  const rows = await deps.db.withReview(tokenHash, (s) => s.heldQueue());
  return partnerOk(decision, 200, { items: rows.map(queueRowBody) });
}

async function handleSla(deps: PartnerReviewDeps, decision: Decision, tokenHash: string): Promise<Response> {
  const limited = await memberLimit(deps, decision, tokenHash);
  if (limited !== null) return limited;
  const summary = await deps.db.withReview(tokenHash, (s) => s.reviewSla());
  return partnerOk(decision, 200, slaBody(summary));
}

async function handlePreviewReceiptCrossUser(req: Request, deps: PartnerReviewDeps, decision: Decision, tokenHash: string): Promise<Response> {
  const parsed = parsePreviewQuery(req.url);
  if (!parsed.ok) throw Errors.badRequest("invalid request", parsed.issues);
  const limited = await memberLimit(deps, decision, tokenHash);
  if (limited !== null) return limited;

  const refs = await deps.db.withReview(tokenHash, (s) => s.receiptCrossUserPreview(parsed.value.id));
  switch (refs.status) {
    case "not_found":
      return partnerError(decision, 404, "not_found", "not found");
    case "not_open":
      return partnerError(decision, 409, "not_open", "this review item is not open");
    case "no_image":
      return partnerError(decision, 404, "no_image", "no receipt image for this review item");
    case "ok":
      break;
  }

  const images: Array<{ label: string; signedUrl: string }> = [];
  let expiresAt: string | null = null;
  for (const [label, path] of [
    ["subject", refs.subjectRef],
    ["matched", refs.matchedRef],
  ] as const) {
    if (path === null) continue;
    const signed = await deps.storage.createSignedUrl(path, RECEIPT_PREVIEW_SIGNED_URL_SECONDS);
    images.push({ label, signedUrl: signed.signedUrl });
    if (expiresAt === null || signed.expiresAt < expiresAt) expiresAt = signed.expiresAt;
  }
  if (images.length === 0) {
    return partnerError(decision, 404, "no_image", "no receipt image for this review item");
  }
  return partnerOk(decision, 200, { images, expiresAt: expiresAt ?? new Date(Date.now() + RECEIPT_PREVIEW_SIGNED_URL_SECONDS * 1000).toISOString() });
}

async function handleResolveOfferCode(req: Request, deps: PartnerReviewDeps, decision: Decision, tokenHash: string): Promise<Response> {
  const parsed = parseResolveBody(await readPartnerJsonBody(req));
  if (!parsed.ok) throw Errors.badRequest("invalid request", parsed.issues);
  const limited = await memberLimit(deps, decision, tokenHash);
  if (limited !== null) return limited;
  const result = await deps.db.withReview(tokenHash, (s) => s.resolveHeldOfferCode(parsed.value.id, parsed.value.approve));
  return resolveResponse(decision, result);
}

async function handleResolveEntitlement(req: Request, deps: PartnerReviewDeps, decision: Decision, tokenHash: string): Promise<Response> {
  const parsed = parseResolveBody(await readPartnerJsonBody(req));
  if (!parsed.ok) throw Errors.badRequest("invalid request", parsed.issues);
  const limited = await memberLimit(deps, decision, tokenHash);
  if (limited !== null) return limited;
  const result = await deps.db.withReview(tokenHash, (s) => s.resolveHeldEntitlement(parsed.value.id, parsed.value.approve));
  return resolveResponse(decision, result);
}

async function handleResolveReceiptCrossUser(req: Request, deps: PartnerReviewDeps, decision: Decision, tokenHash: string): Promise<Response> {
  const parsed = parseResolveBody(await readPartnerJsonBody(req));
  if (!parsed.ok) throw Errors.badRequest("invalid request", parsed.issues);
  const limited = await memberLimit(deps, decision, tokenHash);
  if (limited !== null) return limited;
  const result = await deps.db.withReview(tokenHash, (s) => s.resolveReceiptCrossUserMatch(parsed.value.id, parsed.value.approve));
  return resolveResponse(decision, result);
}
