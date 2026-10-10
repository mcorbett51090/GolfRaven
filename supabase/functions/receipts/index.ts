// supabase/functions/receipts/index.ts
//
// POST /v1/receipts (player-lane receipt image upload). Thin entry over
// _shared/receipts/handler.ts: JWT actor, rate limit before the transaction,
// multipart parse, Storage upload (service role), then receipt_intake_for_actor.

import { getActorFromRequest, hitRateLimitForActor, receiptsStorage, withOwnership } from "../_shared/privileged.ts";
import { errorResponse, handleRequest, okResponse, Errors, HttpError } from "../_shared/http.ts";
import { handleReceiptUpload } from "../_shared/receipts/handler.ts";
import { parseReceiptMultipart, RECEIPTS_MAX_BODY_BYTES } from "../_shared/receipts/request-shape.ts";
import { serve } from "std/http/server";

export const RECEIPTS_BUCKET = "receipts:member";
export const RECEIPTS_PER_HOUR = 60;
export const RECEIPTS_WINDOW_SECONDS = 3600;

async function readMultipartCapped(req: Request): Promise<FormData> {
  const declared = req.headers.get("content-length");
  if (declared !== null) {
    const n = Number(declared);
    if (Number.isFinite(n) && n > RECEIPTS_MAX_BODY_BYTES) {
      throw new HttpError(413, "payload_too_large", `request body exceeds ${RECEIPTS_MAX_BODY_BYTES} bytes`);
    }
  }
  const ct = req.headers.get("content-type") ?? "";
  if (!ct.toLowerCase().includes("multipart/form-data")) {
    throw Errors.unsupportedMediaType("expected multipart/form-data");
  }
  return await req.formData();
}

serve((req) =>
  handleRequest(async () => {
    if (req.method !== "POST") return errorResponse(405, "method_not_allowed", "POST only");

    const actor = await getActorFromRequest(req);
    if (!actor) return Errors.unauthorized().toResponse();

    const limit = await hitRateLimitForActor(actor, RECEIPTS_BUCKET, RECEIPTS_WINDOW_SECONDS, RECEIPTS_PER_HOUR);
    if (!limit.ok) return Errors.tooManyRequests("receipts rate limit exceeded", limit.retryAfterSeconds).toResponse();

    const form = await readMultipartCapped(req);
    const parsed = await parseReceiptMultipart(form);
    if (!parsed.ok) throw Errors.badRequest("invalid receipt upload", { issues: parsed.issues });

    const outcome = await withOwnership(actor, (repo) =>
      handleReceiptUpload(parsed.value, actor.uid, repo, {
        storage: receiptsStorage,
        newObjectId: () => crypto.randomUUID(),
      }),
    );

    return okResponse(outcome.status, outcome.body, { "cache-control": "no-store" });
  }),
);
