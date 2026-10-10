// supabase/functions/receipts/index.ts
//
// POST /v1/receipts (player-lane receipt image upload). Thin entry over
// _shared/receipts/handler.ts: JWT actor, rate limit before the transaction,
// capped multipart parse, Storage upload (service role), then receipt_intake_for_actor.

import { getActorFromRequest, hitRateLimitForActor, receiptsStorage, withOwnership } from "../_shared/privileged.ts";
import { errorResponse, handleRequest, okResponse, Errors, HttpError } from "../_shared/http.ts";
import { handleReceiptUpload } from "../_shared/receipts/handler.ts";
import { parseReceiptMultipart, RECEIPTS_MAX_BODY_BYTES } from "../_shared/receipts/request-shape.ts";
import { serve } from "std/http/server";

export const RECEIPTS_BUCKET = "receipts:member";
export const RECEIPTS_PER_HOUR = 60;
export const RECEIPTS_WINDOW_SECONDS = 3600;

/**
 * Read multipart with a running byte cap (same discipline as readCappedJsonBody).
 * Content-Length is a fast-reject only; omitted/lying lengths still stop at the stream cap.
 */
async function readMultipartCapped(req: Request): Promise<FormData> {
  const ct = req.headers.get("content-type") ?? "";
  if (!ct.toLowerCase().includes("multipart/form-data")) {
    throw Errors.unsupportedMediaType("expected multipart/form-data");
  }

  const declared = req.headers.get("content-length");
  if (declared !== null) {
    const n = Number(declared);
    if (Number.isFinite(n) && n > RECEIPTS_MAX_BODY_BYTES) {
      throw new HttpError(413, "payload_too_large", `request body exceeds ${RECEIPTS_MAX_BODY_BYTES} bytes`);
    }
  }

  const chunks: Uint8Array[] = [];
  let total = 0;
  if (req.body) {
    const reader = req.body.getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > RECEIPTS_MAX_BODY_BYTES) {
        await reader.cancel().catch(() => {});
        throw new HttpError(413, "payload_too_large", `request body exceeds ${RECEIPTS_MAX_BODY_BYTES} bytes`);
      }
      chunks.push(value);
    }
  }

  const buf = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    buf.set(chunk, offset);
    offset += chunk.byteLength;
  }

  // Rebuild a Request so FormData parsing sees the original Content-Type (boundary).
  const rebuilt = new Request("http://receipts.local/upload", {
    method: "POST",
    headers: { "content-type": ct },
    body: buf,
  });
  return await rebuilt.formData();
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
    if (!parsed.ok) {
      const oversize = parsed.issues.some((i) => i.message.includes("exceeds"));
      if (oversize) {
        throw new HttpError(413, "payload_too_large", `receipt file exceeds ${RECEIPTS_MAX_BODY_BYTES} bytes`);
      }
      throw Errors.badRequest("invalid receipt upload", { issues: parsed.issues });
    }

    const outcome = await withOwnership(actor, (repo) =>
      handleReceiptUpload(parsed.value, actor.uid, repo, {
        storage: receiptsStorage,
        newObjectId: () => crypto.randomUUID(),
      }),
    );

    return okResponse(outcome.status, outcome.body, { "cache-control": "no-store" });
  }),
);
