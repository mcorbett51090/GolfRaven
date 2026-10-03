/**
 * HTTP response -> the outbox's `ServerAnswer` (build plan §7.6 table), for `POST evidence` and, per item, `POST evidence-batch`.
 *
 * What the SERVER actually sends (recorded from the real handlers, `test/fixtures/edge-contract.json`; the plan's table differs, the server wins):
 *
 * | situation                              | HTTP  | body                                                  | answer handed to the outbox machine  |
 * |----------------------------------------|-------|-------------------------------------------------------|--------------------------------------|
 * | new submission, or an identical replay | 200   | `{data:{status:"accepted",evidenceId,replay,play}}`   | `response 200 code "accepted"`       |
 * | catalog newer than the server's        | 202   | `{data:{status:"queued_catalog",evidenceId}}`         | `response 202 code "queued_catalog"` |
 * | replay of a row the 7-day drain gave up| 200   | `{data:{status:"needs_attention",evidenceId}}`        | `response 200 code "needs_attention"`|
 * | changed replay (same fix, other bytes) | 409   | `{error:{code:"evidence_conflict"}}`                  | `response 409 code "evidence_conflict"` (dead letter) |
 * | catalog too old / revoked kid          | 422   | `{error:{code:"catalog_stale"}}`                      | `response 422 code "catalog_stale"` (re-match) |
 * | rate limit                             | 429   | `{error:{code:"rate_limited",details:{retryAfterSeconds}}}` | `response 429` + `retryAfterSeconds` |
 * | any other 4xx                          | 4xx   | `{error:{code,message,details?}}`                     | `response <status> code <verbatim>`  |
 * | 5xx / gateway page                     | 5xx   | anything                                              | `response <status>`                  |
 *
 * `code` for a success is the body's own `data.status`; an error's is the server's `error.code`, VERBATIM (the machine keeps it as
 * `lastServerCode`). A 2xx with an unreadable body gets no code, which the machine files as `unexpected_status` (visible, never silently accepted).
 *
 * `POST evidence-batch` answers 200 for the request and puts the outcome of each item in `data.results[i]` as `{ok:true,result:{status,...}}` or
 * `{ok:false,error:{code,message,details?}}` (a rate-limited item has `details.retryAfterSeconds`, honoured by `batchItemAnswer`): there is NO per-item HTTP status. `batchItemAnswer` derives the status an item's error would have had
 * as a single request from its `code` (`BATCH_CODE_STATUS`, built from `_shared/http.ts` `Errors.*` and the codes the handler throws): an
 * INFERENCE, kept to the codes the server defines; an unknown code becomes 422 (dead letter: visible, never retried blindly).
 */
import { z } from "zod";
import type { ServerAnswer } from "../outbox";
import { errorEnvelopeSchema, successEnvelopeSchema } from "./schemas";
import { retryAfterSecondsFrom } from "./retry-after";

export interface RawHttp {
  status: number;
  headers: Pick<Headers, "get">;
  text: string;
}

const statusDataSchema = z.object({ status: z.string() });

export function answerFromHttp(res: RawHttp): ServerAnswer {
  let json: unknown;
  try {
    json = JSON.parse(res.text);
  } catch {
    json = undefined;
  }
  if (res.status >= 200 && res.status < 300) {
    const outer = successEnvelopeSchema.safeParse(json);
    const data = outer.success ? statusDataSchema.safeParse(outer.data.data) : null;
    return { kind: "response", status: res.status, code: data && data.success ? data.data.status : undefined };
  }
  const env = errorEnvelopeSchema.safeParse(json);
  const details = env.success ? env.data.error.details : undefined;
  const retryAfter = retryAfterSecondsFrom({ headers: res.headers as Headers }, details);
  return {
    kind: "response",
    status: res.status,
    code: env.success ? env.data.error.code : undefined,
    ...(retryAfter !== null ? { retryAfterSeconds: retryAfter } : {}),
  };
}

/** HTTP status each batch-item error code has as a single request (`_shared/http.ts`, `evidence/handler.ts`, `batch-handler.ts`). */
export const BATCH_CODE_STATUS: Readonly<Record<string, number>> = {
  bad_request: 400,
  unauthorized: 401,
  forbidden: 403,
  not_found: 404,
  payload_too_large: 413,
  unsupported_media_type: 415,
  evidence_conflict: 409,
  catalog_stale: 422,
  catalog_forged: 422,
  unknown_id: 422,
  facility_course_mismatch: 422,
  device_limit_exceeded: 422,
  local_date_mismatch: 422,
  local_date_out_of_window: 422,
  rate_limited: 429,
  internal_error: 500,
  service_unavailable: 503,
};

const batchItemSchema = z.object({
  index: z.number().int().nonnegative(),
  ok: z.boolean(),
  result: z.object({ status: z.string() }).loose().optional(),
  error: z.object({ code: z.string(), details: z.unknown().optional() }).loose().optional(),
});
const batchDataSchema = z.object({ results: z.array(batchItemSchema) });

const NO_HEADERS = new Headers();

function batchItemAnswer(item: z.infer<typeof batchItemSchema>): ServerAnswer {
  if (item.ok && item.result) {
    // `accepted` / `needs_attention` are 200s and `queued_catalog` is a 202 in the single-request endpoint: the same pairs.
    return { kind: "response", status: item.result.status === "queued_catalog" ? 202 : 200, code: item.result.status };
  }
  if (!item.ok && item.error) {
    // A rate-limited item carries the same wait hint as the single endpoint's 429, under `error.details.retryAfterSeconds` (batch-item-result.ts). There is no
    // per-item header, so only the envelope's details are read.
    const retryAfter = retryAfterSecondsFrom({ headers: NO_HEADERS }, item.error.details);
    return { kind: "response", status: BATCH_CODE_STATUS[item.error.code] ?? 422, code: item.error.code, ...(retryAfter !== null ? { retryAfterSeconds: retryAfter } : {}) };
  }
  return { kind: "network_error", message: "evidence-batch: an item result had neither a result nor an error" };
}

/** One answer per item of the request (`count` items, in request order). A whole-request failure (non-200) gives every item that same answer; a
 * 200 whose body is not the contract's gives every item `network_error` (a retry: replays are idempotent); an item the response does not mention is
 * a `network_error` for that item alone. */
export function answersFromBatchHttp(res: RawHttp, count: number): ServerAnswer[] {
  if (res.status !== 200) return Array.from({ length: count }, () => answerFromHttp(res));
  let json: unknown;
  try {
    json = JSON.parse(res.text);
  } catch {
    json = undefined;
  }
  const outer = successEnvelopeSchema.safeParse(json);
  const data = outer.success ? batchDataSchema.safeParse(outer.data.data) : null;
  if (!data || !data.success) return Array.from({ length: count }, () => ({ kind: "network_error", message: "evidence-batch: unexpected response shape" }) as ServerAnswer);
  const out: ServerAnswer[] = Array.from({ length: count }, () => ({ kind: "network_error", message: "evidence-batch: no result for this item" }) as ServerAnswer);
  const seen = new Set<number>();
  for (const item of data.data.results) {
    if (item.index >= count || seen.has(item.index)) continue; // out of range or duplicated: never trusted
    seen.add(item.index);
    out[item.index] = batchItemAnswer(item);
  }
  return out;
}
