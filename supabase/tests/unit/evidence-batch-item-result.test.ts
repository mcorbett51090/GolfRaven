// supabase/tests/unit/evidence-batch-item-result.test.ts
//
// The per-item result builders of POST /v1/evidence/batch: a rate-limited item carries `error.details.retryAfterSeconds`, the same shape as the
// single endpoint's 429 (`Errors.tooManyRequests(...).toResponse()` -> `error.details.retryAfterSeconds`). The end-to-end cell against the real
// limiter is in supabase/tests/integration/evidence-batch.deno.test.ts.

import { describe, expect, it } from "vitest";
import { Errors } from "../../functions/_shared/http.js";
import { rateLimitedItem, toErrorResult } from "../../functions/_shared/evidence/batch-item-result.js";

describe("evidence-batch per-item errors", () => {
  it("a rate-limited item carries retryAfterSeconds under error.details, like the single endpoint's 429", async () => {
    const item = rateLimitedItem(3, "evidence-batch daily rate limit exceeded", 86400);
    expect(item).toEqual({ index: 3, ok: false, error: { code: "rate_limited", message: "evidence-batch daily rate limit exceeded", details: { retryAfterSeconds: 86400 } } });
    const single = await Errors.tooManyRequests("x", 86400).toResponse().json();
    expect(single.error.details).toEqual(item.error!.details);
  });

  it("omits details when the limiter named no hint (never a NaN or a string)", () => {
    expect(rateLimitedItem(0, "m", undefined).error).toEqual({ code: "rate_limited", message: "m" });
    expect(rateLimitedItem(0, "m", Number.NaN).error).toEqual({ code: "rate_limited", message: "m" });
  });

  it("an HttpError 429 raised inside an item keeps its hint; other HttpErrors carry no details; an unexpected error is opaque", () => {
    expect(toErrorResult(1, Errors.tooManyRequests("slow down", 60)).error).toEqual({ code: "rate_limited", message: "slow down", details: { retryAfterSeconds: 60 } });
    expect(toErrorResult(1, Errors.tooManyRequests("slow down")).error).toEqual({ code: "rate_limited", message: "slow down" });
    expect(toErrorResult(2, Errors.unprocessable("unknown_id", "no", { retryAfterSeconds: 5 })).error).toEqual({ code: "unknown_id", message: "no" });
    expect(toErrorResult(4, new Error("boom"))).toEqual({ index: 4, ok: false, error: { code: "internal_error", message: "internal error" } });
  });
});
