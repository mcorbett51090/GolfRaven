import { vi } from "vitest";

/**
 * Routes a stubbed global `fetch` by URL prefix, so a single test can
 * exercise both the Turnstile siteverify call and the Resend send call
 * without caring about call order.
 */
export function stubExternalFetch(options: {
  turnstileOk?: boolean;
  resendOk?: boolean;
}): ReturnType<typeof vi.fn> {
  const { turnstileOk = true, resendOk = true } = options;
  const fn = vi.fn(async (input: RequestInfo | URL) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    if (url.includes("challenges.cloudflare.com")) {
      return turnstileOk
        ? new Response(JSON.stringify({ success: true }), { status: 200 })
        : new Response(JSON.stringify({ success: false, "error-codes": ["invalid-input-response"] }), {
            status: 200,
          });
    }
    if (url.includes("api.resend.com")) {
      return resendOk
        ? new Response(JSON.stringify({ id: "re_test_123" }), { status: 200 })
        : new Response(JSON.stringify({ message: "send failed" }), { status: 500 });
    }
    throw new Error(`stubExternalFetch: unexpected fetch to ${url}`);
  });
  vi.stubGlobal("fetch", fn);
  return fn;
}

export function resendCalls(fetchMock: ReturnType<typeof vi.fn>): unknown[] {
  return fetchMock.mock.calls.filter((call) => {
    const input = call[0] as RequestInfo | URL;
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    return url.includes("api.resend.com");
  });
}
