/** A recording `fetch` stub for client unit tests: every call is kept as `{ url, init }`; the responder decides the answer. */
export interface Recorded {
  readonly url: string;
  readonly init: RequestInit;
  /** headers of the call as a plain lower-case map, and the original key spellings */
  readonly headers: Record<string, string>;
  readonly headerKeys: string[];
}

export function jsonResponse(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });
}

export function stubFetch(responder: (call: Recorded) => Response | Promise<Response>): { fetch: typeof fetch; calls: Recorded[] } {
  const calls: Recorded[] = [];
  const f = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const initObj = init ?? {};
    const keys = Object.keys((initObj.headers ?? {}) as Record<string, string>);
    const headers: Record<string, string> = {};
    new Headers(initObj.headers).forEach((v, k) => {
      headers[k] = v;
    });
    const call: Recorded = { url: String(input), init: initObj, headers, headerKeys: keys };
    calls.push(call);
    return await responder(call);
  }) as typeof fetch;
  return { fetch: f, calls };
}

export const VALID_TOKEN = "gr_ps_" + "A".repeat(43);
