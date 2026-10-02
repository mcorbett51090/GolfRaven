/**
 * `createFetchBytes` (LOW-9): a whole-request timeout, a streamed byte cap
 * that cancels the body, and no redirects. Driven with a fake `fetch`, so the
 * limits are proved without a network.
 */
import { describe, expect, it } from "vitest";
import { createFetchBytes } from "../src/catalog/manager";

const URL_ = "https://catalog.test/catalog/v1/manifest.json";

/** A body that yields `chunks` chunks of `size` bytes and counts how many were pulled. */
function streamBody(chunks: number, size: number): { body: ReadableStream<Uint8Array>; pulled: () => number; cancelled: () => boolean } {
  let n = 0;
  let cancelled = false;
  const body = new ReadableStream<Uint8Array>({
    pull(c) {
      if (n >= chunks) return c.close();
      n += 1;
      c.enqueue(new Uint8Array(size));
    },
    cancel() {
      cancelled = true;
    },
  });
  return { body, pulled: () => n, cancelled: () => cancelled };
}

const fakeFetch = (make: (url: string, init: RequestInit) => Response | Promise<Response>): typeof fetch =>
  ((url: string, init: RequestInit) => Promise.resolve(make(url, init))) as unknown as typeof fetch;

describe("createFetchBytes", () => {
  it("returns the body and etag of a normal response, and asks fetch to refuse redirects", async () => {
    let seen: RequestInit | undefined;
    const f = createFetchBytes(
      fakeFetch((_u, init) => {
        seen = init;
        return new Response(new Uint8Array([1, 2, 3]), { status: 200, headers: { etag: '"x"' } });
      }),
    );
    const r = await f(URL_, { maxBytes: 100, etag: '"old"' });
    expect(r).toEqual({ status: 200, bytes: new Uint8Array([1, 2, 3]), etag: '"x"' });
    expect(seen?.redirect).toBe("error");
    expect((seen?.headers as Record<string, string>)["If-None-Match"]).toBe('"old"');
    expect(seen?.signal).toBeInstanceOf(AbortSignal);
  });

  it("a 304 has no body", async () => {
    const f = createFetchBytes(fakeFetch(() => new Response(null, { status: 304, headers: { etag: '"x"' } })));
    expect(await f(URL_, { maxBytes: 10 })).toEqual({ status: 304, bytes: new Uint8Array(0), etag: '"x"' });
  });

  it("aborts a stream the moment it exceeds maxBytes: the body is cancelled, not downloaded in full", async () => {
    const s = streamBody(1000, 1024);
    const f = createFetchBytes(fakeFetch(() => new Response(s.body, { status: 200 })));
    await expect(f(URL_, { maxBytes: 4096 })).rejects.toThrow(/exceeds 4096/);
    expect(s.cancelled()).toBe(true);
    expect(s.pulled()).toBeLessThan(20); // nowhere near the 1000 chunks on offer
  });

  it("accepts a stream that is exactly maxBytes", async () => {
    const s = streamBody(4, 1024);
    const f = createFetchBytes(fakeFetch(() => new Response(s.body, { status: 200 })));
    expect((await f(URL_, { maxBytes: 4096 })).bytes).toHaveLength(4096);
  });

  it("refuses a declared content-length above the cap before reading anything", async () => {
    const s = streamBody(1, 10);
    const f = createFetchBytes(fakeFetch(() => new Response(s.body, { status: 200, headers: { "content-length": "9999" } })));
    await expect(f(URL_, { maxBytes: 100 })).rejects.toThrow(/content-length 9999 exceeds 100/);
    expect(s.cancelled()).toBe(true);
    expect(s.pulled()).toBeLessThan(3); // only the stream's own read-ahead, never consumed
  });

  it("times out a request that never answers (the AbortController fires)", async () => {
    const f = createFetchBytes(
      ((_u: string, init: RequestInit) =>
        new Promise((_res, rej) => {
          init.signal?.addEventListener("abort", () => rej(new DOMException("aborted", "AbortError")));
        })) as unknown as typeof fetch,
    );
    await expect(f(URL_, { maxBytes: 100, timeoutMs: 25 })).rejects.toThrow(/timed out after 25 ms/);
  });

  it("times out a body that stalls after the headers", async () => {
    const f = createFetchBytes(
      ((_u: string, init: RequestInit) => {
        const body = new ReadableStream<Uint8Array>({
          start(c) {
            c.enqueue(new Uint8Array(4));
            init.signal?.addEventListener("abort", () => c.error(new DOMException("aborted", "AbortError")));
          },
        });
        return Promise.resolve(new Response(body, { status: 200 }));
      }) as unknown as typeof fetch,
    );
    await expect(f(URL_, { maxBytes: 100, timeoutMs: 25 })).rejects.toThrow(/timed out after 25 ms/);
  });

  it("refuses a response that reports it was redirected", async () => {
    const res = new Response(new Uint8Array(1), { status: 200 });
    Object.defineProperty(res, "redirected", { value: true });
    const f = createFetchBytes(fakeFetch(() => res));
    await expect(f(URL_, { maxBytes: 10 })).rejects.toThrow(/redirected/);
  });

  it("refuses a response whose final URL is another origin (a runtime that ignores redirect: 'error')", async () => {
    const res = new Response(new Uint8Array(1), { status: 200 });
    Object.defineProperty(res, "url", { value: "https://evil.test/catalog/v1/manifest.json" });
    const f = createFetchBytes(fakeFetch(() => res));
    await expect(f(URL_, { maxBytes: 10 })).rejects.toThrow(/another origin/);
  });

  it("accepts a same-origin final URL", async () => {
    const res = new Response(new Uint8Array(1), { status: 200 });
    Object.defineProperty(res, "url", { value: URL_ });
    expect((await createFetchBytes(fakeFetch(() => res))(URL_, { maxBytes: 10 })).bytes).toHaveLength(1);
  });

  it("falls back to arrayBuffer where the runtime has no body stream, still enforcing the cap", async () => {
    const res = { status: 200, headers: new Headers(), body: null, redirected: false, url: "", arrayBuffer: () => Promise.resolve(new ArrayBuffer(50)) } as unknown as Response;
    const f = createFetchBytes(fakeFetch(() => res));
    expect((await f(URL_, { maxBytes: 50 })).bytes).toHaveLength(50);
    await expect(f(URL_, { maxBytes: 49 })).rejects.toThrow(/exceeds 49/);
  });
});
