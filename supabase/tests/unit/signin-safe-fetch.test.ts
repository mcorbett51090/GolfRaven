import { describe, expect, it } from "vitest";
import { VendorUnavailableError } from "../../functions/_shared/signin/errors.ts";
import { createSafeFetcher, parseJsonObject } from "../../functions/_shared/signin/safe-fetch.ts";
import { fakeFetch, json } from "./signin-test-helpers.ts";

const code = async (p: Promise<unknown>) => {
  try {
    await p;
  } catch (e) {
    if (e instanceof VendorUnavailableError) return e.code;
    throw e;
  }
  return "no_error";
};

const mk = (routes: Parameters<typeof fakeFetch>[0], over: Partial<Parameters<typeof createSafeFetcher>[0]> = {}) => {
  const f = fakeFetch(routes);
  return { ...f, safe: createSafeFetcher({ fetch: f.fetch, allowedHosts: ["appleid.apple.com"], timeoutMs: 200, maxBytes: 1024, ...over }) };
};

describe("createSafeFetcher: the allow-list", () => {
  it("allows the listed host and sends redirect: 'error' with an abort signal", async () => {
    const { safe, calls } = mk({ "GET https://appleid.apple.com/x": () => json(200, { ok: true }) });
    const res = await safe("https://appleid.apple.com/x", { method: "GET" });
    expect(res.status).toBe(200);
    expect(calls[0]!.init.redirect).toBe("error");
    expect(calls[0]!.init.signal).toBeInstanceOf(AbortSignal);
  });

  it.each([
    "http://appleid.apple.com/x",
    "https://appleid.apple.com.evil.test/x",
    "https://evil.test/#@appleid.apple.com",
    "https://evil.test/?appleid.apple.com",
    "https://appleid.apple.com@evil.test/x",
    "https://user:pw@appleid.apple.com/x",
    "https://appleid.apple.com:8443/x",
    "https://sub.appleid.apple.com/x",
    "ftp://appleid.apple.com/x",
    "not a url",
    "//appleid.apple.com/x",
  ])("refuses %s before any request is made", async (url) => {
    const { safe, calls } = mk({});
    expect(await code(safe(url, { method: "GET" }))).toMatch(/host_not_allowed|bad_url/);
    expect(calls).toHaveLength(0);
  });

  it("the host match is case-insensitive on the URL side and exact on the list", async () => {
    const { safe } = mk({ "GET https://appleid.apple.com/x": () => json(200, {}) });
    await expect(safe("https://AppleID.Apple.COM/x", { method: "GET" })).resolves.toMatchObject({ status: 200 });
  });
});

describe("createSafeFetcher: failure containment", () => {
  it("a redirect is never followed: a 3xx status, and a fetch that rejects on redirect: 'error'", async () => {
    const { safe } = mk({ "GET https://appleid.apple.com/r": () => new Response(null, { status: 302, headers: { location: "https://evil.test/" } }) });
    expect(await code(safe("https://appleid.apple.com/r", { method: "GET" }))).toBe("redirect");
    const { safe: safe2 } = mk({
      "GET https://appleid.apple.com/r2": () => {
        throw new TypeError("fetch failed: unexpected redirect");
      },
    });
    expect(await code(safe2("https://appleid.apple.com/r2", { method: "GET" }))).toBe("redirect");
  });

  it("times out (the abort signal fires) and reports timeout, not network", async () => {
    const { safe } = mk(
      {
        "GET https://appleid.apple.com/slow": (_u, init) =>
          new Promise<Response>((_res, rej) => {
            init.signal.addEventListener("abort", () => rej(new DOMException("aborted", "AbortError")));
          }),
      },
      { timeoutMs: 30 },
    );
    expect(await code(safe("https://appleid.apple.com/slow", { method: "GET" }))).toBe("timeout");
  });

  it("a plain network failure is 'network'", async () => {
    const { safe } = mk({
      "GET https://appleid.apple.com/down": () => {
        throw new TypeError("connection refused");
      },
    });
    expect(await code(safe("https://appleid.apple.com/down", { method: "GET" }))).toBe("network");
  });

  it("enforces the size cap on the STREAM, not just on Content-Length", async () => {
    const big = "x".repeat(5000);
    const { safe } = mk({ "GET https://appleid.apple.com/big": () => new Response(big, { status: 200 }) });
    expect(await code(safe("https://appleid.apple.com/big", { method: "GET" }))).toBe("too_large");
    const lie = new Response(big, { status: 200, headers: { "content-length": "10" } });
    const { safe: safe2 } = mk({ "GET https://appleid.apple.com/lie": () => lie });
    expect(await code(safe2("https://appleid.apple.com/lie", { method: "GET" }))).toBe("too_large");
    const honest = new Response("ok", { status: 200, headers: { "content-length": "99999" } });
    const { safe: safe3 } = mk({ "GET https://appleid.apple.com/decl": () => honest });
    expect(await code(safe3("https://appleid.apple.com/decl", { method: "GET" }))).toBe("too_large");
  });

  it("invalid UTF-8 in the body is malformed, and the body never appears in an error", async () => {
    const { safe } = mk({ "GET https://appleid.apple.com/bin": () => new Response(new Uint8Array([0xff, 0xfe, 0xfd]), { status: 200 }) });
    expect(await code(safe("https://appleid.apple.com/bin", { method: "GET" }))).toBe("malformed_response");
    const secretBody = "refresh_token=SECRET-TOKEN-VALUE";
    const { safe: safe2 } = mk({ "GET https://appleid.apple.com/e": () => new Response(secretBody, { status: 500 }) });
    const res = await safe2("https://appleid.apple.com/e", { method: "GET" });
    expect(res.status).toBe(500); // the CALLER decides; the wrapper itself never throws a body
  });

  it("passes the method, headers and body through", async () => {
    const { safe, calls } = mk({ "POST https://appleid.apple.com/p": () => json(200, {}) });
    await safe("https://appleid.apple.com/p", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: "a=b" });
    expect(calls[0]!.init.method).toBe("POST");
    expect(calls[0]!.init.body).toBe("a=b");
    expect(calls[0]!.init.headers["content-type"]).toBe("application/x-www-form-urlencoded");
  });
});

describe("parseJsonObject", () => {
  it("returns objects only", () => {
    expect(parseJsonObject('{"a":1}')).toEqual({ a: 1 });
    for (const bad of ["[1]", "1", '"s"', "null", "nope", ""]) expect(parseJsonObject(bad)).toBeNull();
  });
});
