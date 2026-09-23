import { afterEach, describe, expect, it, vi } from "vitest";
import {
  buildAsciiUserAgent,
  classifyFetchRejection,
  fetchWithBlockDetection,
  hostFromUrl,
  isPolicyBlockedResponse,
} from "../src/net.js";

describe("net: buildAsciiUserAgent", () => {
  const ENV_VAR = "NET_TEST_CONTACT";
  afterEach(() => {
    delete process.env[ENV_VAR];
  });

  it("is pure ASCII by default and Headers accepts it", () => {
    delete process.env[ENV_VAR];
    const ua = buildAsciiUserAgent({
      toolTag: "GolfRaven-Test/0.1",
      docRef: "docs/p0/TEST.md",
      envVarName: ENV_VAR,
    });
    expect(ua).toMatch(/^[\x20-\x7E]+$/);
    expect(() => new Headers({ "User-Agent": ua })).not.toThrow();
  });

  it("throws a clear, pointed error on a non-Latin-1 contact", () => {
    process.env[ENV_VAR] = "reachme — see profile";
    expect(() =>
      buildAsciiUserAgent({
        toolTag: "GolfRaven-Test/0.1",
        docRef: "docs/p0/TEST.md",
        envVarName: ENV_VAR,
      }),
    ).toThrow(/Latin-1/);
  });

  it("uses the env var's contact when set", () => {
    process.env[ENV_VAR] = "test@example.com";
    const ua = buildAsciiUserAgent({
      toolTag: "GolfRaven-Test/0.1",
      docRef: "docs/p0/TEST.md",
      envVarName: ENV_VAR,
    });
    expect(ua).toContain("test@example.com");
  });
});

describe("net: hostFromUrl", () => {
  it("extracts the host", () => {
    expect(hostFromUrl("https://www.tnstateparks.com/golf?x=1")).toBe(
      "www.tnstateparks.com",
    );
  });
  it("falls back to the raw string on an unparseable URL", () => {
    expect(hostFromUrl("not a url")).toBe("not a url");
  });
});

describe("net: isPolicyBlockedResponse", () => {
  it("true for a 403 with the proxy's x-deny-reason header", () => {
    const headers = new Headers({ "x-deny-reason": "host_not_allowed" });
    expect(isPolicyBlockedResponse(403, headers, "")).toBe(true);
  });
  it("true for a 403 whose body says the host is not in the allowlist, even without the header", () => {
    const headers = new Headers();
    expect(
      isPolicyBlockedResponse(
        403,
        headers,
        "Host not in allowlist: www.tnstateparks.com.",
      ),
    ).toBe(true);
  });
  it("false for a 403 that is just the destination site's own access-denied page", () => {
    const headers = new Headers({ "content-type": "text/html" });
    expect(isPolicyBlockedResponse(403, headers, "<html>Access Denied</html>")).toBe(
      false,
    );
  });
  it("false for a non-403 status", () => {
    const headers = new Headers({ "x-deny-reason": "host_not_allowed" });
    expect(isPolicyBlockedResponse(404, headers, "")).toBe(false);
  });
});

describe("net: classifyFetchRejection", () => {
  it("classifies a nested CONNECT-tunnel-403 cause chain as blocked (this session's NODE_USE_ENV_PROXY=1 shape)", () => {
    const inner = new Error("Proxy response (403) !== 200 when HTTP Tunneling");
    const middle = new DOMException("Request was cancelled.", "AbortError");
    Object.defineProperty(middle, "cause", { value: inner, enumerable: true });
    const outer = new TypeError("fetch failed", { cause: middle });
    const result = classifyFetchRejection(outer);
    expect(result.blocked).toBe(true);
    expect(result.detail).toContain("403");
  });

  it("classifies a plain curl-style 'CONNECT tunnel failed, response 403' message as blocked", () => {
    const result = classifyFetchRejection(
      new Error("CONNECT tunnel failed, response 403"),
    );
    expect(result.blocked).toBe(true);
  });

  it("does NOT classify a generic network error (e.g. DNS failure) as a policy block", () => {
    const result = classifyFetchRejection(new Error("getaddrinfo ENOTFOUND example.invalid"));
    expect(result.blocked).toBe(false);
  });

  it("does not loop forever on a self-referential cause chain", () => {
    const err = new Error("outer");
    err.cause = err;
    expect(() => classifyFetchRejection(err)).not.toThrow();
  });
});

describe("net: fetchWithBlockDetection", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("returns kind 'ok' for a normal successful response", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response("hello", { status: 200 })),
    );
    const outcome = await fetchWithBlockDetection("https://example.com/", {});
    expect(outcome.kind).toBe("ok");
    if (outcome.kind === "ok") {
      expect(outcome.response.status).toBe(200);
    }
  });

  it("returns kind 'blocked' when fetch resolves to the proxy's own 403 denial page", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response("Host not in allowlist: www.tnstateparks.com.", {
            status: 403,
            headers: { "x-deny-reason": "host_not_allowed" },
          }),
      ),
    );
    const outcome = await fetchWithBlockDetection(
      "https://www.tnstateparks.com/golf",
      {},
    );
    expect(outcome.kind).toBe("blocked");
    if (outcome.kind === "blocked") {
      expect(outcome.host).toBe("www.tnstateparks.com");
      expect(outcome.detail).toContain("403");
    }
  });

  it("returns kind 'blocked' when fetch REJECTS with a CONNECT-tunnel 403 error", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new Error("CONNECT tunnel failed, response 403");
      }),
    );
    const outcome = await fetchWithBlockDetection("https://overpass-api.de/api/interpreter", {});
    expect(outcome.kind).toBe("blocked");
    if (outcome.kind === "blocked") {
      expect(outcome.host).toBe("overpass-api.de");
    }
  });

  it("returns kind 'ok' (status 403 passed through, not classified as blocked) for the destination site's own 403", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response("<html>Access Denied</html>", { status: 403 }),
      ),
    );
    const outcome = await fetchWithBlockDetection("https://example.com/", {});
    expect(outcome.kind).toBe("ok");
    if (outcome.kind === "ok") {
      expect(outcome.response.status).toBe(403);
    }
  });

  it("returns kind 'error' for a non-blocked thrown error", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new Error("getaddrinfo ENOTFOUND example.invalid");
      }),
    );
    const outcome = await fetchWithBlockDetection("https://example.invalid/", {});
    expect(outcome.kind).toBe("error");
  });
});
