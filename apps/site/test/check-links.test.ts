/**
 * check-links.test.ts — unit coverage for `scripts/check-links.mjs`'s
 * SSRF-hardening functions (Opus gate should-fix, "check-links") AND its
 * classification logic (this task's scope item 2: "Unit-test the
 * checker's classification logic with injected fetch responses. No
 * network in tests."). Lives in `apps/site/test/` (imported by relative
 * path) because `scripts/check-links.mjs` is a repo-root ops script with
 * no workspace package of its own — this is still `pnpm -r test`
 * coverage for it, just hosted in the one package whose test runner
 * already exists.
 */
import { describe, expect, it } from "vitest";
import {
  checkLink,
  classifyError,
  classifyResult,
  expandIPv6,
  hardenedCheck,
  isPrivateIp,
  isPrivateIpv6,
  isPrivateV4,
} from "../../../scripts/check-links.mjs";

describe("check-links.mjs SSRF hardening: isPrivateV4 / isPrivateIp", () => {
  it.each([
    ["127.0.0.1", true],
    ["10.0.0.5", true],
    ["172.16.0.1", true],
    ["192.168.1.1", true],
    ["169.254.169.254", true], // cloud metadata
    ["100.64.0.1", true], // CGNAT
    ["0.0.0.0", true],
    ["224.0.0.1", true], // multicast
    ["8.8.8.8", false],
    ["1.1.1.1", false],
    ["203.0.113.5", false],
  ])("isPrivateV4(%s) => %s", (ip, expected) => {
    expect(isPrivateV4(ip)).toBe(expected);
  });

  it.each([
    ["::1", true],
    ["fe80::1", true],
    ["fc00::1", true],
    ["fd12:3456::1", true],
    ["::ffff:127.0.0.1", true], // v4-mapped loopback
    ["::ffff:8.8.8.8", false], // v4-mapped public
    ["2001:4860:4860::8888", false], // public v6 (Google DNS)
  ])("isPrivateIp(%s) => %s", (ip, expected) => {
    expect(isPrivateIp(ip)).toBe(expected);
  });

  it("an unparseable IPv4-looking string is treated as UNSAFE (fail closed)", () => {
    expect(isPrivateV4("not-an-ip")).toBe(true);
  });
});

describe("check-links.mjs SSRF hardening: isPrivateIpv6 — every range the re-gate named", () => {
  it.each([
    ["::", true, "unspecified"],
    ["::1", true, "loopback"],
    ["fe80::1", true, "link-local fe80::/10"],
    ["fec0::1", true, "site-local fec0::/10 (deprecated)"],
    ["fc00::1", true, "unique-local fc00::/7"],
    ["fd12:3456::1", true, "unique-local fc00::/7 (fd range)"],
    ["ff02::1", true, "multicast ff00::/8"],
    ["ff00::", true, "multicast ff00::/8 (base)"],
    ["64:ff9b::10.0.0.1", true, "NAT64 64:ff9b::/96 wrapping a PRIVATE v4"],
    ["64:ff9b::8.8.8.8", false, "NAT64 64:ff9b::/96 wrapping a PUBLIC v4"],
    ["2002:0a00:0001::", true, "6to4 2002::/16 wrapping a PRIVATE v4 (10.0.0.1)"],
    ["2002:0808:0808::", false, "6to4 2002::/16 wrapping a PUBLIC v4 (8.8.8.8)"],
    ["::0.0.0.0", true, "v4-compatible ::/96 (deprecated) wrapping 0.0.0.0"],
    ["::10.0.0.1", true, "v4-compatible ::/96 (deprecated) wrapping a PRIVATE v4"],
    ["::8.8.8.8", false, "v4-compatible ::/96 (deprecated) wrapping a PUBLIC v4"],
    ["::ffff:127.0.0.1", true, "v4-mapped ::ffff:0:0/96 wrapping loopback"],
    ["::ffff:8.8.8.8", false, "v4-mapped ::ffff:0:0/96 wrapping a PUBLIC v4"],
    ["2001:4860:4860::8888", false, "public v6 (Google DNS) — not in any reserved range"],
  ])("isPrivateIpv6(%s) => %s (%s)", (ip, expected) => {
    expect(isPrivateIpv6(ip)).toBe(expected);
  });

  it("expandIPv6 correctly expands '::'-compressed and embedded-IPv4 forms", () => {
    expect(expandIPv6("::1")).toEqual([0, 0, 0, 0, 0, 0, 0, 1]);
    expect(expandIPv6("::")).toEqual([0, 0, 0, 0, 0, 0, 0, 0]);
    expect(expandIPv6("2001:db8::1")).toEqual([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1]);
    expect(expandIPv6("::ffff:1.2.3.4")).toEqual([0, 0, 0, 0, 0, 0xffff, 0x0102, 0x0304]);
    expect(expandIPv6("64:ff9b::1.2.3.4")).toEqual([0x64, 0xff9b, 0, 0, 0, 0, 0x0102, 0x0304]);
  });

  it("an unparseable IPv6-looking string is treated as UNSAFE (fail closed)", () => {
    expect(expandIPv6("not-an-ipv6")).toBe(null);
    expect(isPrivateIpv6("not-an-ipv6")).toBe(true);
  });

  it("isPrivateIp dispatches IPv4 vs IPv6 correctly (no ':' => v4 path)", () => {
    expect(isPrivateIp("8.8.8.8")).toBe(false);
    expect(isPrivateIp("2001:4860:4860::8888")).toBe(false);
  });
});

// ---------------------------------------------------------------------
// Classification logic (this task's scope item 2: "Unit-test the
// checker's classification logic with injected fetch responses. No
// network in tests."). Every test below injects BOTH `fetchImpl` (a fake
// standing in for undici's `fetch`) and a no-op `assertPublicHost` into
// `hardenedCheck()`/`checkLink()` — the real DNS/TCP path is never
// exercised, only the decision logic: allow-list checks, manual-redirect
// following, and how a resolved result or a thrown error maps to one of
// the report's classifications.
// ---------------------------------------------------------------------

/** A minimal stand-in for the undici Response shape `hardenedCheck` reads:
 * `.status`, `.ok`, `.headers.get("location")`, `.body.cancel()`. */
function fakeResponse(status: number, { location }: { location?: string } = {}) {
  return {
    status,
    ok: status >= 200 && status < 300,
    headers: { get: (name: string) => (name.toLowerCase() === "location" ? (location ?? null) : null) },
    body: { cancel: async () => {} },
  };
}

/** No-op — stands in for the real DNS/private-IP pre-flight check so
 * these tests never touch the network. */
async function noopAssertPublicHost() {}

describe("classifyResult (pure — no network)", () => {
  it("ok:true => 'ok'", () => {
    expect(classifyResult({ ok: true, status: 200 })).toBe("ok");
  });
  it("ok:false (any status/reason) => 'dead'", () => {
    expect(classifyResult({ ok: false, status: 404 })).toBe("dead");
    expect(classifyResult({ ok: false, status: 500 })).toBe("dead");
    expect(classifyResult({ ok: false, status: null, reason: "too-many-redirects" })).toBe("dead");
    expect(classifyResult({ ok: false, status: 301, reason: "redirect-no-location" })).toBe("dead");
  });
});

describe("classifyError (pure — no network)", () => {
  it("NOT_ALLOW_LISTED at hop 0 => 'not-allow-listed' (the link's OWN host was never allowed)", () => {
    expect(classifyError({ code: "NOT_ALLOW_LISTED", hop: 0 })).toBe("not-allow-listed");
  });
  it("NOT_ALLOW_LISTED at hop > 0 => 'redirect-off-host' (an allowed host redirected off-list)", () => {
    expect(classifyError({ code: "NOT_ALLOW_LISTED", hop: 1 })).toBe("redirect-off-host");
    expect(classifyError({ code: "NOT_ALLOW_LISTED", hop: 3 })).toBe("redirect-off-host");
  });
  it("a network-unreachable error (undici's own .cause.code shape) => 'no-network'", () => {
    expect(classifyError(Object.assign(new Error("fetch failed"), { cause: { code: "ENOTFOUND" } }))).toBe(
      "no-network",
    );
    expect(classifyError(Object.assign(new Error("fetch failed"), { cause: { code: "ECONNREFUSED" } }))).toBe(
      "no-network",
    );
    expect(classifyError(new Error("EGRESS_BLOCKED by sandbox proxy"))).toBe("no-network");
  });
  it("anything else => 'error'", () => {
    expect(classifyError(new Error("timeout"))).toBe("error");
    expect(classifyError(new Error("bad-scheme:http: (https only)"))).toBe("error");
  });
});

describe("hardenedCheck + checkLink end-to-end, with an injected fetchImpl (no real network/DNS)", () => {
  const ALLOWED = ["www.golfnow.com"];
  const link = {
    facilitySlug: "test-course",
    facilityName: "Test Course",
    facilityUrl: null,
    trail: null,
    provider: "golfnow",
    url: "https://www.golfnow.com/example/test-course",
    checkedAt: "2026-01-01",
  };

  it("a 200 from an allowed host classifies as 'ok'", async () => {
    const fetchImpl = async () => fakeResponse(200);
    const record = await checkLink(link, ALLOWED, 1000, { fetchImpl, assertPublicHost: noopAssertPublicHost });
    expect(record.classification).toBe("ok");
    expect(record.status).toBe(200);
  });

  it("a 404 from an allowed host classifies as 'dead'", async () => {
    const fetchImpl = async () => fakeResponse(404);
    const record = await checkLink(link, ALLOWED, 1000, { fetchImpl, assertPublicHost: noopAssertPublicHost });
    expect(record.classification).toBe("dead");
    expect(record.status).toBe(404);
  });

  it("a redirect chain that STAYS on allowed hosts follows through and classifies the final response", async () => {
    const fetchImpl = async (url: string) => {
      if (url === "https://www.golfnow.com/example/test-course") {
        return fakeResponse(301, { location: "https://www.golfnow.com/example/test-course/" });
      }
      return fakeResponse(200);
    };
    const record = await checkLink(link, ALLOWED, 1000, { fetchImpl, assertPublicHost: noopAssertPublicHost });
    expect(record.classification).toBe("ok");
    expect(record.status).toBe(200);
  });

  it("a link whose OWN host is not on the allow-list classifies as 'not-allow-listed' (never fetched)", async () => {
    let fetchCalled = false;
    const fetchImpl = async () => {
      fetchCalled = true;
      return fakeResponse(200);
    };
    const offListLink = { ...link, url: "https://not-allowed.example.com/book" };
    const record = await checkLink(offListLink, ALLOWED, 1000, {
      fetchImpl,
      assertPublicHost: noopAssertPublicHost,
    });
    expect(record.classification).toBe("not-allow-listed");
    // The gate never even fetches a host that was never allowed.
    expect(fetchCalled).toBe(false);
  });

  it("an ALLOWED host redirecting OFF the allow-list classifies as 'redirect-off-host' — never followed", async () => {
    let followedOffHost = false;
    const fetchImpl = async (url: string) => {
      if (url === "https://www.golfnow.com/example/test-course") {
        return fakeResponse(302, { location: "https://evil-redirect.example.net/steal" });
      }
      followedOffHost = true;
      return fakeResponse(200);
    };
    const record = await checkLink(link, ALLOWED, 1000, { fetchImpl, assertPublicHost: noopAssertPublicHost });
    expect(record.classification).toBe("redirect-off-host");
    // The off-list redirect target was validated and rejected, never fetched.
    expect(followedOffHost).toBe(false);
  });

  it("more than MAX_REDIRECTS (3) hops on allowed hosts classifies as 'dead' (too-many-redirects)", async () => {
    let hops = 0;
    const fetchImpl = async () => {
      hops += 1;
      return fakeResponse(302, { location: "https://www.golfnow.com/example/test-course" });
    };
    const record = await checkLink(link, ALLOWED, 1000, { fetchImpl, assertPublicHost: noopAssertPublicHost });
    expect(record.classification).toBe("dead");
    expect(hops).toBeGreaterThan(1);
  });

  it("a redirect with no Location header classifies as 'dead' (redirect-no-location)", async () => {
    const fetchImpl = async () => fakeResponse(302, {});
    const record = await checkLink(link, ALLOWED, 1000, { fetchImpl, assertPublicHost: noopAssertPublicHost });
    expect(record.classification).toBe("dead");
  });

  it("a host that rejects HEAD (405) is retried as GET on the SAME, already-validated hop", async () => {
    const calls: string[] = [];
    const fetchImpl = async (_url: string, init: { method: string }) => {
      calls.push(init.method);
      if (init.method === "HEAD") return fakeResponse(405);
      return fakeResponse(200);
    };
    const record = await checkLink(link, ALLOWED, 1000, { fetchImpl, assertPublicHost: noopAssertPublicHost });
    expect(record.classification).toBe("ok");
    expect(calls).toEqual(["HEAD", "GET"]);
  });

  it("plain http: (not https:) is refused outright, classified as 'error'", async () => {
    const fetchImpl = async () => fakeResponse(200);
    const httpLink = { ...link, url: "http://www.golfnow.com/example/test-course" };
    const record = await checkLink(httpLink, ALLOWED, 1000, { fetchImpl, assertPublicHost: noopAssertPublicHost });
    expect(record.classification).toBe("error");
    expect(record.detail).toMatch(/https only/);
  });

  it("hardenedCheck itself (not just checkLink) accepts the same injected opts, for direct testing", async () => {
    const fetchImpl = async () => fakeResponse(200);
    const result = await hardenedCheck(link.url, ALLOWED, 1000, {
      fetchImpl,
      assertPublicHost: noopAssertPublicHost,
    });
    expect(result).toEqual({ ok: true, status: 200 });
  });
});
