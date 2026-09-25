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
  probeControlHost,
  runLinkChecks,
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
    ["2001:0:4136:e378::1", true, "Teredo 2001::/32 (RFC 4380 tunneling)"],
    ["2001::1", true, "Teredo 2001::/32, minimal form"],
    ["2001:db8::1", false, "documentation-only 2001:db8::/32 is NOT Teredo (distinct prefix, g1=0xdb8 != 0)"],
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
  it("ok:false (any OTHER status/reason) => 'dead'", () => {
    expect(classifyResult({ ok: false, status: 404 })).toBe("dead");
    expect(classifyResult({ ok: false, status: 500 })).toBe("dead");
    expect(classifyResult({ ok: false, status: null, reason: "too-many-redirects" })).toBe("dead");
    expect(classifyResult({ ok: false, status: 301, reason: "redirect-no-location" })).toBe("dead");
  });
  it("gate review S4b: 401, 403 and 429 => 'blocked' (inconclusive), never 'dead'", () => {
    expect(classifyResult({ ok: false, status: 401 })).toBe("blocked");
    expect(classifyResult({ ok: false, status: 403 })).toBe("blocked");
    expect(classifyResult({ ok: false, status: 429 })).toBe("blocked");
  });
  it("a NEIGHBOURING status (400, 404, 451) is NOT folded into 'blocked'", () => {
    expect(classifyResult({ ok: false, status: 400 })).toBe("dead");
    expect(classifyResult({ ok: false, status: 404 })).toBe("dead");
    expect(classifyResult({ ok: false, status: 451 })).toBe("dead");
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
  it("a network-unreachable error (undici's own .cause.code shape) => 'no-network' — but ENOTFOUND is NOT one of these (re-gate R1)", () => {
    expect(classifyError(Object.assign(new Error("fetch failed"), { cause: { code: "ECONNREFUSED" } }))).toBe(
      "no-network",
    );
    expect(classifyError(Object.assign(new Error("fetch failed"), { cause: { code: "ENETUNREACH" } }))).toBe(
      "no-network",
    );
    expect(classifyError(Object.assign(new Error("fetch failed"), { cause: { code: "EAI_AGAIN" } }))).toBe(
      "no-network",
    );
    expect(classifyError(new Error("EGRESS_BLOCKED by sandbox proxy"))).toBe("no-network");
    // Re-gate R1 (blocking): ENOTFOUND used to be folded into "no-network"
    // here too — that was the regression. A resolver that POSITIVELY
    // answers "no such domain" is telling us the DOMAIN is dead, not that
    // the network is unreachable; see the next test.
    expect(classifyError(Object.assign(new Error("fetch failed"), { cause: { code: "ENOTFOUND" } }))).not.toBe(
      "no-network",
    );
  });
  it("gate review R1 (blocking correction of S4a): a real assertPublicHost-shaped ENOTFOUND (NXDOMAIN) => 'dead', NEVER 'no-network'", () => {
    // The EXACT shape `assertPublicHost()` throws:
    // `Object.assign(new Error(\`dns-fail:${e.code}\`), { code: e.code })` —
    // `.code` lives on the error object itself, not folded only into the
    // message text.
    //
    // R1 repro: `node scripts/check-links.mjs --live --demo` — the first
    // link (ridge-overlook.example.com) fails DNS with ENOTFOUND, and the
    // OLD code classified that as "no-network", aborting the whole run
    // ("no network reachable ... stopping") instead of recording ONE dead
    // link and checking the rest of the catalog.
    expect(classifyError(Object.assign(new Error("dns-fail:ENOTFOUND"), { code: "ENOTFOUND" }))).toBe("dead");
  });
  it("gate review R1: EAI_AGAIN (the resolver itself unreachable/timed out — NOT 'no such name') is still 'no-network'", () => {
    expect(classifyError(Object.assign(new Error("dns-fail:EAI_AGAIN"), { code: "EAI_AGAIN" }))).toBe(
      "no-network",
    );
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

  it("gate review S4b: a 403/429 from an allowed host classifies as 'blocked', not 'dead' — end-to-end through checkLink()", async () => {
    for (const status of [401, 403, 429]) {
      const fetchImpl = async () => fakeResponse(status);
      const record = await checkLink(link, ALLOWED, 1000, { fetchImpl, assertPublicHost: noopAssertPublicHost });
      expect(record.classification).toBe("blocked");
      expect(record.status).toBe(status);
    }
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

// ---------------------------------------------------------------------
// Re-gate R1 (blocking): `probeControlHost` + `runLinkChecks`'s
// abort-vs-continue decision. "Add tests: NXDOMAIN on the first link lets
// the run continue and classes it `dead`; the control succeeding means no
// abort; the control failing means abort." All three, plus
// `probeControlHost` in direct isolation, below — every one injects a fake
// `fetchImpl`/`assertPublicHost`, no real network or DNS.
// ---------------------------------------------------------------------

describe("probeControlHost (pure decision logic — no network)", () => {
  const CONTROL = "www.golfnow.com";

  it("the control host resolving/responding successfully => true (network is reachable)", async () => {
    const fetchImpl = async () => fakeResponse(200);
    const ok = await probeControlHost(CONTROL, 1000, { fetchImpl, assertPublicHost: noopAssertPublicHost });
    expect(ok).toBe(true);
  });

  it("the control host failing for a NON-network reason (e.g. 404) => still true — that's not this checker's network being down", async () => {
    const fetchImpl = async () => fakeResponse(404);
    const ok = await probeControlHost(CONTROL, 1000, { fetchImpl, assertPublicHost: noopAssertPublicHost });
    expect(ok).toBe(true);
  });

  it("the control host itself failing with a no-network-shaped error => false (network really is unreachable)", async () => {
    const assertPublicHost = async () => {
      throw Object.assign(new Error("dns-fail:EAI_AGAIN"), { code: "EAI_AGAIN" });
    };
    const fetchImpl = async () => fakeResponse(200); // never reached — assertPublicHost throws first
    const ok = await probeControlHost(CONTROL, 1000, { fetchImpl, assertPublicHost });
    expect(ok).toBe(false);
  });

  it("no control host configured => false, fail closed (nothing to probe)", async () => {
    const fetchImpl = async () => fakeResponse(200);
    const ok = await probeControlHost(null, 1000, { fetchImpl, assertPublicHost: noopAssertPublicHost });
    expect(ok).toBe(false);
  });
});

describe("runLinkChecks abort-vs-continue (re-gate R1, blocking)", () => {
  const CONFIGURED_HOSTS = ["www.golfnow.com"];
  function makeLink(url: string, overrides: Partial<Record<string, unknown>> = {}) {
    return {
      facilitySlug: "test-course",
      facilityName: "Test Course",
      facilityUrl: null,
      trail: null,
      provider: "golfnow",
      url,
      checkedAt: "2026-01-01",
      ...overrides,
    };
  }

  it("R1 repro: NXDOMAIN on the FIRST link classifies it 'dead' and the run CONTINUES to check every remaining link (never aborts)", async () => {
    const links = [
      makeLink("https://ridge-overlook.example.com/book"), // this file's own repro host — never allow-listed for real, but the assertPublicHost DNS failure fires before the allow-list check even matters here since it's injected directly below
      makeLink("https://www.golfnow.com/example/test-course"),
    ];
    // Allow-list both hosts so the SECOND link's own allow-list check
    // never masks whether checking continued.
    const allowList = ["ridge-overlook.example.com", "www.golfnow.com"];
    let assertCalls = 0;
    const assertPublicHost = async (hostname: string) => {
      assertCalls += 1;
      if (hostname === "ridge-overlook.example.com") {
        throw Object.assign(new Error("dns-fail:ENOTFOUND"), { code: "ENOTFOUND" });
      }
      // second link's host resolves fine
    };
    const fetchImpl = async () => fakeResponse(200);
    const { results, networkUnreachable, controlHost } = await runLinkChecks(
      links,
      allowList,
      1000,
      { fetchImpl, assertPublicHost },
    );
    expect(networkUnreachable).toBe(false);
    expect(controlHost).toBe(null);
    expect(results).toHaveLength(2);
    expect(results[0].classification).toBe("dead");
    expect(results[0].detail).toBe("nxdomain");
    expect(results[1].classification).toBe("ok");
    // ENOTFOUND on the first link is never even eligible for a control
    // probe (only a "no-network" classification triggers one) — so
    // assertPublicHost is called exactly once per link, never a 3rd time
    // for a control host.
    expect(assertCalls).toBe(2);
  });

  it("first link classifies 'no-network' AND the control host succeeds => NO abort, every link still gets checked", async () => {
    const links = [
      makeLink("https://www.golfnow.com/example/test-course"),
      makeLink("https://www.golfnow.com/example/second-course"),
    ];
    let call = 0;
    const assertPublicHost = async () => {
      call += 1;
      if (call === 1) {
        // first link's own resolution: no-network-shaped
        throw Object.assign(new Error("dns-fail:EAI_AGAIN"), { code: "EAI_AGAIN" });
      }
      // the control-host probe (call 2) and the second link (call 3) both resolve fine
    };
    const fetchImpl = async () => fakeResponse(200);
    const { results, networkUnreachable, controlHost } = await runLinkChecks(
      links,
      CONFIGURED_HOSTS,
      1000,
      { fetchImpl, assertPublicHost },
    );
    expect(networkUnreachable).toBe(false);
    expect(controlHost).toBe(null);
    expect(results).toHaveLength(2);
    expect(results[0].classification).toBe("no-network");
    // The run continued past the first link's own no-network finding and
    // checked the second link too.
    expect(results[1].classification).toBe("ok");
    expect(call).toBe(3); // link 1, control probe, link 2
  });

  it("first link classifies 'no-network' AND the control host ALSO fails => abort, only the first link's finding is returned", async () => {
    const links = [
      makeLink("https://www.golfnow.com/example/test-course"),
      makeLink("https://www.golfnow.com/example/second-course"),
    ];
    let secondLinkChecked = false;
    const assertPublicHost = async () => {
      throw Object.assign(new Error("dns-fail:EAI_AGAIN"), { code: "EAI_AGAIN" });
    };
    const fetchImpl = async (url: string) => {
      if (url.includes("second-course")) secondLinkChecked = true;
      return fakeResponse(200);
    };
    const { results, networkUnreachable, controlHost } = await runLinkChecks(
      links,
      CONFIGURED_HOSTS,
      1000,
      { fetchImpl, assertPublicHost },
    );
    expect(networkUnreachable).toBe(true);
    expect(controlHost).toBe("www.golfnow.com");
    expect(results).toHaveLength(1);
    expect(results[0].classification).toBe("no-network");
    expect(secondLinkChecked).toBe(false);
  });

  it("a no-network classification on a link OTHER than the first does NOT trigger a control probe or abort", async () => {
    const links = [
      makeLink("https://www.golfnow.com/example/test-course"),
      makeLink("https://www.golfnow.com/example/second-course"),
    ];
    let call = 0;
    const assertPublicHost = async () => {
      call += 1;
      if (call === 2) {
        throw Object.assign(new Error("dns-fail:EAI_AGAIN"), { code: "EAI_AGAIN" });
      }
    };
    const fetchImpl = async () => fakeResponse(200);
    const { results, networkUnreachable } = await runLinkChecks(links, CONFIGURED_HOSTS, 1000, {
      fetchImpl,
      assertPublicHost,
    });
    expect(networkUnreachable).toBe(false);
    expect(results).toHaveLength(2);
    expect(results[0].classification).toBe("ok");
    expect(results[1].classification).toBe("no-network");
    // Only 2 assertPublicHost calls (one per link) — no control probe was made.
    expect(call).toBe(2);
  });

  it("onResult is called once per checked link, in order, with the running index", async () => {
    const links = [makeLink("https://www.golfnow.com/example/a"), makeLink("https://www.golfnow.com/example/b")];
    const fetchImpl = async () => fakeResponse(200);
    const seen: Array<[string, number]> = [];
    await runLinkChecks(links, CONFIGURED_HOSTS, 1000, { fetchImpl, assertPublicHost: noopAssertPublicHost }, (record, i) => {
      seen.push([record.classification as string, i]);
    });
    expect(seen).toEqual([
      ["ok", 0],
      ["ok", 1],
    ]);
  });
});
