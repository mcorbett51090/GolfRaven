// supabase/tests/unit/devicecheck-egress.test.ts
//
// The DeviceCheck client's EGRESS GUARD: the same protections the sign-in modules apply to Apple (`signin/safe-fetch.ts`, `signin-safe-fetch.test.ts`)
// — an in-code allow-list of the exact DeviceCheck hosts, `redirect: "error"`, and a wall-clock bound — plus the shared PEM parser's key forms.
// Every vendor response here is invented (`[unverified]`; no Apple credential or route in this environment); what is proved is what the CLIENT sends
// and refuses, and that a refusal is a retryable 503-class error (`VendorUnavailableError`), never a clean reading.

import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import { createDeviceCheckClient, DEVICECHECK_ALLOWED_HOSTS, isAllowedDeviceCheckUrl, type DeviceCheckConfig } from "../../functions/_shared/rewards/devicecheck-client.js";
import { VendorNotConfiguredError, VendorUnavailableError } from "../../functions/_shared/rewards/types.js";
import type { VendorHttp } from "../../functions/_shared/rewards/vendor-http.js";
import { toB64 } from "./rewards-test-crypto.js";

interface Call {
  url: string;
  init: Parameters<VendorHttp["fetch"]>[1];
}

function http(over: Partial<VendorHttp> & { respond?: (c: Call) => Promise<Response> } = {}): VendorHttp & { calls: Call[] } {
  const calls: Call[] = [];
  const { respond, ...rest } = over;
  return {
    calls,
    timeoutMs: 1_000,
    nowMs: () => 1_780_000_000_000,
    randomUuid: () => "00000000-0000-4000-8000-000000000001",
    fetch: async (url, init) => {
      calls.push({ url, init });
      return respond ? respond({ url, init }) : new Response('{"bit0":false,"bit1":false}', { status: 200 });
    },
    ...rest,
  };
}

// Fences assembled at run time: no source line carries a literal PEM header (gitleaks' private-key rule would read one; nothing here is a key).
const FENCE = "-".repeat(5);
const block = (body: string) => `${FENCE}BEGIN PRIVATE KEY${FENCE}\n${body}\n${FENCE}END PRIVATE KEY${FENCE}`;

let p8: string;
beforeAll(async () => {
  const kp = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const b64 = toB64(new Uint8Array(await crypto.subtle.exportKey("pkcs8", kp.privateKey))).replace(/(.{64})/g, "$1\n");
  p8 = block(b64);
}, 30_000);

const cfg = (over: Partial<DeviceCheckConfig> = {}): DeviceCheckConfig => ({ teamId: "T", keyId: "K", privateKeyPem: p8, environment: "production", ...over });

describe("the DeviceCheck host allow-list", () => {
  it("is exactly the two Apple DeviceCheck API hosts", () => {
    expect([...DEVICECHECK_ALLOWED_HOSTS].sort()).toEqual(["api.development.devicecheck.apple.com", "api.devicecheck.apple.com"]);
  });

  it("allows the two exact hosts over https (hostname case is not significant)", () => {
    for (const u of ["https://api.devicecheck.apple.com/v1/query_two_bits", "https://api.development.devicecheck.apple.com/v1/update_two_bits", "https://API.DEVICECHECK.APPLE.COM/v1/query_two_bits"]) {
      expect(isAllowedDeviceCheckUrl(u), u).toBe(true);
    }
  });

  it("refuses everything else: other hosts, look-alikes, userinfo, a port, a non-https scheme, junk", () => {
    const refused = [
      "https://evil.test/v1/query_two_bits",
      "https://appleid.apple.com/v1/query_two_bits", // another Apple host (the Sign in with Apple one) is not a DeviceCheck host
      "https://api.devicecheck.apple.com.evil.test/v1/query_two_bits",
      "https://evil.apple.com/v1/query_two_bits",
      "https://xapi.devicecheck.apple.com/v1/query_two_bits",
      "https://api.devicecheck.apple.com@evil.test/v1/query_two_bits",
      "https://evil.test/#@api.devicecheck.apple.com",
      "https://evil.test/?h=api.devicecheck.apple.com",
      "https://user:pw@api.devicecheck.apple.com/v1/query_two_bits",
      "https://user@api.devicecheck.apple.com/v1/query_two_bits", // username only
      "https://:pw@api.devicecheck.apple.com/v1/query_two_bits", // password only
      "https://api.devicecheck.apple.com:8443/v1/query_two_bits",
      "http://api.devicecheck.apple.com/v1/query_two_bits",
      "ftp://api.devicecheck.apple.com/v1/query_two_bits",
      "//api.devicecheck.apple.com/v1/query_two_bits",
      "api.devicecheck.apple.com/v1/query_two_bits",
      "undefined/v1/query_two_bits",
      "",
    ];
    for (const u of refused) expect(isAllowedDeviceCheckUrl(u), u).toBe(false);
  });
});

describe("the DeviceCheck client's egress behaviour", () => {
  it("sends every call to an allow-listed host over https with redirect:\"error\" and an abort signal, in both environments and for both methods", async () => {
    for (const environment of ["production", "development"] as const) {
      const h = http();
      const c = createDeviceCheckClient(cfg({ environment }), h);
      await c.queryTwoBits("dG9rZW4=");
      await c.updateTwoBits("dG9rZW4=", { bit0: true, bit1: false });
      expect(h.calls).toHaveLength(2);
      for (const { url, init } of h.calls) {
        expect(isAllowedDeviceCheckUrl(url), url).toBe(true);
        expect(new URL(url).hostname).toBe(environment === "production" ? "api.devicecheck.apple.com" : "api.development.devicecheck.apple.com");
        expect(init.redirect).toBe("error");
        expect(init.signal).toBeInstanceOf(AbortSignal);
        expect(init.method).toBe("POST");
      }
    }
  });

  it("refuses a host that is not on the allow-list BEFORE signing anything or sending a request (a retryable 503-class error)", async () => {
    const h = http();
    const evil = { production: "https://evil.test", development: "https://api.devicecheck.apple.com.evil.test" };
    for (const environment of ["production", "development"] as const) {
      const c = createDeviceCheckClient(cfg({ environment }), h, evil);
      await expect(c.queryTwoBits("dG9rZW4=")).rejects.toBeInstanceOf(VendorUnavailableError);
      await expect(c.updateTwoBits("dG9rZW4=", { bit0: true, bit1: false })).rejects.toBeInstanceOf(VendorUnavailableError);
    }
    expect(h.calls).toEqual([]);
  });

  it("checks the host BEFORE anything is signed: a refused host never reads the clock (the JWT's `iat`) or draws a transaction id, whatever the key", async () => {
    const evil = { production: "https://evil.test", development: "https://evil.test" };
    for (const privateKeyPem of [p8, "not a pem at all"]) {
      let clock = 0;
      let uuid = 0;
      const h = http({ nowMs: () => (clock++, 1_780_000_000_000), randomUuid: () => (uuid++, "00000000-0000-4000-8000-000000000001") });
      // a refused host wins over an unusable key: Unavailable (host), not NotConfigured (key), and neither signing nor the request happens
      await expect(createDeviceCheckClient(cfg({ privateKeyPem }), h, evil).queryTwoBits("dG9rZW4=")).rejects.toBeInstanceOf(VendorUnavailableError);
      expect([clock, uuid, h.calls.length]).toEqual([0, 0, 0]);
    }
    // and for an allowed host the clock IS read (the guard above is observing something real)
    let clock = 0;
    await createDeviceCheckClient(cfg(), http({ nowMs: () => (clock++, 1_780_000_000_000) })).queryTwoBits("dG9rZW4=");
    expect(clock).toBeGreaterThan(0);
  });

  it("refuses a redirect: a rejected fetch (redirect:\"error\"), a flagged redirected response and a 3xx are all unavailable, never read as a body", async () => {
    const redirected = new Response('{"bit0":false,"bit1":false}', { status: 200 });
    Object.defineProperty(redirected, "redirected", { value: true });
    const cases: Array<() => Promise<Response>> = [
      () => Promise.reject(new TypeError("fetch failed: redirect mode is set to error")),
      () => Promise.resolve(redirected),
      () => Promise.resolve(new Response(null, { status: 302, headers: { location: "https://evil.test/" } })),
    ];
    for (const respond of cases) {
      const c = createDeviceCheckClient(cfg(), http({ respond }));
      await expect(c.queryTwoBits("dG9rZW4=")).rejects.toBeInstanceOf(VendorUnavailableError);
    }
  });

  it("a response flagged redirected is refused for BOTH calls even when its body is valid (a followed redirect is never trusted as an answer)", async () => {
    const flagged = () => {
      const r = new Response('{"bit0":true,"bit1":false,"last_update_time":"2026-10"}', { status: 200 });
      Object.defineProperty(r, "redirected", { value: true });
      return Promise.resolve(r);
    };
    const c = createDeviceCheckClient(cfg(), http({ respond: flagged }));
    await expect(c.queryTwoBits("dG9rZW4=")).rejects.toBeInstanceOf(VendorUnavailableError);
    await expect(c.updateTwoBits("dG9rZW4=", { bit0: true, bit1: false })).rejects.toBeInstanceOf(VendorUnavailableError);
    // the control: the same body, not flagged, is read normally
    const ok = createDeviceCheckClient(cfg(), http({ respond: () => Promise.resolve(new Response('{"bit0":true,"bit1":false,"last_update_time":"2026-10"}', { status: 200 })) }));
    expect((await ok.queryTwoBits("dG9rZW4=")).bit0).toBe(true);
  });

  it("is time-bounded: a hanging call is aborted at timeoutMs and reported as unavailable", async () => {
    let seen: AbortSignal | undefined;
    const h = http({
      timeoutMs: 25,
      respond: ({ init }) =>
        new Promise<Response>((_res, rej) => {
          seen = init.signal;
          init.signal.addEventListener("abort", () => rej(new Error("aborted")));
        }),
    });
    const c = createDeviceCheckClient(cfg(), h);
    await expect(c.queryTwoBits("dG9rZW4=")).rejects.toBeInstanceOf(VendorUnavailableError);
    expect(seen?.aborted).toBe(true);
  });

  it("no production call site passes the `hosts` override (it exists for the test above only)", () => {
    const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "functions");
    const files: string[] = [];
    const walk = (d: string) => {
      for (const n of readdirSync(d)) {
        const f = join(d, n);
        if (statSync(f).isDirectory()) walk(f);
        else if (f.endsWith(".ts")) files.push(f);
      }
    };
    walk(root);
    // Balanced-parenthesis scan: finds every `createDeviceCheckClient(` and counts the TOP-LEVEL arguments of that call (nested calls, arrays,
    // objects and template literals with commas inside do not add arguments). Its bound: it does not parse strings or comments, so an unbalanced
    // parenthesis inside a string literal in an argument could mislead it; no such call exists, and the self-test below proves the counter on shapes.
    const topLevelArgs = (src: string, open: number): number => {
      let depth = 0;
      let args = 0;
      let seen = false;
      for (let i = open; i < src.length; i++) {
        const ch = src[i]!;
        if (ch === "(" || ch === "[" || ch === "{") {
          if (depth++ === 0 && ch === "(") continue;
        } else if (ch === ")" || ch === "]" || ch === "}") {
          if (--depth === 0) return seen ? args + 1 : 0;
        } else if (ch === "," && depth === 1) args++;
        if (depth >= 1 && !/\s/.test(ch) && !(depth === 1 && ch === ",")) seen = true;
      }
      return -1;
    };
    expect(topLevelArgs("f(a, g(b, c), [d, e])", 1)).toBe(3);
    expect(topLevelArgs("f(apple, http, hosts)", 1)).toBe(3);
    expect(topLevelArgs("f(a, { x: 1, y: (2, 3) })", 1)).toBe(2);
    expect(topLevelArgs("f()", 1)).toBe(0);
    const sites = files.flatMap((f) => {
      const src = readFileSync(f, "utf8");
      return [...src.matchAll(/createDeviceCheckClient\(/g)].map((m) => ({ f, args: topLevelArgs(src, m.index! + m[0].length - 1) }));
    });
    const calls = sites.filter((s) => !s.f.endsWith("devicecheck-client.ts"));
    expect(calls.length).toBeGreaterThan(0);
    for (const s of calls) expect(s.args, s.f).toBe(2);
  });
});

describe("the DeviceCheck client accepts the shared PEM forms", () => {
  const forms: Record<string, (pem: string) => string> = {
    "real newlines": (p) => p,
    "CRLF line breaks": (p) => p.replace(/\n/g, "\r\n"),
    "one line with a literal backslash-n": (p) => p.replace(/\n/g, "\\n"),
    "surrounding whitespace": (p) => `\n  ${p}\n\n`,
  };
  for (const [name, mk] of Object.entries(forms)) {
    it(`signs and sends with a key given as: ${name}`, async () => {
      const h = http();
      await createDeviceCheckClient(cfg({ privateKeyPem: mk(p8) }), h).queryTwoBits("dG9rZW4=");
      expect(h.calls).toHaveLength(1);
      expect(h.calls[0]!.init.headers.authorization).toMatch(/^Bearer [\w-]+\.[\w-]+\.[\w-]+$/);
    });
  }

  it("a malformed PEM stays NOT CONFIGURED (a 503-class error): never a crash, and nothing is sent", async () => {
    const bad = ["", "   ", "nope", block("!!!"), `${FENCE}BEGIN PRIVATE KEY${FENCE}\\nAAAA`, p8.replace("END PRIVATE", "END PUBLIC"), `${p8}\n${p8}`, `${p8}junk`];
    for (const privateKeyPem of bad) {
      const h = http();
      await expect(createDeviceCheckClient(cfg({ privateKeyPem }), h).queryTwoBits("dG9rZW4="), JSON.stringify(privateKeyPem).slice(0, 40)).rejects.toBeInstanceOf(VendorNotConfiguredError);
      expect(h.calls).toEqual([]);
    }
  });
});
