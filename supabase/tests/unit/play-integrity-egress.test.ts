// supabase/tests/unit/play-integrity-egress.test.ts
//
// The Play Integrity decoder's EGRESS GUARD (K11): the same protections the DeviceCheck client (`devicecheck-egress.test.ts`) and the sign-in
// modules (`signin-safe-fetch.test.ts`) apply — an in-code allow-list of the exact Google hosts, `redirect: "error"`, and a wall-clock bound —
// on BOTH calls the adapter makes (the OAuth token POST, which carries the signed service-account assertion, and `decodeIntegrityToken`, which
// carries the integrity token). Every Google response here is invented (`[unverified]`; no Google credential or route in this environment);
// what is proved is what the CLIENT sends and refuses, and that a refusal is a retryable 503-class error (`VendorUnavailableError`), never a
// clean reading.

import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import {
  createIntegrityDecoder,
  isAllowedPlayIntegrityUrl,
  PLAY_INTEGRITY_ALLOWED_HOSTS,
  type PlayIntegrityConfig,
  type PlayIntegrityEndpoints,
} from "../../functions/_shared/rewards/play-integrity-client.js";
import { VendorNotConfiguredError, VendorUnavailableError } from "../../functions/_shared/rewards/types.js";
import type { VendorHttp } from "../../functions/_shared/rewards/vendor-http.js";
import { toB64 } from "./rewards-test-crypto.js";

interface Call {
  url: string;
  init: Parameters<VendorHttp["fetch"]>[1];
}

const PAYLOAD = { requestDetails: { requestHash: "h" } };
const tokenOk = () => new Response(JSON.stringify({ access_token: "ya29.test", expires_in: 3600 }), { status: 200 });
const payloadOk = () =>
  new Response(JSON.stringify({ tokenPayloadExternal: PAYLOAD }), {
    status: 200,
  });
const flagged = (r: Response): Response => {
  Object.defineProperty(r, "redirected", { value: true });
  return r;
};

/** A scripted `VendorHttp`: `respond` sees each call (and may reject); the default answers the OAuth exchange, then the decode. */
function http(
  over: Partial<VendorHttp> & {
    respond?: (c: Call, n: number) => Promise<Response>;
  } = {},
): VendorHttp & { calls: Call[] } {
  const calls: Call[] = [];
  const { respond, ...rest } = over;
  return {
    calls,
    timeoutMs: 1_000,
    nowMs: () => 1_780_000_000_000,
    randomUuid: () => "00000000-0000-4000-8000-000000000001",
    fetch: async (url, init) => {
      calls.push({ url, init });
      if (respond) return respond({ url, init }, calls.length - 1);
      return url.includes("oauth2") ? tokenOk() : payloadOk();
    },
    ...rest,
  };
}

// Fences assembled at run time: no source line carries a literal PEM header (gitleaks' private-key rule would read one; nothing here is a key).
const FENCE = "-".repeat(5);
const block = (body: string) => `${FENCE}BEGIN PRIVATE KEY${FENCE}\n${body}\n${FENCE}END PRIVATE KEY${FENCE}`;

let rsaPem: string;
beforeAll(async () => {
  const kp = (await crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  rsaPem = block(toB64(new Uint8Array(await crypto.subtle.exportKey("pkcs8", kp.privateKey))).replace(/(.{64})/g, "$1\n"));
}, 30_000);

const cfg = (over: Partial<PlayIntegrityConfig> = {}): PlayIntegrityConfig => ({
  packageName: "com.example.golfraven",
  certificateSha256Digests: ["AAAA"],
  serviceAccountEmail: "svc@example.iam.gserviceaccount.test",
  serviceAccountPrivateKeyPem: rsaPem,
  ...over,
});

const evilToken: PlayIntegrityEndpoints = {
  tokenUrl: "https://oauth2.googleapis.com.evil.test/token",
  apiBase: "https://playintegrity.googleapis.com",
};
const evilApi: PlayIntegrityEndpoints = {
  tokenUrl: "https://oauth2.googleapis.com/token",
  apiBase: "https://evil.test",
};

describe("the Play Integrity host allow-list", () => {
  it("is exactly Google's OAuth host and the Play Integrity API host", () => {
    expect([...PLAY_INTEGRITY_ALLOWED_HOSTS].sort()).toEqual(["oauth2.googleapis.com", "playintegrity.googleapis.com"]);
  });

  it("allows the two exact hosts over https (hostname case is not significant)", () => {
    for (const u of [
      "https://oauth2.googleapis.com/token",
      "https://playintegrity.googleapis.com/v1/com.example.golfraven:decodeIntegrityToken",
      "https://OAUTH2.GOOGLEAPIS.COM/token",
      "https://PlayIntegrity.GoogleAPIs.com/v1/x:decodeIntegrityToken",
    ]) {
      expect(isAllowedPlayIntegrityUrl(u), u).toBe(true);
    }
  });

  it("refuses everything else: other hosts, other Google hosts, look-alikes, userinfo, a port, a non-https scheme, junk", () => {
    const refused = [
      "https://evil.test/token",
      "https://www.googleapis.com/auth/playintegrity", // the OAuth SCOPE is a name, not an endpoint
      "https://accounts.google.com/o/oauth2/token", // another Google host is not a Play Integrity host
      "https://googleapis.com/token",
      "https://appleid.apple.com/auth/token",
      "https://oauth2.googleapis.com.evil.test/token",
      "https://playintegrity.googleapis.com.evil.test/v1/x:decodeIntegrityToken",
      "https://evil.googleapis.com/token",
      "https://xoauth2.googleapis.com/token",
      "https://oauth2.googleapis.com@evil.test/token",
      "https://evil.test/#@oauth2.googleapis.com",
      "https://evil.test/?h=playintegrity.googleapis.com",
      "https://user:pw@oauth2.googleapis.com/token",
      "https://user@oauth2.googleapis.com/token", // username only
      "https://:pw@oauth2.googleapis.com/token", // password only
      "https://oauth2.googleapis.com:8443/token",
      "http://oauth2.googleapis.com/token",
      "ftp://oauth2.googleapis.com/token",
      "//oauth2.googleapis.com/token",
      "oauth2.googleapis.com/token",
      "undefined/v1/x:decodeIntegrityToken",
      "",
    ];
    for (const u of refused) expect(isAllowedPlayIntegrityUrl(u), u).toBe(false);
  });
});

describe("the Play Integrity decoder's egress behaviour", () => {
  it('sends BOTH calls (the OAuth exchange and the decode) to an allow-listed host over https with redirect:"error" and an abort signal', async () => {
    const h = http();
    await createIntegrityDecoder(cfg(), h).decode("INTEGRITYTOKEN");
    expect(h.calls).toHaveLength(2);
    expect(h.calls.map((c) => new URL(c.url).hostname)).toEqual(["oauth2.googleapis.com", "playintegrity.googleapis.com"]);
    for (const { url, init } of h.calls) {
      expect(isAllowedPlayIntegrityUrl(url), url).toBe(true);
      expect(init.redirect).toBe("error");
      expect(init.signal).toBeInstanceOf(AbortSignal);
      expect(init.method).toBe("POST");
    }
  });

  it("refuses an OAuth host that is not on the allow-list BEFORE signing or sending anything (a retryable 503-class error)", async () => {
    const h = http();
    await expect(createIntegrityDecoder(cfg(), h, evilToken).decode("T")).rejects.toBeInstanceOf(VendorUnavailableError);
    expect(h.calls).toEqual([]);
  });

  it("refuses a decode host that is not on the allow-list BEFORE the OAuth exchange: no assertion is signed, no request is made", async () => {
    const h = http();
    await expect(createIntegrityDecoder(cfg(), h, evilApi).decode("T")).rejects.toBeInstanceOf(VendorUnavailableError);
    expect(h.calls).toEqual([]);
  });

  it("checks the host BEFORE anything is signed: a refused host never reads the clock (the assertion's `iat`), whatever the key", async () => {
    for (const [endpoints, privateKey] of [
      [evilToken, rsaPem],
      [evilToken, "not a pem at all"],
      [evilApi, rsaPem],
      [evilApi, "not a pem at all"],
    ] as const) {
      let clock = 0;
      const h = http({ nowMs: () => (clock++, 1_780_000_000_000) });
      // a refused host wins over an unusable key: Unavailable (host), not NotConfigured (key), and neither signing nor a request happens
      await expect(createIntegrityDecoder(cfg({ serviceAccountPrivateKeyPem: privateKey }), h, endpoints).decode("T")).rejects.toBeInstanceOf(VendorUnavailableError);
      expect([clock, h.calls.length]).toEqual([0, 0]);
    }
    // and for allowed hosts the clock IS read (the guard above is observing something real)
    let clock = 0;
    await createIntegrityDecoder(cfg(), http({ nowMs: () => (clock++, 1_780_000_000_000) })).decode("T");
    expect(clock).toBeGreaterThan(0);
  });

  it("refuses a redirect on the OAuth exchange: a rejected fetch, a flagged redirected response and a 3xx are all unavailable, and the decode is never reached", async () => {
    const cases: Array<() => Promise<Response>> = [
      () => Promise.reject(new TypeError("fetch failed: redirect mode is set to error")),
      () => Promise.resolve(flagged(tokenOk())),
      () =>
        Promise.resolve(
          new Response(null, {
            status: 307,
            headers: { location: "https://evil.test/" },
          }),
        ),
      () =>
        Promise.resolve(
          new Response(null, {
            status: 308,
            headers: { location: "https://evil.test/" },
          }),
        ),
    ];
    for (const respond of cases) {
      const h = http({ respond });
      await expect(createIntegrityDecoder(cfg(), h).decode("T")).rejects.toBeInstanceOf(VendorUnavailableError);
      expect(h.calls).toHaveLength(1);
    }
  });

  it("refuses a redirect on the DECODE: a rejected fetch, a flagged redirected response and a 3xx are all unavailable, never read as a payload", async () => {
    const cases: Array<() => Promise<Response>> = [
      () => Promise.reject(new TypeError("fetch failed: redirect mode is set to error")),
      () => Promise.resolve(flagged(payloadOk())), // a valid body that arrived via a followed redirect is NOT trusted as an answer
      () =>
        Promise.resolve(
          new Response(null, {
            status: 302,
            headers: { location: "https://evil.test/" },
          }),
        ),
    ];
    for (const decodeResponse of cases) {
      const h = http({
        respond: ({ url }) => (url.includes("oauth2") ? Promise.resolve(tokenOk()) : decodeResponse()),
      });
      await expect(createIntegrityDecoder(cfg(), h).decode("T")).rejects.toBeInstanceOf(VendorUnavailableError);
    }
    // the control: the same body, not flagged, is read normally
    expect(await createIntegrityDecoder(cfg(), http()).decode("T")).toEqual(PAYLOAD);
  });

  it("a flagged-redirected OAuth answer is not cached: the next decode starts a fresh exchange rather than reusing a token that arrived via a redirect", async () => {
    let oauthCalls = 0;
    const h = http({
      respond: ({ url }) => {
        if (url.includes("oauth2")) return Promise.resolve(++oauthCalls === 1 ? flagged(tokenOk()) : tokenOk());
        return Promise.resolve(payloadOk());
      },
    });
    const decoder = createIntegrityDecoder(cfg(), h);
    await expect(decoder.decode("A")).rejects.toBeInstanceOf(VendorUnavailableError);
    expect(await decoder.decode("B")).toEqual(PAYLOAD);
    expect(oauthCalls).toBe(2);
  });

  it("is time-bounded on both calls: a hanging call is aborted at timeoutMs and reported as unavailable", async () => {
    for (const hangOn of ["oauth2", "playintegrity"] as const) {
      let seen: AbortSignal | undefined;
      const h = http({
        timeoutMs: 25,
        respond: ({ url, init }) => {
          if (!url.includes(hangOn)) return Promise.resolve(url.includes("oauth2") ? tokenOk() : payloadOk());
          return new Promise<Response>((_res, rej) => {
            seen = init.signal;
            init.signal.addEventListener("abort", () => rej(new Error("aborted")));
          });
        },
      });
      await expect(createIntegrityDecoder(cfg(), h).decode("T"), hangOn).rejects.toBeInstanceOf(VendorUnavailableError);
      expect(seen?.aborted, hangOn).toBe(true);
    }
  });

  it("a refusal is never a clean reading and never leaks a secret into its message", async () => {
    const err = await createIntegrityDecoder(
      cfg(),
      http({
        respond: () => Promise.reject(new TypeError("redirect mode is set to error")),
      }),
    )
      .decode("SECRETINTEGRITYTOKEN")
      .then(
        () => null,
        (e: unknown) => e as Error,
      );
    expect(err).toBeInstanceOf(VendorUnavailableError);
    expect(String(err!.message)).not.toContain("SECRETINTEGRITYTOKEN");
    expect(String(err!.message)).not.toMatch(/eyJ/);
  });

  it("an unconfigured decoder still FAILS CLOSED as not configured, and never reaches the host check or the network", async () => {
    const h = http();
    await expect(createIntegrityDecoder(null, h, evilApi).decode("T")).rejects.toBeInstanceOf(VendorNotConfiguredError);
    expect(h.calls).toEqual([]);
  });

  it("no production call site passes the `endpoints` override (it exists for the tests above only)", () => {
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
    // Balanced-parenthesis scan (the same one `devicecheck-egress.test.ts` uses): finds every `createIntegrityDecoder(` and counts the TOP-LEVEL
    // arguments of that call (nested calls, arrays, objects and template literals with commas inside do not add arguments). Its bound: it does not
    // parse strings or comments, so an unbalanced parenthesis inside a string literal in an argument could mislead it; no such call exists, and
    // the self-test below proves the counter on shapes.
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
    expect(topLevelArgs("f(google, http, endpoints)", 1)).toBe(3);
    expect(topLevelArgs("f(a, { x: 1, y: (2, 3) })", 1)).toBe(2);
    expect(topLevelArgs("f()", 1)).toBe(0);
    const sites = files.flatMap((f) => {
      const src = readFileSync(f, "utf8");
      return [...src.matchAll(/createIntegrityDecoder\(/g)].map((m) => ({
        f,
        args: topLevelArgs(src, m.index! + m[0].length - 1),
      }));
    });
    const calls = sites.filter((s) => !s.f.endsWith("play-integrity-client.ts"));
    expect(calls.length).toBeGreaterThan(0);
    for (const s of calls) expect(s.args, s.f).toBe(2);
  });
});
