// Client-secret minting (ES256, Web Crypto), the token exchange and the revoke call, against a synthetic Apple.

import { beforeAll, describe, expect, it } from "vitest";
import { AppleGrantError, AppleTokenError, NotConfiguredError, VendorUnavailableError } from "../../functions/_shared/signin/errors.ts";
import { createClientSecretMinter, mintAppleClientSecret, pkcs8PemToDer, CLIENT_SECRET_TTL_SECONDS, type AppleSecretConfig } from "../../functions/_shared/signin/apple-client-secret.ts";
import { APPLE_REVOKE_URL, APPLE_TOKEN_URL, createAppleClient } from "../../functions/_shared/signin/apple-client.ts";
import { createGoogleRevoker, GOOGLE_REVOKE_URL } from "../../functions/_shared/signin/google-client.ts";
import { createSafeFetcher } from "../../functions/_shared/signin/safe-fetch.ts";
import { buildSigninPorts } from "../../functions/_shared/signin/production.ts";
import { APPLE_JWKS_URL } from "../../functions/_shared/signin/apple-id-token.ts";
import { CLIENT_ID, NOW_MS, NOW_SEC, TEAM_ID, decodeJwt, fakeFetch, json, jwksBody, makeP8, makeRsaKey, mintIdentityToken, type TestRsaKey } from "./signin-test-helpers.ts";

let p8: { pem: string; publicKey: CryptoKey };
let appleKey: TestRsaKey;
let cfg: AppleSecretConfig;

beforeAll(async () => {
  p8 = await makeP8();
  appleKey = await makeRsaKey("apple-kid-1");
  cfg = { teamId: TEAM_ID, clientId: CLIENT_ID, keyId: "KEYID12345", privateKeyPem: p8.pem };
});

async function verifyEs256(jwt: string): Promise<boolean> {
  const d = decodeJwt(jwt);
  return crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, p8.publicKey, d.sig.slice().buffer, new TextEncoder().encode(d.signingInput));
}

describe("the Apple client secret (ES256 JWT minted server-side from the .p8)", () => {
  it("mints the documented claim set, signed so the matching public key verifies it", async () => {
    const jwt = await mintAppleClientSecret(cfg, NOW_SEC);
    const d = decodeJwt(jwt);
    expect(d.header).toEqual({ alg: "ES256", kid: "KEYID12345" });
    expect(d.payload).toEqual({ iss: TEAM_ID, iat: NOW_SEC, exp: NOW_SEC + CLIENT_SECRET_TTL_SECONDS, aud: "https://appleid.apple.com", sub: CLIENT_ID });
    expect(d.sig.length).toBe(64); // raw r||s, as a JWS needs
    expect(await verifyEs256(jwt)).toBe(true);
  });

  it("is short-lived (10 minutes, far under Apple's 6-month ceiling)", async () => {
    const d = decodeJwt(await mintAppleClientSecret(cfg, NOW_SEC));
    expect((d.payload.exp as number) - (d.payload.iat as number)).toBeLessThanOrEqual(15_777_000);
    expect((d.payload.exp as number) - (d.payload.iat as number)).toBe(600);
  });

  it("accepts a PEM carried on one line with literal backslash-n (how an environment variable holds it)", async () => {
    const oneLine = p8.pem.replace(/\n/g, "\\n");
    const jwt = await mintAppleClientSecret({ ...cfg, privateKeyPem: oneLine }, NOW_SEC);
    expect(await verifyEs256(jwt)).toBe(true);
  });

  it("caches, and RE-MINTS before expiry (within 2 minutes of exp), never serving an expired secret", async () => {
    let t = NOW_MS;
    const minter = createClientSecretMinter(cfg, () => t);
    const a = await minter.get();
    expect(await minter.get()).toBe(a);
    t += 7 * 60_000; // still > 120 s left of the 600 s life
    expect(await minter.get()).toBe(a);
    t += 60_000; // 8 min in: under 2 min remain -> re-mint
    const b = await minter.get();
    expect(b).not.toBe(a);
    const exp = decodeJwt(b).payload.exp as number;
    expect(exp * 1000).toBeGreaterThan(t + 5 * 60_000);
  });

  it("concurrent callers share one mint", async () => {
    const minter = createClientSecretMinter(cfg, () => NOW_MS);
    const [a, b, c] = await Promise.all([minter.get(), minter.get(), minter.get()]);
    expect(a).toBe(b);
    expect(b).toBe(c);
  });

  it.each([
    ["null config", null],
    ["blank team id", { teamId: " ", clientId: CLIENT_ID, keyId: "K", privateKeyPem: "x" }],
    ["blank client id", { teamId: TEAM_ID, clientId: "", keyId: "K", privateKeyPem: "x" }],
    ["blank key id", { teamId: TEAM_ID, clientId: CLIENT_ID, keyId: "", privateKeyPem: "x" }],
    ["blank key", { teamId: TEAM_ID, clientId: CLIENT_ID, keyId: "K", privateKeyPem: "  " }],
  ] as const)("FAILS CLOSED when unconfigured: %s", async (_name, c) => {
    await expect(createClientSecretMinter(c as AppleSecretConfig | null, () => NOW_MS).get()).rejects.toBeInstanceOf(NotConfiguredError);
  });

  // Block markers are assembled at run time (no literal PEM header in the source: see apple-client-secret.ts).
  const pemOf = (label: string, body: string) => `${"-".repeat(5)}BEGIN ${label}${"-".repeat(5)}\n${body}\n${"-".repeat(5)}END ${label}${"-".repeat(5)}`;
  it.each([
    ["not a PEM", "hello"],
    ["a PUBLIC key block", pemOf("PUBLIC KEY", "AAAA")],
    ["an EC PRIVATE KEY (SEC1) block, not PKCS#8", pemOf("EC PRIVATE KEY", "AAAA")],
    ["valid PEM framing around garbage bytes", pemOf("PRIVATE KEY", "AAAAAAAA")],
    ["two blocks", `${pemOf("PRIVATE KEY", "AAAA")}\n${pemOf("PRIVATE KEY", "AAAA")}`],
  ])("FAILS CLOSED on an unusable key: %s (no default, no previously-valid secret)", async (_n, pem) => {
    const minter = createClientSecretMinter({ ...cfg, privateKeyPem: pem }, () => NOW_MS);
    await expect(minter.get()).rejects.toBeInstanceOf(NotConfiguredError);
  });

  it("pkcs8PemToDer is strict", () => {
    expect(pkcs8PemToDer(p8.pem)).not.toBeNull();
    expect(pkcs8PemToDer("")).toBeNull();
  });
});

function appleClient(routes: Parameters<typeof fakeFetch>[0]) {
  const f = fakeFetch(routes);
  const fetcher = createSafeFetcher({ fetch: f.fetch, allowedHosts: ["appleid.apple.com"], timeoutMs: 500, maxBytes: 65536 });
  const client = createAppleClient({
    fetcher,
    secret: createClientSecretMinter(cfg, () => NOW_MS),
    clientId: CLIENT_ID,
    verifyReturnedIdToken: async () => ({ subject: "apple-sub-1", email: null, emailVerified: false, isPrivateRelay: false }),
  });
  return { ...f, client };
}

const parseForm = (body: string | undefined) => Object.fromEntries(new URLSearchParams(body ?? ""));

describe("Apple token exchange", () => {
  it("POSTs the code with the server-minted client secret as a form and returns the refresh token and the verified id_token subject", async () => {
    const { client, calls } = appleClient({ [`POST ${APPLE_TOKEN_URL}`]: () => json(200, { access_token: "a", refresh_token: "r.refresh-1", id_token: "x.y.z", expires_in: 3600, token_type: "Bearer" }) });
    const r = await client.exchangeAuthorizationCode("the-auth-code");
    expect(r).toEqual({ refreshToken: "r.refresh-1", subject: "apple-sub-1" });
    const body = parseForm(calls[0]!.init.body);
    expect(body).toMatchObject({ client_id: CLIENT_ID, code: "the-auth-code", grant_type: "authorization_code" });
    expect(decodeJwt(body.client_secret!).header.alg).toBe("ES256");
    expect(calls[0]!.init.headers["content-type"]).toBe("application/x-www-form-urlencoded");
    expect(calls[0]!.init.redirect).toBe("error");
  });

  it("invalid_grant is the REQUEST being wrong: AppleGrantError (not retryable)", async () => {
    const { client } = appleClient({ [`POST ${APPLE_TOKEN_URL}`]: () => json(400, { error: "invalid_grant" }) });
    await expect(client.exchangeAuthorizationCode("bad")).rejects.toBeInstanceOf(AppleGrantError);
  });

  it("invalid_client (OUR credentials) and 5xx are unavailable, never blamed on the caller", async () => {
    for (const res of [json(400, { error: "invalid_client" }), json(500, {}), json(401, {}), new Response("nope", { status: 400 })]) {
      const { client } = appleClient({ [`POST ${APPLE_TOKEN_URL}`]: () => res.clone() });
      await expect(client.exchangeAuthorizationCode("c")).rejects.toBeInstanceOf(VendorUnavailableError);
    }
  });

  it("a 200 without a refresh_token or id_token is unavailable (never an empty grant)", async () => {
    for (const body of [{ id_token: "x.y.z" }, { refresh_token: "r" }, { refresh_token: "", id_token: "x.y.z" }, { refresh_token: "r".repeat(5000), id_token: "x.y.z" }, []]) {
      const { client } = appleClient({ [`POST ${APPLE_TOKEN_URL}`]: () => json(200, body) });
      await expect(client.exchangeAuthorizationCode("c")).rejects.toBeInstanceOf(VendorUnavailableError);
    }
  });

  it("the error carries only a short code, never Apple's body", async () => {
    const { client } = appleClient({ [`POST ${APPLE_TOKEN_URL}`]: () => new Response(JSON.stringify({ error: "invalid_client", error_description: "client_secret=LEAK" }), { status: 400 }) });
    try {
      await client.exchangeAuthorizationCode("c");
      expect.unreachable();
    } catch (e) {
      expect(String((e as Error).message)).not.toContain("LEAK");
      expect((e as VendorUnavailableError).code).toBe("token_invalid_client");
    }
  });

  it("with the key unconfigured it fails closed before any request is made", async () => {
    const f = fakeFetch({});
    const fetcher = createSafeFetcher({ fetch: f.fetch, allowedHosts: ["appleid.apple.com"], timeoutMs: 500, maxBytes: 65536 });
    const client = createAppleClient({ fetcher, secret: createClientSecretMinter(null, () => NOW_MS), clientId: CLIENT_ID, verifyReturnedIdToken: async () => { throw new Error("unreachable"); } });
    await expect(client.exchangeAuthorizationCode("c")).rejects.toBeInstanceOf(NotConfiguredError);
    expect(f.calls).toHaveLength(0);
  });

  it("an id_token Apple returns that does not verify fails the exchange (no grant is returned)", async () => {
    const f = fakeFetch({ [`POST ${APPLE_TOKEN_URL}`]: () => json(200, { refresh_token: "r", id_token: "x.y.z" }) });
    const fetcher = createSafeFetcher({ fetch: f.fetch, allowedHosts: ["appleid.apple.com"], timeoutMs: 500, maxBytes: 65536 });
    const client = createAppleClient({
      fetcher,
      secret: createClientSecretMinter(cfg, () => NOW_MS),
      clientId: CLIENT_ID,
      verifyReturnedIdToken: async () => {
        throw new AppleTokenError("signature");
      },
    });
    await expect(client.exchangeAuthorizationCode("c")).rejects.toBeInstanceOf(AppleTokenError);
  });
});

describe("Apple revocation", () => {
  it("POSTs the refresh token with token_type_hint=refresh_token and a server-minted client secret", async () => {
    const { client, calls } = appleClient({ [`POST ${APPLE_REVOKE_URL}`]: () => new Response("", { status: 200 }) });
    await expect(client.revokeRefreshToken("r.the-token")).resolves.toBeUndefined();
    const body = parseForm(calls[0]!.init.body);
    expect(body).toMatchObject({ client_id: CLIENT_ID, token: "r.the-token", token_type_hint: "refresh_token" });
    expect(decodeJwt(body.client_secret!).payload).toMatchObject({ iss: TEAM_ID, sub: CLIENT_ID });
    expect(calls[0]!.url).toBe(APPLE_REVOKE_URL);
  });

  it("a token that is already not valid at Apple counts as revoked (the goal state)", async () => {
    for (const error of ["invalid_grant", "invalid_token", "invalid_request"]) {
      const { client } = appleClient({ [`POST ${APPLE_REVOKE_URL}`]: () => json(400, { error }) });
      await expect(client.revokeRefreshToken("r")).resolves.toBeUndefined();
    }
  });

  it("invalid_client, 5xx, 401, an unparseable 400, and a redirect leave the grant live: unavailable (the queue retries)", async () => {
    for (const make of [() => json(400, { error: "invalid_client" }), () => json(500, {}), () => json(401, {}), () => new Response("???", { status: 400 }), () => new Response(null, { status: 302 })]) {
      const { client } = appleClient({ [`POST ${APPLE_REVOKE_URL}`]: make });
      await expect(client.revokeRefreshToken("r")).rejects.toBeInstanceOf(VendorUnavailableError);
    }
  });
});

describe("Google revocation (the cheap half; capture is a TODO)", () => {
  const google = (routes: Parameters<typeof fakeFetch>[0]) => {
    const f = fakeFetch(routes);
    return { ...f, revoker: createGoogleRevoker(createSafeFetcher({ fetch: f.fetch, allowedHosts: ["oauth2.googleapis.com"], timeoutMs: 500, maxBytes: 65536 })) };
  };

  it("POSTs token=<token> and resolves on 200", async () => {
    const { revoker, calls } = google({ [`POST ${GOOGLE_REVOKE_URL}`]: () => new Response("", { status: 200 }) });
    await revoker.revokeToken("g.token");
    expect(parseForm(calls[0]!.init.body)).toEqual({ token: "g.token" });
  });

  it("already-invalid is success; anything else is unavailable", async () => {
    await expect(google({ [`POST ${GOOGLE_REVOKE_URL}`]: () => json(400, { error: "invalid_token" }) }).revoker.revokeToken("t")).resolves.toBeUndefined();
    for (const res of [json(400, { error: "other" }), json(503, {}), json(401, {})]) {
      await expect(google({ [`POST ${GOOGLE_REVOKE_URL}`]: () => res.clone() }).revoker.revokeToken("t")).rejects.toBeInstanceOf(VendorUnavailableError);
    }
  });
});

describe("buildSigninPorts (production assembly)", () => {
  it("unconfigured -> apple is null (every Apple operation answers 503), google still exists", () => {
    const f = fakeFetch({});
    for (const c of [null, { ...cfg, keyId: "" }]) {
      const ports = buildSigninPorts(c as AppleSecretConfig | null, { fetch: f.fetch, nowMs: () => NOW_MS });
      expect(ports.apple).toBeNull();
      expect(ports.google).toBeDefined();
    }
  });

  it("configured -> the full path works end to end against the synthetic Apple: verify, exchange, revoke", async () => {
    const raw = "raw-nonce-0123456789";
    const f = fakeFetch({
      [`GET ${APPLE_JWKS_URL}`]: () => json(200, jwksBody(appleKey)),
      [`POST ${APPLE_TOKEN_URL}`]: async () => json(200, { refresh_token: "r.end-to-end", id_token: await mintIdentityToken(appleKey, "sub-e2e", { omit: ["nonce"] }) }),
      [`POST ${APPLE_REVOKE_URL}`]: () => new Response("", { status: 200 }),
    });
    const ports = buildSigninPorts(cfg, { fetch: f.fetch, nowMs: () => NOW_MS });
    const id = await ports.apple!.verifyIdentityToken(await mintIdentityToken(appleKey, "sub-e2e", { rawNonce: raw }), raw);
    expect(id.subject).toBe("sub-e2e");
    const grant = await ports.apple!.exchangeAuthorizationCode("code-1");
    expect(grant).toEqual({ refreshToken: "r.end-to-end", subject: "sub-e2e" });
    await ports.apple!.revokeRefreshToken(grant.refreshToken);
    // only appleid.apple.com was ever contacted, every call redirect:error with a timeout signal
    expect(new Set(f.calls.map((c) => new URL(c.url).hostname))).toEqual(new Set(["appleid.apple.com"]));
    expect(f.calls.every((c) => c.init.redirect === "error" && c.init.signal instanceof AbortSignal)).toBe(true);
  });

  it("the token endpoint's id_token for a DIFFERENT audience fails the exchange", async () => {
    const f = fakeFetch({
      [`GET ${APPLE_JWKS_URL}`]: () => json(200, jwksBody(appleKey)),
      [`POST ${APPLE_TOKEN_URL}`]: async () => json(200, { refresh_token: "r", id_token: await mintIdentityToken(appleKey, "sub", { omit: ["nonce"], claims: { aud: "another.app" } }) }),
    });
    const ports = buildSigninPorts(cfg, { fetch: f.fetch, nowMs: () => NOW_MS });
    await expect(ports.apple!.exchangeAuthorizationCode("c")).rejects.toMatchObject({ reason: "audience" });
  });
});
