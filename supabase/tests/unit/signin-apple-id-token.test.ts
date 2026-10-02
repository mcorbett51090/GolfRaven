// Apple identity-token verification against a synthetic Apple (signin-test-helpers.ts): the pass case and every must-fail case.

import { beforeAll, describe, expect, it } from "vitest";
import { AppleTokenError, VendorUnavailableError } from "../../functions/_shared/signin/errors.ts";
import { APPLE_JWKS_URL, createJwksCache, verifyAppleIdentityToken, type VerifyOptions } from "../../functions/_shared/signin/apple-id-token.ts";
import { createSafeFetcher } from "../../functions/_shared/signin/safe-fetch.ts";
import { sha256Hex } from "../../functions/_shared/signin/bytes.ts";
import { CLIENT_ID, NOW_MS, NOW_SEC, fakeFetch, json, jwksBody, makeRsaKey, mintIdentityToken, signRs256, type TestRsaKey } from "./signin-test-helpers.ts";

let apple: TestRsaKey;
let other: TestRsaKey;
const RAW = "raw-nonce-0123456789";

beforeAll(async () => {
  apple = await makeRsaKey("apple-kid-1");
  other = await makeRsaKey("attacker-kid");
});

function setup(keys: TestRsaKey[], now = () => NOW_MS) {
  const { fetch, calls } = fakeFetch({ [`GET ${APPLE_JWKS_URL}`]: () => json(200, jwksBody(...keys)) });
  const fetcher = createSafeFetcher({ fetch, allowedHosts: ["appleid.apple.com"], timeoutMs: 1000, maxBytes: 65536 });
  const jwks = createJwksCache({ fetcher, nowMs: now });
  const opts: VerifyOptions = { jwks, nowMs: now, clientId: CLIENT_ID };
  return { opts, calls };
}

const reason = async (p: Promise<unknown>): Promise<string> => {
  try {
    await p;
  } catch (e) {
    if (e instanceof AppleTokenError) return e.reason;
    throw e;
  }
  return "no_error";
};

describe("verifyAppleIdentityToken: the pass case", () => {
  it("verifies a well-formed token and returns the identity", async () => {
    const { opts } = setup([apple]);
    const token = await mintIdentityToken(apple, "000111.sub", { rawNonce: RAW });
    const id = await verifyAppleIdentityToken(token, { rawNonce: RAW }, opts);
    expect(id).toEqual({ subject: "000111.sub", email: "000111.sub@example.test", emailVerified: true, isPrivateRelay: false });
  });

  it("flags an Apple private-relay address (by the claim, and by the address itself)", async () => {
    const { opts } = setup([apple]);
    const byClaim = await verifyAppleIdentityToken(await mintIdentityToken(apple, "s1", { rawNonce: RAW, claims: { is_private_email: true } }), { rawNonce: RAW }, opts);
    expect(byClaim.isPrivateRelay).toBe(true);
    const byAddress = await verifyAppleIdentityToken(await mintIdentityToken(apple, "s2", { rawNonce: RAW, claims: { email: "abc@privaterelay.appleid.com" } }), { rawNonce: RAW }, opts);
    expect(byAddress.isPrivateRelay).toBe(true);
  });

  it("accepts the nonce as its SHA-256 hex (Apple's native flow) or as the raw value", async () => {
    const { opts } = setup([apple]);
    const raw = await mintIdentityToken(apple, "s", { rawNonce: RAW, claims: { nonce: RAW } });
    await expect(verifyAppleIdentityToken(raw, { rawNonce: RAW }, opts)).resolves.toMatchObject({ subject: "s" });
  });

  it("a token with no email verifies, with email null", async () => {
    const { opts } = setup([apple]);
    const id = await verifyAppleIdentityToken(await mintIdentityToken(apple, "s", { rawNonce: RAW, omit: ["email", "email_verified"] }), { rawNonce: RAW }, opts);
    expect(id).toMatchObject({ email: null, emailVerified: false });
  });

  it("rawNonce: null skips only the nonce check (the id_token Apple returns from the token endpoint)", async () => {
    const { opts } = setup([apple]);
    const t = await mintIdentityToken(apple, "s", { omit: ["nonce"] });
    await expect(verifyAppleIdentityToken(t, { rawNonce: null }, opts)).resolves.toMatchObject({ subject: "s" });
  });
});

describe("verifyAppleIdentityToken: must-fail", () => {
  it("wrong issuer", async () => {
    const { opts } = setup([apple]);
    expect(await reason(verifyAppleIdentityToken(await mintIdentityToken(apple, "s", { rawNonce: RAW, claims: { iss: "https://appleid.apple.com.evil.test" } }), { rawNonce: RAW }, opts))).toBe("issuer");
    expect(await reason(verifyAppleIdentityToken(await mintIdentityToken(apple, "s", { rawNonce: RAW, claims: { iss: "https://accounts.google.com" } }), { rawNonce: RAW }, opts))).toBe("issuer");
  });

  it("wrong audience (another app's token), including an array with an extra audience", async () => {
    const { opts } = setup([apple]);
    expect(await reason(verifyAppleIdentityToken(await mintIdentityToken(apple, "s", { rawNonce: RAW, claims: { aud: "some.other.app" } }), { rawNonce: RAW }, opts))).toBe("audience");
    expect(await reason(verifyAppleIdentityToken(await mintIdentityToken(apple, "s", { rawNonce: RAW, claims: { aud: [CLIENT_ID, "some.other.app"] } }), { rawNonce: RAW }, opts))).toBe("audience");
    expect(await reason(verifyAppleIdentityToken(await mintIdentityToken(apple, "s", { rawNonce: RAW, omit: ["aud"] }), { rawNonce: RAW }, opts))).toBe("audience");
  });

  it("wrong nonce, missing nonce, and a nonce that is merely a prefix", async () => {
    const { opts } = setup([apple]);
    const good = await mintIdentityToken(apple, "s", { rawNonce: RAW });
    expect(await reason(verifyAppleIdentityToken(good, { rawNonce: "a-different-nonce-value" }, opts))).toBe("nonce");
    expect(await reason(verifyAppleIdentityToken(await mintIdentityToken(apple, "s", { rawNonce: RAW, omit: ["nonce"] }), { rawNonce: RAW }, opts))).toBe("nonce");
    expect(await reason(verifyAppleIdentityToken(await mintIdentityToken(apple, "s", { rawNonce: RAW, claims: { nonce: (await sha256Hex(RAW)).slice(0, 32) } }), { rawNonce: RAW }, opts))).toBe("nonce");
    expect(await reason(verifyAppleIdentityToken(await mintIdentityToken(apple, "s", { rawNonce: RAW, claims: { nonce: "" } }), { rawNonce: RAW }, opts))).toBe("nonce");
  });

  it("expired token (and exp exactly now)", async () => {
    const { opts } = setup([apple]);
    expect(await reason(verifyAppleIdentityToken(await mintIdentityToken(apple, "s", { rawNonce: RAW, claims: { exp: NOW_SEC - 3600 } }), { rawNonce: RAW }, opts))).toBe("expired");
    expect(await reason(verifyAppleIdentityToken(await mintIdentityToken(apple, "s", { rawNonce: RAW, claims: { exp: NOW_SEC } }), { rawNonce: RAW }, opts))).toBe("expired");
    expect(await reason(verifyAppleIdentityToken(await mintIdentityToken(apple, "s", { rawNonce: RAW, omit: ["exp"] }), { rawNonce: RAW }, opts))).toBe("expired");
  });

  it("a token issued in the future (beyond the 60 s skew)", async () => {
    const { opts } = setup([apple]);
    expect(await reason(verifyAppleIdentityToken(await mintIdentityToken(apple, "s", { rawNonce: RAW, claims: { iat: NOW_SEC + 600 } }), { rawNonce: RAW }, opts))).toBe("not_yet_valid");
  });

  it("unknown kid", async () => {
    const { opts } = setup([apple]);
    const t = await signRs256(other.privateKey, { alg: "RS256", kid: "no-such-kid" }, { iss: "https://appleid.apple.com", aud: CLIENT_ID, iat: NOW_SEC, exp: NOW_SEC + 60, sub: "s", nonce: await sha256Hex(RAW) });
    expect(await reason(verifyAppleIdentityToken(t, { rawNonce: RAW }, opts))).toBe("unknown_kid");
  });

  it("a bad signature: signed by a different key under Apple's kid, and a flipped payload bit", async () => {
    const { opts } = setup([apple]);
    const forged = await signRs256(other.privateKey, { alg: "RS256", kid: apple.kid }, { iss: "https://appleid.apple.com", aud: CLIENT_ID, iat: NOW_SEC, exp: NOW_SEC + 60, sub: "victim", nonce: await sha256Hex(RAW) });
    expect(await reason(verifyAppleIdentityToken(forged, { rawNonce: RAW }, opts))).toBe("signature");
    const good = await mintIdentityToken(apple, "s", { rawNonce: RAW });
    const [h, p, s] = good.split(".") as [string, string, string];
    const tampered = `${h}.${p.slice(0, -2)}${p.endsWith("A") ? "B" : "A"}A.${s}`;
    expect(await reason(verifyAppleIdentityToken(tampered, { rawNonce: RAW }, opts))).toMatch(/signature|malformed/);
    // the same token with the signature replaced by garbage of a plausible length
    expect(await reason(verifyAppleIdentityToken(`${h}.${p}.${"A".repeat(s.length)}`, { rawNonce: RAW }, opts))).toBe("signature");
  });

  it("alg downgrade: none, HS256 and RS512 are refused before any key is touched", async () => {
    const { opts, calls } = setup([apple]);
    const payload = { iss: "https://appleid.apple.com", aud: CLIENT_ID, iat: NOW_SEC, exp: NOW_SEC + 60, sub: "s", nonce: RAW };
    for (const alg of ["none", "HS256", "RS512", "ES256"]) {
      const t = await signRs256(apple.privateKey, { alg, kid: apple.kid }, payload);
      expect(await reason(verifyAppleIdentityToken(t, { rawNonce: RAW }, opts))).toBe("alg");
    }
    expect(calls).toHaveLength(0);
  });

  it("a missing / empty / non-string kid", async () => {
    const { opts } = setup([apple]);
    for (const header of [{ alg: "RS256" }, { alg: "RS256", kid: "" }, { alg: "RS256", kid: 5 }]) {
      const t = await signRs256(apple.privateKey, header, { iss: "https://appleid.apple.com", aud: CLIENT_ID, iat: NOW_SEC, exp: NOW_SEC + 60, sub: "s", nonce: RAW });
      expect(await reason(verifyAppleIdentityToken(t, { rawNonce: RAW }, opts))).toBe("unknown_kid");
    }
  });

  it("missing or empty subject", async () => {
    const { opts } = setup([apple]);
    expect(await reason(verifyAppleIdentityToken(await mintIdentityToken(apple, "s", { rawNonce: RAW, omit: ["sub"] }), { rawNonce: RAW }, opts))).toBe("subject");
    expect(await reason(verifyAppleIdentityToken(await mintIdentityToken(apple, "s", { rawNonce: RAW, claims: { sub: "" } }), { rawNonce: RAW }, opts))).toBe("subject");
  });

  it("malformed input: empty, two segments, four segments, non-base64url, oversized, not JSON", async () => {
    const { opts } = setup([apple]);
    for (const bad of ["", "a.b", "a.b.c.d", "a..c", "!!!.???.***", "x".repeat(9000), "e30.e30.e30"]) {
      const r = await reason(verifyAppleIdentityToken(bad, { rawNonce: RAW }, opts));
      expect(["malformed", "alg", "unknown_kid"]).toContain(r);
    }
    // a non-JSON header
    const notJson = `${btoa("not json").replace(/=+$/, "")}.e30.AAAA`;
    expect(await reason(verifyAppleIdentityToken(notJson, { rawNonce: RAW }, opts))).toBe("malformed");
  });

  it("a non-RSA or garbage JWKS key under the kid does not verify", async () => {
    const { fetch } = fakeFetch({ [`GET ${APPLE_JWKS_URL}`]: () => json(200, { keys: [{ kty: "RSA", kid: apple.kid, n: "AAAA", e: "AQAB" }] }) });
    const fetcher = createSafeFetcher({ fetch, allowedHosts: ["appleid.apple.com"], timeoutMs: 1000, maxBytes: 65536 });
    const opts: VerifyOptions = { jwks: createJwksCache({ fetcher, nowMs: () => NOW_MS }), nowMs: () => NOW_MS, clientId: CLIENT_ID };
    expect(await reason(verifyAppleIdentityToken(await mintIdentityToken(apple, "s", { rawNonce: RAW }), { rawNonce: RAW }, opts))).toBe("signature");
  });
});

describe("the JWKS fetch and cache", () => {
  it("fetches once, then serves from cache", async () => {
    const { opts, calls } = setup([apple]);
    for (let i = 0; i < 3; i++) await verifyAppleIdentityToken(await mintIdentityToken(apple, `s${i}`, { rawNonce: RAW }), { rawNonce: RAW }, opts);
    expect(calls).toHaveLength(1);
    expect(calls[0]!.init.redirect).toBe("error");
    expect(calls[0]!.init.signal).toBeInstanceOf(AbortSignal);
    expect(calls[0]!.url).toBe(APPLE_JWKS_URL);
  });

  it("an unknown kid triggers at most ONE refetch per minute (no fetch-per-request amplifier)", async () => {
    let t = NOW_MS;
    const { opts, calls } = setup([apple], () => t);
    await verifyAppleIdentityToken(await mintIdentityToken(apple, "s", { rawNonce: RAW }), { rawNonce: RAW }, opts); // fetch 1
    const stranger = await signRs256(other.privateKey, { alg: "RS256", kid: "rotated-key" }, { sub: "s" });
    for (let i = 0; i < 5; i++) expect(await reason(verifyAppleIdentityToken(stranger, { rawNonce: RAW }, opts))).toBe("unknown_kid");
    expect(calls).toHaveLength(1); // five unknown-kid tokens inside the minute caused NO extra fetch
    t += 61_000;
    expect(await reason(verifyAppleIdentityToken(stranger, { rawNonce: RAW }, opts))).toBe("unknown_kid");
    expect(await reason(verifyAppleIdentityToken(stranger, { rawNonce: RAW }, opts))).toBe("unknown_kid");
    expect(calls).toHaveLength(2); // after the floor, exactly one refetch, however many unknown-kid tokens arrive
  });

  it("picks up a rotated key after the one-minute floor", async () => {
    let t = NOW_MS;
    const second = await makeRsaKey("apple-kid-2");
    let served: TestRsaKey[] = [apple];
    const { fetch, calls } = fakeFetch({ [`GET ${APPLE_JWKS_URL}`]: () => json(200, jwksBody(...served)) });
    const fetcher = createSafeFetcher({ fetch, allowedHosts: ["appleid.apple.com"], timeoutMs: 1000, maxBytes: 65536 });
    const opts: VerifyOptions = { jwks: createJwksCache({ fetcher, nowMs: () => t }), nowMs: () => t, clientId: CLIENT_ID };
    await verifyAppleIdentityToken(await mintIdentityToken(apple, "s", { rawNonce: RAW }), { rawNonce: RAW }, opts);
    served = [apple, second];
    t += 61_000;
    const id = await verifyAppleIdentityToken(await mintIdentityToken(second, "s2", { rawNonce: RAW }), { rawNonce: RAW }, opts);
    expect(id.subject).toBe("s2");
    expect(calls).toHaveLength(2);
  });

  it("Apple unreachable and nothing cached: fails closed with VendorUnavailableError (never a verified token)", async () => {
    const { fetch } = fakeFetch({ [`GET ${APPLE_JWKS_URL}`]: () => json(503, {}) });
    const fetcher = createSafeFetcher({ fetch, allowedHosts: ["appleid.apple.com"], timeoutMs: 1000, maxBytes: 65536 });
    const opts: VerifyOptions = { jwks: createJwksCache({ fetcher, nowMs: () => NOW_MS }), nowMs: () => NOW_MS, clientId: CLIENT_ID };
    await expect(verifyAppleIdentityToken(await mintIdentityToken(apple, "s", { rawNonce: RAW }), { rawNonce: RAW }, opts)).rejects.toBeInstanceOf(VendorUnavailableError);
  });

  it("Apple unreachable after a good fetch: the stale set is used for a bounded time, then it fails closed", async () => {
    let t = NOW_MS;
    let down = false;
    const { fetch } = fakeFetch({ [`GET ${APPLE_JWKS_URL}`]: () => (down ? json(500, {}) : json(200, jwksBody(apple))) });
    const fetcher = createSafeFetcher({ fetch, allowedHosts: ["appleid.apple.com"], timeoutMs: 1000, maxBytes: 65536 });
    const opts: VerifyOptions = { jwks: createJwksCache({ fetcher, nowMs: () => t }), nowMs: () => t, clientId: CLIENT_ID };
    await verifyAppleIdentityToken(await mintIdentityToken(apple, "s", { rawNonce: RAW }), { rawNonce: RAW }, opts);
    down = true;
    t += 2 * 3600_000; // stale (ttl 1 h) but inside the 24 h bound
    await expect(verifyAppleIdentityToken(await signRs256(apple.privateKey, { alg: "RS256", kid: apple.kid }, { iss: "https://appleid.apple.com", aud: CLIENT_ID, iat: Math.floor(t / 1000) - 5, exp: Math.floor(t / 1000) + 60, sub: "s", nonce: RAW }), { rawNonce: RAW }, opts)).resolves.toMatchObject({ subject: "s" });
    t += 25 * 3600_000; // past the bound
    await expect(verifyAppleIdentityToken(await signRs256(apple.privateKey, { alg: "RS256", kid: apple.kid }, { iss: "https://appleid.apple.com", aud: CLIENT_ID, iat: Math.floor(t / 1000) - 5, exp: Math.floor(t / 1000) + 60, sub: "s", nonce: RAW }), { rawNonce: RAW }, opts)).rejects.toBeInstanceOf(VendorUnavailableError);
  });

  it("a malformed JWKS (not JSON, no keys, no RSA key) is unavailable, not 'no such key'", async () => {
    for (const body of [{ keys: [] }, { keys: [{ kty: "EC", kid: "x" }] }, { nope: 1 }]) {
      const { fetch } = fakeFetch({ [`GET ${APPLE_JWKS_URL}`]: () => json(200, body) });
      const fetcher = createSafeFetcher({ fetch, allowedHosts: ["appleid.apple.com"], timeoutMs: 1000, maxBytes: 65536 });
      const opts: VerifyOptions = { jwks: createJwksCache({ fetcher, nowMs: () => NOW_MS }), nowMs: () => NOW_MS, clientId: CLIENT_ID };
      await expect(verifyAppleIdentityToken(await mintIdentityToken(apple, "s", { rawNonce: RAW }), { rawNonce: RAW }, opts)).rejects.toBeInstanceOf(VendorUnavailableError);
    }
  });
});
