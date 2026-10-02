// supabase/tests/unit/signin-test-helpers.ts
//
// A SYNTHETIC Apple for the sign-in tests: no secret and no network. Every key is generated at run time (Web Crypto), the JWKS is
// served by a scripted fake `fetch`, and identity tokens are minted here with the same RS256 shape Apple uses. Nothing in this
// file is, or resembles, a real credential.

import type { AppleJwk } from "../../functions/_shared/signin/apple-id-token.ts";
import type { FetchInit, FetchLike } from "../../functions/_shared/signin/safe-fetch.ts";
import { sha256Hex, toBase64Url } from "../../functions/_shared/signin/bytes.ts";

export const NOW_MS = Date.parse("2026-10-02T12:00:00.000Z");
export const NOW_SEC = Math.floor(NOW_MS / 1000);
export const CLIENT_ID = "test.golfraven.app";
export const TEAM_ID = "TEAMTEST01";

export interface TestRsaKey {
  kid: string;
  privateKey: CryptoKey;
  jwk: AppleJwk;
}

export async function makeRsaKey(kid: string): Promise<TestRsaKey> {
  const pair = await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]);
  const pub = (await crypto.subtle.exportKey("jwk", pair.publicKey)) as JsonWebKey;
  return { kid, privateKey: pair.privateKey, jwk: { kty: "RSA", kid, n: pub.n!, e: pub.e! } };
}

const b64 = (v: unknown) => toBase64Url(new TextEncoder().encode(JSON.stringify(v)));

/** Signs a compact RS256 JWT with `key`; header and payload are exactly what the caller passes (so a test can forge a bad claim). */
export async function signRs256(key: CryptoKey, header: Record<string, unknown>, payload: Record<string, unknown>): Promise<string> {
  const input = `${b64(header)}.${b64(payload)}`;
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "RSASSA-PKCS1-v1_5" }, key, new TextEncoder().encode(input)));
  return `${input}.${toBase64Url(sig)}`;
}

export interface TokenOverrides {
  header?: Record<string, unknown>;
  claims?: Record<string, unknown>;
  /** The raw nonce the client generated; the token carries its SHA-256 hex unless `claims.nonce` overrides it. */
  rawNonce?: string;
  omit?: string[];
}

/** A well-formed Apple identity token for `sub`, valid at NOW_MS, signed with `key`; every field overridable. */
export async function mintIdentityToken(key: TestRsaKey, sub: string, o: TokenOverrides = {}): Promise<string> {
  const rawNonce = o.rawNonce ?? "raw-nonce-0123456789";
  const payload: Record<string, unknown> = {
    iss: "https://appleid.apple.com",
    aud: CLIENT_ID,
    iat: NOW_SEC - 30,
    exp: NOW_SEC + 600,
    sub,
    nonce: await sha256Hex(rawNonce),
    email: `${sub}@example.test`,
    email_verified: "true",
    is_private_email: "false",
    ...o.claims,
  };
  for (const k of o.omit ?? []) delete payload[k];
  return signRs256(key.privateKey, { alg: "RS256", kid: key.kid, ...o.header }, payload);
}

export interface RecordedCall {
  url: string;
  init: FetchInit;
}

export type FetchHandler = (url: string, init: FetchInit, call: number) => Response | Promise<Response>;

/** A scripted `fetch`. Routes are matched on "<METHOD> <url>"; an unmatched call fails the test loudly. */
export function fakeFetch(routes: Record<string, FetchHandler>): { fetch: FetchLike; calls: RecordedCall[] } {
  const calls: RecordedCall[] = [];
  const counts = new Map<string, number>();
  const f: FetchLike = async (url, init) => {
    calls.push({ url, init });
    const key = `${init.method} ${url}`;
    const handler = routes[key];
    if (!handler) throw new Error(`fakeFetch: no route for ${key}`);
    const n = (counts.get(key) ?? 0) + 1;
    counts.set(key, n);
    return handler(url, init, n);
  };
  return { fetch: f, calls };
}

export const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

export const jwksBody = (...keys: TestRsaKey[]) => ({ keys: keys.map((k) => ({ ...k.jwk, use: "sig", alg: "RS256" })) });

/** A P-256 key as PKCS#8 PEM (what a `.p8` file holds), generated at run time, with its public half for verifying the minted JWTs. */
export async function makeP8(): Promise<{ pem: string; publicKey: CryptoKey }> {
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const der = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
  let bin = "";
  for (const b of der) bin += String.fromCharCode(b);
  const body = btoa(bin).match(/.{1,64}/g)!.join("\n");
  return { pem: `-----BEGIN PRIVATE KEY-----\n${body}\n-----END PRIVATE KEY-----\n`, publicKey: pair.publicKey };
}

export function decodeJwt(jwt: string): { header: Record<string, unknown>; payload: Record<string, unknown>; signingInput: string; sig: Uint8Array } {
  const [h, p, s] = jwt.split(".") as [string, string, string];
  const dec = (x: string) => JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(x.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (x.length % 4)) % 4)), (c) => c.charCodeAt(0))));
  const raw = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (s.length % 4)) % 4));
  return { header: dec(h), payload: dec(p), signingInput: `${h}.${p}`, sig: Uint8Array.from(raw, (c) => c.charCodeAt(0)) };
}
