// supabase/tests/unit/course-qr-handler.test.ts
//
// The `course-qr` handler (docs/security/partner-auth-design.md 4.2, 6.3, 8, 12.1 S2a/S2b: AT(19), PA-26; S2b, the Edge half of migration 0055), against the in-memory `CourseQrDb` of course-qr-fakes.ts. What is
// decided HERE: the order of the checks (Origin, route, bearer, body, rate limit, transaction), the strict shapes, the status map, and above all the MINT: that the token the handler hands out is the one the
// player lane's format.ts VERIFIES (proved against the test minter's patterns, byte for byte), that its nonce hash is the one the database was given, that the Vault seed appears in no response, and that every
// refusal after the PIN grant was consumed ROLLS BACK (a refused mint gives the grant back). What is decided in the database (scope, the class prerequisites, the PIN derivation, the row) is
// supabase/tests/matrix/33_course_qr_staff.sql.

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { ROTATING_TOKEN_TYP, base64UrlDecode, nonceHashHex, parseRotatingToken, verifyRotatingToken } from "../../functions/_shared/course-qr/format.ts";
import { COURSE_QR_FUNCTION, handleCourseQrRequest, MINT_BUCKET, MINT_PER_MEMBER_PER_HOUR, REFRESH_BUCKET, ROTATE_BUCKET, type CourseQrDeps } from "../../functions/_shared/partner/course-qr-handler.ts";
import { CourseQrKeyMismatch, publicKeyOfSeed, signRotatingToken } from "../../functions/_shared/partner/course-qr-signer.ts";
import { generateTestSigningKey, mintRotatingToken } from "./course-qr-test-keys.ts";
import { FACILITY, makeCourseQrWorld, makeSeed, OTHER_FACILITY, type CourseQrWorld } from "./course-qr-fakes.ts";
import { authed, fnReq, ORIGIN, sha256Hex, SESSION_TOKEN } from "./partner-fakes.ts";

const FN = COURSE_QR_FUNCTION;
const LINK_ORIGIN = "https://golfraven.example.test";
const NONCE = new Uint8Array(16).map((_, i) => i + 1);

async function sha256HexOfBytes(b: Uint8Array): Promise<string> {
  return nonceHashHex(b, async (x) => Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", x.slice().buffer)), (v) => v.toString(16).padStart(2, "0")).join(""));
}

function deps(w: CourseQrWorld, over: Partial<CourseQrDeps> = {}): CourseQrDeps {
  return { db: w.db, allowedOrigin: ORIGIN, linkOrigin: LINK_ORIGIN, randomNonce: () => NONCE, ...over };
}

const get = (path: string, headers: Record<string, string> = authed()) => fnReq(FN, "GET", path, { headers });
const post = (path: string, body: unknown, headers: Record<string, string> = authed()) => fnReq(FN, "POST", path, { headers, body });

async function json(res: Response): Promise<{ data?: Record<string, unknown>; error?: { code: string; message: string } }> {
  return await res.json();
}

describe("the order: origin, preflight, route, method, bearer, body, rate limit, transaction", () => {
  it("a foreign Origin is refused 403 before anything else, with no port touched", async () => {
    const w = await makeCourseQrWorld();
    const res = await handleCourseQrRequest(get("pin?facilityId=fac_x", { authorization: `Bearer ${SESSION_TOKEN}`, origin: "https://evil.test" }), deps(w));
    expect(res.status).toBe(403);
    expect(w.calls).toEqual([]);
  });

  it("OPTIONS is answered with no port touched", async () => {
    const w = await makeCourseQrWorld();
    const res = await handleCourseQrRequest(fnReq(FN, "OPTIONS", "tokens", { headers: { origin: ORIGIN } }), deps(w));
    expect(res.status).toBe(204);
    expect(res.headers.get("access-control-allow-origin")).toBe(ORIGIN);
    expect(w.calls).toEqual([]);
  });

  it("an unknown route is 404 and a wrong method 405 (with Allow), no port touched", async () => {
    const w = await makeCourseQrWorld();
    expect((await handleCourseQrRequest(get("nope"), deps(w))).status).toBe(404);
    const res = await handleCourseQrRequest(post("pin", { facilityId: FACILITY }), deps(w));
    expect(res.status).toBe(405);
    expect(res.headers.get("allow")).toBe("GET");
    expect((await handleCourseQrRequest(get("tokens"), deps(w))).status).toBe(405);
    expect(w.calls).toEqual([]);
  });

  it("no bearer, a Supabase JWT and a malformed partner token are the ONE 401 with no port touched", async () => {
    const w = await makeCourseQrWorld();
    for (const headers of [{ origin: ORIGIN }, { origin: ORIGIN, authorization: "Bearer eyJhbGciOiJIUzI1NiJ9.e30.sig" }, { origin: ORIGIN, authorization: "Bearer gr_ps_short" }]) {
      const res = await handleCourseQrRequest(post("tokens", { facilityId: FACILITY }, headers), deps(w));
      expect(res.status).toBe(401);
      expect(await res.json()).toEqual({ error: { code: "unauthenticated", message: "authentication failed" } });
    }
    expect(w.calls).toEqual([]);
  });

  it("a refused bind (an unknown, idle or revoked session) is the same 401", async () => {
    const w = await makeCourseQrWorld({ bindRefused: true });
    for (const [path, body] of [["tokens", { facilityId: FACILITY }], ["pin/rotate", { facilityId: FACILITY }], ["tokens/refresh", { facilityId: FACILITY, nonceHash: "a".repeat(64) }]] as const) {
      const res = await handleCourseQrRequest(post(path, body), deps(w));
      expect(res.status, path).toBe(401);
    }
    expect((await handleCourseQrRequest(get("pin?facilityId=fac_x"), deps(w))).status).toBe(401);
  });

  it("every response is no-store and varies by Origin", async () => {
    const w = await makeCourseQrWorld();
    const res = await handleCourseQrRequest(get("pin?facilityId=fac_x"), deps(w));
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(res.headers.get("vary")).toBe("Origin");
  });

  it("a body that is not exactly JSON is 415 and an invalid one 400, BEFORE the rate limit or a transaction", async () => {
    const w = await makeCourseQrWorld();
    const wrongType = await handleCourseQrRequest(fnReq(FN, "POST", "tokens", { headers: authed({ "content-type": "text/plain; x=application/json" }), raw: JSON.stringify({ facilityId: FACILITY }) }), deps(w));
    expect(wrongType.status).toBe(415);
    for (const body of [{}, { facilityId: "" }, { facilityId: "fac x" }, { facilityId: "a".repeat(129) }, { facilityId: 1 }, { facilityId: FACILITY, extra: 1 }, null, [], "x"]) {
      const res = await handleCourseQrRequest(post("tokens", body), deps(w));
      expect(res.status, JSON.stringify(body)).toBe(400);
    }
    expect(w.calls).toEqual([]);
  });
});

describe("GET pin: today's PIN comes from the database and nowhere else", () => {
  it("returns the PIN, the local date, the end of the day and the epoch", async () => {
    const w = await makeCourseQrWorld();
    const res = await handleCourseQrRequest(get(`pin?facilityId=${FACILITY}`), deps(w));
    expect(res.status).toBe(200);
    expect((await json(res)).data).toEqual({ facilityId: FACILITY, pin: "4821", localDate: "2030-01-01", validUntil: "2030-01-02T06:00:00.000Z", pinEpoch: 0 });
    expect(w.calls).toEqual(["db.withCourseQr", "tx.pinShow"]);
  });

  it("AT(19): staff at X asking for the PIN of Y is 403 (the database's scope refusal), whatever the facility id", async () => {
    const w = await makeCourseQrWorld();
    const res = await handleCourseQrRequest(get(`pin?facilityId=${OTHER_FACILITY}`), deps(w));
    expect(res.status).toBe(403);
    expect((await json(res)).error?.code).toBe("forbidden");
  });

  it("no programme is a 409 and an unknown facility (an admin's question) a 404", async () => {
    const w = await makeCourseQrWorld({ programme: false });
    expect((await handleCourseQrRequest(get(`pin?facilityId=${FACILITY}`), deps(w))).status).toBe(409);
    const stub = await makeCourseQrWorld();
    const db = { ...stub.db, withCourseQr: <T>(_h: string, op: (s: never) => Promise<T>) => op({ pinShow: async () => ({ status: "no_facility" as const }) } as never) };
    expect((await handleCourseQrRequest(get("pin?facilityId=fac_nope"), deps(stub, { db }))).status).toBe(404);
  });

  it("the query is strict: facilityId once, nothing else", async () => {
    const w = await makeCourseQrWorld();
    for (const q of ["pin", "pin?facilityId=", "pin?facilityId=fac_x&facilityId=fac_y", "pin?facilityId=fac_x&x=1", "pin?x=1", "pin?facilityId=a%20b"]) {
      expect((await handleCourseQrRequest(get(q), deps(w))).status, q).toBe(400);
    }
    expect(w.calls).toEqual([]);
  });

  it("a PIN is never derived in the Edge: no non-test source under supabase/functions carries the derivation's label, and nothing named hmac or pbkdf2 sits in the course-qr modules", () => {
    const root = join(import.meta.dirname, "..", "..", "functions");
    const files: string[] = [];
    const walk = (d: string): void => {
      for (const e of readdirSync(d)) {
        const p = join(d, e);
        if (statSync(p).isDirectory()) walk(p);
        else if (p.endsWith(".ts")) files.push(p);
      }
    };
    walk(root);
    expect(files.length).toBeGreaterThan(50);
    for (const f of files) expect(readFileSync(f, "utf8"), f).not.toContain("golfraven/course-pin/v1");
    for (const f of ["course-qr-handler.ts", "qr-print-handler.ts", "course-qr-shape.ts", "course-qr-signer.ts"]) {
      const src = readFileSync(join(root, "_shared", "partner", f), "utf8").replace(/\/\/.*$/gm, "");
      expect(src, f).not.toMatch(/hmac|pbkdf2|deriveBits/i);
    }
  });
});

describe("POST pin/rotate", () => {
  it("rotates and answers the new epoch; the rotation bucket is hit first and a refusal does not rotate", async () => {
    const w = await makeCourseQrWorld();
    const res = await handleCourseQrRequest(post("pin/rotate", { facilityId: FACILITY }), deps(w));
    expect(res.status).toBe(200);
    expect((await json(res)).data).toEqual({ facilityId: FACILITY, pinEpoch: 1 });
    expect(w.calls).toEqual(["db.hitRateLimit", "db.withCourseQr", "tx.pinRotate"]);
    expect(w.rateLimitHits).toEqual([{ bucket: ROTATE_BUCKET, windowSeconds: 3600, max: 10 }]);
  });

  it("A2 not satisfied (no fresh PIN or passkey) and no scope are both 403", async () => {
    expect((await handleCourseQrRequest(post("pin/rotate", { facilityId: FACILITY }), deps(await makeCourseQrWorld({ a2: false })))).status).toBe(403);
    expect((await handleCourseQrRequest(post("pin/rotate", { facilityId: OTHER_FACILITY }), deps(await makeCourseQrWorld()))).status).toBe(403);
  });

  it("over the cap is 429 with Retry-After and no transaction", async () => {
    const w = await makeCourseQrWorld({ rateLimitOk: false });
    const res = await handleCourseQrRequest(post("pin/rotate", { facilityId: FACILITY }), deps(w));
    expect(res.status).toBe(429);
    expect(res.headers.get("retry-after")).toBe("3600");
    expect(w.calls).toEqual(["db.hitRateLimit"]);
  });

  it("no programme is 409", async () => {
    const res = await handleCourseQrRequest(post("pin/rotate", { facilityId: FACILITY }), deps(await makeCourseQrWorld({ programme: false })));
    expect(res.status).toBe(409);
  });
});

describe("POST tokens: Marker sold", () => {
  it("AT(19): hands out a token the player lane's format.ts VERIFIES, with the nonce hash the database was given", async () => {
    const w = await makeCourseQrWorld();
    const res = await handleCourseQrRequest(post("tokens", { facilityId: FACILITY }), deps(w));
    expect(res.status).toBe(201);
    const d = (await json(res)).data!;
    const parsed = parseRotatingToken(String(d.token));
    expect(parsed, "the player lane's parser accepts it").not.toBeNull();
    expect(await verifyRotatingToken(parsed!, w.keys.rotatingPublic), "the signature verifies under the registered PUBLIC key").toBe(true);
    expect(parsed!.claims).toMatchObject({ fac: FACILITY, kid: "kidrot1", iat: w.state.nowS, exp: w.state.nowS + 120 });
    expect(Array.from(parsed!.claims.nonce)).toEqual(Array.from(NONCE));
    const hash = await sha256HexOfBytes(NONCE);
    expect(d.nonceHash).toBe(hash);
    expect(w.state.tokens).toEqual([{ nonceHash: hash, facilityId: FACILITY, issuedAt: w.state.nowS, usedAt: null }]);
    expect(d).toMatchObject({ facilityId: FACILITY, kid: "kidrot1", issuedAt: new Date(w.state.nowS * 1000).toISOString(), expiresAt: new Date((w.state.nowS + 120) * 1000).toISOString() });
    expect(d.link).toBe(`${LINK_ORIGIN}/q/m#${d.token}`);
    expect(w.calls).toEqual(["db.hitRateLimit", "db.withCourseQr", "tx.mint"]);
  });

  it("the token is BYTE-IDENTICAL to the test minter's under the same key (Ed25519 is deterministic): the same format, the same member order", async () => {
    const seed = await makeSeed();
    const publicKey = await publicKeyOfSeed(seed);
    const w = await makeCourseQrWorld({ rotatingSeed: seed, rotatingPublicKey: publicKey });
    const res = await handleCourseQrRequest(post("tokens", { facilityId: FACILITY }), deps(w));
    const token = String((await json(res)).data!.token);
    // the test minter wants a CryptoKey: the same seed through PKCS#8
    const pkcs8 = new Uint8Array([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20, ...base64UrlDecode(seed)!]);
    const privateKey = await crypto.subtle.importKey("pkcs8", pkcs8.buffer, { name: "Ed25519" }, false, ["sign"]);
    const reference = await mintRotatingToken({ key: { publicKeyB64Url: publicKey, privateKey }, kid: "kidrot1", facilityId: FACILITY, iat: w.state.nowS, nonce: NONCE });
    expect(token).toBe(reference.token);
    const header = JSON.parse(new TextDecoder().decode(base64UrlDecode(token.split(".")[0]!)!));
    expect(header).toEqual({ alg: "EdDSA", kid: "kidrot1", typ: ROTATING_TOKEN_TYP });
    expect((await generateTestSigningKey()).publicKeyB64Url).toHaveLength(43);
  });

  it("the Vault seed is in NO response: not the body, not a header", async () => {
    const w = await makeCourseQrWorld();
    const res = await handleCourseQrRequest(post("tokens", { facilityId: FACILITY }), deps(w));
    const text = await res.clone().text();
    expect(text).not.toContain(w.state.rotatingSeed);
    expect(text.toLowerCase()).not.toContain("signingkey");
    expect(text.toLowerCase()).not.toContain("seed");
    for (const [k, v] of res.headers) expect(`${k}: ${v}`).not.toContain(w.state.rotatingSeed);
  });

  it("without a configured link origin the token is returned and the link is null", async () => {
    const w = await makeCourseQrWorld();
    const res = await handleCourseQrRequest(post("tokens", { facilityId: FACILITY }), deps(w, { linkOrigin: null }));
    const d = (await json(res)).data!;
    expect(d.link).toBeNull();
    expect(typeof d.token).toBe("string");
  });

  it("each mint draws its own nonce and writes its own row; one PIN, one token: the second mint with no new grant is 403", async () => {
    const w = await makeCourseQrWorld();
    let n = 0;
    const d = deps(w, { randomNonce: () => new Uint8Array(16).fill(++n) });
    expect((await handleCourseQrRequest(post("tokens", { facilityId: FACILITY }), d)).status).toBe(201);
    w.state.grant = true;
    expect((await handleCourseQrRequest(post("tokens", { facilityId: FACILITY }), d)).status).toBe(201);
    expect(new Set(w.state.tokens.map((t) => t.nonceHash)).size).toBe(2);
    expect((await handleCourseQrRequest(post("tokens", { facilityId: FACILITY }), d)).status, "no grant left").toBe(403);
    expect(w.state.tokens).toHaveLength(2);
  });

  it("AT(19): staff at X cannot mint for Y (403), and nothing is written", async () => {
    const w = await makeCourseQrWorld();
    const res = await handleCourseQrRequest(post("tokens", { facilityId: OTHER_FACILITY }), deps(w));
    expect(res.status).toBe(403);
    expect(w.state.tokens).toEqual([]);
    expect(w.state.grant).toBe(true);
  });

  it("the 60-a-member-an-hour bucket is hit once per request, BEFORE the request transaction; over it is 429 with no transaction and no row", async () => {
    const w = await makeCourseQrWorld();
    await handleCourseQrRequest(post("tokens", { facilityId: FACILITY }), deps(w));
    expect(w.rateLimitHits).toEqual([{ bucket: MINT_BUCKET, windowSeconds: 3600, max: MINT_PER_MEMBER_PER_HOUR }]);
    expect(MINT_PER_MEMBER_PER_HOUR).toBe(60);
    expect(w.calls.indexOf("db.hitRateLimit")).toBeLessThan(w.calls.indexOf("db.withCourseQr"));
    const limited = await makeCourseQrWorld({ rateLimitOk: false });
    const res = await handleCourseQrRequest(post("tokens", { facilityId: FACILITY }), deps(limited));
    expect(res.status).toBe(429);
    expect(res.headers.get("retry-after")).toBe("3600");
    expect(limited.calls).toEqual(["db.hitRateLimit"]);
    expect(limited.state.tokens).toEqual([]);
    expect(limited.state.grant).toBe(true);
  });

  it("a facility with no programme is 409 and ROLLS BACK: the PIN grant is given back and no row remains", async () => {
    const w = await makeCourseQrWorld({ programme: false });
    const res = await handleCourseQrRequest(post("tokens", { facilityId: FACILITY }), deps(w));
    expect(res.status).toBe(409);
    expect((await json(res)).error?.code).toBe("no_programme");
    expect(w.transactions).toEqual([{ committed: false }]);
    expect(w.state.grant).toBe(true);
    expect(w.state.tokens).toEqual([]);
  });

  it("a Vault seed that does not belong to the registered public key is a bare 503 and ROLLS BACK (the row and the PIN grant)", async () => {
    const w = await makeCourseQrWorld();
    w.state.rotatingPublicKey = w.keys.printedPublic; // some OTHER key is registered for the kid
    const res = await handleCourseQrRequest(post("tokens", { facilityId: FACILITY }), deps(w));
    expect(res.status).toBe(503);
    expect(await res.json()).toEqual({ error: { code: "service_unavailable", message: "partner service is not available" } });
    expect(w.transactions).toEqual([{ committed: false }]);
    expect(w.state.grant).toBe(true);
    expect(w.state.tokens).toEqual([]);
  });

  it("an unexpected failure is the constant 500 with no detail", async () => {
    const w = await makeCourseQrWorld();
    const res = await handleCourseQrRequest(post("tokens", { facilityId: FACILITY }), deps(w, { randomNonce: () => { throw new Error("boom " + w.state.rotatingSeed); } }));
    expect(res.status).toBe(500);
    const text = await res.text();
    expect(text).not.toContain("boom");
    expect(text).not.toContain(w.state.rotatingSeed);
  });

  it("the signer refuses a seed that is not 32 bytes and a nonce that is not 16, without echoing either", async () => {
    const seed = await makeSeed();
    const publicKey = await publicKeyOfSeed(seed);
    await expect(signRotatingToken({ kid: "k", facilityId: FACILITY, iat: 1, nonce: new Uint8Array(15), seed, publicKey })).rejects.toBeInstanceOf(CourseQrKeyMismatch);
    await expect(signRotatingToken({ kid: "k", facilityId: FACILITY, iat: 1, nonce: NONCE, seed: "short", publicKey })).rejects.toBeInstanceOf(CourseQrKeyMismatch);
    await expect(signRotatingToken({ kid: "k", facilityId: FACILITY, iat: 1, nonce: NONCE, seed, publicKey: await publicKeyOfSeed(await makeSeed()) })).rejects.toBeInstanceOf(CourseQrKeyMismatch);
    const err = await signRotatingToken({ kid: "k", facilityId: FACILITY, iat: 1, nonce: NONCE, seed: "x".repeat(43), publicKey }).catch((e: Error) => e);
    expect((err as Error).message).not.toContain("xxxx");
  });
});

describe("POST tokens/refresh: the heartbeat of one's own token", () => {
  it("reports the state and creates nothing: no row, no grant spent, no idle advance (PA-26)", async () => {
    const w = await makeCourseQrWorld();
    const minted = await json(await handleCourseQrRequest(post("tokens", { facilityId: FACILITY }), deps(w)));
    const nonceHash = String(minted.data!.nonceHash);
    w.state.grant = true;
    const seenBefore = (w.state.lastSeenAt = 5);
    w.state.nowS += 30;
    const res = await handleCourseQrRequest(post("tokens/refresh", { facilityId: FACILITY, nonceHash }), deps(w));
    expect(res.status).toBe(200);
    expect((await json(res)).data).toEqual({ state: "live", secondsLeft: 90 });
    expect(w.state.tokens).toHaveLength(1);
    expect(w.state.grant, "a refresh does not consume a PIN grant").toBe(true);
    expect(w.state.lastSeenAt, "PA-26: a refresh never advances last_seen_at").toBe(seenBefore);
    expect(w.rateLimitHits.at(-1)).toEqual({ bucket: REFRESH_BUCKET, windowSeconds: 3600, max: 1000 });
  });

  it("a used token, an expired one and an unknown one are told apart only as the database tells them", async () => {
    const w = await makeCourseQrWorld();
    const nonceHash = "b".repeat(64);
    w.state.tokens.push({ nonceHash, facilityId: FACILITY, issuedAt: w.state.nowS, usedAt: null });
    expect((await json(await handleCourseQrRequest(post("tokens/refresh", { facilityId: FACILITY, nonceHash }), deps(w)))).data).toEqual({ state: "live", secondsLeft: 120 });
    w.state.tokens[0]!.usedAt = w.state.nowS;
    expect((await json(await handleCourseQrRequest(post("tokens/refresh", { facilityId: FACILITY, nonceHash }), deps(w)))).data).toEqual({ state: "used", secondsLeft: 0 });
    w.state.tokens[0]!.usedAt = null;
    w.state.nowS += 500;
    expect((await json(await handleCourseQrRequest(post("tokens/refresh", { facilityId: FACILITY, nonceHash }), deps(w)))).data).toEqual({ state: "expired", secondsLeft: 0 });
    expect((await json(await handleCourseQrRequest(post("tokens/refresh", { facilityId: FACILITY, nonceHash: "c".repeat(64) }), deps(w)))).data).toEqual({ state: "unknown", secondsLeft: 0 });
  });

  it("the body is strict: both fields, a 64-character lower-case hex hash, nothing else", async () => {
    const w = await makeCourseQrWorld();
    for (const body of [{ facilityId: FACILITY }, { nonceHash: "a".repeat(64) }, { facilityId: FACILITY, nonceHash: "A".repeat(64) }, { facilityId: FACILITY, nonceHash: "a".repeat(63) }, { facilityId: FACILITY, nonceHash: "g".repeat(64) }, { facilityId: FACILITY, nonceHash: "a".repeat(64), x: 1 }]) {
      expect((await handleCourseQrRequest(post("tokens/refresh", body), deps(w))).status, JSON.stringify(body)).toBe(400);
    }
    expect(w.calls).toEqual([]);
  });

  it("another facility's scope is 403 (the database refuses it before it looks at the nonce)", async () => {
    const res = await handleCourseQrRequest(post("tokens/refresh", { facilityId: OTHER_FACILITY, nonceHash: "a".repeat(64) }), deps(await makeCourseQrWorld()));
    expect(res.status).toBe(403);
  });
});

describe("the handler keeps the session token out of the database", () => {
  it("passes only the sha256 of the bearer to the port", async () => {
    const w = await makeCourseQrWorld();
    const seen: string[] = [];
    const db = { ...w.db, withCourseQr: <T>(h: string, op: Parameters<typeof w.db.withCourseQr<T>>[1]) => (seen.push(h), w.db.withCourseQr(h, op)) };
    await handleCourseQrRequest(get(`pin?facilityId=${FACILITY}`), deps(w, { db }));
    expect(seen).toEqual([await sha256Hex(SESSION_TOKEN)]);
    expect(seen[0]).not.toContain("gr_ps_");
  });
});
