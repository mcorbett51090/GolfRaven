// supabase/tests/unit/qr-print-handler.test.ts
//
// The `qr-print` handler (docs/security/partner-auth-design.md 6.3 "qr-print", "Course QR token format" Q2; S2b, the Edge half of migration 0055), against the in-memory `CourseQrDb` of course-qr-fakes.ts. What is decided HERE:
// that the signature the handler registers is the one the player lane's format.ts VERIFIES (`verifyPrintedQr`, and byte-identical to the test minter's `mintPrintedQrSig` under the same key), that the facility id is
// bound into the signed bytes (the QR of X is useless for Y), that printing again is idempotent, that a seed that is not the registered key's writes NOTHING, and that no key material leaves in a response.
// Class A3, the operator's scope and the public-key rows are the database's: supabase/tests/matrix/33_course_qr_staff.sql.

import { describe, expect, it } from "vitest";
import { base64UrlDecode, base64UrlEncode, parsePrintedQr, printedQrMessage, verifyPrintedQr } from "../../functions/_shared/course-qr/format.ts";
import { signPrintedQr } from "../../functions/_shared/partner/course-qr-signer.ts";
import { handleQrPrintRequest, PRINT_BUCKET, PRINT_PER_MEMBER_PER_HOUR, QR_PRINT_FUNCTION, type QrPrintDeps } from "../../functions/_shared/partner/qr-print-handler.ts";
import { mintPrintedQrSig } from "./course-qr-test-keys.ts";
import { FACILITY, makeCourseQrWorld, OTHER_FACILITY, type CourseQrWorld } from "./course-qr-fakes.ts";
import { authed, fnReq, ORIGIN, SESSION_TOKEN } from "./partner-fakes.ts";

const FN = QR_PRINT_FUNCTION;
const LINK_ORIGIN = "https://golfraven.example.test";

function deps(w: CourseQrWorld, over: Partial<QrPrintDeps> = {}): QrPrintDeps {
  return { db: w.db, allowedOrigin: ORIGIN, linkOrigin: LINK_ORIGIN, ...over };
}
const get = (query = "", headers: Record<string, string> = authed()) => fnReq(FN, "GET", query === "" ? "" : `?${query}`, { headers });
const post = (body: unknown, headers: Record<string, string> = authed()) => fnReq(FN, "POST", "", { headers, body });
async function json(res: Response): Promise<{ data?: Record<string, unknown>; error?: { code: string; message: string } }> {
  return await res.json();
}

describe("the order: origin, preflight, method, bearer, body, rate limit, transaction", () => {
  it("a foreign Origin is 403, OPTIONS is 204, a wrong method is 405 (with Allow), a missing or foreign bearer is the one 401: no port touched", async () => {
    const w = await makeCourseQrWorld();
    expect((await handleQrPrintRequest(get(`facilityId=${FACILITY}`, { authorization: `Bearer ${SESSION_TOKEN}`, origin: "https://evil.test" }), deps(w))).status).toBe(403);
    expect((await handleQrPrintRequest(fnReq(FN, "OPTIONS", "", { headers: { origin: ORIGIN } }), deps(w))).status).toBe(204);
    const m = await handleQrPrintRequest(fnReq(FN, "DELETE", "", { headers: authed() }), deps(w));
    expect(m.status).toBe(405);
    expect(m.headers.get("allow")).toBe("GET, POST");
    expect((await handleQrPrintRequest(fnReq(FN, "GET", "sub/path", { headers: authed() }), deps(w))).status).toBe(404);
    expect((await handleQrPrintRequest(post({ facilityId: FACILITY }, { origin: ORIGIN }), deps(w))).status).toBe(401);
    expect((await handleQrPrintRequest(post({ facilityId: FACILITY }, { origin: ORIGIN, authorization: "Bearer eyJ.e30.sig" }), deps(w))).status).toBe(401);
    expect(w.calls).toEqual([]);
  });

  it("the body and the query are strict (400 before the limiter and any transaction)", async () => {
    const w = await makeCourseQrWorld();
    for (const body of [{}, { facilityId: "" }, { facilityId: FACILITY, qrKid: "k" }, { facilityId: "a b" }, []]) expect((await handleQrPrintRequest(post(body), deps(w))).status, JSON.stringify(body)).toBe(400);
    for (const q of ["", "facilityId=", "facilityId=fac_x&facilityId=fac_y", "facilityId=fac_x&x=1"]) expect((await handleQrPrintRequest(get(q), deps(w))).status, q).toBe(400);
    expect(w.calls).toEqual([]);
  });

  it("a refused bind is the one 401", async () => {
    const w = await makeCourseQrWorld({ bindRefused: true });
    expect((await handleQrPrintRequest(post({ facilityId: FACILITY }), deps(w))).status).toBe(401);
    expect((await handleQrPrintRequest(get(`facilityId=${FACILITY}`), deps(w))).status).toBe(401);
  });
});

describe("POST: sign and register the printed QR", () => {
  it("registers a signature the player lane VERIFIES, bound to this facility's id, under the public key the database now holds", async () => {
    const w = await makeCourseQrWorld();
    const res = await handleQrPrintRequest(post({ facilityId: FACILITY }), deps(w));
    expect(res.status).toBe(201);
    const d = (await json(res)).data!;
    expect(d).toMatchObject({ facilityId: FACILITY, qrKid: "kidprt1", changed: true });
    const sig = String(d.sig);
    expect(sig).toHaveLength(86);
    const parsed = parsePrintedQr("kidprt1", sig);
    expect(parsed).not.toBeNull();
    expect(w.state.printedPublicKey, "the public key row was ensured").toBe(w.keys.printedPublic);
    expect(await verifyPrintedQr(parsed!, FACILITY, w.keys.printedPublic)).toBe(true);
    expect(await verifyPrintedQr(parsed!, OTHER_FACILITY, w.keys.printedPublic), "the QR of X is useless for Y").toBe(false);
    expect(d.link).toBe(`${LINK_ORIGIN}/q/f/facility-x#kidprt1.${sig}`);
    expect(w.state.printed).toMatchObject({ kid: "kidprt1", sig, revokedAt: null });
    expect(w.calls).toEqual(["db.hitRateLimit", "db.withCourseQr", "tx.printKey", "tx.printWrite"]);
    expect(w.rateLimitHits).toEqual([{ bucket: PRINT_BUCKET, windowSeconds: 3600, max: PRINT_PER_MEMBER_PER_HOUR }]);
  });

  it("is BYTE-IDENTICAL to the test minter's signature under the same key and signs exactly the documented message", async () => {
    const w = await makeCourseQrWorld();
    const sig = String((await json(await handleQrPrintRequest(post({ facilityId: FACILITY }), deps(w)))).data!.sig);
    const pkcs8 = new Uint8Array([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20, ...base64UrlDecode(w.state.printedSeed)!]);
    const privateKey = await crypto.subtle.importKey("pkcs8", pkcs8.buffer, { name: "Ed25519" }, false, ["sign"]);
    expect(sig).toBe(await mintPrintedQrSig({ publicKeyB64Url: w.keys.printedPublic, privateKey }, FACILITY, "kidprt1"));
    expect(new TextDecoder().decode(printedQrMessage(FACILITY, "kidprt1"))).toBe(`golfraven/printed-qr/v1\u0000${FACILITY}\u0000kidprt1`);
    expect(base64UrlEncode(new Uint8Array(64))).toHaveLength(86);
  });

  it("printing again is idempotent: 200, changed false, the same signature", async () => {
    const w = await makeCourseQrWorld();
    const first = (await json(await handleQrPrintRequest(post({ facilityId: FACILITY }), deps(w)))).data!;
    const res = await handleQrPrintRequest(post({ facilityId: FACILITY }), deps(w));
    expect(res.status).toBe(200);
    const second = (await json(res)).data!;
    expect(second.changed).toBe(false);
    expect(second.sig).toBe(first.sig);
  });

  it("a key rotation (a new Vault kid) REPLACES the registration", async () => {
    const w = await makeCourseQrWorld();
    const first = (await json(await handleQrPrintRequest(post({ facilityId: FACILITY }), deps(w)))).data!;
    const next = await makeCourseQrWorld();
    w.state.printedSeed = next.state.printedSeed;
    w.state.printedKid = "kidprt2";
    w.state.printedPublicKey = null;
    const res = await handleQrPrintRequest(post({ facilityId: FACILITY }), deps(w));
    expect(res.status).toBe(201);
    const d = (await json(res)).data!;
    expect(d).toMatchObject({ qrKid: "kidprt2", changed: true });
    expect(d.sig).not.toBe(first.sig);
    expect(w.state.printed?.kid).toBe("kidprt2");
  });

  it("a Vault seed that is NOT the registered public key's writes NOTHING and is a bare 503", async () => {
    const w = await makeCourseQrWorld();
    w.state.printedPublicKey = w.keys.rotatingPublic; // the database holds some other key for the kid
    const res = await handleQrPrintRequest(post({ facilityId: FACILITY }), deps(w));
    expect(res.status).toBe(503);
    expect(await res.json()).toEqual({ error: { code: "service_unavailable", message: "partner service is not available" } });
    expect(w.state.printed).toBeNull();
    expect(w.calls).toEqual(["db.hitRateLimit", "db.withCourseQr", "tx.printKey"]);
    expect(w.transactions).toEqual([{ committed: false }]);
  });

  it("a revoked Vault key, and a database that refuses the kid or the key at the write, are a bare 503 with the transaction rolled back", async () => {
    const revoked = await makeCourseQrWorld({ printedKeyRevoked: true });
    expect((await handleQrPrintRequest(post({ facilityId: FACILITY }), deps(revoked))).status).toBe(503);
    expect(revoked.state.printed).toBeNull();
    const w = await makeCourseQrWorld();
    const real = w.db.withCourseQr.bind(w.db);
    const db = {
      ...w.db,
      withCourseQr: <T>(h: string, op: (s: never) => Promise<T>) => real(h, (s) => op({ ...s, printWrite: async () => ({ status: "kid_mismatch" as const, changed: false }) } as never)),
    };
    expect((await handleQrPrintRequest(post({ facilityId: FACILITY }), deps(w, { db }))).status).toBe(503);
    expect(w.state.printed).toBeNull();
  });

  it("an operator with no A3 window, or no scope at the facility, is 403", async () => {
    expect((await handleQrPrintRequest(post({ facilityId: FACILITY }), deps(await makeCourseQrWorld({ a3: false })))).status).toBe(403);
    expect((await handleQrPrintRequest(post({ facilityId: OTHER_FACILITY }), deps(await makeCourseQrWorld()))).status).toBe(403);
  });

  it("an unknown facility (an admin's question) is a 404", async () => {
    const w = await makeCourseQrWorld();
    const db = { ...w.db, withCourseQr: <T>(_h: string, op: (s: never) => Promise<T>) => op({ printKey: async () => ({ status: "no_facility" as const }) } as never) };
    expect((await handleQrPrintRequest(post({ facilityId: "fac_nope" }), deps(w, { db }))).status).toBe(404);
  });

  it("over the cap is 429 with Retry-After, before any transaction", async () => {
    const w = await makeCourseQrWorld({ rateLimitOk: false });
    const res = await handleQrPrintRequest(post({ facilityId: FACILITY }), deps(w));
    expect(res.status).toBe(429);
    expect(res.headers.get("retry-after")).toBe("3600");
    expect(w.calls).toEqual(["db.hitRateLimit"]);
  });

  it("no key material leaves: not the seed, not a field named for it", async () => {
    const w = await makeCourseQrWorld();
    const res = await handleQrPrintRequest(post({ facilityId: FACILITY }), deps(w));
    const text = await res.clone().text();
    expect(text).not.toContain(w.state.printedSeed);
    expect(text.toLowerCase()).not.toMatch(/seed|signingkey|privatekey/);
    expect(res.headers.get("cache-control")).toBe("no-store");
  });

  it("without a link origin the answer carries the kid and signature and a null link", async () => {
    const w = await makeCourseQrWorld();
    const d = (await json(await handleQrPrintRequest(post({ facilityId: FACILITY }), deps(w, { linkOrigin: null })))).data!;
    expect(d.link).toBeNull();
    expect(d.qrKid).toBe("kidprt1");
  });

  it("the signer itself: deterministic, and the public key it derives is the seed's", async () => {
    const w = await makeCourseQrWorld();
    const a = await signPrintedQr({ facilityId: FACILITY, qrKid: "kidprt1", seed: w.state.printedSeed });
    const b = await signPrintedQr({ facilityId: FACILITY, qrKid: "kidprt1", seed: w.state.printedSeed });
    expect(a).toEqual(b);
    expect(a.publicKey).toBe(w.keys.printedPublic);
    expect((await signPrintedQr({ facilityId: OTHER_FACILITY, qrKid: "kidprt1", seed: w.state.printedSeed })).sig).not.toBe(a.sig);
  });
});

describe("GET: the registered printed QR", () => {
  it("not printed is 404 not_printed; printed is the kid, signature and times; revoked says so", async () => {
    const w = await makeCourseQrWorld();
    const none = await handleQrPrintRequest(get(`facilityId=${FACILITY}`), deps(w));
    expect(none.status).toBe(404);
    expect((await json(none)).error?.code).toBe("not_printed");
    await handleQrPrintRequest(post({ facilityId: FACILITY }), deps(w));
    const ok = await handleQrPrintRequest(get(`facilityId=${FACILITY}`), deps(w));
    expect(ok.status).toBe(200);
    expect((await json(ok)).data).toMatchObject({ facilityId: FACILITY, qrKid: "kidprt1", revoked: false, revokedAt: null });
    w.state.printed!.revokedAt = "2030-01-02T00:00:00.000Z";
    expect((await json(await handleQrPrintRequest(get(`facilityId=${FACILITY}`), deps(w)))).data).toMatchObject({ revoked: true, revokedAt: "2030-01-02T00:00:00.000Z" });
  });

  it("another facility's scope is 403", async () => {
    expect((await handleQrPrintRequest(get(`facilityId=${OTHER_FACILITY}`), deps(await makeCourseQrWorld()))).status).toBe(403);
  });
});
