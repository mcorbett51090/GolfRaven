// supabase/tests/unit/course-qr-format.test.ts
//
// The course QR's two wire formats and their verification (_shared/course-qr/format.ts): what a rotating token and a printed-QR signature must look like, and the ways a forged or
// mangled one is refused. Tokens are minted by TEST-ONLY code (course-qr-test-keys.ts) under keys generated at run time. S2b's signing side must produce exactly what these tests mint.

import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  PRINTED_QR_LABEL,
  ROTATING_TOKEN_TYP,
  base64UrlDecode,
  base64UrlEncode,
  nonceHashHex,
  parsePrintedQr,
  parseRotatingToken,
  printedQrMessage,
  verifyEd25519,
  verifyPrintedQr,
  verifyRotatingToken,
} from "../../functions/_shared/course-qr/format.ts";
import { ROTATING_TOKEN_WINDOW_SECONDS } from "../../functions/_shared/course-qr/params.ts";
import { generateTestSigningKey, mintPrintedQrSig, mintRotatingToken } from "./course-qr-test-keys.ts";

const IAT = 1_790_000_000;
const sha256Hex = async (b: Uint8Array) => createHash("sha256").update(b).digest("hex");
const flip = (s: string, at: number) => s.slice(0, at) + (s[at] === "A" ? "B" : "A") + s.slice(at + 1);

describe("base64url", () => {
  it("round-trips and is strict: no padding, no other alphabet, no impossible length, no empty string", () => {
    const bytes = Uint8Array.from([251, 255, 0, 1, 2, 250]);
    const enc = base64UrlEncode(bytes);
    expect(enc).toBe("-_8AAQL6");
    expect([...base64UrlDecode(enc)!]).toEqual([...bytes]);
    expect(base64UrlDecode("AAAA=")).toBeNull();
    expect(base64UrlDecode("AA+A")).toBeNull();
    expect(base64UrlDecode("A")).toBeNull(); // length % 4 === 1 is no byte string
    expect(base64UrlDecode("")).toBeNull();
    expect(base64UrlDecode("AA AA")).toBeNull();
  });
});

describe("the rotating token (Q1)", () => {
  it("a token minted as documented parses, verifies under its kid's key, and carries the documented claims", async () => {
    const key = await generateTestSigningKey();
    const m = await mintRotatingToken({ key, kid: "rk1", facilityId: "fac_x", iat: IAT });
    const parsed = parseRotatingToken(m.token)!;
    expect(parsed).not.toBeNull();
    expect(parsed.claims).toMatchObject({ fac: "fac_x", iat: IAT, exp: IAT + ROTATING_TOKEN_WINDOW_SECONDS, kid: "rk1" });
    expect(ROTATING_TOKEN_WINDOW_SECONDS).toBe(120);
    expect(parsed.claims.nonce.length).toBe(16);
    expect(await verifyRotatingToken(parsed, key.publicKeyB64Url)).toBe(true);
  });

  it("the header is exactly {alg: EdDSA, kid, typ: golfraven-course-qr+jwt} and the signing input is the received header.payload", async () => {
    const key = await generateTestSigningKey();
    const m = await mintRotatingToken({ key, kid: "rk1", facilityId: "fac_x", iat: IAT });
    const [h, p] = m.token.split(".");
    expect(JSON.parse(Buffer.from(h!, "base64url").toString())).toEqual({ alg: "EdDSA", kid: "rk1", typ: ROTATING_TOKEN_TYP });
    expect(ROTATING_TOKEN_TYP).toBe("golfraven-course-qr+jwt");
    expect(Object.keys(JSON.parse(Buffer.from(p!, "base64url").toString())).sort()).toEqual(["exp", "fac", "iat", "kid", "nonce"]);
    expect(new TextDecoder().decode(parseRotatingToken(m.token)!.signingInput)).toBe(`${h}.${p}`);
  });

  it("the nonce hash is the lower-case hex SHA-256 of the 16 RAW nonce bytes (app.course_qr_token.nonce_hash)", async () => {
    const key = await generateTestSigningKey();
    const nonce = Uint8Array.from({ length: 16 }, (_, i) => i * 7);
    const m = await mintRotatingToken({ key, kid: "rk1", facilityId: "fac_x", iat: IAT, nonce });
    const parsed = parseRotatingToken(m.token)!;
    const hash = await nonceHashHex(parsed.claims.nonce, sha256Hex);
    expect(hash).toBe(createHash("sha256").update(Buffer.from(nonce)).digest("hex"));
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("a signature that does not verify: another key, a tampered payload, a tampered header, a tampered signature", async () => {
    const key = await generateTestSigningKey();
    const other = await generateTestSigningKey();
    const m = await mintRotatingToken({ key, kid: "rk1", facilityId: "fac_x", iat: IAT });
    expect(await verifyRotatingToken(parseRotatingToken(m.token)!, other.publicKeyB64Url)).toBe(false);
    const [h, p, s] = m.token.split(".") as [string, string, string];
    const forgedPayload = base64UrlEncode(new TextEncoder().encode(JSON.stringify({ ...m.payload, fac: "fac_y" })));
    const t1 = parseRotatingToken(`${h}.${forgedPayload}.${s}`)!;
    expect(t1).not.toBeNull(); // well-formed: only the signature can refuse it
    expect(await verifyRotatingToken(t1, key.publicKeyB64Url)).toBe(false);
    const t2 = parseRotatingToken(`${h}.${p}.${flip(s, 10)}`)!;
    expect(await verifyRotatingToken(t2, key.publicKeyB64Url)).toBe(false);
  });

  it("is refused before any key is chosen when it is not even shaped like a token", async () => {
    const key = await generateTestSigningKey();
    const good = await mintRotatingToken({ key, kid: "rk1", facilityId: "fac_x", iat: IAT });
    const [h, p, s] = good.token.split(".") as [string, string, string];
    const enc = (o: unknown) => base64UrlEncode(new TextEncoder().encode(JSON.stringify(o)));
    const bad: Array<[string, string]> = [
      ["empty", ""],
      ["two parts", `${h}.${p}`],
      ["four parts", `${h}.${p}.${s}.${s}`],
      ["a part with padding", `${h}=.${p}.${s}`],
      ["a signature of the wrong length", `${h}.${p}.${s.slice(0, 80)}`],
      ["too long", "A".repeat(700)],
    ];
    for (const [why, t] of bad) expect(parseRotatingToken(t), why).toBeNull();
    const variants: Array<[string, Record<string, unknown>, Record<string, unknown>]> = [
      ["alg none", { alg: "none", kid: "rk1", typ: ROTATING_TOKEN_TYP }, good.payload],
      ["alg HS256", { alg: "HS256", kid: "rk1", typ: ROTATING_TOKEN_TYP }, good.payload],
      ["another typ", { alg: "EdDSA", kid: "rk1", typ: "JWT" }, good.payload],
      ["an extra header member", { alg: "EdDSA", kid: "rk1", typ: ROTATING_TOKEN_TYP, jku: "https://x.invalid/keys" }, good.payload],
      ["a header with no kid", { alg: "EdDSA", typ: ROTATING_TOKEN_TYP }, good.payload],
      ["a kid with a bad character", { alg: "EdDSA", kid: "r k1", typ: ROTATING_TOKEN_TYP }, { ...good.payload, kid: "r k1" }],
      ["an extra payload member", { alg: "EdDSA", kid: "rk1", typ: ROTATING_TOKEN_TYP }, { ...good.payload, admin: true }],
      ["a missing payload member", { alg: "EdDSA", kid: "rk1", typ: ROTATING_TOKEN_TYP }, { exp: IAT + 120, fac: "fac_x", iat: IAT, kid: "rk1" }],
      ["a payload kid that is not the header's", { alg: "EdDSA", kid: "rk1", typ: ROTATING_TOKEN_TYP }, { ...good.payload, kid: "rk2" }],
      ["exp that is not iat + 120", { alg: "EdDSA", kid: "rk1", typ: ROTATING_TOKEN_TYP }, { ...good.payload, exp: IAT + 3600 }],
      ["a fractional iat", { alg: "EdDSA", kid: "rk1", typ: ROTATING_TOKEN_TYP }, { ...good.payload, iat: IAT + 0.5, exp: IAT + 120.5 }],
      ["a nonce that is too short (64 bits)", { alg: "EdDSA", kid: "rk1", typ: ROTATING_TOKEN_TYP }, { ...good.payload, nonce: base64UrlEncode(new Uint8Array(8)) }],
      ["a nonce that is too long (24 bytes)", { alg: "EdDSA", kid: "rk1", typ: ROTATING_TOKEN_TYP }, { ...good.payload, nonce: base64UrlEncode(new Uint8Array(24)) }],
      ["a facility with a space", { alg: "EdDSA", kid: "rk1", typ: ROTATING_TOKEN_TYP }, { ...good.payload, fac: "fac x" }],
      ["a numeric facility", { alg: "EdDSA", kid: "rk1", typ: ROTATING_TOKEN_TYP }, { ...good.payload, fac: 7 }],
    ];
    for (const [why, header, payload] of variants) {
      const m = await mintRotatingToken({ key, kid: "rk1", facilityId: "fac_x", iat: IAT, header, payload });
      expect(parseRotatingToken(m.token), why).toBeNull();
    }
    // a JSON array or a scalar where an object belongs
    expect(parseRotatingToken(`${enc([1])}.${p}.${s}`)).toBeNull();
    expect(parseRotatingToken(`${h}.${enc("x")}.${s}`)).toBeNull();
  });

  it("an Ed25519 verification with a malformed key or signature is `false`, never a throw", async () => {
    const key = await generateTestSigningKey();
    const msg = new TextEncoder().encode("x");
    expect(await verifyEd25519("short", msg, new Uint8Array(64))).toBe(false);
    expect(await verifyEd25519(key.publicKeyB64Url, msg, new Uint8Array(63))).toBe(false);
    expect(await verifyEd25519("!".repeat(43), msg, new Uint8Array(64))).toBe(false);
    expect(await verifyEd25519(key.publicKeyB64Url, msg, new Uint8Array(64))).toBe(false);
  });
});

describe("the printed facility QR (Q2)", () => {
  it("the signed bytes are `golfraven/printed-qr/v1` NUL <facility id> NUL <qr_kid> (a pinned encoding)", () => {
    expect(PRINTED_QR_LABEL).toBe("golfraven/printed-qr/v1");
    const bytes = printedQrMessage("fac_x", "pq1");
    expect(Buffer.from(bytes).toString("hex")).toBe(
      Buffer.from("golfraven/printed-qr/v1", "utf8").toString("hex") + "00" + Buffer.from("fac_x", "utf8").toString("hex") + "00" + Buffer.from("pq1", "utf8").toString("hex"),
    );
    expect(Buffer.from(bytes).toString("hex")).toBe("676f6c66726176656e2f7072696e7465642d71722f7631" + "00" + "6661635f78" + "00" + "707131");
  });

  it("a signature verifies for ITS facility and kid only: the QR of facility X is useless for Y, and a re-labelled kid fails", async () => {
    const key = await generateTestSigningKey();
    const sig = await mintPrintedQrSig(key, "fac_x", "pq1");
    expect(sig).toMatch(/^[A-Za-z0-9_-]{86}$/);
    const parsed = parsePrintedQr("pq1", sig)!;
    expect(parsed).not.toBeNull();
    expect(await verifyPrintedQr(parsed, "fac_x", key.publicKeyB64Url)).toBe(true);
    expect(await verifyPrintedQr(parsed, "fac_y", key.publicKeyB64Url)).toBe(false);
    expect(await verifyPrintedQr(parsePrintedQr("pq2", sig)!, "fac_x", key.publicKeyB64Url)).toBe(false);
    expect(await verifyPrintedQr(parsed, "fac_x", (await generateTestSigningKey()).publicKeyB64Url)).toBe(false);
  });

  it("a facility id and a kid cannot be shifted across the separator (the NUL makes the encoding unambiguous)", async () => {
    const key = await generateTestSigningKey();
    const sig = await mintPrintedQrSig(key, "fac_x", "pq1");
    const parsed = parsePrintedQr("pq1", sig)!;
    // the same concatenation with the boundary moved is a different message
    expect(await verifyPrintedQr(parsed, "fac_x\u0000pq", key.publicKeyB64Url)).toBe(false);
    expect(await verifyPrintedQr(parsePrintedQr("1", sig)!, "fac_xpq", key.publicKeyB64Url)).toBe(false);
  });

  it("a malformed kid or signature is refused at the parse", () => {
    expect(parsePrintedQr("pq1", "x".repeat(85))).toBeNull();
    expect(parsePrintedQr("pq1", "x".repeat(87))).toBeNull();
    expect(parsePrintedQr("pq1", "!".repeat(86))).toBeNull();
    expect(parsePrintedQr("bad kid", "A".repeat(86))).toBeNull();
    expect(parsePrintedQr("", "A".repeat(86))).toBeNull();
    expect(parsePrintedQr("pq1", "A".repeat(86))).not.toBeNull();
  });

  it("a rotating-token signature is not a printed-QR signature, and the reverse (different bytes are signed)", async () => {
    const key = await generateTestSigningKey();
    const m = await mintRotatingToken({ key, kid: "k1", facilityId: "fac_x", iat: IAT });
    const sigPart = m.token.split(".")[2]!;
    expect(await verifyPrintedQr(parsePrintedQr("k1", sigPart)!, "fac_x", key.publicKeyB64Url)).toBe(false);
    const printed = await mintPrintedQrSig(key, "fac_x", "k1");
    const [h, p] = m.token.split(".");
    expect(await verifyRotatingToken(parseRotatingToken(`${h}.${p}.${printed}`)!, key.publicKeyB64Url)).toBe(false);
  });
});
