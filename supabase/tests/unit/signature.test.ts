// supabase/tests/unit/signature.test.ts
//
// Real Ed25519 sign/verify round trip (Node's Web Crypto — the SAME
// `crypto.subtle` API supabase/functions/_shared/catalog/signature.ts
// uses, confirmed this session to also work under Deno 2.5.2 via `deno
// eval`; see that module's own header comment).
import { describe, expect, it } from "vitest";
import { base64ToBytes, base64UrlToBytes, bytesToBase64Url, verifyArtifactSignature, verifyManifestSignature } from "../../functions/_shared/catalog/signature.js";

async function generateKeypair() {
  const kp = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const rawPublic = await crypto.subtle.exportKey("raw", kp.publicKey);
  return { keyPair: kp, publicKeyB64Url: bytesToBase64Url(new Uint8Array(rawPublic)) };
}

async function sign(privateKey: CryptoKey, payload: string): Promise<string> {
  const sig = await crypto.subtle.sign("Ed25519", privateKey, new TextEncoder().encode(payload));
  return bytesToBase64Url(new Uint8Array(sig));
}

/** Standard (padded) base64 — the REAL `tools/catalog/src/sign.ts#signBytes`
 * encoding (`cryptoSign(...).toString("base64")`), never base64url. Node's
 * `Buffer` isn't used here (this module stays framework-free, matching
 * signature.ts's own header) — `btoa` over the raw signature bytes IS
 * standard base64 by definition; only `bytesToBase64Url` above post
 * -processes it into the url-safe, unpadded variant. */
function toStdBase64(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

async function signStd(privateKey: CryptoKey, payload: string): Promise<string> {
  const sig = await crypto.subtle.sign("Ed25519", privateKey, new TextEncoder().encode(payload));
  return toStdBase64(new Uint8Array(sig));
}

describe("verifyManifestSignature", () => {
  it("verifies a real signature over the exact payload it was made for", async () => {
    const { keyPair, publicKeyB64Url } = await generateKeypair();
    const signatureB64Url = await sign(keyPair.privateKey, "42");
    const ok = await verifyManifestSignature({ publicKeyB64Url, signatureB64Url, payload: "42" });
    expect(ok).toBe(true);
  });

  it("rejects a signature over a DIFFERENT payload than the one presented", async () => {
    const { keyPair, publicKeyB64Url } = await generateKeypair();
    const signatureB64Url = await sign(keyPair.privateKey, "42");
    const ok = await verifyManifestSignature({ publicKeyB64Url, signatureB64Url, payload: "43" });
    expect(ok).toBe(false);
  });

  it("rejects a signature verified against the WRONG public key", async () => {
    const a = await generateKeypair();
    const b = await generateKeypair();
    const signatureB64Url = await sign(a.keyPair.privateKey, "42");
    const ok = await verifyManifestSignature({ publicKeyB64Url: b.publicKeyB64Url, signatureB64Url, payload: "42" });
    expect(ok).toBe(false);
  });

  it("never throws on garbage input — resolves false", async () => {
    await expect(verifyManifestSignature({ publicKeyB64Url: "not-a-key", signatureB64Url: "not-a-sig", payload: "x" })).resolves.toBe(false);
    await expect(verifyManifestSignature({ publicKeyB64Url: "", signatureB64Url: "", payload: "" })).resolves.toBe(false);
  });

  it("base64UrlToBytes/bytesToBase64Url round-trip", () => {
    const original = new Uint8Array([0, 1, 2, 253, 254, 255, 10, 20, 30]);
    const encoded = bytesToBase64Url(original);
    expect(encoded).not.toMatch(/[+/=]/);
    expect([...base64UrlToBytes(encoded)]).toEqual([...original]);
  });
});

// ⛔ NEW (P3e round 2 gate, B1: "add an interop test that signs with the
// real tools/catalog signer... your self-signed fixtures hid this").
// `verifyArtifactSignature` is the decoder import-handler.ts actually
// uses for manifest/versions artifact signatures — this section proves
// it accepts the REAL P1 wire encoding (standard, padded base64,
// `tools/catalog/src/sign.ts#signBytes`'s own
// `cryptoSign(...).toString("base64")`), which `verifyManifestSignature`
// above (the base64url-pinned decoder for evidence intake's own
// `manifestSig` field) correctly does NOT accept.
describe("verifyArtifactSignature (B1: the REAL P1 artifact signature encoding — standard, padded base64)", () => {
  it("verifies a real signature encoded as standard base64 over the exact payload it was made for", async () => {
    const { keyPair, publicKeyB64Url } = await generateKeypair();
    const signatureB64Url = await signStd(keyPair.privateKey, "42");
    // Confirms this is genuinely standard base64, not merely base64url in
    // disguise — a signature of ANY meaningful length almost always
    // contains at least one of +, / or a trailing = pad char.
    expect(signatureB64Url).toMatch(/[+/=]/);
    const ok = await verifyArtifactSignature({ publicKeyB64Url, signatureB64Url, payload: "42" });
    expect(ok).toBe(true);
  });

  it("rejects a signature over a DIFFERENT payload than the one presented", async () => {
    const { keyPair, publicKeyB64Url } = await generateKeypair();
    const signatureB64Url = await signStd(keyPair.privateKey, "42");
    const ok = await verifyArtifactSignature({ publicKeyB64Url, signatureB64Url, payload: "43" });
    expect(ok).toBe(false);
  });

  it("rejects a signature verified against the WRONG public key", async () => {
    const a = await generateKeypair();
    const b = await generateKeypair();
    const signatureB64Url = await signStd(a.keyPair.privateKey, "42");
    const ok = await verifyArtifactSignature({ publicKeyB64Url: b.publicKeyB64Url, signatureB64Url, payload: "42" });
    expect(ok).toBe(false);
  });

  // The bug B1 fixes, pinned directly: a real P1 signature (standard
  // base64) verified through the OLD, base64url-only decoder must fail
  // — proving `verifyManifestSignature` and `verifyArtifactSignature` are
  // genuinely different decoders, not the same function under two names.
  it("a real standard-base64 P1 signature is REJECTED by the base64url-only verifyManifestSignature — the exact bug B1 fixes", async () => {
    const { keyPair, publicKeyB64Url } = await generateKeypair();
    const signatureB64Url = await signStd(keyPair.privateKey, "42");
    const ok = await verifyManifestSignature({ publicKeyB64Url, signatureB64Url, payload: "42" });
    expect(ok).toBe(false);
  });

  it("never throws on garbage input — resolves false", async () => {
    await expect(verifyArtifactSignature({ publicKeyB64Url: "not-a-key", signatureB64Url: "not-a-sig", payload: "x" })).resolves.toBe(false);
    await expect(verifyArtifactSignature({ publicKeyB64Url: "", signatureB64Url: "", payload: "" })).resolves.toBe(false);
  });

  it("base64ToBytes round-trips standard (padded) base64, including a padding character", () => {
    // 5 bytes -> base64 groups of 3 leave a 2-byte remainder -> exactly
    // one "=" pad char — proves the decoder handles real padding, not
    // just the unpadded case base64url always produces.
    const original = new Uint8Array([251, 255, 62, 63, 0]);
    const encoded = toStdBase64(original);
    expect(encoded).toMatch(/=$/);
    expect([...base64ToBytes(encoded)]).toEqual([...original]);
  });

  it("base64ToBytes rejects unpadded base64url (the two encodings are not interchangeable)", () => {
    const original = new Uint8Array([251, 255, 62, 63, 0, 1]);
    const urlEncoded = bytesToBase64Url(original);
    expect(() => base64ToBytes(urlEncoded)).toThrow();
  });
});
