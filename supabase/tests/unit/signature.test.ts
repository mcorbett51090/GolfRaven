// supabase/tests/unit/signature.test.ts
//
// Real Ed25519 sign/verify round trip (Node's Web Crypto — the SAME
// `crypto.subtle` API supabase/functions/_shared/catalog/signature.ts
// uses, confirmed this session to also work under Deno 2.5.2 via `deno
// eval`; see that module's own header comment).
import { describe, expect, it } from "vitest";
import { base64UrlToBytes, bytesToBase64Url, verifyManifestSignature } from "../../functions/_shared/catalog/signature.js";

async function generateKeypair() {
  const kp = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const rawPublic = await crypto.subtle.exportKey("raw", kp.publicKey);
  return { keyPair: kp, publicKeyB64Url: bytesToBase64Url(new Uint8Array(rawPublic)) };
}

async function sign(privateKey: CryptoKey, payload: string): Promise<string> {
  const sig = await crypto.subtle.sign("Ed25519", privateKey, new TextEncoder().encode(payload));
  return bytesToBase64Url(new Uint8Array(sig));
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
