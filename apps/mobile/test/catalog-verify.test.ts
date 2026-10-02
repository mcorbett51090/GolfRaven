/**
 * The app-side verifier against artifacts produced by the REAL
 * `tools/catalog` emitter/signer. The signing side hashes and signs with
 * `node:crypto`; the verifier here uses `@noble/*` — so every `ok` result
 * below is also an interop proof between the two implementations of the
 * primitives, and every rejection is one of `verifyArtifact`'s own failure
 * classes.
 */
import { signVersions } from "@golfraven/catalog-tools/sign";
import { canonicalStringify } from "@golfraven/catalog-tools/manifest-core";
import { createPrivateKey } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { nobleCatalogCrypto } from "../src/catalog/crypto";
import { verifyCatalogEnvelope, type EnvelopeBytes, type VerifyContext, type VerifyResult } from "../src/catalog/verify";
import { CatalogPublisher, flipByte, makeKey, replaceText, type SignedCatalog } from "./support/signed-catalog";

const KEY_A = makeKey("k-prod-a");
const KEY_B = makeKey("k-prod-b");
const pub = new CatalogPublisher();
let v1: SignedCatalog;
let v2: SignedCatalog;

beforeAll(async () => {
  v1 = await pub.emit({ version: "20260101-aaaaaaa", generatedAt: "2026-01-01T00:00:00.000Z", key: KEY_A });
  v2 = await pub.emit({ version: "20260201-bbbbbbb", generatedAt: "2026-02-01T00:00:00.000Z", key: KEY_A });
});
afterAll(() => pub.dispose());

const env = (c: SignedCatalog): EnvelopeBytes => ({
  manifest: c.files.get("manifest.json")!,
  manifestSig: c.files.get("manifest.sig.json")!,
  versions: c.files.get("versions.json")!,
  versionsSig: c.files.get("versions.sig.json")!,
});

const ctx = (over: Partial<VerifyContext> = {}): VerifyContext => ({
  crypto: nobleCatalogCrypto,
  trustedKeys: [KEY_A.trusted, KEY_B.trusted],
  revokedKids: new Set(),
  supportedContractMajor: 0,
  ...over,
});

function codes(r: VerifyResult): string[] {
  return r.ok ? [] : r.issues.map((i) => i.code);
}

describe("verifyCatalogEnvelope — genuine artifacts", () => {
  it("accepts a catalog the real signer produced (noble verifies node:crypto's Ed25519 + sha256)", () => {
    const r = verifyCatalogEnvelope(env(v1), ctx());
    expect(codes(r)).toEqual([]);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.value.manifest.catalogVersion).toBe("20260101-aaaaaaa");
      expect(r.value.versions.map((v) => v.version)).toEqual(["20260101-aaaaaaa"]);
    }
  });

  it("accepts the newest version of a two-entry versions.json", () => {
    const r = verifyCatalogEnvelope(env(v2), ctx({ minCatalogVersion: "20260101-aaaaaaa" }));
    expect(codes(r)).toEqual([]);
    if (r.ok) expect(r.value.versions).toHaveLength(2);
  });

  it("accepts a re-fetch of the cached version (anti-rollback uses 'older than', not 'not newer')", () => {
    expect(verifyCatalogEnvelope(env(v1), ctx({ minCatalogVersion: "20260101-aaaaaaa" })).ok).toBe(true);
  });
});

describe("verifyCatalogEnvelope — fails closed", () => {
  it("a flipped signature byte is BAD_SIGNATURE", () => {
    const e = env(v1);
    const sigDoc = Buffer.from(e.manifestSig).toString("utf8");
    const sig = (JSON.parse(sigDoc) as { sig: string }).sig;
    const bytes = Buffer.from(sig, "base64");
    bytes[10] = bytes[10]! ^ 0xff;
    const forged = replaceText(e.manifestSig, sig, bytes.toString("base64"));
    expect(codes(verifyCatalogEnvelope({ ...e, manifestSig: forged }, ctx()))).toEqual(["BAD_SIGNATURE"]);
  });

  it("a modified manifest.json (e.g. lowering minAppVersion) with the original sidecar is MANIFEST_TAMPERED", () => {
    const e = env(v1);
    const tampered = replaceText(e.manifest, '"minAppVersion": "0.0.0"', '"minAppVersion": "0.0.1"');
    expect(codes(verifyCatalogEnvelope({ ...e, manifest: tampered }, ctx()))).toContain("MANIFEST_TAMPERED");
  });

  it("a kid not in the compiled-in keyset is UNKNOWN_KID", () => {
    expect(codes(verifyCatalogEnvelope(env(v1), ctx({ trustedKeys: [KEY_B.trusted] })))).toContain("UNKNOWN_KID");
  });

  it("an empty keyset (what a build compiles in before the §3.5 production keyset exists) verifies nothing", () => {
    const r = verifyCatalogEnvelope(env(v1), ctx({ trustedKeys: [] }));
    expect(r.ok).toBe(false);
    expect(codes(r)).toContain("UNKNOWN_KID");
  });

  it("the right kid label with the wrong public key is BAD_SIGNATURE", () => {
    const impostor = { kid: KEY_A.kid, publicKeyB64Url: KEY_B.trusted.publicKeyB64Url };
    expect(codes(verifyCatalogEnvelope(env(v1), ctx({ trustedKeys: [impostor] })))).toEqual(["BAD_SIGNATURE"]);
  });

  it("a kid in the install's revoked set is REVOKED_KID even though the signature is valid", () => {
    expect(codes(verifyCatalogEnvelope(env(v1), ctx({ revokedKids: new Set([KEY_A.kid]) })))).toContain("REVOKED_KID");
  });

  it("a manifest that lists its own signing kid in revokedKids[] is refused (self-revoking)", async () => {
    const p = new CatalogPublisher();
    try {
      const c = await p.emit({ version: "20260301-ccccccc", generatedAt: "2026-03-01T00:00:00.000Z", key: KEY_A, revokedKids: [KEY_A.kid] });
      expect(codes(verifyCatalogEnvelope(env(c), ctx()))).toEqual(["REVOKED_KID"]);
    } finally {
      await p.dispose();
    }
  });

  it("an older catalogVersion than the cached one is CATALOG_VERSION_ROLLBACK", () => {
    expect(codes(verifyCatalogEnvelope(env(v1), ctx({ minCatalogVersion: "20260201-bbbbbbb" })))).toEqual(["CATALOG_VERSION_ROLLBACK"]);
  });

  it("a different contract MAJOR is CONTRACT_MAJOR_MISMATCH", () => {
    expect(codes(verifyCatalogEnvelope(env(v1), ctx({ supportedContractMajor: 1 })))).toEqual(["CONTRACT_MAJOR_MISMATCH"]);
  });

  it("a modified versions.json is VERSIONS_TAMPERED", () => {
    const e = env(v2);
    const tampered = replaceText(e.versions, "20260101-aaaaaaa", "20250101-aaaaaaa");
    expect(codes(verifyCatalogEnvelope({ ...e, versions: tampered }, ctx()))).toContain("VERSIONS_TAMPERED");
  });

  it("a validly signed versions.json whose last entry is not this manifest is VERSIONS_MISMATCH", () => {
    const e = env(v2);
    const versions = JSON.parse(Buffer.from(e.versions).toString("utf8")) as unknown[];
    const stale = Buffer.from(canonicalStringify(versions.slice(0, -1)), "utf8"); // drops the current version
    const sig = signVersions(stale, KEY_A.kid, createPrivateKey(KEY_A.privateKeyPem));
    const out = verifyCatalogEnvelope(
      { ...e, versions: new Uint8Array(stale), versionsSig: new Uint8Array(Buffer.from(canonicalStringify(sig), "utf8")) },
      ctx(),
    );
    expect(codes(out)).toEqual(["VERSIONS_MISMATCH"]);
  });

  it("domain separation: the manifest's signature cannot stand in for the versions signature", () => {
    const e = env(v1);
    const mSig = JSON.parse(Buffer.from(e.manifestSig).toString("utf8")) as { sig: string };
    const vSig = JSON.parse(Buffer.from(e.versionsSig).toString("utf8")) as { kid: string; versionsSha: string; sig: string };
    const swapped = Buffer.from(canonicalStringify({ kid: vSig.kid, versionsSha: vSig.versionsSha, sig: mSig.sig }), "utf8");
    expect(codes(verifyCatalogEnvelope({ ...e, versionsSig: new Uint8Array(swapped) }, ctx()))).toEqual(["BAD_SIGNATURE"]);
  });

  it("a versions.json signed by a key the manifest revokes is REVOKED_KID", () => {
    const p = new CatalogPublisher();
    return p
      .emit({ version: "20260301-ddddddd", generatedAt: "2026-03-01T00:00:00.000Z", key: KEY_B, revokedKids: [KEY_A.kid] })
      .then((c) => {
        // versions.json/sig by KEY_B (valid, not revoked) => ok; then swap in a versions.sig by KEY_A
        const base = env(c);
        expect(verifyCatalogEnvelope(base, ctx()).ok).toBe(true);
        const versionsRaw = Buffer.from(base.versions);
        const bySigA = signVersions(versionsRaw, KEY_A.kid, createPrivateKey(KEY_A.privateKeyPem));
        const r = verifyCatalogEnvelope({ ...base, versionsSig: new Uint8Array(Buffer.from(canonicalStringify(bySigA), "utf8")) }, ctx());
        expect(codes(r)).toContain("REVOKED_KID");
      })
      .finally(() => p.dispose());
  });
});

describe("verifyCatalogEnvelope — malformed input", () => {
  it("duplicate keys in manifest.json are refused by the strict parser", () => {
    const e = env(v1);
    const dup = new Uint8Array(Buffer.from('{"contractVersion":0,"contractVersion":0}', "utf8"));
    const r = verifyCatalogEnvelope({ ...e, manifest: dup }, ctx());
    expect(codes(r)).toEqual(["MALFORMED"]);
  });

  it("a non-UTF-8 manifest is MALFORMED", () => {
    const e = env(v1);
    expect(codes(verifyCatalogEnvelope({ ...e, manifest: Uint8Array.from([0xff, 0xfe, 0x7b]) }, ctx()))).toEqual(["MALFORMED"]);
  });

  it("an unknown extra field is MALFORMED (strict schemas)", () => {
    const e = env(v1);
    const extra = replaceText(e.manifest, '"kid":', '"zzz": 1,\n  "kid":');
    expect(codes(verifyCatalogEnvelope({ ...e, manifest: extra }, ctx()))).toEqual(["MALFORMED"]);
  });

  it("oversized documents are SIZE_LIMIT", () => {
    const e = env(v1);
    expect(codes(verifyCatalogEnvelope({ ...e, manifestSig: new Uint8Array(65 * 1024) }, ctx()))).toEqual(["SIZE_LIMIT"]);
    expect(codes(verifyCatalogEnvelope({ ...e, manifest: new Uint8Array(5 * 1024 * 1024 + 1) }, ctx()))).toEqual(["SIZE_LIMIT"]);
  });

  it("a sidecar signature that is not standard base64 is BAD_SIGNATURE, never an exception", () => {
    const e = env(v1);
    const sig = (JSON.parse(Buffer.from(e.manifestSig).toString("utf8")) as { sig: string }).sig;
    const bad = replaceText(e.manifestSig, sig, "!!!notbase64!!!");
    expect(codes(verifyCatalogEnvelope({ ...e, manifestSig: bad }, ctx()))).toEqual(["BAD_SIGNATURE"]);
  });

  it("flipping any single byte of manifest.json never verifies", () => {
    const e = env(v1);
    for (let i = 0; i < e.manifest.length; i += 7) {
      expect(verifyCatalogEnvelope({ ...e, manifest: flipByte(e.manifest, i) }, ctx()).ok).toBe(false);
    }
  });
});
