/**
 * AT(2) (build plan §10 P1): "The signature verifies per `kid`, a
 * tampered shard fails, and a manifest whose `kid` is in `revokedKids` is
 * refused." Every keypair here is generated in-process
 * (`crypto.generateKeyPairSync('ed25519')`) — never a committed or
 * on-disk key (task constraint).
 */
import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { emitCatalogArtifact } from "../src/emit-catalog.js";
import { canonicalStringify, sha256Hex, type CatalogManifest } from "../src/manifest.js";
import {
  privateKeyFromPem,
  publicKeyFromPem,
  signBytes,
  signManifest,
  verifyArtifact,
  verifyBytes,
  type TrustedKey,
} from "../src/sign.js";
import { minimalBundle } from "./emit-test-helpers.js";

function generateEd25519Pem(): { privateKeyPem: string; publicKeyPem: string } {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return {
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
  };
}

describe("signBytes / verifyBytes", () => {
  it("round-trips: a signature made with the private key verifies with the matching public key", () => {
    const { privateKeyPem, publicKeyPem } = generateEd25519Pem();
    const data = Buffer.from("hello catalog");
    const sig = signBytes(privateKeyFromPem(privateKeyPem), data);
    expect(verifyBytes(publicKeyFromPem(publicKeyPem), data, sig)).toBe(true);
  });

  it("fails against the wrong public key", () => {
    const a = generateEd25519Pem();
    const b = generateEd25519Pem();
    const data = Buffer.from("hello catalog");
    const sig = signBytes(privateKeyFromPem(a.privateKeyPem), data);
    expect(verifyBytes(publicKeyFromPem(b.publicKeyPem), data, sig)).toBe(false);
  });

  it("fails on tampered data", () => {
    const { privateKeyPem, publicKeyPem } = generateEd25519Pem();
    const sig = signBytes(privateKeyFromPem(privateKeyPem), Buffer.from("original"));
    expect(verifyBytes(publicKeyFromPem(publicKeyPem), Buffer.from("tampered"), sig)).toBe(false);
  });

  it("is deterministic: signing the same bytes twice with the same key produces the same signature", () => {
    const { privateKeyPem } = generateEd25519Pem();
    const key = privateKeyFromPem(privateKeyPem);
    const data = Buffer.from("determinism check");
    expect(signBytes(key, data)).toBe(signBytes(key, data));
  });
});

describe("AT(2) — verifyArtifact over a real emitted artifact", () => {
  let dir: string;
  let keyA: { privateKeyPem: string; publicKeyPem: string };
  let keyB: { privateKeyPem: string; publicKeyPem: string };
  const KID_A = "pre-p3-test-key-a";
  const KID_B = "pre-p3-test-key-b";

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "golfraven-artifact-"));
    keyA = generateEd25519Pem();
    keyB = generateEd25519Pem();
  });

  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  async function emit(opts: { kid?: string; revokedKids?: string[] } = {}) {
    return emitCatalogArtifact(minimalBundle(), {
      outDir: dir,
      catalogVersion: "20260101-abc0001",
      minAppVersion: "0.0.0",
      kid: opts.kid ?? KID_A,
      privateKeyPem: keyA.privateKeyPem,
      now: new Date("2026-01-01T00:00:00.000Z"),
      ...(opts.revokedKids ? { revokedKids: opts.revokedKids } : {}),
    });
  }

  it("passes: the signature verifies per kid and every shard matches", async () => {
    await emit();
    const trustedKeys: TrustedKey[] = [{ kid: KID_A, publicKeyPem: keyA.publicKeyPem }];
    const result = await verifyArtifact(dir, trustedKeys);
    expect(result.issues).toEqual([]);
    expect(result.ok).toBe(true);
  });

  it("fails: a tampered shard", async () => {
    const emitted = await emit();
    const shard = emitted.manifest.shards[0];
    expect(shard).toBeDefined();
    const shardPath = join(emitted.v1Dir, ...shard!.path.split("/"));
    await writeFile(shardPath, Buffer.concat([await readFile(shardPath), Buffer.from("TAMPERED")]));

    const trustedKeys: TrustedKey[] = [{ kid: KID_A, publicKeyPem: keyA.publicKeyPem }];
    const result = await verifyArtifact(dir, trustedKeys);
    expect(result.ok).toBe(false);
    expect(result.issues.some((i) => i.startsWith("SHARD_TAMPERED:") && i.includes(shard!.path))).toBe(
      true,
    );
  });

  it("fails: a tampered manifest (a field edited in place, still valid JSON)", async () => {
    const emitted = await emit();
    const manifestPath = join(emitted.v1Dir, "manifest.json");
    const tampered: CatalogManifest = { ...emitted.manifest, minAppVersion: "99.99.99" };
    await writeFile(manifestPath, canonicalStringify(tampered));

    const trustedKeys: TrustedKey[] = [{ kid: KID_A, publicKeyPem: keyA.publicKeyPem }];
    const result = await verifyArtifact(dir, trustedKeys);
    expect(result.ok).toBe(false);
    expect(result.issues.some((i) => i.startsWith("MANIFEST_TAMPERED:"))).toBe(true);
    expect(result.issues.some((i) => i.startsWith("BAD_SIGNATURE:"))).toBe(true);
  });

  it("fails: verifying with the wrong kid's public key (signed by A, trust set only has B under a mismatched claim)", async () => {
    await emit({ kid: KID_A });
    // The verifier's trusted keyset doesn't include KID_A at all here —
    // this is the UNKNOWN_KID path, exercised on its own below. This test
    // instead covers "the same kid string is trusted, but the stored
    // public key is for a DIFFERENT keypair" — a swapped-key
    // misconfiguration, which must fail signature verification rather
    // than silently passing.
    const trustedKeys: TrustedKey[] = [{ kid: KID_A, publicKeyPem: keyB.publicKeyPem }];
    const result = await verifyArtifact(dir, trustedKeys);
    expect(result.ok).toBe(false);
    expect(result.issues.some((i) => i.startsWith("BAD_SIGNATURE:"))).toBe(true);
  });

  it("refuses: an unknown kid (not in the trusted keyset)", async () => {
    await emit({ kid: KID_A });
    const trustedKeys: TrustedKey[] = [{ kid: KID_B, publicKeyPem: keyB.publicKeyPem }];
    const result = await verifyArtifact(dir, trustedKeys);
    expect(result.ok).toBe(false);
    expect(result.issues.some((i) => i.startsWith("UNKNOWN_KID:"))).toBe(true);
  });

  it("refuses: a manifest whose kid is in its own revokedKids[] (AT(2), literal)", async () => {
    await emit({ kid: KID_A, revokedKids: [KID_A] });
    const trustedKeys: TrustedKey[] = [{ kid: KID_A, publicKeyPem: keyA.publicKeyPem }];
    const result = await verifyArtifact(dir, trustedKeys);
    expect(result.ok).toBe(false);
    expect(result.issues.some((i) => i.startsWith("REVOKED_KID:"))).toBe(true);
    // The signature itself is still cryptographically valid — revocation
    // is a separate, additional reason to refuse, not a signature failure.
    expect(result.issues.some((i) => i.startsWith("BAD_SIGNATURE:"))).toBe(false);
  });

  it("does not refuse a DIFFERENT kid appearing in revokedKids[] — only self-revocation is checked here", async () => {
    // §3.5/§4.8: `revokedKids[]` is how the app learns to stop trusting a
    // COMPROMISED key going forward, signed by a surviving key — the
    // common case is `manifest.kid !== <a compromised, different kid>`.
    // AT(2)'s literal fixture is the self-revoking case (see the previous
    // test); this test documents that the emitter/verifier pairing here
    // doesn't reject a manifest just for mentioning some other kid.
    await emit({ kid: KID_A, revokedKids: [KID_B] });
    const trustedKeys: TrustedKey[] = [{ kid: KID_A, publicKeyPem: keyA.publicKeyPem }];
    const result = await verifyArtifact(dir, trustedKeys);
    expect(result.ok).toBe(true);
  });

  it("fails: missing manifest.json", async () => {
    const result = await verifyArtifact(dir, []);
    expect(result.ok).toBe(false);
    expect(result.issues[0]).toMatch(/cannot read\/parse manifest\.json/);
  });

  it("fails: a shard listed in the manifest but missing from disk", async () => {
    const emitted = await emit();
    const shard = emitted.manifest.shards[0];
    expect(shard).toBeDefined();
    await rm(join(emitted.v1Dir, ...shard!.path.split("/")));

    const trustedKeys: TrustedKey[] = [{ kid: KID_A, publicKeyPem: keyA.publicKeyPem }];
    const result = await verifyArtifact(dir, trustedKeys);
    expect(result.ok).toBe(false);
    expect(result.issues.some((i) => i.startsWith("SHARD_MISSING:"))).toBe(true);
  });
});

describe("signManifest", () => {
  it("produces a manifestSha that matches the manifest's actual canonical sha256", () => {
    const { privateKeyPem } = generateEd25519Pem();
    const manifest: CatalogManifest = {
      contractVersion: 0,
      catalogVersion: "20260101-abc0001",
      minAppVersion: "0.0.0",
      kid: "k1",
      revokedKids: [],
      generatedAt: "2026-01-01T00:00:00.000Z",
      shards: [],
    };
    const sigDoc = signManifest(manifest, privateKeyFromPem(privateKeyPem));
    expect(sigDoc.manifestSha).toBe(sha256Hex(Buffer.from(canonicalStringify(manifest), "utf8")));
    expect(sigDoc.kid).toBe("k1");
  });
});
