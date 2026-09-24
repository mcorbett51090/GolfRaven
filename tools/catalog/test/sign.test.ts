/**
 * AT(2) (build plan §10 P1) plus the Opus security gate's 4 blocking
 * findings on commit 7692919. Every keypair here is generated in-process
 * (`crypto.generateKeyPairSync('ed25519')`) — never a committed or
 * on-disk key.
 */
import { generateKeyPairSync } from "node:crypto";
import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { emitCatalogArtifact } from "../src/emit-catalog.js";
import { canonicalStringify, sha256Hex } from "../src/manifest.js";
import {
  loadSigningKeyPem,
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

  it("is deterministic: signing the same bytes twice with the same key produces the same signature", () => {
    const { privateKeyPem } = generateEd25519Pem();
    const key = privateKeyFromPem(privateKeyPem);
    const data = Buffer.from("determinism check");
    expect(signBytes(key, data)).toBe(signBytes(key, data));
  });
});

describe("finding #10: key hygiene", () => {
  it("privateKeyFromPem refuses a non-Ed25519 key", () => {
    const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const pem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
    expect(() => privateKeyFromPem(pem)).toThrow(/Ed25519/);
  });

  it("publicKeyFromPem refuses a non-Ed25519 key", () => {
    const { publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const pem = publicKey.export({ type: "spki", format: "pem" }).toString();
    expect(() => publicKeyFromPem(pem)).toThrow(/Ed25519/);
  });

  it("signManifest self-checks against a supplied expectedPublicKeyPem and refuses a mismatch", () => {
    const a = generateEd25519Pem();
    const b = generateEd25519Pem();
    const manifest = {
      catalogVersion: "20260101-abc0001",
      contractVersion: 0,
      kid: "k1",
    };
    const bytes = Buffer.from("fake manifest bytes");
    expect(() =>
      signManifest(manifest, bytes, privateKeyFromPem(a.privateKeyPem), b.publicKeyPem),
    ).toThrow(/does NOT match --kid-public-key/);
    // The matching key does not throw.
    expect(() =>
      signManifest(manifest, bytes, privateKeyFromPem(a.privateKeyPem), a.publicKeyPem),
    ).not.toThrow();
  });

  describe("loadSigningKeyPem: file mode", () => {
    let dir: string;
    beforeEach(async () => {
      dir = await mkdtemp(join(tmpdir(), "golfraven-keyfile-"));
    });
    afterEach(async () => {
      await rm(dir, { recursive: true, force: true });
    });

    it("refuses a key file that is group- or world-readable", async () => {
      const keyPath = join(dir, "key.pem");
      await writeFile(keyPath, generateEd25519Pem().privateKeyPem);
      await chmod(keyPath, 0o644);
      await expect(loadSigningKeyPem({ keyFilePath: keyPath })).rejects.toThrow(
        /group- or world-readable/,
      );
    });

    it("accepts a key file that is owner-only readable", async () => {
      const keyPath = join(dir, "key.pem");
      const { privateKeyPem } = generateEd25519Pem();
      await writeFile(keyPath, privateKeyPem);
      await chmod(keyPath, 0o600);
      await expect(loadSigningKeyPem({ keyFilePath: keyPath })).resolves.toContain(
        "BEGIN PRIVATE KEY",
      );
    });
  });
});

describe("AT(2) + security-gate — verifyArtifact over a real emitted artifact", () => {
  let dir: string;
  let keyA: { privateKeyPem: string; publicKeyPem: string };
  let keyB: { privateKeyPem: string; publicKeyPem: string };
  const KID_A = "pre-p3-test-key-a";
  const KID_B = "pre-p3-test-key-b";
  const FIXED = new Date("2026-01-01T00:00:00.000Z");

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "golfraven-artifact-"));
    keyA = generateEd25519Pem();
    keyB = generateEd25519Pem();
  });

  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  async function emit(opts: { kid?: string; revokedKids?: string[]; catalogVersion?: string } = {}) {
    return emitCatalogArtifact(minimalBundle(), {
      outDir: dir,
      catalogVersion: opts.catalogVersion ?? "20260101-abc0001",
      minAppVersion: "0.0.0",
      kid: opts.kid ?? KID_A,
      privateKeyPem: keyA.privateKeyPem,
      generatedAt: FIXED,
      ...(opts.revokedKids ? { revokedKids: opts.revokedKids } : {}),
    });
  }

  function trusted(...keys: { kid: string; pem: string }[]): TrustedKey[] {
    return keys.map((k) => ({ kid: k.kid, publicKeyPem: k.pem }));
  }

  it("passes: signature verifies, shards match, versions.json signature and last-entry match", async () => {
    await emit();
    const result = await verifyArtifact(dir, {
      trustedKeys: trusted({ kid: KID_A, pem: keyA.publicKeyPem }),
      revokedKids: new Set(),
    });
    expect(result.issues).toEqual([]);
    expect(result.ok).toBe(true);
    expect(result.revokedKids).toEqual([]);
  });

  it("fails: a tampered shard", async () => {
    const emitted = await emit();
    const shard = emitted.manifest.shards[0];
    expect(shard).toBeDefined();
    const shardPath = join(emitted.v1Dir, ...shard!.path.split("/"));
    await writeFile(shardPath, Buffer.concat([await readFile(shardPath), Buffer.from("TAMPERED")]));

    const result = await verifyArtifact(dir, {
      trustedKeys: trusted({ kid: KID_A, pem: keyA.publicKeyPem }),
      revokedKids: new Set(),
    });
    expect(result.ok).toBe(false);
    expect(result.issues.some((i) => i.startsWith("SHARD_TAMPERED:") && i.includes(shard!.path))).toBe(
      true,
    );
  });

  it("fails: a whitespace-only change to manifest.json (finding #1 — raw bytes, never re-canonicalized)", async () => {
    const emitted = await emit();
    const manifestPath = join(emitted.v1Dir, "manifest.json");
    const raw = await readFile(manifestPath, "utf8");
    // A single extra trailing space inside the file — still perfectly
    // valid JSON, and re-parsing + re-canonicalizing it would erase the
    // difference. The fix under test is that verifyArtifact never does
    // that: it hashes the RAW bytes.
    await writeFile(manifestPath, raw.replace('"shards"', '"shards" '));

    const result = await verifyArtifact(dir, {
      trustedKeys: trusted({ kid: KID_A, pem: keyA.publicKeyPem }),
      revokedKids: new Set(),
    });
    expect(result.ok).toBe(false);
    expect(result.issues.some((i) => i.startsWith("MANIFEST_TAMPERED:"))).toBe(true);
  });

  it("PROBE: a duplicate minAppVersion key in manifest.json fails verification", async () => {
    const emitted = await emit();
    const manifestPath = join(emitted.v1Dir, "manifest.json");
    const raw = await readFile(manifestPath, "utf8");
    const tampered = raw.replace(
      /"minAppVersion": "([^"]*)"/,
      '"minAppVersion": "$1",\n  "minAppVersion": "9.9.9"',
    );
    expect(tampered).not.toBe(raw);
    await writeFile(manifestPath, tampered);

    const result = await verifyArtifact(dir, {
      trustedKeys: trusted({ kid: KID_A, pem: keyA.publicKeyPem }),
      revokedKids: new Set(),
    });
    expect(result.ok).toBe(false);
    expect(result.issues[0]).toContain("duplicate object key");
  });

  it("PROBE: an injected __proto__ key in manifest.json fails verification", async () => {
    const emitted = await emit();
    const manifestPath = join(emitted.v1Dir, "manifest.json");
    const raw = await readFile(manifestPath, "utf8");
    const tampered = raw.replace("{\n", '{\n  "__proto__": {"polluted": true},\n');
    expect(tampered).not.toBe(raw);
    await writeFile(manifestPath, tampered);

    const result = await verifyArtifact(dir, {
      trustedKeys: trusted({ kid: KID_A, pem: keyA.publicKeyPem }),
      revokedKids: new Set(),
    });
    expect(result.ok).toBe(false);
    expect(result.issues[0]).toContain("forbidden object key");
  });

  it("PROBE: a -0.0e0 number in manifest.json fails verification", async () => {
    const emitted = await emit();
    const manifestPath = join(emitted.v1Dir, "manifest.json");
    const raw = await readFile(manifestPath, "utf8");
    const tampered = raw.replace('"contractVersion": 0', '"contractVersion": -0.0e0');
    expect(tampered).not.toBe(raw);
    await writeFile(manifestPath, tampered);

    const result = await verifyArtifact(dir, {
      trustedKeys: trusted({ kid: KID_A, pem: keyA.publicKeyPem }),
      revokedKids: new Set(),
    });
    expect(result.ok).toBe(false);
    expect(result.issues[0]).toContain("negative zero");
  });

  it("G3-10 PROBE: a far-future forged catalogVersion (manifest edited, sig untouched) is refused", async () => {
    const emitted = await emit();
    const manifestPath = join(emitted.v1Dir, "manifest.json");
    const raw = await readFile(manifestPath, "utf8");
    const forged = raw.replace(emitted.manifest.catalogVersion, "29990101-fffffff");
    expect(forged).not.toBe(raw);
    await writeFile(manifestPath, forged);
    // manifest.sig.json is left exactly as originally signed — it still
    // names the ORIGINAL catalogVersion, so it now disagrees with
    // manifest.json's forged one.

    const result = await verifyArtifact(dir, {
      trustedKeys: trusted({ kid: KID_A, pem: keyA.publicKeyPem }),
      revokedKids: new Set(),
    });
    expect(result.ok).toBe(false);
    expect(
      result.issues.some((i) => i.startsWith("SIG_FIELD_MISMATCH:") || i.startsWith("MANIFEST_TAMPERED:")),
    ).toBe(true);
  });

  it("G3-10 PROBE: a far-future forged catalogVersion, forged consistently in BOTH files, still fails (no valid signature exists over it)", async () => {
    const emitted = await emit();
    const manifestPath = join(emitted.v1Dir, "manifest.json");
    const sigPath = join(emitted.v1Dir, "manifest.sig.json");
    const manifestRaw = await readFile(manifestPath, "utf8");
    const sigRaw = await readFile(sigPath, "utf8");
    const forgedManifest = manifestRaw.replace(emitted.manifest.catalogVersion, "29990101-fffffff");
    const forgedSig = sigRaw.replace(emitted.manifest.catalogVersion, "29990101-fffffff");
    await writeFile(manifestPath, forgedManifest);
    await writeFile(sigPath, forgedSig);
    // Now manifest.json and manifest.sig.json AGREE on the forged
    // catalogVersion, but the attacker has no private key, so `sig` is
    // still the ORIGINAL signature — which no longer verifies over the
    // (now-different) statement bytes.

    const result = await verifyArtifact(dir, {
      trustedKeys: trusted({ kid: KID_A, pem: keyA.publicKeyPem }),
      revokedKids: new Set(),
    });
    expect(result.ok).toBe(false);
    expect(result.issues.some((i) => i.startsWith("BAD_SIGNATURE:"))).toBe(true);
  });

  it("fails: verifying with a swapped-in wrong public key for a trusted kid", async () => {
    await emit({ kid: KID_A });
    const result = await verifyArtifact(dir, {
      trustedKeys: trusted({ kid: KID_A, pem: keyB.publicKeyPem }),
      revokedKids: new Set(),
    });
    expect(result.ok).toBe(false);
    expect(result.issues.some((i) => i.startsWith("BAD_SIGNATURE:"))).toBe(true);
  });

  it("refuses: an unknown kid (not in the trusted keyset)", async () => {
    await emit({ kid: KID_A });
    const result = await verifyArtifact(dir, {
      trustedKeys: trusted({ kid: KID_B, pem: keyB.publicKeyPem }),
      revokedKids: new Set(),
    });
    expect(result.ok).toBe(false);
    expect(result.issues.some((i) => i.startsWith("UNKNOWN_KID:"))).toBe(true);
  });

  it("refuses: a manifest whose kid is in its own revokedKids[] (self-revocation)", async () => {
    await emit({ kid: KID_A, revokedKids: [KID_A] });
    const result = await verifyArtifact(dir, {
      trustedKeys: trusted({ kid: KID_A, pem: keyA.publicKeyPem }),
      revokedKids: new Set(),
    });
    expect(result.ok).toBe(false);
    expect(result.issues.some((i) => i.startsWith("REVOKED_KID:") && i.includes("its own"))).toBe(true);
  });

  it("finding #3 PROBE: a revoked key that leaves itself OUT of its own manifest's revokedKids[] is still refused", async () => {
    // The manifest itself claims no revocations at all — an attacker (or
    // a stale, compromised signer) simply doesn't list itself. The
    // verifier's OWN trusted state (opts.revokedKids) is what must catch
    // this, independent of anything the manifest says about itself.
    await emit({ kid: KID_A, revokedKids: [] });
    const result = await verifyArtifact(dir, {
      trustedKeys: trusted({ kid: KID_A, pem: keyA.publicKeyPem }),
      revokedKids: new Set([KID_A]),
    });
    expect(result.ok).toBe(false);
    expect(result.issues.some((i) => i.startsWith("REVOKED_KID:"))).toBe(true);
  });

  it("finding #3: on success, returns the manifest's own revokedKids[] so the caller can persist the union", async () => {
    await emit({ kid: KID_A, revokedKids: ["some-other-retired-kid"] });
    const result = await verifyArtifact(dir, {
      trustedKeys: trusted({ kid: KID_A, pem: keyA.publicKeyPem }),
      revokedKids: new Set(),
    });
    expect(result.ok).toBe(true);
    expect(result.revokedKids).toEqual(["some-other-retired-kid"]);
  });

  it("finding #6: refuses a catalogVersion older than minCatalogVersion (rollback)", async () => {
    await emit({ catalogVersion: "20250101-aaa0001" });
    const result = await verifyArtifact(dir, {
      trustedKeys: trusted({ kid: KID_A, pem: keyA.publicKeyPem }),
      revokedKids: new Set(),
      minCatalogVersion: "20260101-eee9999",
    });
    expect(result.ok).toBe(false);
    expect(result.issues.some((i) => i.startsWith("CATALOG_VERSION_ROLLBACK:"))).toBe(true);
  });

  it("finding #9: refuses a manifest whose contractVersion is not the supported major", async () => {
    await emit();
    const result = await verifyArtifact(dir, {
      trustedKeys: trusted({ kid: KID_A, pem: keyA.publicKeyPem }),
      revokedKids: new Set(),
      supportedContractMajor: 7,
    });
    expect(result.ok).toBe(false);
    expect(result.issues.some((i) => i.startsWith("CONTRACT_MAJOR_MISMATCH:"))).toBe(true);
  });

  it("finding #7: reports a stray file on disk that the manifest does not list", async () => {
    const emitted = await emit();
    await writeFile(join(emitted.v1Dir, "not-a-real-shard.json"), "{}\n");
    const result = await verifyArtifact(dir, {
      trustedKeys: trusted({ kid: KID_A, pem: keyA.publicKeyPem }),
      revokedKids: new Set(),
    });
    expect(result.ok).toBe(false);
    expect(result.issues.some((i) => i.startsWith("STRAY_FILE:") && i.includes("not-a-real-shard.json"))).toBe(
      true,
    );
  });

  it("finding #4: versions.json signature is checked, and a tamper is caught", async () => {
    const emitted = await emit();
    const versionsPath = join(emitted.v1Dir, "versions.json");
    const raw = await readFile(versionsPath, "utf8");
    await writeFile(versionsPath, raw.replace("{", "{ "));
    const result = await verifyArtifact(dir, {
      trustedKeys: trusted({ kid: KID_A, pem: keyA.publicKeyPem }),
      revokedKids: new Set(),
    });
    expect(result.ok).toBe(false);
    expect(result.issues.some((i) => i.startsWith("VERSIONS_TAMPERED:"))).toBe(true);
  });

  it("finding #4: versions.json's last entry must describe THIS manifest", async () => {
    const emitted = await emit();
    const versionsPath = join(emitted.v1Dir, "versions.json");
    const versionsSigPath = join(emitted.v1Dir, "versions.sig.json");
    // Replace versions.json (and re-sign it, as if a second, independent
    // process wrote a DIFFERENT last entry) so its content is internally
    // consistent (signature verifies) but no longer describes the
    // manifest this test is verifying.
    const bogus = [{ version: "20200101-0000000", publishedAt: "2020-01-01T00:00:00.000Z", kid: KID_A, sha256: "0".repeat(64) }];
    const bogusBytes = Buffer.from(canonicalStringify(bogus), "utf8");
    await writeFile(versionsPath, bogusBytes);
    const versionsSha = sha256Hex(bogusBytes);
    const statementBytes = Buffer.from(
      "golfraven/catalog/v1/versions\n" + canonicalStringify({ kid: KID_A, versionsSha }),
      "utf8",
    );
    const sig = signBytes(privateKeyFromPem(keyA.privateKeyPem), statementBytes);
    await writeFile(
      versionsSigPath,
      Buffer.from(canonicalStringify({ kid: KID_A, versionsSha, sig }), "utf8"),
    );

    const result = await verifyArtifact(dir, {
      trustedKeys: trusted({ kid: KID_A, pem: keyA.publicKeyPem }),
      revokedKids: new Set(),
    });
    expect(result.ok).toBe(false);
    expect(result.issues.some((i) => i.startsWith("VERSIONS_MISMATCH:"))).toBe(true);
  });

  it("fails: missing manifest.json", async () => {
    const result = await verifyArtifact(dir, { trustedKeys: [], revokedKids: new Set() });
    expect(result.ok).toBe(false);
    expect(result.issues[0]).toMatch(/cannot read manifest\.json/);
  });

  it("fails: a shard listed in the manifest but missing from disk (and never reads a shard before the signature verifies)", async () => {
    const emitted = await emit();
    const shard = emitted.manifest.shards[0];
    expect(shard).toBeDefined();
    await rm(join(emitted.v1Dir, ...shard!.path.split("/")));

    const result = await verifyArtifact(dir, {
      trustedKeys: trusted({ kid: KID_A, pem: keyA.publicKeyPem }),
      revokedKids: new Set(),
    });
    expect(result.ok).toBe(false);
    expect(result.issues.some((i) => i.startsWith("SHARD_MISSING:"))).toBe(true);
  });

  it("finding #8: never reads any shard file when the signature is bad (unknown kid)", async () => {
    const emitted = await emit({ kid: KID_A });
    const shard = emitted.manifest.shards[0];
    expect(shard).toBeDefined();
    // Delete a shard the manifest lists — if the verifier read shards
    // before confirming trust, this would surface as SHARD_MISSING. It
    // must not: kid is unknown, so verification stops before ever
    // opening a shard file.
    await rm(join(emitted.v1Dir, ...shard!.path.split("/")));

    const result = await verifyArtifact(dir, {
      trustedKeys: [], // no trusted keys at all
      revokedKids: new Set(),
    });
    expect(result.ok).toBe(false);
    expect(result.issues.some((i) => i.startsWith("UNKNOWN_KID:"))).toBe(true);
    expect(result.issues.some((i) => i.startsWith("SHARD_MISSING:"))).toBe(false);
  });
});
