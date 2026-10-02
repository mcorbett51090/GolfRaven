// supabase/tests/unit/catalog-artifact-fixtures.ts
//
// Builds a REAL, Ed25519-signed catalog artifact (manifest.json +
// manifest.sig.json + versions.json + versions.sig.json +
// id-ledger.json), byte-for-byte the same way tools/catalog/src/sign.ts
// + emit-catalog.ts would — used by import-handler.test.ts so the
// signature-verification path is exercised against REAL bytes, not a
// hand-waved fixture. Mirrors signature.test.ts's own
// `crypto.subtle.generateKey({name: "Ed25519"}, ...)` round trip.
import { canonicalStringify, MANIFEST_DOMAIN, VERSIONS_DOMAIN } from "../../functions/_shared/catalog/manifest-artifact.js";
import { bytesToBase64Url } from "../../functions/_shared/catalog/signature.js";

export async function generateKeypair() {
  const kp = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const rawPublic = await crypto.subtle.exportKey("raw", kp.publicKey);
  return { privateKey: kp.privateKey, publicKeyB64Url: bytesToBase64Url(new Uint8Array(rawPublic)) };
}

// ⛔ FIX (P3e round 2 gate, B1): `tools/catalog/src/sign.ts#signBytes`
// signs every REAL artifact (manifest.sig.json/versions.sig.json) with
// STANDARD, PADDED base64 (`cryptoSign(...).toString("base64")`), never
// base64url — this fixture used to sign with `bytesToBase64Url` instead,
// which is exactly how a self-signed fixture hid the B1 bug from round 1
// (the gate's own words: "your self-signed fixtures hid this"). `btoa`
// over the raw signature bytes directly IS standard base64 by
// definition — no further encoding step needed, unlike
// `bytesToBase64Url`'s own url-safe/unpadded post-processing.
export async function signBytes(privateKey: CryptoKey, bytes: Uint8Array): Promise<string> {
  const sig = await crypto.subtle.sign("Ed25519", privateKey, bytes.slice().buffer);
  let bin = "";
  for (const b of new Uint8Array(sig)) bin += String.fromCharCode(b);
  return btoa(bin);
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes.slice().buffer);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export interface ShardFixture {
  path: string;
  bytes: Uint8Array;
}

export interface BuiltArtifact {
  manifestBytes: Uint8Array;
  manifestSigBytes: Uint8Array;
  versionsBytes: Uint8Array;
  versionsSigBytes: Uint8Array;
  shardsByPath: Map<string, Uint8Array>;
}

export interface VersionFixture {
  version: string;
  publishedAt: string;
  kid: string;
  sha256: string;
}

/** Builds a full, real, signed artifact. `versionHistory` should include
 * the CURRENT entry as its own last element (mirrors the real emitter's
 * append-only versions.json). `shards`' own declared sha256/bytes are
 * computed from the actual bytes given — a test that wants a MISMATCHED
 * shard entry mutates the returned manifest bytes afterward instead. */
export async function buildSignedArtifact(input: {
  privateKey: CryptoKey;
  kid: string;
  contractVersion: number;
  catalogVersion: string;
  minAppVersion: string;
  revokedKids: string[];
  generatedAt: string;
  versionHistory: VersionFixture[];
  shards: ShardFixture[];
}): Promise<BuiltArtifact> {
  const shardsByPath = new Map<string, Uint8Array>();
  const shardEntries: { path: string; sha256: string; bytes: number }[] = [];
  for (const s of input.shards) {
    shardsByPath.set(s.path, s.bytes);
    shardEntries.push({ path: s.path, sha256: await sha256Hex(s.bytes), bytes: s.bytes.length });
  }

  const manifest = {
    contractVersion: input.contractVersion,
    catalogVersion: input.catalogVersion,
    minAppVersion: input.minAppVersion,
    kid: input.kid,
    revokedKids: input.revokedKids,
    generatedAt: input.generatedAt,
    shards: shardEntries,
  };
  const manifestBytes = new TextEncoder().encode(canonicalStringify(manifest));
  const manifestSha = await sha256Hex(manifestBytes);
  const manifestStatement = { catalogVersion: input.catalogVersion, contractVersion: input.contractVersion, kid: input.kid, manifestSha };
  const manifestStatementBytes = new TextEncoder().encode(MANIFEST_DOMAIN + canonicalStringify(manifestStatement));
  const manifestSig = await signBytes(input.privateKey, manifestStatementBytes);
  const manifestSigBytes = new TextEncoder().encode(canonicalStringify({ ...manifestStatement, sig: manifestSig }));

  const versionsBytes = new TextEncoder().encode(canonicalStringify(input.versionHistory));
  const versionsSha = await sha256Hex(versionsBytes);
  const versionsStatement = { kid: input.kid, versionsSha };
  const versionsStatementBytes = new TextEncoder().encode(VERSIONS_DOMAIN + canonicalStringify(versionsStatement));
  const versionsSig = await signBytes(input.privateKey, versionsStatementBytes);
  const versionsSigBytes = new TextEncoder().encode(canonicalStringify({ ...versionsStatement, sig: versionsSig }));

  return { manifestBytes, manifestSigBytes, versionsBytes, versionsSigBytes, shardsByPath };
}

export function jsonBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(canonicalStringify(value));
}
