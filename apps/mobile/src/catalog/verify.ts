/**
 * Pure verification of a fetched catalog envelope (`manifest.json`,
 * `manifest.sig.json`, `versions.json`, `versions.sig.json`) — the app-side
 * twin of `verifyArtifact` in `tools/catalog/src/sign.ts` (steps 1–5 and
 * 7; step 6, the shard files, is checked as each shard is downloaded,
 * `manager.ts`).
 *
 * **Nothing here re-implements the signing algorithm.** Canonical JSON, the
 * domain tags (`golfraven/catalog/v1/manifest\n`, `…/versions\n`), the
 * statement shapes, the strict parser and the zod schemas all come from
 * `@golfraven/catalog-tools/manifest-core` — the SAME module the signer and
 * emitter import. The only things supplied here are the two primitives
 * (SHA-256, Ed25519 verify), injected via `CatalogCrypto`.
 *
 * Like the Node verifier it checks the RAW BYTES: the manifest's SHA-256 is
 * taken over the exact bytes that were fetched, and the signature is
 * verified over the statement the sidecar carries — it never re-serialises
 * a parsed manifest and verifies against that.
 *
 * **Fail closed.** Any issue at all => `ok: false`; the caller must not
 * apply anything (build plan §3.5: "a manifest that fails verification is
 * never applied").
 */
import {
  CatalogManifestSchema,
  ManifestSignatureSchema,
  VersionsArraySchema,
  VersionsSignatureSchema,
  compareCatalogVersions,
  manifestStatementText,
  strictParseAndValidateText,
  versionsStatementText,
  type CatalogManifest,
  type VersionEntry,
} from "@golfraven/catalog-tools/manifest-core";
import { base64ToBytes, base64UrlToBytes, utf8DecodeStrict, utf8Encode } from "./bytes";
import type { CatalogCrypto } from "./crypto";
import type { TrustedKey } from "./keys";

/** Same caps as `verifyArtifact` (`MANIFEST_MAX_BYTES`, `SIDECAR_MAX_BYTES`). */
export const MANIFEST_MAX_BYTES = 5 * 1024 * 1024;
export const SIDECAR_MAX_BYTES = 64 * 1024;

export type VerifyIssueCode =
  | "MALFORMED"
  | "SIZE_LIMIT"
  | "UNKNOWN_KID"
  | "REVOKED_KID"
  | "SIG_KID_MISMATCH"
  | "SIG_FIELD_MISMATCH"
  | "MANIFEST_TAMPERED"
  | "BAD_SIGNATURE"
  | "CATALOG_VERSION_ROLLBACK"
  | "CONTRACT_MAJOR_MISMATCH"
  | "VERSIONS_TAMPERED"
  | "VERSIONS_EMPTY"
  | "VERSIONS_MISMATCH";

export interface VerifyIssue {
  code: VerifyIssueCode;
  message: string;
}

export interface EnvelopeBytes {
  manifest: Uint8Array;
  manifestSig: Uint8Array;
  versions: Uint8Array;
  versionsSig: Uint8Array;
}

export interface VerifyContext {
  crypto: CatalogCrypto;
  trustedKeys: readonly TrustedKey[];
  /** Every `kid` this install has ever been told is revoked (the union of
   * `revokedKids[]` over every manifest it verified). */
  revokedKids: ReadonlySet<string>;
  /** The contract MAJOR this build understands. */
  supportedContractMajor: number;
  /** The currently cached `catalogVersion`: anything OLDER is refused
   * (anti-rollback). Equal is allowed (idempotent re-fetch). */
  minCatalogVersion?: string | undefined;
}

export interface VerifiedEnvelope {
  manifest: CatalogManifest;
  /** SHA-256 of `manifest.json`'s raw bytes (what the signature commits to). */
  manifestSha: string;
  versions: VersionEntry[];
}

export type VerifyResult =
  | { ok: true; value: VerifiedEnvelope; issues: [] }
  | { ok: false; issues: VerifyIssue[] };

function decode(bytes: Uint8Array, max: number, label: string): { ok: true; text: string } | { ok: false; issue: VerifyIssue } {
  if (bytes.length > max) {
    return { ok: false, issue: { code: "SIZE_LIMIT", message: `${label}: ${bytes.length} bytes exceeds the ${max}-byte cap` } };
  }
  try {
    return { ok: true, text: utf8DecodeStrict(bytes) };
  } catch (err) {
    return { ok: false, issue: { code: "MALFORMED", message: `${label}: ${err instanceof Error ? err.message : String(err)}` } };
  }
}

function keyBytes(key: TrustedKey): Uint8Array | null {
  try {
    const raw = base64UrlToBytes(key.publicKeyB64Url);
    return raw.length === 32 ? raw : null;
  } catch {
    return null;
  }
}

function verifySig(
  ctx: VerifyContext,
  key: TrustedKey,
  statementText: string,
  sigB64: string,
): boolean {
  const pub = keyBytes(key);
  if (!pub) return false;
  let sig: Uint8Array;
  try {
    sig = base64ToBytes(sigB64); // the Node signer emits STANDARD padded base64
  } catch {
    return false;
  }
  return ctx.crypto.ed25519Verify(pub, utf8Encode(statementText), sig);
}

export function verifyCatalogEnvelope(env: EnvelopeBytes, ctx: VerifyContext): VerifyResult {
  const trusted = new Map(ctx.trustedKeys.map((k) => [k.kid, k] as const));

  // 1–2. Decode + strictly parse + schema-validate the two documents the
  //      signature governs. Any parse failure ends verification here.
  const mText = decode(env.manifest, MANIFEST_MAX_BYTES, "manifest.json");
  if (!mText.ok) return { ok: false, issues: [mText.issue] };
  const mParsed = strictParseAndValidateText(mText.text, CatalogManifestSchema, "manifest.json");
  if (!mParsed.ok) return { ok: false, issues: mParsed.issues.map((message) => ({ code: "MALFORMED" as const, message })) };
  const manifest = mParsed.value;

  const sText = decode(env.manifestSig, SIDECAR_MAX_BYTES, "manifest.sig.json");
  if (!sText.ok) return { ok: false, issues: [sText.issue] };
  const sParsed = strictParseAndValidateText(sText.text, ManifestSignatureSchema, "manifest.sig.json");
  if (!sParsed.ok) return { ok: false, issues: sParsed.issues.map((message) => ({ code: "MALFORMED" as const, message })) };
  const sigDoc = sParsed.value;

  const issues: VerifyIssue[] = [];
  const add = (code: VerifyIssueCode, message: string): void => {
    issues.push({ code, message });
  };

  // 3. Key trust.
  const key = trusted.get(manifest.kid);
  if (!key) add("UNKNOWN_KID", `manifest kid "${manifest.kid}" is not in the compiled-in keyset`);
  if (ctx.revokedKids.has(manifest.kid) || ctx.revokedKids.has(sigDoc.kid)) {
    add("REVOKED_KID", `kid "${manifest.kid}" has been revoked`);
  }
  if (manifest.revokedKids.includes(manifest.kid)) {
    add("REVOKED_KID", `manifest kid "${manifest.kid}" lists itself in revokedKids[] (self-revoking manifest)`);
  }
  if (sigDoc.kid !== manifest.kid) add("SIG_KID_MISMATCH", `manifest.sig.json kid "${sigDoc.kid}" != manifest.json kid "${manifest.kid}"`);
  if (sigDoc.catalogVersion !== manifest.catalogVersion) {
    add("SIG_FIELD_MISMATCH", `manifest.sig.json catalogVersion "${sigDoc.catalogVersion}" != manifest.json "${manifest.catalogVersion}"`);
  }
  if (sigDoc.contractVersion !== manifest.contractVersion) {
    add("SIG_FIELD_MISMATCH", `manifest.sig.json contractVersion ${sigDoc.contractVersion} != manifest.json ${manifest.contractVersion}`);
  }

  // 4. The sidecar's hash must be the hash of the bytes we actually hold.
  const actualManifestSha = ctx.crypto.sha256Hex(env.manifest);
  if (sigDoc.manifestSha !== actualManifestSha) {
    add("MANIFEST_TAMPERED", `manifest.sig.json manifestSha (${sigDoc.manifestSha}) != sha256 of the fetched manifest.json (${actualManifestSha})`);
  }

  // 5. Anti-rollback and contract MAJOR.
  if (ctx.minCatalogVersion && compareCatalogVersions(manifest.catalogVersion, ctx.minCatalogVersion) < 0) {
    add("CATALOG_VERSION_ROLLBACK", `catalogVersion "${manifest.catalogVersion}" is older than the cached "${ctx.minCatalogVersion}"`);
  }
  if (manifest.contractVersion !== ctx.supportedContractMajor) {
    add("CONTRACT_MAJOR_MISMATCH", `manifest contractVersion ${manifest.contractVersion} != supported ${ctx.supportedContractMajor}`);
  }

  // 6. The signature itself — over the statement the sidecar carries.
  if (key) {
    const text = manifestStatementText({
      catalogVersion: sigDoc.catalogVersion,
      contractVersion: sigDoc.contractVersion,
      kid: sigDoc.kid,
      manifestSha: sigDoc.manifestSha,
    });
    if (!verifySig(ctx, key, text, sigDoc.sig)) {
      add("BAD_SIGNATURE", `the Ed25519 signature over the manifest statement does not verify against kid "${manifest.kid}"`);
    }
  }

  // Anything above is blocking: do not even look at versions.json.
  if (issues.length > 0) return { ok: false, issues };

  // 7. versions.json + versions.sig.json: own signature, and the last entry
  //    must describe exactly this manifest.
  const vText = decode(env.versions, MANIFEST_MAX_BYTES, "versions.json");
  if (!vText.ok) return { ok: false, issues: [vText.issue] };
  const vParsed = strictParseAndValidateText(vText.text, VersionsArraySchema, "versions.json");
  if (!vParsed.ok) return { ok: false, issues: vParsed.issues.map((message) => ({ code: "MALFORMED" as const, message })) };
  const vsText = decode(env.versionsSig, SIDECAR_MAX_BYTES, "versions.sig.json");
  if (!vsText.ok) return { ok: false, issues: [vsText.issue] };
  const vsParsed = strictParseAndValidateText(vsText.text, VersionsSignatureSchema, "versions.sig.json");
  if (!vsParsed.ok) return { ok: false, issues: vsParsed.issues.map((message) => ({ code: "MALFORMED" as const, message })) };
  const versions = vParsed.value;
  const versionsSig = vsParsed.value;

  const actualVersionsSha = ctx.crypto.sha256Hex(env.versions);
  if (versionsSig.versionsSha !== actualVersionsSha) {
    add("VERSIONS_TAMPERED", `versions.sig.json versionsSha (${versionsSig.versionsSha}) != sha256 of the fetched versions.json (${actualVersionsSha})`);
  }
  const vKey = trusted.get(versionsSig.kid);
  if (!vKey) {
    add("UNKNOWN_KID", `versions.sig.json kid "${versionsSig.kid}" is not in the compiled-in keyset`);
  } else if (ctx.revokedKids.has(versionsSig.kid) || manifest.revokedKids.includes(versionsSig.kid)) {
    add("REVOKED_KID", `versions.sig.json kid "${versionsSig.kid}" has been revoked`);
  } else if (!verifySig(ctx, vKey, versionsStatementText({ kid: versionsSig.kid, versionsSha: versionsSig.versionsSha }), versionsSig.sig)) {
    add("BAD_SIGNATURE", `versions.json signature does not verify against kid "${versionsSig.kid}"`);
  }
  const last = versions[versions.length - 1];
  if (!last) {
    add("VERSIONS_EMPTY", "versions.json has no entries, but a signed manifest was just verified");
  } else if (last.sha256 !== actualManifestSha || last.version !== manifest.catalogVersion || last.kid !== manifest.kid) {
    add(
      "VERSIONS_MISMATCH",
      `versions.json's last entry (version=${last.version} kid=${last.kid} sha256=${last.sha256}) does not describe this manifest (version=${manifest.catalogVersion} kid=${manifest.kid} sha256=${actualManifestSha})`,
    );
  }

  if (issues.length > 0) return { ok: false, issues };
  return { ok: true, value: { manifest, manifestSha: actualManifestSha, versions }, issues: [] };
}
