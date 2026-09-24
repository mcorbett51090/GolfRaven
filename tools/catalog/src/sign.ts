/**
 * Ed25519 signing and artifact verification (build plan §3.5 "Signing",
 * §4.8 "Keys, secrets and rotation", §10 P1 AT(2): "The signature verifies
 * per `kid`, a tampered shard fails, and a manifest whose `kid` is in
 * `revokedKids` is refused."). Node's built-in `node:crypto` only — no
 * dependency added (task constraint).
 *
 * **The private key never lives in this repo.** `loadSigningKeyPem` reads
 * it from a `--key-file` path or an env var (`GOLFRAVEN_CATALOG_SIGNING_KEY`
 * by default), supplied at run time by the protected CI environment (§4.8:
 * "Signing runs in a GitHub protected environment with required
 * reviewers"). Nothing here defaults a key path to anywhere inside the
 * repo, writes a key to disk, or logs key contents. Every test in
 * `test/sign.test.ts` and `test/emit-catalog.test.ts` generates its own
 * throwaway keypair in-process (`crypto.generateKeyPairSync('ed25519')`)
 * rather than reading or committing one.
 */
import { readFile } from "node:fs/promises";
import { realpath } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import {
  createPrivateKey,
  createPublicKey,
  sign as cryptoSign,
  verify as cryptoVerify,
  type KeyObject,
} from "node:crypto";
import { canonicalStringify, sha256Hex, type CatalogManifest } from "./manifest.js";

export const DEFAULT_SIGNING_KEY_ENV_VAR = "GOLFRAVEN_CATALOG_SIGNING_KEY";

/** One entry of the trusted keyset `verifyArtifact` checks against — the
 * "`kid`-addressed keyset of at least 2 public keys compiled into the app
 * and the import function" (§3.5). This module doesn't enforce the
 * "at least 2" part; that's a deploy-time property of the compiled
 * keyset, not something a single verify call can check. */
export interface TrustedKey {
  kid: string;
  publicKeyPem: string;
}

export interface LoadSigningKeyOptions {
  keyFilePath?: string;
  envVar?: string;
}

/**
 * Reads the Ed25519 private key PEM from `--key-file` if given, else from
 * the env var (default `GOLFRAVEN_CATALOG_SIGNING_KEY`). Never defaults to
 * a path inside the repo — the caller decides where `keyFilePath` points.
 * A PEM held in an env var commonly arrives with literal `\n` escapes
 * (most CI secret stores can't hold a real multi-line value in one
 * variable without that); those are un-escaped before parsing.
 */
export async function loadSigningKeyPem(
  opts: LoadSigningKeyOptions = {},
): Promise<string> {
  if (opts.keyFilePath) {
    return (await readFile(opts.keyFilePath, "utf8")).trim();
  }
  const envVar = opts.envVar ?? DEFAULT_SIGNING_KEY_ENV_VAR;
  const raw = process.env[envVar];
  if (!raw) {
    throw new Error(
      `no signing key supplied: pass --key-file <path>, or set ${envVar} to the PEM text ` +
        `(literal "\\n" escapes are un-escaped automatically) — never from a file inside the repo`,
    );
  }
  return raw.includes("\\n") ? raw.replace(/\\n/g, "\n").trim() : raw.trim();
}

export function privateKeyFromPem(pem: string): KeyObject {
  return createPrivateKey({ key: pem, format: "pem" });
}

export function publicKeyFromPem(pem: string): KeyObject {
  return createPublicKey({ key: pem, format: "pem" });
}

/** Signs `data` with an Ed25519 private key, base64-encoded. Ed25519 is
 * PureEdDSA and hashes internally, so the crypto `algorithm` argument must
 * be `null` — passing anything else is a Node API misuse, not a choice. */
export function signBytes(privateKey: KeyObject, data: Buffer): string {
  return cryptoSign(null, data, privateKey).toString("base64");
}

export function verifyBytes(
  publicKey: KeyObject,
  data: Buffer,
  signatureBase64: string,
): boolean {
  try {
    return cryptoVerify(null, data, publicKey, Buffer.from(signatureBase64, "base64"));
  } catch {
    return false;
  }
}

/** The `manifest.sig.json` sidecar — mirrors §3.3's own
 * `manifestSig: {catalogVersion, manifestSha, kid, sig}` shape (the header
 * the app attaches to evidence when it proves a newer catalog version is
 * real). Kept as a sidecar rather than inlined into `manifest.json` so
 * signing is "sign these exact bytes", with nothing about the signature
 * itself feeding back into what got signed. */
export interface ManifestSignature {
  catalogVersion: string;
  manifestSha: string;
  kid: string;
  sig: string;
}

/** Signs the canonical bytes of `manifest` (via `canonicalStringify`) and
 * returns the `manifest.sig.json` document. The caller writes both files;
 * this function has no filesystem access of its own. */
export function signManifest(
  manifest: CatalogManifest,
  privateKey: KeyObject,
): ManifestSignature {
  const bytes = Buffer.from(canonicalStringify(manifest), "utf8");
  return {
    catalogVersion: manifest.catalogVersion,
    manifestSha: sha256Hex(bytes),
    kid: manifest.kid,
    sig: signBytes(privateKey, bytes),
  };
}

export interface VerifyArtifactResult {
  ok: boolean;
  issues: string[];
}

/**
 * The AT(2) gate: "The signature verifies per `kid`, a tampered shard
 * fails, and a manifest whose `kid` is in `revokedKids` is refused."
 *
 * Every check runs and appends to `issues` rather than stopping at the
 * first problem — a caller sees every issue in one run, matching
 * `verify-catalog`'s own style (`tools/catalog/src/verify-catalog.ts`):
 *
 *  1. `manifest.json` and `manifest.sig.json` both exist and parse —
 *     otherwise this returns immediately (nothing else is checkable).
 *  2. `manifest.kid` is present in `trustedKeys` — an unknown `kid` is
 *     refused (`UNKNOWN_KID`).
 *  3. `manifest.kid` is NOT a member of `manifest.revokedKids` — a
 *     manifest that lists its own signing key as revoked is refused
 *     (`REVOKED_KID`; this is the literal AT(2) fixture).
 *  4. `manifest.sig.json`'s `kid` matches `manifest.json`'s `kid`
 *     (`SIG_KID_MISMATCH`), its `manifestSha` matches the actual sha256 of
 *     the re-canonicalized `manifest.json` bytes (`MANIFEST_TAMPERED` —
 *     catches a byte-level edit even if it still parses as valid JSON),
 *     and, when the `kid` is trusted, the Ed25519 signature verifies over
 *     those bytes (`BAD_SIGNATURE`).
 *  5. Every shard in `manifest.shards[]` exists on disk under
 *     `<dir>/catalog/v1/`, and its sha256 (`SHARD_TAMPERED`) and byte
 *     length (`SHARD_SIZE_MISMATCH`) match the manifest.
 */
export async function verifyArtifact(
  dir: string,
  trustedKeys: readonly TrustedKey[],
): Promise<VerifyArtifactResult> {
  const issues: string[] = [];
  const v1Dir = join(dir, "catalog", "v1");

  let manifest: CatalogManifest;
  try {
    const manifestBytes = await readFile(join(v1Dir, "manifest.json"));
    manifest = JSON.parse(manifestBytes.toString("utf8")) as CatalogManifest;
  } catch (err) {
    return { ok: false, issues: [`cannot read/parse manifest.json: ${errMessage(err)}`] };
  }

  let sigDoc: ManifestSignature;
  try {
    const sigBytes = await readFile(join(v1Dir, "manifest.sig.json"));
    sigDoc = JSON.parse(sigBytes.toString("utf8")) as ManifestSignature;
  } catch (err) {
    return { ok: false, issues: [`cannot read/parse manifest.sig.json: ${errMessage(err)}`] };
  }

  const trusted = new Map(trustedKeys.map((k) => [k.kid, k.publicKeyPem] as const));
  const publicKeyPem = trusted.get(manifest.kid);
  if (!publicKeyPem) {
    issues.push(`UNKNOWN_KID: manifest kid "${manifest.kid}" is not in the trusted keyset`);
  }
  if (manifest.revokedKids.includes(manifest.kid)) {
    issues.push(`REVOKED_KID: manifest kid "${manifest.kid}" is listed in its own revokedKids[]`);
  }
  if (sigDoc.kid !== manifest.kid) {
    issues.push(
      `SIG_KID_MISMATCH: manifest.sig.json kid "${sigDoc.kid}" does not match manifest.json kid "${manifest.kid}"`,
    );
  }

  // Re-canonicalize what was actually read off disk, so a byte-level tamper
  // of manifest.json (whitespace, key order, a changed field value) is
  // caught even though it still parses as valid JSON.
  const canonicalBytes = Buffer.from(canonicalStringify(manifest), "utf8");
  const actualSha = sha256Hex(canonicalBytes);
  if (sigDoc.manifestSha !== actualSha) {
    issues.push(
      `MANIFEST_TAMPERED: manifest.sig.json's manifestSha (${sigDoc.manifestSha}) does not match manifest.json's actual sha256 (${actualSha})`,
    );
  }

  if (publicKeyPem) {
    const sigValid = verifyBytes(publicKeyFromPem(publicKeyPem), canonicalBytes, sigDoc.sig);
    if (!sigValid) {
      issues.push(
        `BAD_SIGNATURE: the Ed25519 signature over manifest.json does not verify against kid "${manifest.kid}"`,
      );
    }
  }

  for (const shard of manifest.shards ?? []) {
    let bytes: Buffer;
    try {
      bytes = await readFile(join(v1Dir, ...shard.path.split("/")));
    } catch (err) {
      issues.push(`SHARD_MISSING: ${shard.path}: ${errMessage(err)}`);
      continue;
    }
    const actual = sha256Hex(bytes);
    if (actual !== shard.sha256) {
      issues.push(
        `SHARD_TAMPERED: ${shard.path}: manifest says sha256 ${shard.sha256}, file on disk is actually ${actual}`,
      );
    }
    if (bytes.length !== shard.bytes) {
      issues.push(
        `SHARD_SIZE_MISMATCH: ${shard.path}: manifest says ${shard.bytes} bytes, file on disk is actually ${bytes.length}`,
      );
    }
  }

  return { ok: issues.length === 0, issues };
}

function errMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/* ------------------------------------------------------------------ */
/* CLI — `verify-artifact`                                             */
/* ------------------------------------------------------------------ */

interface CliArgs {
  dir: string;
  trustedKeysPath: string;
}

function parseArgs(argv: string[]): CliArgs {
  const opts: Record<string, string> = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg && arg.startsWith("--")) {
      opts[arg.slice(2)] = argv[i + 1] ?? "";
      i += 1;
    }
  }
  const dir = opts["dir"];
  const trustedKeysPath = opts["trusted-keys"];
  if (!dir || !trustedKeysPath) {
    throw new Error(
      "Usage: node dist/sign.js --dir <artifact-dir> --trusted-keys <keys.json>\n" +
        '  <keys.json> is an array of {"kid": string, "publicKeyPem": string}',
    );
  }
  return { dir, trustedKeysPath };
}

async function main(argv: string[]): Promise<void> {
  const args = parseArgs(argv);
  const trustedKeys = JSON.parse(
    await readFile(args.trustedKeysPath, "utf8"),
  ) as TrustedKey[];
  const result = await verifyArtifact(args.dir, trustedKeys);
  if (result.ok) {
    process.stdout.write("verify-artifact: PASS\n");
    return;
  }
  process.stdout.write(`verify-artifact: FAIL (${result.issues.length} issue(s))\n`);
  for (const issue of result.issues) {
    process.stdout.write(`  ${issue}\n`);
  }
  process.exitCode = 1;
}

async function isMainModule(): Promise<boolean> {
  if (!process.argv[1]) return false;
  try {
    const [herePath, argvPath] = await Promise.all([
      realpath(fileURLToPath(import.meta.url)),
      realpath(process.argv[1]),
    ]);
    return herePath === argvPath;
  } catch {
    return false;
  }
}

if (await isMainModule()) {
  main(process.argv.slice(2)).catch((err: unknown) => {
    process.stderr.write(`verify-artifact: ${errMessage(err)}\n`);
    process.exitCode = 1;
  });
}
