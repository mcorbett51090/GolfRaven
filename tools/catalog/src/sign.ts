/**
 * Ed25519 signing and artifact verification (build plan §3.5 "Signing",
 * §3.3(ii), §4.8 "Keys, secrets and rotation", §10 P1 AT(2)). Node's
 * built-in `node:crypto` only — no dependency added.
 *
 * **Rewritten after the Opus security gate (commit 7692919, 4 blocking
 * findings).** The core fix: `verifyArtifact` checks the RAW bytes of
 * `manifest.json`/`versions.json` on disk — hashing them directly and
 * comparing to the sidecar's committed hash — and never re-serializes a
 * parsed object before checking a signature against it. Signing itself
 * covers a small, domain-separated STATEMENT (`manifestStatementBytes` /
 * `versionsStatementBytes` in `manifest.ts`) whose `manifestSha`/
 * `versionsSha` field is that raw-bytes hash, so a valid signature
 * transitively commits to the exact bytes on disk without the statement
 * itself needing to carry the (potentially large) manifest/versions body.
 *
 * **The private key never lives in this repo.** `loadSigningKeyPem` reads
 * it from a `--key-file` path (refused if the file is group- or
 * world-readable) or an env var (`GOLFRAVEN_CATALOG_SIGNING_KEY` by
 * default), supplied at run time by the protected CI environment (§4.8).
 * Every test generates its own throwaway Ed25519 keypair in-process
 * (`crypto.generateKeyPairSync('ed25519')`) rather than reading or
 * committing one.
 */
import { lstat, open, readdir, readFile } from "node:fs/promises";
import { realpath } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { join, relative } from "node:path";
import {
  createPrivateKey,
  createPublicKey,
  sign as cryptoSign,
  verify as cryptoVerify,
  type KeyObject,
} from "node:crypto";
import {
  CatalogManifestSchema,
  ManifestSignatureSchema,
  VersionsArraySchema,
  VersionsSignatureSchema,
  compareCatalogVersions,
  manifestStatementBytes,
  sha256Hex,
  strictParseAndValidate,
  versionsStatementBytes,
  type CatalogManifest,
  type ManifestSignature,
  type ManifestStatement,
  type VersionsSignature,
  type VersionsStatement,
} from "./manifest.js";

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
 * a path inside the repo. A key file that is group- or world-readable
 * (`mode & 0o077 !== 0`) is refused outright, regardless of content — a
 * CI secret mount should be `0600`, and a looser mode is itself a finding
 * worth failing loudly on rather than silently signing with. **The mode
 * check and the read happen against the SAME open file handle** (`open`
 * → `handle.stat()` → `handle.readFile()` → `handle.close()`), not two
 * separate `stat`/`readFile` calls against a path — a path-based
 * check-then-read has a TOCTOU race (the file at that path could be
 * swapped between the two calls); an open handle cannot be swapped out
 * from under itself. A PEM held in an env var commonly arrives with
 * literal `\n` escapes (most CI secret stores can't hold a real
 * multi-line value in one variable without that); those are un-escaped
 * before parsing.
 */
export async function loadSigningKeyPem(
  opts: LoadSigningKeyOptions = {},
): Promise<string> {
  if (opts.keyFilePath) {
    const handle = await open(opts.keyFilePath, "r");
    try {
      const stats = await handle.stat();
      if ((stats.mode & 0o077) !== 0) {
        throw new Error(
          `loadSigningKeyPem: refusing "${opts.keyFilePath}" — mode ${(stats.mode & 0o777).toString(8)} ` +
            `is group- or world-readable (need e.g. \`chmod 600\`)`,
        );
      }
      const bytes = await handle.readFile();
      return bytes.toString("utf8").trim();
    } finally {
      await handle.close();
    }
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

function assertEd25519(key: KeyObject, what: string): KeyObject {
  if (key.asymmetricKeyType !== "ed25519") {
    throw new Error(
      `${what}: expected an Ed25519 key, got "${String(key.asymmetricKeyType)}"`,
    );
  }
  return key;
}

export function privateKeyFromPem(pem: string): KeyObject {
  return assertEd25519(
    createPrivateKey({ key: pem, format: "pem" }),
    "privateKeyFromPem",
  );
}

export function publicKeyFromPem(pem: string): KeyObject {
  return assertEd25519(
    createPublicKey({ key: pem, format: "pem" }),
    "publicKeyFromPem",
  );
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
    return cryptoVerify(
      null,
      data,
      publicKey,
      Buffer.from(signatureBase64, "base64"),
    );
  } catch {
    return false;
  }
}

/**
 * Builds and signs the manifest statement (§3.3(ii)) over `manifestBytes`
 * — the EXACT bytes the caller is about to write as `manifest.json` (or
 * already has). Self-checks the signature against the public key derived
 * from `privateKey` before returning (finding #10) and, if
 * `expectedPublicKeyPem` is given (the CLI's `--kid-public-key`), also
 * cross-checks it — catching "signed with the wrong key for this `kid`
 * label" at emit time rather than at the next verify.
 */
export function signManifest(
  manifest: Pick<CatalogManifest, "catalogVersion" | "contractVersion" | "kid">,
  manifestBytes: Buffer,
  privateKey: KeyObject,
  expectedPublicKeyPem?: string,
): ManifestSignature {
  const statement: ManifestStatement = {
    catalogVersion: manifest.catalogVersion,
    contractVersion: manifest.contractVersion,
    kid: manifest.kid,
    manifestSha: sha256Hex(manifestBytes),
  };
  const bytes = manifestStatementBytes(statement);
  const sig = signBytes(privateKey, bytes);
  if (!verifyBytes(createPublicKey(privateKey), bytes, sig)) {
    throw new Error(
      "signManifest: self-check failed — signature does not verify against its own derived public key",
    );
  }
  if (
    expectedPublicKeyPem &&
    !verifyBytes(publicKeyFromPem(expectedPublicKeyPem), bytes, sig)
  ) {
    throw new Error(
      `signManifest: the supplied private key does NOT match --kid-public-key for kid "${manifest.kid}" — refusing to sign with the wrong key`,
    );
  }
  return { ...statement, sig };
}

/** Same shape as `signManifest`, for `versions.json`'s own, separately
 * domain-tagged signature. */
export function signVersions(
  versionsBytes: Buffer,
  kid: string,
  privateKey: KeyObject,
  expectedPublicKeyPem?: string,
): VersionsSignature {
  const statement: VersionsStatement = {
    kid,
    versionsSha: sha256Hex(versionsBytes),
  };
  const bytes = versionsStatementBytes(statement);
  const sig = signBytes(privateKey, bytes);
  if (!verifyBytes(createPublicKey(privateKey), bytes, sig)) {
    throw new Error(
      "signVersions: self-check failed — signature does not verify against its own derived public key",
    );
  }
  if (
    expectedPublicKeyPem &&
    !verifyBytes(publicKeyFromPem(expectedPublicKeyPem), bytes, sig)
  ) {
    throw new Error(
      `signVersions: the supplied private key does NOT match --kid-public-key for kid "${kid}" — refusing to sign with the wrong key`,
    );
  }
  return { ...statement, sig };
}

export interface VerifyArtifactOptions {
  trustedKeys: readonly TrustedKey[];
  /** The verifier's own compiled denylist, unioned with every
   * `revokedKids[]` already accepted from a previously-verified manifest —
   * maintaining that union across runs is the CALLER's job (finding #3);
   * this function only checks membership in whatever set it's given. */
  revokedKids: ReadonlySet<string> | readonly string[];
  /** Rollback protection (finding #6): refuse a `catalogVersion` older
   * than this. Compared via `compareCatalogVersions` (date-prefix first). */
  minCatalogVersion?: string;
  /** Refuse a manifest whose `contractVersion` isn't this exact value
   * (finding #9). `contractVersion` is a plain non-negative integer in
   * this schema, and IS the "MAJOR" the plan's §3.5 describes ("A MAJOR
   * bump publishes `/catalog/v2/`") — there is no separate minor/patch
   * component to strip. */
  supportedContractMajor?: number;
}

export interface VerifyArtifactResult {
  ok: boolean;
  issues: string[];
  /** The verified manifest's own `revokedKids[]` — present only when
   * `ok: true`, so the caller can union it into their persisted denylist
   * before the next run (finding #3). */
  revokedKids?: string[];
}

/** `manifest.json`/`versions.json` are content-bearing (they grow with the
 * catalog); `manifest.sig.json`/`versions.sig.json` are small, fixed-shape
 * signature blobs. Both caps are deliberately generous relative to what
 * these files should ever actually contain — they exist to refuse a
 * pathological/adversarial file outright, not to constrain normal growth. */
const MANIFEST_MAX_BYTES = 5 * 1024 * 1024; // 5 MB
const SIDECAR_MAX_BYTES = 64 * 1024; // 64 KB

type SmallFileRead = { ok: true; bytes: Buffer } | { ok: false; issue: string };

/**
 * Reads a small, trust-relevant file safely (finding #3): `lstat`s it
 * first and refuses a symlink or anything that isn't a regular file, caps
 * its size before ever calling `readFile` on it, and turns every failure
 * into an `issue` string rather than a thrown error — callers in
 * `verifyArtifact` fold this straight into their `issues[]` accumulation.
 */
async function readSmallFile(
  path: string,
  maxBytes: number,
  label: string,
): Promise<SmallFileRead> {
  let stats;
  try {
    stats = await lstat(path);
  } catch (err) {
    return { ok: false, issue: `cannot read ${label}: ${errMessage(err)}` };
  }
  if (stats.isSymbolicLink()) {
    return { ok: false, issue: `${label} is a symlink — refused` };
  }
  if (!stats.isFile()) {
    return { ok: false, issue: `${label} is not a regular file — refused` };
  }
  if (stats.size > maxBytes) {
    return {
      ok: false,
      issue: `${label} is ${stats.size} bytes, over the ${maxBytes}-byte cap — refused`,
    };
  }
  try {
    const bytes = await readFile(path);
    return { ok: true, bytes };
  } catch (err) {
    return { ok: false, issue: `cannot read ${label}: ${errMessage(err)}` };
  }
}

/**
 * The AT(2) gate, rebuilt around raw-byte signing (finding #1), a
 * domain-separated statement (finding #2), caller-supplied revocation
 * state (finding #3), and `versions.json`'s own signature (finding #4).
 *
 * Order of operations matters here, deliberately:
 *  1. Strict-parse + schema-validate `manifest.json` and
 *     `manifest.sig.json`'s raw bytes (§8: issues, never a thrown
 *     `TypeError`, on a malformed file — shard PATHS are validated here
 *     too, as part of the manifest schema, so a path-traversal or
 *     absolute shard path is refused before any filesystem access is
 *     attempted against it).
 *  2. `kid` trust + revocation + sidecar-field-agreement checks.
 *  3. `manifestSha` vs. the ACTUAL sha256 of the raw bytes just read.
 *  4. Rollback / contract-major checks.
 *  5. The Ed25519 signature, over the rebuilt statement.
 *  6. **Only if 1–5 all pass** does this function open a single shard
 *     file (finding #8: "Read shards only after the signature
 *     verifies") — hash/size match, symlink refusal (`lstat`), and a scan
 *     for any file on disk the manifest doesn't list (`STRAY_FILE`).
 *  7. `versions.json` + `versions.sig.json`: their own signature, and
 *     that the last entry describes exactly this manifest.
 */
export async function verifyArtifact(
  dir: string,
  opts: VerifyArtifactOptions,
): Promise<VerifyArtifactResult> {
  const issues: string[] = [];
  const v1Dir = join(dir, "catalog", "v1");
  const revoked =
    opts.revokedKids instanceof Set
      ? opts.revokedKids
      : new Set(opts.revokedKids);
  const trusted = new Map(
    opts.trustedKeys.map((k) => [k.kid, k.publicKeyPem] as const),
  );

  const manifestRead = await readSmallFile(
    join(v1Dir, "manifest.json"),
    MANIFEST_MAX_BYTES,
    "manifest.json",
  );
  if (!manifestRead.ok) {
    return { ok: false, issues: [manifestRead.issue] };
  }
  const manifestRaw = manifestRead.bytes;
  const manifestParsed = strictParseAndValidate(
    manifestRaw,
    CatalogManifestSchema,
    "manifest.json",
  );
  if (!manifestParsed.ok) {
    return { ok: false, issues: manifestParsed.issues };
  }
  const manifest = manifestParsed.value;

  const sigRead = await readSmallFile(
    join(v1Dir, "manifest.sig.json"),
    SIDECAR_MAX_BYTES,
    "manifest.sig.json",
  );
  if (!sigRead.ok) {
    return { ok: false, issues: [sigRead.issue] };
  }
  const sigRaw = sigRead.bytes;
  const sigParsed = strictParseAndValidate(
    sigRaw,
    ManifestSignatureSchema,
    "manifest.sig.json",
  );
  if (!sigParsed.ok) {
    return { ok: false, issues: sigParsed.issues };
  }
  const sigDoc = sigParsed.value;

  const publicKeyPem = trusted.get(manifest.kid);
  if (!publicKeyPem) {
    issues.push(
      `UNKNOWN_KID: manifest kid "${manifest.kid}" is not in the trusted keyset`,
    );
  }
  if (revoked.has(manifest.kid) || revoked.has(sigDoc.kid)) {
    issues.push(
      `REVOKED_KID: kid "${manifest.kid}" is in the verifier's revoked-kids set`,
    );
  }
  if (manifest.revokedKids.includes(manifest.kid)) {
    issues.push(
      `REVOKED_KID: manifest kid "${manifest.kid}" is listed in its own revokedKids[] (self-revoking manifest)`,
    );
  }
  if (sigDoc.kid !== manifest.kid) {
    issues.push(
      `SIG_KID_MISMATCH: manifest.sig.json kid "${sigDoc.kid}" != manifest.json kid "${manifest.kid}"`,
    );
  }
  if (sigDoc.catalogVersion !== manifest.catalogVersion) {
    issues.push(
      `SIG_FIELD_MISMATCH: manifest.sig.json catalogVersion "${sigDoc.catalogVersion}" != manifest.json "${manifest.catalogVersion}"`,
    );
  }
  if (sigDoc.contractVersion !== manifest.contractVersion) {
    issues.push(
      `SIG_FIELD_MISMATCH: manifest.sig.json contractVersion ${sigDoc.contractVersion} != manifest.json ${manifest.contractVersion}`,
    );
  }

  const actualManifestSha = sha256Hex(manifestRaw);
  if (sigDoc.manifestSha !== actualManifestSha) {
    issues.push(
      `MANIFEST_TAMPERED: manifest.sig.json manifestSha (${sigDoc.manifestSha}) != actual sha256 of manifest.json's raw bytes (${actualManifestSha})`,
    );
  }

  if (
    opts.minCatalogVersion &&
    compareCatalogVersions(manifest.catalogVersion, opts.minCatalogVersion) < 0
  ) {
    issues.push(
      `CATALOG_VERSION_ROLLBACK: catalogVersion "${manifest.catalogVersion}" is older than the minimum accepted "${opts.minCatalogVersion}"`,
    );
  }
  if (
    opts.supportedContractMajor !== undefined &&
    manifest.contractVersion !== opts.supportedContractMajor
  ) {
    issues.push(
      `CONTRACT_MAJOR_MISMATCH: manifest contractVersion ${manifest.contractVersion} != supported major ${opts.supportedContractMajor}`,
    );
  }

  let sigValid = false;
  if (publicKeyPem) {
    const statement: ManifestStatement = {
      catalogVersion: sigDoc.catalogVersion,
      contractVersion: sigDoc.contractVersion,
      kid: sigDoc.kid,
      manifestSha: sigDoc.manifestSha,
    };
    sigValid = verifyBytes(
      publicKeyFromPem(publicKeyPem),
      manifestStatementBytes(statement),
      sigDoc.sig,
    );
    if (!sigValid) {
      issues.push(
        `BAD_SIGNATURE: the Ed25519 signature over the manifest statement does not verify against kid "${manifest.kid}"`,
      );
    }
  }

  const blocking = issues.some(
    (i) =>
      i.startsWith("UNKNOWN_KID") ||
      i.startsWith("REVOKED_KID") ||
      i.startsWith("BAD_SIGNATURE") ||
      i.startsWith("MANIFEST_TAMPERED") ||
      i.startsWith("SIG_KID_MISMATCH") ||
      i.startsWith("SIG_FIELD_MISMATCH"),
  );
  if (blocking || !sigValid) {
    return { ok: false, issues };
  }

  // From here on the manifest is authentically signed by a trusted,
  // non-revoked kid over exactly these bytes — only now do we touch any
  // shard file.
  const onDisk = await listFilesRecursive(v1Dir);
  const allowedRoot = new Set([
    "manifest.json",
    "manifest.sig.json",
    "versions.json",
    "versions.sig.json",
  ]);
  const shardPaths = new Set(manifest.shards.map((s) => s.path));

  for (const shard of manifest.shards) {
    const absPath = join(v1Dir, ...shard.path.split("/"));
    let stats;
    try {
      stats = await lstat(absPath);
    } catch (err) {
      issues.push(`SHARD_MISSING: ${shard.path}: ${errMessage(err)}`);
      continue;
    }
    if (stats.isSymbolicLink()) {
      issues.push(`SHARD_SYMLINK: ${shard.path} is a symlink — refused`);
      continue;
    }
    if (!stats.isFile()) {
      issues.push(`SHARD_NOT_A_FILE: ${shard.path}`);
      continue;
    }
    const bytes = await readFile(absPath);
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

  for (const relPath of onDisk) {
    if (allowedRoot.has(relPath) || shardPaths.has(relPath)) continue;
    issues.push(
      `STRAY_FILE: ${relPath} is on disk but not listed in manifest.shards[] or a root document`,
    );
  }

  // versions.json + versions.sig.json.
  let versionsRaw: Buffer | undefined;
  const versionsRead = await readSmallFile(
    join(v1Dir, "versions.json"),
    MANIFEST_MAX_BYTES,
    "versions.json",
  );
  if (versionsRead.ok) {
    versionsRaw = versionsRead.bytes;
  } else {
    issues.push(versionsRead.issue);
  }
  let versionsSigRaw: Buffer | undefined;
  const versionsSigRead = await readSmallFile(
    join(v1Dir, "versions.sig.json"),
    SIDECAR_MAX_BYTES,
    "versions.sig.json",
  );
  if (versionsSigRead.ok) {
    versionsSigRaw = versionsSigRead.bytes;
  } else {
    issues.push(versionsSigRead.issue);
  }
  if (versionsRaw && versionsSigRaw) {
    const versionsParsed = strictParseAndValidate(
      versionsRaw,
      VersionsArraySchema,
      "versions.json",
    );
    const versionsSigParsed = strictParseAndValidate(
      versionsSigRaw,
      VersionsSignatureSchema,
      "versions.sig.json",
    );
    if (!versionsParsed.ok) issues.push(...versionsParsed.issues);
    if (!versionsSigParsed.ok) issues.push(...versionsSigParsed.issues);
    if (versionsParsed.ok && versionsSigParsed.ok) {
      const versions = versionsParsed.value;
      const versionsSig = versionsSigParsed.value;
      const actualVersionsSha = sha256Hex(versionsRaw);
      if (versionsSig.versionsSha !== actualVersionsSha) {
        issues.push(
          `VERSIONS_TAMPERED: versions.sig.json versionsSha (${versionsSig.versionsSha}) != actual sha256 of versions.json (${actualVersionsSha})`,
        );
      }
      const versionsPublicKeyPem = trusted.get(versionsSig.kid);
      if (!versionsPublicKeyPem) {
        issues.push(
          `UNKNOWN_KID: versions.sig.json kid "${versionsSig.kid}" is not in the trusted keyset`,
        );
      } else if (revoked.has(versionsSig.kid)) {
        issues.push(
          `REVOKED_KID: versions.sig.json kid "${versionsSig.kid}" is in the verifier's revoked-kids set`,
        );
      } else {
        const stmt: VersionsStatement = {
          kid: versionsSig.kid,
          versionsSha: versionsSig.versionsSha,
        };
        const vSigValid = verifyBytes(
          publicKeyFromPem(versionsPublicKeyPem),
          versionsStatementBytes(stmt),
          versionsSig.sig,
        );
        if (!vSigValid) {
          issues.push(
            `BAD_SIGNATURE: versions.json signature does not verify against kid "${versionsSig.kid}"`,
          );
        }
      }
      const last = versions[versions.length - 1];
      if (!last) {
        issues.push(
          `VERSIONS_EMPTY: versions.json has no entries, but a signed manifest was just verified`,
        );
      } else if (
        last.sha256 !== actualManifestSha ||
        last.version !== manifest.catalogVersion ||
        last.kid !== manifest.kid
      ) {
        issues.push(
          `VERSIONS_MISMATCH: versions.json's last entry does not describe this manifest ` +
            `(last: version=${last.version} kid=${last.kid} sha256=${last.sha256}; ` +
            `manifest: version=${manifest.catalogVersion} kid=${manifest.kid} sha256=${actualManifestSha})`,
        );
      }
    }
  }

  return {
    ok: issues.length === 0,
    issues,
    ...(issues.length === 0 ? { revokedKids: manifest.revokedKids } : {}),
  };
}

async function listFilesRecursive(root: string): Promise<string[]> {
  const out: string[] = [];
  async function walk(dir: string): Promise<void> {
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const full = join(dir, entry.name);
      if (entry.isSymbolicLink()) {
        out.push(toPosixRelative(root, full));
        continue;
      }
      if (entry.isDirectory()) {
        await walk(full);
      } else {
        out.push(toPosixRelative(root, full));
      }
    }
  }
  await walk(root);
  return out;
}

function toPosixRelative(root: string, full: string): string {
  const sep = process.platform === "win32" ? "\\" : "/";
  return relative(root, full).split(sep).join("/");
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
  revokedKidsFile?: string;
  revokedKidsInline: string[];
  minCatalogVersion?: string;
  supportedContractMajor?: number;
}

function parseArgs(argv: string[]): CliArgs {
  const opts: Record<string, string> = {};
  const seen = new Set<string>();
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg && arg.startsWith("--")) {
      const key = arg.slice(2);
      opts[key] = argv[i + 1] ?? "";
      seen.add(key);
      i += 1;
    }
  }
  const dir = opts["dir"];
  const trustedKeysPath = opts["trusted-keys"];
  if (!dir || !trustedKeysPath) {
    throw new Error(
      "Usage: node dist/sign.js --dir <artifact-dir> --trusted-keys <keys.json> " +
        "[--revoked-kids-file <kids.json>] [--revoked-kids a,b] " +
        "[--min-catalog-version <yyyymmdd-gitsha7>] [--supported-contract-major <n>]\n" +
        '  <keys.json> is an array of {"kid": string, "publicKeyPem": string}\n' +
        "  <kids.json> is an array of kid strings (the caller's compiled + persisted denylist)",
    );
  }
  return {
    dir,
    trustedKeysPath,
    ...(opts["revoked-kids-file"]
      ? { revokedKidsFile: opts["revoked-kids-file"] }
      : {}),
    revokedKidsInline: seen.has("revoked-kids")
      ? (opts["revoked-kids"] ?? "").split(",").filter(Boolean)
      : [],
    ...(opts["min-catalog-version"]
      ? { minCatalogVersion: opts["min-catalog-version"] }
      : {}),
    ...(opts["supported-contract-major"]
      ? { supportedContractMajor: Number(opts["supported-contract-major"]) }
      : {}),
  };
}

async function main(argv: string[]): Promise<void> {
  const args = parseArgs(argv);
  const trustedKeys = JSON.parse(
    await readFile(args.trustedKeysPath, "utf8"),
  ) as TrustedKey[];
  const revokedFromFile = args.revokedKidsFile
    ? (JSON.parse(await readFile(args.revokedKidsFile, "utf8")) as string[])
    : [];
  const revokedKids = new Set([...revokedFromFile, ...args.revokedKidsInline]);
  const result = await verifyArtifact(args.dir, {
    trustedKeys,
    revokedKids,
    ...(args.minCatalogVersion
      ? { minCatalogVersion: args.minCatalogVersion }
      : {}),
    ...(args.supportedContractMajor !== undefined
      ? { supportedContractMajor: args.supportedContractMajor }
      : {}),
  });
  if (result.ok) {
    process.stdout.write(
      `verify-artifact: PASS (revokedKids to persist: ${JSON.stringify(result.revokedKids ?? [])})\n`,
    );
    return;
  }
  process.stdout.write(
    `verify-artifact: FAIL (${result.issues.length} issue(s))\n`,
  );
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
