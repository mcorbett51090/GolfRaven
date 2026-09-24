/**
 * `emit-catalog` — the catalog artifact emitter (build plan §3.3 "Catalog
 * flow", §3.5, §4.1 "ODbL layer split", §10 P1). Takes a verified
 * `CatalogBundle` (`./bundle.js`) and writes the signed `catalog/v1/*`
 * tree to a caller-supplied output directory.
 *
 * **Rewritten after the Opus security gate (commit 7692919).** Three
 * structural changes beyond the signing rewrite in `sign.ts`/`manifest.ts`:
 *
 * 1. **Every check runs before any write.** Bundle-derived shard content,
 *    the manifest, its signature, the new `versions.json` (append-only
 *    checked against whatever's already published) and ITS signature are
 *    all built and validated in memory first. Nothing touches disk until
 *    every one of those has succeeded.
 * 2. **Write-to-temp-then-rename.** The whole `catalog/v1/` tree is
 *    written under a fresh `catalog/.v1.tmp-<random>/` directory, the
 *    existing `catalog/v1/` (if any) is renamed to a `.v1.backup-<random>`
 *    sibling, and only then is the temp directory renamed into
 *    `catalog/v1/`. Renaming the OLD tree out of the way rather than
 *    deleting it first means a failure at the final swap can roll back by
 *    renaming the backup back into place — the previous tree is never
 *    observably gone before the new one is observably present.
 * 3. **Deterministic time, explicitly.** `generatedAt`/`publishedAt` come
 *    from `--generated-at`, or `SOURCE_DATE_EPOCH` if set, and ONLY fall
 *    back to the wall clock when this exact `catalogVersion` has never
 *    been published before (a first-time emit has no "previous run" to
 *    disagree with). Re-emitting an ALREADY-published version without a
 *    pinned time source is refused outright, rather than silently
 *    producing different bytes that `appendVersion` would reject anyway
 *    with a much less specific error.
 *
 * **Shard layout.** §3.3 names `directory/<ISO-region>.json`,
 * `facilities/<ISO-region>.json` and `geometry/<ISO-region>.json` as the
 * site's per-region shards; §5.2 shards geometry by GEOHASH instead
 * ("so `US-CA`/`US-FL` cannot approach the per-file cap") because raw
 * polygon data can be large per region. This bundle carries no geometry
 * payload (`Course.geometry` is a pointer, not inline polygon data — the
 * geometry pipeline is P1.1+, out of `bundle.ts`'s scope), so nothing
 * here needs geohash-sized sharding; `facilities/<region>.json` shards by
 * ISO region, exactly as §5.2 already states for "Directory JSON".
 *
 * **Shard path case.** Every shard PATH is lower-cased (`facilities/us-tn.json`,
 * not `facilities/US-TN.json`) to satisfy the verifier's path allowlist
 * (`ShardPathSchema` in `manifest.ts`, a security-review requirement — see
 * that schema's own doc). The `Region`/`Facility.region` VALUE stored
 * inside the shard's JSON content is untouched — still the real, upper-case
 * ISO 3166-2 code (`"US-TN"`) — only the on-disk filename is lower-cased.
 *
 * **ODbL layer split (§4.1).** `bundle.osm` (present only when the bundle
 * carries seed-joined OSM content) is sharded by the region of the
 * facility/course whose `seed.osmRef` it's joined through, written under
 * `osm/directory/<region>.json` (any entry not referenced by a known
 * `osmRef` lands in `osm/directory/unassigned.json`), plus a plain-text
 * `osm/attribution.txt` — every one of those shards flagged
 * `license: "ODbL-1.0"` in the manifest.
 */
import { lstat, mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { realpath } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { randomBytes } from "node:crypto";
import { dirname, join } from "node:path";
import { parseCatalogBundle, type CatalogBundle } from "./bundle.js";
import {
  CatalogManifestSchema,
  CatalogVersionSchema,
  SemverSchema,
  ShardPathSchema,
  VersionsArraySchema,
  appendVersion,
  canonicalStringify,
  compareCodePoints,
  parseStrictJson,
  sha256Hex,
  sortById,
  strictParseAndValidate,
  type CatalogManifest,
  type ManifestSignature,
  type ShardEntry,
  type VersionEntry,
  type VersionsSignature,
} from "./manifest.js";
import {
  loadSigningKeyPem,
  privateKeyFromPem,
  signManifest,
  signVersions,
} from "./sign.js";

const ODBL_ATTRIBUTION =
  "© OpenStreetMap contributors.\n" +
  "This file is made available under the Open Database License (ODbL) v1.0:\n" +
  "https://opendatacommons.org/licenses/odbl/1-0/\n" +
  "Build plan §4.1 — the ODbL layer split.\n";

export interface EmitCatalogOptions {
  /** The directory the artifact tree is written under, as
   * `<outDir>/catalog/v1/...` — supplied by the caller; never a repo path. */
  outDir: string;
  /** `yyyymmdd-gitsha7` (§3.5). */
  catalogVersion: string;
  minAppVersion: string;
  kid: string;
  revokedKids?: string[];
  privateKeyPem: string;
  /** Cross-checked against the public key derived from `privateKeyPem` —
   * refuses to sign if they don't match (finding #10: "signed with the
   * wrong key for this `kid` label" caught at emit time). */
  expectedPublicKeyPem?: string;
  /** Explicit timestamp source (finding #11). Accepts a `Date` (tests) or
   * an ISO string (the CLI's `--generated-at`). When omitted, falls back
   * to `SOURCE_DATE_EPOCH` if set, else the wall clock — but ONLY for a
   * `catalogVersion` that has never been published before; see this
   * module's doc. */
  generatedAt?: Date | string;
  /**
   * A previously-published `versions.json` to append to, for a fresh
   * `outDir` that doesn't already carry one. If
   * `<outDir>/catalog/v1/versions.json` already exists, it wins. A file
   * given here that cannot be read or fails to parse/validate THROWS — it
   * never silently falls back to an empty list (finding #5).
   */
  previousVersionsPath?: string;
}

export interface EmitCatalogResult {
  manifest: CatalogManifest;
  manifestSignature: ManifestSignature;
  versions: VersionEntry[];
  versionsSignature: VersionsSignature;
  shardCount: number;
  v1Dir: string;
}

export async function emitCatalogArtifact(
  bundle: CatalogBundle,
  opts: EmitCatalogOptions,
): Promise<EmitCatalogResult> {
  /* ---------------------------------------------------------------- */
  /* 1. Validate inputs and load the key — no filesystem writes yet.   */
  /* ---------------------------------------------------------------- */
  if (!CatalogVersionSchema.safeParse(opts.catalogVersion).success) {
    throw new Error(`emit-catalog: --catalog-version "${opts.catalogVersion}" must match "yyyymmdd-gitsha7"`);
  }
  if (!SemverSchema.safeParse(opts.minAppVersion).success) {
    throw new Error(`emit-catalog: --min-app-version "${opts.minAppVersion}" must be a semver string`);
  }
  if (!opts.kid) {
    throw new Error("emit-catalog: --kid is required");
  }
  const revokedKidsSorted = [...(opts.revokedKids ?? [])].sort(compareCodePoints);
  const privateKey = privateKeyFromPem(opts.privateKeyPem); // throws if not Ed25519

  const v1Dir = join(opts.outDir, "catalog", "v1");

  /* ---------------------------------------------------------------- */
  /* 2. Load whatever's already published (read-only) and resolve the  */
  /*    emit timestamp deterministically.                              */
  /* ---------------------------------------------------------------- */
  const previousVersions = await loadPreviousVersions(v1Dir, opts.previousVersionsPath);
  const now = resolveGeneratedAt(opts, previousVersions);

  /* ---------------------------------------------------------------- */
  /* 3. Build every shard's bytes in memory.                           */
  /* ---------------------------------------------------------------- */
  const shardBuilds: { path: string; bytes: Buffer; license?: "ODbL-1.0" }[] = [];
  function addJsonShard(relPath: string, content: unknown, license?: "ODbL-1.0"): void {
    shardBuilds.push({
      path: relPath,
      bytes: Buffer.from(canonicalStringify(content), "utf8"),
      ...(license ? { license } : {}),
    });
  }
  function addRawShard(relPath: string, bytes: Buffer, license?: "ODbL-1.0"): void {
    shardBuilds.push({ path: relPath, bytes, ...(license ? { license } : {}) });
  }

  addJsonShard("trails.json", sortById(bundle.trails));
  addJsonShard("id-ledger.json", bundle.idLedger);
  if (bundle.designers !== undefined) {
    addJsonShard("designers.json", sortById(bundle.designers));
  }
  if (bundle.offerTerms !== undefined) {
    addJsonShard("offer-terms.json", sortById(bundle.offerTerms));
  }

  const byRegion = new Map<string, CatalogBundle["facilities"]>();
  for (const facility of bundle.facilities) {
    const list = byRegion.get(facility.region) ?? [];
    list.push(facility);
    byRegion.set(facility.region, list);
  }
  for (const region of [...byRegion.keys()].sort(compareCodePoints)) {
    const list = byRegion.get(region);
    if (list) {
      addJsonShard(`facilities/${regionShardSlug(region)}.json`, sortById(list));
    }
  }

  if (bundle.osm !== undefined) {
    const osmByRegion = shardOsmByRegion(bundle);
    for (const region of [...osmByRegion.keys()].sort(compareCodePoints)) {
      const content = osmByRegion.get(region);
      if (content) {
        addJsonShard(`osm/directory/${regionShardSlug(region)}.json`, content, "ODbL-1.0");
      }
    }
    addRawShard("osm/attribution.txt", Buffer.from(ODBL_ATTRIBUTION, "utf8"), "ODbL-1.0");
  }

  const shards: ShardEntry[] = shardBuilds
    .map((s) => ({
      path: s.path,
      sha256: sha256Hex(s.bytes),
      bytes: s.bytes.length,
      ...(s.license ? { license: s.license } : {}),
    }))
    .sort((a, b) => compareCodePoints(a.path, b.path));

  for (const shard of shards) {
    if (!ShardPathSchema.safeParse(shard.path).success) {
      // Defense in depth: `CatalogManifestSchema` below would also catch
      // this, but failing here is failing before anything else runs.
      throw new Error(`emit-catalog: internal error — generated an invalid shard path "${shard.path}"`);
    }
  }

  /* ---------------------------------------------------------------- */
  /* 4. Build, self-check and sign the manifest.                       */
  /* ---------------------------------------------------------------- */
  const manifestCandidate = {
    contractVersion: bundle.contractVersion,
    catalogVersion: opts.catalogVersion,
    minAppVersion: opts.minAppVersion,
    kid: opts.kid,
    revokedKids: revokedKidsSorted,
    generatedAt: now.toISOString(),
    shards,
  };
  const manifestParsed = CatalogManifestSchema.safeParse(manifestCandidate);
  if (!manifestParsed.success) {
    throw new Error(`emit-catalog: internal error — built an invalid manifest: ${manifestParsed.error.message}`);
  }
  const manifest: CatalogManifest = manifestParsed.data;

  const manifestBytes = Buffer.from(canonicalStringify(manifest), "utf8");
  assertCanonicalRoundTrip(manifestBytes, "manifest.json");

  const manifestSignature = signManifest(manifest, manifestBytes, privateKey, opts.expectedPublicKeyPem);
  const manifestSigBytes = Buffer.from(canonicalStringify(manifestSignature), "utf8");
  assertCanonicalRoundTrip(manifestSigBytes, "manifest.sig.json");

  /* ---------------------------------------------------------------- */
  /* 5. Append, self-check and sign `versions.json` (still no writes). */
  /* ---------------------------------------------------------------- */
  const newEntry: VersionEntry = {
    version: opts.catalogVersion,
    publishedAt: now.toISOString(),
    kid: opts.kid,
    sha256: manifestSignature.manifestSha,
  };
  const versions = appendVersion(previousVersions, newEntry); // throws before any write on a violation

  const versionsBytes = Buffer.from(canonicalStringify(versions), "utf8");
  assertCanonicalRoundTrip(versionsBytes, "versions.json");

  const versionsSignature = signVersions(versionsBytes, opts.kid, privateKey, opts.expectedPublicKeyPem);
  const versionsSigBytes = Buffer.from(canonicalStringify(versionsSignature), "utf8");
  assertCanonicalRoundTrip(versionsSigBytes, "versions.sig.json");

  /* ---------------------------------------------------------------- */
  /* 6. Everything validated — write to a temp dir, then atomically     */
  /*    swap it into place. A failure at any point up to here has      */
  /*    touched no file under `outDir` at all.                         */
  /* ---------------------------------------------------------------- */
  const catalogDir = join(opts.outDir, "catalog");
  await mkdir(catalogDir, { recursive: true });
  const suffix = randomBytes(6).toString("hex");
  const tmpDir = join(catalogDir, `.v1.tmp-${suffix}`);
  await mkdir(tmpDir, { recursive: true });

  try {
    for (const shard of shardBuilds) {
      const absPath = join(tmpDir, ...shard.path.split("/"));
      await mkdir(dirname(absPath), { recursive: true });
      await writeFile(absPath, shard.bytes);
    }
    await writeFile(join(tmpDir, "manifest.json"), manifestBytes);
    await writeFile(join(tmpDir, "manifest.sig.json"), manifestSigBytes);
    await writeFile(join(tmpDir, "versions.json"), versionsBytes);
    await writeFile(join(tmpDir, "versions.sig.json"), versionsSigBytes);
  } catch (err) {
    // A failure partway through writing the temp tree — nothing under
    // `catalog/v1` has been touched yet, and this cleans up the orphaned
    // partial temp directory rather than leaving debris behind.
    await rm(tmpDir, { recursive: true, force: true }).catch(() => {});
    throw err;
  }

  let backupDir: string | undefined;
  const v1Existed = await pathExists(v1Dir);
  if (v1Existed) {
    backupDir = join(catalogDir, `.v1.backup-${suffix}`);
    await rename(v1Dir, backupDir);
  }
  try {
    await rename(tmpDir, v1Dir);
  } catch (err) {
    if (backupDir) {
      await rename(backupDir, v1Dir).catch(() => {
        // Best-effort rollback; the original error is what matters to the caller.
      });
    }
    throw err;
  }
  if (backupDir) {
    await rm(backupDir, { recursive: true, force: true }).catch(() => {});
  }

  return {
    manifest,
    manifestSignature,
    versions,
    versionsSignature,
    shardCount: manifest.shards.length,
    v1Dir,
  };
}

/** Groups `bundle.osm` entries by the ISO region of the facility/course
 * whose `seed.osmRef` references them; an entry no known `osmRef` points
 * at lands in an `"unassigned"` bucket rather than being silently dropped. */
function shardOsmByRegion(bundle: CatalogBundle): Map<string, Record<string, unknown>> {
  const byRegion = new Map<string, Record<string, unknown>>();
  if (bundle.osm === undefined) return byRegion;
  const consumed = new Set<string>();
  for (const facility of bundle.facilities) {
    const refs: string[] = [];
    if (facility.seed.osmRef) refs.push(facility.seed.osmRef);
    for (const course of facility.courses) {
      if (course.seed?.osmRef) refs.push(course.seed.osmRef);
    }
    for (const ref of refs) {
      const content = bundle.osm[ref];
      if (content === undefined) continue;
      const bucket = byRegion.get(facility.region) ?? {};
      bucket[ref] = content;
      byRegion.set(facility.region, bucket);
      consumed.add(ref);
    }
  }
  const unassigned: Record<string, unknown> = {};
  for (const [ref, content] of Object.entries(bundle.osm)) {
    if (!consumed.has(ref)) unassigned[ref] = content;
  }
  if (Object.keys(unassigned).length > 0) {
    byRegion.set("unassigned", unassigned);
  }
  return byRegion;
}

/** Lower-cases a region code for use as a shard-path SEGMENT only — see
 * this module's doc "Shard path case". */
function regionShardSlug(region: string): string {
  return region.toLowerCase();
}

function assertCanonicalRoundTrip(bytes: Buffer, label: string): void {
  const text = bytes.toString("utf8");
  let reparsed: unknown;
  try {
    reparsed = parseStrictJson(text);
  } catch (err) {
    throw new Error(`emit-catalog: internal error — ${label} failed to re-parse: ${errMessage(err)}`);
  }
  const roundTrip = canonicalStringify(reparsed);
  if (roundTrip !== text) {
    throw new Error(
      `emit-catalog: internal error — ${label} did not round-trip through canonicalStringify(parseStrictJson(raw))`,
    );
  }
}

function resolveGeneratedAt(opts: EmitCatalogOptions, previousVersions: VersionEntry[]): Date {
  if (opts.generatedAt !== undefined) {
    const d = opts.generatedAt instanceof Date ? opts.generatedAt : new Date(opts.generatedAt);
    if (Number.isNaN(d.getTime())) {
      throw new Error(`emit-catalog: invalid --generated-at "${String(opts.generatedAt)}"`);
    }
    return d;
  }
  const sourceDateEpoch = process.env["SOURCE_DATE_EPOCH"];
  if (sourceDateEpoch) {
    const seconds = Number(sourceDateEpoch);
    if (!Number.isFinite(seconds)) {
      throw new Error(`emit-catalog: invalid SOURCE_DATE_EPOCH "${sourceDateEpoch}"`);
    }
    return new Date(seconds * 1000);
  }
  const alreadyPublished = previousVersions.some((v) => v.version === opts.catalogVersion);
  if (alreadyPublished) {
    throw new Error(
      `emit-catalog: refusing a non-deterministic re-emit of already-published version "${opts.catalogVersion}" ` +
        `without --generated-at or SOURCE_DATE_EPOCH — the wall clock would silently produce different bytes`,
    );
  }
  return new Date();
}

async function loadPreviousVersions(
  v1Dir: string,
  previousVersionsPath?: string,
): Promise<VersionEntry[]> {
  const versionsPath = join(v1Dir, "versions.json");
  let raw: Buffer | undefined;
  try {
    raw = await readFile(versionsPath);
  } catch (err) {
    if (!isEnoent(err)) {
      throw new Error(`emit-catalog: cannot read existing versions.json at ${versionsPath}: ${errMessage(err)}`);
    }
    raw = undefined;
  }
  if (raw === undefined && previousVersionsPath) {
    // Deliberately NOT wrapped in try/catch — a missing or unreadable
    // `--previous-versions` file throws (finding #5: "never falls back to
    // `[]`"), rather than being treated as "no prior publish".
    raw = await readFile(previousVersionsPath);
  }
  if (raw === undefined) {
    return [];
  }
  const parsed = strictParseAndValidate(raw, VersionsArraySchema, "previous versions.json");
  if (!parsed.ok) {
    throw new Error(`emit-catalog: malformed previous versions.json:\n${parsed.issues.join("\n")}`);
  }
  return parsed.value;
}

async function pathExists(path: string): Promise<boolean> {
  try {
    await lstat(path);
    return true;
  } catch {
    return false;
  }
}

function isEnoent(err: unknown): boolean {
  return typeof err === "object" && err !== null && "code" in err && (err as { code?: unknown }).code === "ENOENT";
}

function errMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/* ------------------------------------------------------------------ */
/* CLI — `emit-catalog`                                                */
/* ------------------------------------------------------------------ */

interface CliArgs {
  bundlePath: string;
  outDir: string;
  keyFilePath?: string;
  kid: string;
  minAppVersion: string;
  catalogVersion: string;
  revokedKids?: string[];
  previousVersionsPath?: string;
  generatedAt?: string;
  kidPublicKeyPath?: string;
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
  const bundlePath = opts["bundle"];
  const outDir = opts["out"];
  const kid = opts["kid"];
  const minAppVersion = opts["min-app-version"];
  const catalogVersion = opts["catalog-version"];
  if (!bundlePath || !outDir || !kid || !minAppVersion || !catalogVersion) {
    throw new Error(
      "Usage: node dist/emit-catalog.js --bundle <bundle.json> --out <dir> --kid <kid> " +
        "--min-app-version <semver> --catalog-version <yyyymmdd-gitsha7> " +
        "[--key-file <path> | env GOLFRAVEN_CATALOG_SIGNING_KEY] [--kid-public-key <pem-file>] " +
        "[--revoked-kids a,b] [--previous-versions <versions.json>] " +
        "[--generated-at <iso8601> | env SOURCE_DATE_EPOCH]",
    );
  }
  return {
    bundlePath,
    outDir,
    kid,
    minAppVersion,
    catalogVersion,
    ...(opts["key-file"] ? { keyFilePath: opts["key-file"] } : {}),
    ...(seen.has("revoked-kids")
      ? { revokedKids: (opts["revoked-kids"] ?? "").split(",").filter(Boolean) }
      : {}),
    ...(opts["previous-versions"] ? { previousVersionsPath: opts["previous-versions"] } : {}),
    ...(opts["generated-at"] ? { generatedAt: opts["generated-at"] } : {}),
    ...(opts["kid-public-key"] ? { kidPublicKeyPath: opts["kid-public-key"] } : {}),
  };
}

async function main(argv: string[]): Promise<void> {
  const args = parseArgs(argv);
  const bundleRaw = JSON.parse(await readFile(args.bundlePath, "utf8"));
  const parsed = parseCatalogBundle(bundleRaw);
  if (!parsed.ok) {
    process.stderr.write(
      `emit-catalog: --bundle failed schema validation:\n${parsed.schemaIssues
        .map((i) => `  ${i.path}: ${i.message}`)
        .join("\n")}\n`,
    );
    process.exitCode = 1;
    return;
  }

  const privateKeyPem = await loadSigningKeyPem(
    args.keyFilePath ? { keyFilePath: args.keyFilePath } : {},
  );
  const expectedPublicKeyPem = args.kidPublicKeyPath
    ? (await readFile(args.kidPublicKeyPath, "utf8")).trim()
    : undefined;

  const result = await emitCatalogArtifact(parsed.bundle, {
    outDir: args.outDir,
    catalogVersion: args.catalogVersion,
    minAppVersion: args.minAppVersion,
    kid: args.kid,
    privateKeyPem,
    ...(args.revokedKids ? { revokedKids: args.revokedKids } : {}),
    ...(args.previousVersionsPath ? { previousVersionsPath: args.previousVersionsPath } : {}),
    ...(args.generatedAt ? { generatedAt: args.generatedAt } : {}),
    ...(expectedPublicKeyPem ? { expectedPublicKeyPem } : {}),
  });

  process.stdout.write(
    `emit-catalog: wrote ${result.shardCount} shard(s) to ${result.v1Dir} ` +
      `(catalogVersion=${result.manifest.catalogVersion}, kid=${result.manifest.kid}, ` +
      `versions.json has ${result.versions.length} entr${result.versions.length === 1 ? "y" : "ies"}, ` +
      `revokedKids=${JSON.stringify(result.manifest.revokedKids)})\n`,
  );
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
    process.stderr.write(`emit-catalog: ${errMessage(err)}\n`);
    process.exitCode = 1;
  });
}
