/**
 * `emit-catalog` — the catalog artifact emitter (build plan §3.3 "Catalog
 * flow", §3.5 "How the website and the app share the contract", §4.1 "ODbL
 * layer split", §10 P1: "artifact emitter + Ed25519 `kid` signing in a
 * protected environment, with `minAppVersion` and `revokedKids[]` in the
 * manifest").
 *
 * Takes a verified `CatalogBundle` — the same shape `verify-catalog`
 * consumes (`./bundle.js`) — and writes the signed `catalog/v1/*` artifact
 * tree to an **output directory the caller supplies**. This module never
 * writes into the repo and never defaults `--out` to anywhere inside it;
 * every test in `test/emit-catalog.test.ts` writes into an `os.tmpdir()`
 * directory it creates and removes itself.
 *
 * **Shard layout, and the choice behind it.** §3.3's data flow names
 * `directory/<ISO-region>.json`, `facilities/<ISO-region>.json` and
 * `geometry/<ISO-region>.json` as the site's per-region shards, while
 * §5.2's build-budget gate shards geometry by GEOHASH instead ("so
 * `US-CA`/`US-FL` cannot approach the per-file cap") because raw polygon
 * data can be large per region. This task's bundle format carries no
 * geometry payload (`Course.geometry` is a `{layer, ref, file, ...}`
 * pointer, not inline polygon data — the geometry pipeline itself is
 * P1.1+, out of scope here per `bundle.ts`'s own module doc), so there is
 * nothing that would need geohash-sized sharding yet. This emitter shards
 * the one thing that plausibly could grow large per region —
 * `facilities/<ISO-region>.json` — by ISO region, exactly as §5.2 already
 * states for "Directory JSON". `trails.json`, `id-ledger.json`,
 * `designers.json` and `offer-terms.json` are each a single shard; they
 * are catalog-wide, small, cross-cut region already (a `Trail` spans many
 * `regions[]`), and sharding them per region would just require every
 * reader to re-merge them.
 *
 * **ODbL layer split (§4.1).** `bundle.osm` (present only when the bundle
 * carries seed-joined OSM content) is written under its own `osm/`
 * subtree, each shard flagged `license: "ODbL-1.0"` in the manifest, plus
 * a plain-text `osm/ATTRIBUTION.txt` — kept structurally separate from the
 * curated content, per the plan's own framing of this as "the separately
 * licensed `catalog/v1/osm/*`".
 */
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { realpath } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { parseCatalogBundle, type CatalogBundle } from "./bundle.js";
import {
  appendVersion,
  canonicalStringify,
  sha256Hex,
  sortById,
  type CatalogManifest,
  type ShardEntry,
  type VersionEntry,
} from "./manifest.js";
import {
  loadSigningKeyPem,
  privateKeyFromPem,
  signManifest,
  type ManifestSignature,
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
  /** `yyyymmdd-gitsha7` (§3.5) — this module does not compute or validate
   * the shape; the CLI's caller decides. */
  catalogVersion: string;
  minAppVersion: string;
  kid: string;
  revokedKids?: string[];
  privateKeyPem: string;
  /** Overrides `new Date()` for `generatedAt` / `publishedAt` — tests pin
   * this so two emits with identical inputs are byte-identical even across
   * a millisecond boundary. */
  now?: Date;
  /**
   * A previously-published `versions.json` to append to, for a fresh
   * `outDir` that doesn't already carry one (e.g. downloaded from the last
   * publish before this run). If `<outDir>/catalog/v1/versions.json`
   * already exists, it wins — a re-run into the same directory has the
   * more current copy of the two.
   */
  previousVersionsPath?: string;
}

export interface EmitCatalogResult {
  manifest: CatalogManifest;
  manifestSignature: ManifestSignature;
  versions: VersionEntry[];
  shardCount: number;
  v1Dir: string;
}

export async function emitCatalogArtifact(
  bundle: CatalogBundle,
  opts: EmitCatalogOptions,
): Promise<EmitCatalogResult> {
  const now = opts.now ?? new Date();
  const v1Dir = join(opts.outDir, "catalog", "v1");
  await mkdir(v1Dir, { recursive: true });

  const shards: ShardEntry[] = [];

  async function writeShardBytes(
    relPath: string,
    bytes: Buffer,
    license?: "ODbL-1.0",
  ): Promise<void> {
    const absPath = join(v1Dir, ...relPath.split("/"));
    await mkdir(dirname(absPath), { recursive: true });
    await writeFile(absPath, bytes);
    shards.push({
      path: relPath,
      sha256: sha256Hex(bytes),
      bytes: bytes.length,
      ...(license ? { license } : {}),
    });
  }

  async function writeShardJson(
    relPath: string,
    content: unknown,
    license?: "ODbL-1.0",
  ): Promise<void> {
    await writeShardBytes(relPath, Buffer.from(canonicalStringify(content), "utf8"), license);
  }

  // trails.json — catalog-wide, sorted by id for determinism.
  await writeShardJson("trails.json", sortById(bundle.trails));

  // id-ledger.json — the full ledger, so the import function can ingest it
  // whole (§3.3: "the function ... imports it, including the full ID
  // ledger into `app.catalog_id_ledger`").
  await writeShardJson("id-ledger.json", bundle.idLedger);

  // designers.json — optional field, written only when the bundle carries
  // designers at all (an omitted key means "this run says nothing about
  // designers", distinct from "there are zero").
  if (bundle.designers !== undefined) {
    await writeShardJson("designers.json", sortById(bundle.designers));
  }

  // offer-terms.json — same optional-field discipline as designers.
  if (bundle.offerTerms !== undefined) {
    await writeShardJson("offer-terms.json", sortById(bundle.offerTerms));
  }

  // facilities/<ISO-region>.json — sharded by region (§5.2: "Directory JSON
  // is sharded by ISO region for the app").
  const byRegion = new Map<string, CatalogBundle["facilities"]>();
  for (const facility of bundle.facilities) {
    const list = byRegion.get(facility.region) ?? [];
    list.push(facility);
    byRegion.set(facility.region, list);
  }
  for (const region of [...byRegion.keys()].sort()) {
    const list = byRegion.get(region);
    if (list) {
      await writeShardJson(`facilities/${region}.json`, sortById(list));
    }
  }

  // osm/ — the separately-licensed ODbL part (§4.1), only when the bundle
  // carries any joined OSM content at all.
  if (bundle.osm !== undefined) {
    await writeShardJson("osm/content.json", bundle.osm, "ODbL-1.0");
    await writeShardBytes(
      "osm/ATTRIBUTION.txt",
      Buffer.from(ODBL_ATTRIBUTION, "utf8"),
      "ODbL-1.0",
    );
  }

  const manifest: CatalogManifest = {
    contractVersion: bundle.contractVersion,
    catalogVersion: opts.catalogVersion,
    minAppVersion: opts.minAppVersion,
    kid: opts.kid,
    revokedKids: [...(opts.revokedKids ?? [])].sort(),
    generatedAt: now.toISOString(),
    shards: [...shards].sort((a, b) => a.path.localeCompare(b.path)),
  };

  const privateKey = privateKeyFromPem(opts.privateKeyPem);
  const manifestSignature = signManifest(manifest, privateKey);

  // manifest.json / manifest.sig.json are the artifact's root documents,
  // not shards of themselves (a manifest cannot list its own hash inside
  // its own shard list) — written directly, not through writeShardJson.
  await writeFile(
    join(v1Dir, "manifest.json"),
    Buffer.from(canonicalStringify(manifest), "utf8"),
  );
  await writeFile(
    join(v1Dir, "manifest.sig.json"),
    Buffer.from(canonicalStringify(manifestSignature), "utf8"),
  );

  // versions.json — append-only (§3.3).
  const versionsPath = join(v1Dir, "versions.json");
  let previousVersions: VersionEntry[] = [];
  try {
    previousVersions = JSON.parse(await readFile(versionsPath, "utf8")) as VersionEntry[];
  } catch {
    if (opts.previousVersionsPath) {
      try {
        previousVersions = JSON.parse(
          await readFile(opts.previousVersionsPath, "utf8"),
        ) as VersionEntry[];
      } catch {
        previousVersions = [];
      }
    }
  }
  const newEntry: VersionEntry = {
    version: opts.catalogVersion,
    publishedAt: now.toISOString(),
    kid: opts.kid,
    sha256: manifestSignature.manifestSha,
  };
  const versions = appendVersion(previousVersions, newEntry);
  await writeFile(versionsPath, Buffer.from(canonicalStringify(versions), "utf8"));

  return {
    manifest,
    manifestSignature,
    versions,
    shardCount: manifest.shards.length,
    v1Dir,
  };
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
        "[--key-file <path> | env GOLFRAVEN_CATALOG_SIGNING_KEY] " +
        "[--revoked-kids a,b] [--previous-versions <versions.json>]",
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

  const result = await emitCatalogArtifact(parsed.bundle, {
    outDir: args.outDir,
    catalogVersion: args.catalogVersion,
    minAppVersion: args.minAppVersion,
    kid: args.kid,
    privateKeyPem,
    ...(args.revokedKids ? { revokedKids: args.revokedKids } : {}),
    ...(args.previousVersionsPath ? { previousVersionsPath: args.previousVersionsPath } : {}),
  });

  process.stdout.write(
    `emit-catalog: wrote ${result.shardCount} shard(s) to ${result.v1Dir} ` +
      `(catalogVersion=${result.manifest.catalogVersion}, kid=${result.manifest.kid}, ` +
      `versions.json has ${result.versions.length} entr${result.versions.length === 1 ? "y" : "ies"})\n`,
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
    const message = err instanceof Error ? err.message : String(err);
    process.stderr.write(`emit-catalog: ${message}\n`);
    process.exitCode = 1;
  });
}
