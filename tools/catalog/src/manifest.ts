/**
 * Manifest and `versions.json` shape, canonical-JSON, and append-only
 * helpers for the catalog artifact (build plan §3.3 "A signed, append-only
 * `catalog/v1/versions.json`", §3.5 "App lifecycle fields in the signed
 * manifest", §10 P1 AT(2): "The signature verifies per `kid`, a tampered
 * shard fails, and a manifest whose `kid` is in `revokedKids` is
 * refused.").
 *
 * Deliberately dependency-free (no `@golfraven/catalog` import) so
 * `emit-catalog.ts` and `sign.ts` share one small module for the parts of
 * the artifact format that are not about the bundle shape or signing
 * itself — the two other pieces of this task.
 */
import { createHash } from "node:crypto";

/** One entry in `manifest.json`'s `shards[]` — every file the artifact
 * tree carries besides `manifest.json`/`manifest.sig.json`/`versions.json`
 * themselves (those three are not self-listed; see `emit-catalog.ts`). */
export interface ShardEntry {
  /** POSIX-style path relative to `catalog/v1/`, e.g.
   * `"facilities/US-CA.json"`. Always forward slashes, even if this ever
   * runs on Windows. */
  path: string;
  sha256: string;
  bytes: number;
  /** Present only on the separately-licensed ODbL part (§4.1 "the ODbL
   * layer split"). Absent = ordinary catalog content under the project's
   * own terms. */
  license?: "ODbL-1.0";
}

/** `manifest.json`'s shape. Signed as a whole by `sign.ts`'s
 * `signManifest` — the signature and its sidecar `manifestSha` live in
 * `manifest.sig.json`, not inline, mirroring §3.3's own
 * `manifestSig: {catalogVersion, manifestSha, kid, sig}` shape for the
 * header the app attaches to evidence. */
export interface CatalogManifest {
  contractVersion: number;
  /** `yyyymmdd-gitsha7` (§3.5) — this module does not enforce the shape;
   * the caller (the emitter's CLI) decides how to compute it. */
  catalogVersion: string;
  /** Below this app version, the app shows a force-update screen and
   * keeps the last good cached catalog read-only (§3.5 FM-24). */
  minAppVersion: string;
  /** The `kid` that signs THIS manifest. */
  kid: string;
  /** Keys the app/import function must stop trusting from this manifest
   * on (§3.5, §4.8 "Catalog key revocation"). May include `manifest.kid`
   * itself — that is a self-revoking manifest (AT(2)'s "a manifest whose
   * `kid` is in `revokedKids` is refused" fixture) and `verifyArtifact`
   * refuses it; this module does not filter it out on write, since the
   * emitter must be able to produce that exact fixture for tests. */
  revokedKids: string[];
  generatedAt: string;
  shards: ShardEntry[];
}

/** One entry in the append-only `catalog/v1/versions.json` (§3.3: "the
 * site publishes a signed, append-only `catalog/v1/versions.json`
 * (version, `published_at`, `kid`, sha)"). */
export interface VersionEntry {
  version: string;
  publishedAt: string;
  kid: string;
  /** sha256 of the manifest this version entry describes (matches
   * `ManifestSignature.manifestSha` for that emit). */
  sha256: string;
}

/**
 * Deterministic JSON: object keys sorted recursively (array element order
 * is left exactly as the caller built it — the caller is responsible for
 * putting array elements in a canonical order, e.g. sorted by `id`, since
 * "sort the array" is not well-defined for arbitrary array content the
 * way "sort the keys" is for objects). Two-space indent, trailing newline,
 * so two emits with the same logical content are byte-identical.
 */
export function canonicalStringify(value: unknown): string {
  return `${JSON.stringify(sortKeysDeep(value), null, 2)}\n`;
}

function sortKeysDeep(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(sortKeysDeep);
  }
  if (value !== null && typeof value === "object") {
    const input = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(input).sort()) {
      out[key] = sortKeysDeep(input[key]);
    }
    return out;
  }
  return value;
}

export function sha256Hex(data: Buffer | string): string {
  return createHash("sha256").update(data).digest("hex");
}

/**
 * Enforces `versions.json`'s append-only discipline (§3.3), the same
 * discipline `data/id-ledger.json` follows (§3.5): every entry in
 * `previous` must appear, unchanged, at the same position, in `next` —
 * `next` may only add entries after `previous`'s. Throws with a message
 * naming the exact violation; never silently drops or rewrites data.
 */
export function assertVersionsAppendOnly(
  previous: readonly VersionEntry[],
  next: readonly VersionEntry[],
): void {
  if (next.length < previous.length) {
    throw new Error(
      `versions.json append-only violation: ${previous.length} previous entries, only ${next.length} in the new list`,
    );
  }
  for (let i = 0; i < previous.length; i += 1) {
    const before = previous[i];
    const after = next[i];
    if (!before || !after || before.version !== after.version) {
      throw new Error(
        `versions.json append-only violation: entry ${i} was version "${before?.version ?? "<missing>"}", now "${after?.version ?? "<missing>"}"`,
      );
    }
    if (
      before.publishedAt !== after.publishedAt ||
      before.kid !== after.kid ||
      before.sha256 !== after.sha256
    ) {
      throw new Error(
        `versions.json append-only violation: version "${before.version}" changed (was publishedAt=${before.publishedAt} kid=${before.kid} sha256=${before.sha256}, now publishedAt=${after.publishedAt} kid=${after.kid} sha256=${after.sha256})`,
      );
    }
  }
}

/**
 * Appends `entry` to `previous`, refusing (via `assertVersionsAppendOnly`)
 * whenever that would drop or change any earlier entry. A duplicate
 * `version` republished with IDENTICAL content is treated as re-emitting
 * the same already-published version and is a no-op (idempotent); a
 * duplicate `version` with DIFFERENT content is refused outright, since
 * that would silently rewrite what that version means.
 */
export function appendVersion(
  previous: readonly VersionEntry[],
  entry: VersionEntry,
): VersionEntry[] {
  const existingIndex = previous.findIndex((v) => v.version === entry.version);
  if (existingIndex !== -1) {
    const existing = previous[existingIndex];
    if (
      !existing ||
      existing.publishedAt !== entry.publishedAt ||
      existing.kid !== entry.kid ||
      existing.sha256 !== entry.sha256
    ) {
      throw new Error(
        `versions.json append-only violation: version "${entry.version}" was already published with different content`,
      );
    }
    return [...previous];
  }
  const next = [...previous, entry];
  assertVersionsAppendOnly(previous, next);
  return next;
}

/** Sorts an array of `{id: string}`-shaped records by `id`, for
 * deterministic shard output regardless of the bundle's own array order. */
export function sortById<T extends { id: string }>(items: readonly T[]): T[] {
  return [...items].sort((a, b) => a.id.localeCompare(b.id));
}
