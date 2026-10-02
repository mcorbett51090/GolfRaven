/**
 * The signed-catalog cache: fetch, verify, apply — fail closed (build plan
 * §3.5 "App lifecycle fields in the signed manifest", §7.6, P4 AT 12).
 *
 * Rules, in the order they are applied to a fetched manifest:
 *   1. Verify the whole envelope (`verify.ts`): signature by a compiled-in,
 *      non-revoked `kid` over the exact fetched bytes; versions.json agrees;
 *      same contract MAJOR; not older than what is cached. ANY failure =>
 *      `rejected`; nothing is stored, nothing is applied, the previously
 *      cached catalog stays in use, and the UI shows the "catalog out of
 *      date" banner.
 *   2. Only now is the manifest's `revokedKids[]` honoured: the install's
 *      persisted revoked set grows by it (monotonically — a `kid` is never
 *      un-revoked), so those keys stop being trusted at once.
 *   3. `minAppVersion` above this build => `update_required`: the force-update
 *      screen; shards are NOT downloaded; the cached catalog is left readable.
 *   4. Every shard is fetched and checked against the manifest's SHA-256 and
 *      byte length BEFORE the new catalog replaces the old one; one bad shard
 *      rejects the whole update.
 *
 * On every load the cached catalog is re-verified with the CURRENT keyset
 * and revoked set, so a tampered database row, a later key revocation or a
 * keyset change drops a cache rather than silently trusting it.
 */
import { compareCatalogVersions } from "@golfraven/catalog-tools/manifest-core";
import { utf8DecodeStrict, utf8Encode } from "./bytes";
import type { CatalogCrypto } from "./crypto";
import type { TrustedKey } from "./keys";
import { isBelowMinAppVersion } from "./semver";
import { buildSnapshot, SnapshotParseError, type CatalogSnapshot } from "./snapshot";
import type { CatalogCacheStore, StoredCatalog } from "./store";
import { verifyCatalogEnvelope, type VerifyIssue } from "./verify";

export interface FetchResult {
  status: number;
  bytes: Uint8Array;
  etag: string | null;
}
export interface FetchOptions {
  etag?: string | null;
  /** Reject (throw) a body larger than this. */
  maxBytes: number;
}
export type FetchBytes = (url: string, options: FetchOptions) => Promise<FetchResult>;

/** `fetch`-backed implementation. A response larger than `maxBytes` is
 * refused after download (RN's `fetch` cannot stream-abort portably). */
export const fetchBytes: FetchBytes = async (url, options) => {
  const headers: Record<string, string> = {};
  if (options.etag) headers["If-None-Match"] = options.etag;
  const res = await fetch(url, { headers });
  if (res.status === 304) return { status: 304, bytes: new Uint8Array(0), etag: res.headers.get("etag") };
  const len = Number(res.headers.get("content-length") ?? "0");
  if (len > options.maxBytes) throw new Error(`${url}: content-length ${len} exceeds ${options.maxBytes}`);
  const buf = new Uint8Array(await res.arrayBuffer());
  if (buf.length > options.maxBytes) throw new Error(`${url}: body ${buf.length} bytes exceeds ${options.maxBytes}`);
  return { status: res.status, bytes: buf, etag: res.headers.get("etag") };
};

const ROOT_DOC_MAX = 5 * 1024 * 1024;
const SIDECAR_MAX = 64 * 1024;
/** Defence in depth beyond the per-shard `bytes` the manifest declares. */
const SHARD_HARD_MAX = 64 * 1024 * 1024;

export type ShardIssueCode = "SHARD_MISMATCH" | "SHARD_MALFORMED" | "SHARD_FETCH";
export interface ShardIssue {
  code: ShardIssueCode;
  message: string;
}
export type RejectionIssue = VerifyIssue | ShardIssue;

export type RefreshOutcome =
  | { kind: "disabled" }
  | { kind: "up_to_date"; catalogVersion: string }
  | { kind: "updated"; from: string | null; to: string }
  | { kind: "update_required"; minAppVersion: string; catalogVersion: string }
  | { kind: "rejected"; issues: RejectionIssue[] }
  | { kind: "network_error"; message: string };

export interface UpdateRequired {
  minAppVersion: string;
  catalogVersion: string;
}

export interface CatalogState {
  /** The last good, re-verified catalog; null when none is cached or the
   * cache failed re-verification. Always safe to read (browse-only until
   * a later phase says otherwise). */
  snapshot: CatalogSnapshot | null;
  /** Why a stored cache was NOT used on load, if one was stored. */
  cacheDropped: VerifyIssue[] | null;
  updateRequired: UpdateRequired | null;
  /** True after a refresh was `rejected`: show "catalog out of date". */
  outOfDateBanner: boolean;
  lastOutcome: RefreshOutcome | null;
}

export interface CatalogManagerOptions {
  /** `https://host/` base; the artifact lives under `catalog/v1/`. `null`
   * disables network refresh (cache only). */
  baseUrl: string | null;
  store: CatalogCacheStore;
  crypto: CatalogCrypto;
  trustedKeys: readonly TrustedKey[];
  appVersion: string;
  supportedContractMajor: number;
  fetchBytes?: FetchBytes;
  now?: () => Date;
  /** Parallel shard downloads. */
  concurrency?: number;
}

const META_REVOKED = "revokedKids";
const META_UPDATE_REQUIRED = "updateRequired";

export class CatalogManager {
  private loaded = false;
  private state: CatalogState = { snapshot: null, cacheDropped: null, updateRequired: null, outOfDateBanner: false, lastOutcome: null };
  private readonly fetchImpl: FetchBytes;
  private readonly now: () => Date;

  constructor(private readonly opts: CatalogManagerOptions) {
    this.fetchImpl = opts.fetchBytes ?? fetchBytes;
    this.now = opts.now ?? (() => new Date());
  }

  getState(): CatalogState {
    return this.state;
  }

  private async revokedSet(): Promise<Set<string>> {
    const raw = await this.opts.store.readMeta(META_REVOKED);
    if (!raw) return new Set();
    try {
      const arr: unknown = JSON.parse(raw);
      return new Set(Array.isArray(arr) ? arr.filter((x): x is string => typeof x === "string") : []);
    } catch {
      return new Set();
    }
  }

  /** Verifies a stored catalog against the current keyset; returns the
   * snapshot or the reasons it cannot be used. */
  private async verifyStored(
    stored: StoredCatalog,
    revoked: ReadonlySet<string>,
  ): Promise<{ ok: true; snapshot: CatalogSnapshot; catalogVersion: string } | { ok: false; issues: VerifyIssue[] }> {
    const { crypto } = this.opts;
    let envelope;
    try {
      envelope = {
        manifest: utf8Encode(stored.manifestText),
        manifestSig: utf8Encode(stored.manifestSigText),
        versions: utf8Encode(stored.versionsText),
        versionsSig: utf8Encode(stored.versionsSigText),
      };
    } catch (err) {
      return { ok: false, issues: [{ code: "MALFORMED", message: err instanceof Error ? err.message : String(err) }] };
    }
    const v = verifyCatalogEnvelope(envelope, {
      crypto,
      trustedKeys: this.opts.trustedKeys,
      revokedKids: revoked,
      supportedContractMajor: this.opts.supportedContractMajor,
    });
    if (!v.ok) return { ok: false, issues: v.issues };
    const { manifest } = v.value;
    const byPath = new Map(stored.shards.map((s) => [s.path, s.text] as const));
    for (const entry of manifest.shards) {
      const text = byPath.get(entry.path);
      if (text === undefined) return { ok: false, issues: [{ code: "MALFORMED", message: `cached shard ${entry.path} is missing` }] };
      const bytes = utf8Encode(text);
      if (bytes.length !== entry.bytes || crypto.sha256Hex(bytes) !== entry.sha256) {
        return { ok: false, issues: [{ code: "MANIFEST_TAMPERED", message: `cached shard ${entry.path} does not match the signed manifest` }] };
      }
    }
    try {
      const snapshot = buildSnapshot({
        catalogVersion: manifest.catalogVersion,
        generatedAt: manifest.generatedAt,
        shards: manifest.shards.map((s) => ({ path: s.path, text: byPath.get(s.path) as string })),
      });
      return { ok: true, snapshot, catalogVersion: manifest.catalogVersion };
    } catch (err) {
      return { ok: false, issues: [{ code: "MALFORMED", message: err instanceof Error ? err.message : String(err) }] };
    }
  }

  private async readUpdateRequired(): Promise<UpdateRequired | null> {
    const raw = await this.opts.store.readMeta(META_UPDATE_REQUIRED);
    if (!raw) return null;
    try {
      const o = JSON.parse(raw) as Partial<UpdateRequired>;
      if (typeof o.minAppVersion === "string" && typeof o.catalogVersion === "string") {
        // A newer build of the app clears a stale requirement.
        return isBelowMinAppVersion(this.opts.appVersion, o.minAppVersion) ? { minAppVersion: o.minAppVersion, catalogVersion: o.catalogVersion } : null;
      }
    } catch {
      /* fall through */
    }
    return null;
  }

  /** Loads and re-verifies whatever is cached. Never touches the network. */
  async loadCached(): Promise<CatalogState> {
    const revoked = await this.revokedSet();
    const stored = await this.opts.store.loadCatalog();
    let snapshot: CatalogSnapshot | null = null;
    let cacheDropped: VerifyIssue[] | null = null;
    if (stored) {
      const r = await this.verifyStored(stored, revoked);
      if (r.ok) snapshot = r.snapshot;
      else cacheDropped = r.issues;
    }
    this.loaded = true;
    this.state = {
      ...this.state,
      snapshot,
      cacheDropped,
      updateRequired: await this.readUpdateRequired(),
    };
    return this.state;
  }

  private rejected(issues: RejectionIssue[]): RefreshOutcome {
    const outcome: RefreshOutcome = { kind: "rejected", issues };
    this.state = { ...this.state, outOfDateBanner: true, lastOutcome: outcome };
    return outcome;
  }

  private finish(outcome: RefreshOutcome, patch: Partial<CatalogState> = {}): RefreshOutcome {
    this.state = { ...this.state, lastOutcome: outcome, ...patch };
    return outcome;
  }

  /** Fetch + verify + apply. Never throws; every failure is an outcome. */
  async refresh(): Promise<RefreshOutcome> {
    const { baseUrl, store, crypto } = this.opts;
    if (baseUrl === null) return this.finish({ kind: "disabled" });
    const root = `${baseUrl.replace(/\/+$/, "")}/catalog/v1/`;

    try {
      if (!this.loaded) await this.loadCached();
      const revoked = await this.revokedSet();
      const stored = await store.loadCatalog();
      const cachedUsable = this.state.snapshot !== null && stored !== null;
      const cachedVersion = cachedUsable ? this.state.snapshot!.catalogVersion : null;

      const mRes = await this.fetchImpl(`${root}manifest.json`, { etag: cachedUsable ? stored!.etag : null, maxBytes: ROOT_DOC_MAX });
      if (mRes.status === 304 && cachedUsable) {
        return this.finish({ kind: "up_to_date", catalogVersion: cachedVersion! }, { outOfDateBanner: false });
      }
      if (mRes.status !== 200) return this.finish({ kind: "network_error", message: `manifest.json: HTTP ${mRes.status}` });

      const [sRes, vRes, vsRes] = await Promise.all([
        this.fetchImpl(`${root}manifest.sig.json`, { maxBytes: SIDECAR_MAX }),
        this.fetchImpl(`${root}versions.json`, { maxBytes: ROOT_DOC_MAX }),
        this.fetchImpl(`${root}versions.sig.json`, { maxBytes: SIDECAR_MAX }),
      ]);
      for (const [name, r] of [["manifest.sig.json", sRes], ["versions.json", vRes], ["versions.sig.json", vsRes]] as const) {
        if (r.status !== 200) return this.finish({ kind: "network_error", message: `${name}: HTTP ${r.status}` });
      }

      // 1. Verify the whole envelope. Fail closed.
      const verified = verifyCatalogEnvelope(
        { manifest: mRes.bytes, manifestSig: sRes.bytes, versions: vRes.bytes, versionsSig: vsRes.bytes },
        {
          crypto,
          trustedKeys: this.opts.trustedKeys,
          revokedKids: revoked,
          supportedContractMajor: this.opts.supportedContractMajor,
          minCatalogVersion: cachedVersion ?? undefined,
        },
      );
      if (!verified.ok) return this.rejected(verified.issues);
      const { manifest } = verified.value;

      // 2. Honour revokedKids[] (monotonic union).
      const nextRevoked = new Set([...revoked, ...manifest.revokedKids]);
      if (nextRevoked.size !== revoked.size) {
        await store.writeMeta(META_REVOKED, JSON.stringify([...nextRevoked].sort()));
      }

      // 3. Force update: keep the cache, download nothing.
      if (isBelowMinAppVersion(this.opts.appVersion, manifest.minAppVersion)) {
        const info: UpdateRequired = { minAppVersion: manifest.minAppVersion, catalogVersion: manifest.catalogVersion };
        await store.writeMeta(META_UPDATE_REQUIRED, JSON.stringify(info));
        // A revocation learned here may invalidate the cache that is on screen.
        const reloaded = await this.loadCached();
        return this.finish({ kind: "update_required", ...info }, { snapshot: reloaded.snapshot, cacheDropped: reloaded.cacheDropped, updateRequired: info, outOfDateBanner: false });
      }
      await store.deleteMeta(META_UPDATE_REQUIRED);

      // Same version already cached: nothing to download.
      if (cachedVersion !== null && compareCatalogVersions(manifest.catalogVersion, cachedVersion) === 0) {
        await store.saveCatalog({ ...stored!, etag: mRes.etag ?? stored!.etag, fetchedAt: this.now().toISOString() });
        const reloaded = await this.loadCached();
        return this.finish({ kind: "up_to_date", catalogVersion: cachedVersion }, { snapshot: reloaded.snapshot, cacheDropped: reloaded.cacheDropped, updateRequired: null, outOfDateBanner: false });
      }

      // 4. Download + check every shard before replacing anything.
      const shardTexts = new Map<string, string>();
      const queue = [...manifest.shards];
      const failure: { v: ShardIssue | null } = { v: null };
      const worker = async (): Promise<void> => {
        for (;;) {
          const entry = queue.shift();
          if (!entry || failure.v) return;
          let res: FetchResult;
          try {
            res = await this.fetchImpl(`${root}${entry.path}`, { maxBytes: Math.min(entry.bytes + 1, SHARD_HARD_MAX) });
          } catch (err) {
            failure.v = { code: "SHARD_FETCH", message: `${entry.path}: ${err instanceof Error ? err.message : String(err)}` };
            return;
          }
          if (res.status !== 200) {
            failure.v = { code: "SHARD_FETCH", message: `${entry.path}: HTTP ${res.status}` };
            return;
          }
          if (res.bytes.length !== entry.bytes || crypto.sha256Hex(res.bytes) !== entry.sha256) {
            failure.v = { code: "SHARD_MISMATCH", message: `${entry.path}: bytes/sha256 do not match the signed manifest` };
            return;
          }
          try {
            shardTexts.set(entry.path, utf8DecodeStrict(res.bytes));
          } catch (err) {
            failure.v = { code: "SHARD_MALFORMED", message: `${entry.path}: ${err instanceof Error ? err.message : String(err)}` };
            return;
          }
        }
      };
      await Promise.all(Array.from({ length: Math.max(1, this.opts.concurrency ?? 4) }, worker));
      if (failure.v) {
        const f = failure.v;
        return f.code === "SHARD_FETCH" ? this.finish({ kind: "network_error", message: f.message }) : this.rejected([f]);
      }

      const next: StoredCatalog = {
        manifestText: utf8DecodeStrict(mRes.bytes),
        manifestSigText: utf8DecodeStrict(sRes.bytes),
        versionsText: utf8DecodeStrict(vRes.bytes),
        versionsSigText: utf8DecodeStrict(vsRes.bytes),
        shards: manifest.shards.map((s) => ({ path: s.path, text: shardTexts.get(s.path) as string })),
        etag: mRes.etag,
        fetchedAt: this.now().toISOString(),
      };

      // The new catalog must parse BEFORE it replaces the old one.
      let snapshot: CatalogSnapshot;
      try {
        snapshot = buildSnapshot({ catalogVersion: manifest.catalogVersion, generatedAt: manifest.generatedAt, shards: next.shards });
      } catch (err) {
        if (err instanceof SnapshotParseError) return this.rejected([{ code: "SHARD_MALFORMED", message: err.message }]);
        throw err;
      }

      await store.saveCatalog(next);
      return this.finish({ kind: "updated", from: cachedVersion, to: manifest.catalogVersion }, { snapshot, cacheDropped: null, updateRequired: null, outOfDateBanner: false });
    } catch (err) {
      return this.finish({ kind: "network_error", message: err instanceof Error ? err.message : String(err) });
    }
  }
}
