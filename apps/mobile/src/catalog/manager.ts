/**
 * The signed-catalog cache: fetch, verify, apply — fail closed (build plan
 * §3.5 "App lifecycle fields in the signed manifest", §7.6, P4 AT 12).
 *
 * Rules, in the order they are applied to a fetched manifest:
 *   0. The install's trust state is read first: the persisted revoked set and
 *      the persisted anti-rollback floor (`maxVerifiedCatalogVersion`). A row
 *      that is present but unreadable means REFUSE EVERYTHING
 *      (`TRUST_STATE_CORRUPT`) — an unreadable revoked set must never read as
 *      "nothing is revoked".
 *   1. Verify the whole envelope (`verify.ts`): signature by a compiled-in,
 *      non-revoked `kid` over the exact fetched bytes; versions.json agrees;
 *      same contract MAJOR; not older than the FLOOR. ANY failure =>
 *      `rejected`; nothing is stored, nothing is applied, the previously
 *      cached catalog stays in use, and the UI shows the "catalog out of
 *      date" banner.
 *   2. The floor is raised to this manifest's `catalogVersion` (on every
 *      verified manifest — including an `update_required` one and an
 *      equal-version one). It is persisted in its OWN meta row, not in the
 *      cache, so it survives the cache being dropped (revocation, keyset
 *      change, corruption) and a fresh-database start only loses it if the
 *      whole database is wiped (a reinstall). A compiled-in
 *      `MIN_CATALOG_VERSION` (`keys.ts`), when set, is an additional floor.
 *   3. Only now is the manifest's `revokedKids[]` honoured: the install's
 *      persisted revoked set grows by it (monotonically — a `kid` is never
 *      un-revoked; the union is one atomic store update, so two writers
 *      cannot lose each other's revocation), so those keys stop being
 *      trusted at once. The cache is re-verified straight away.
 *   4. `minAppVersion` above this build => `update_required`: the force-update
 *      screen; shards are NOT downloaded; the cached catalog is left readable.
 *      A stored requirement is cleared only by a verified manifest at least
 *      as new as the one that set it.
 *   5. Every shard is fetched and checked against the manifest's SHA-256 and
 *      byte length BEFORE the new catalog replaces the old one; one bad shard
 *      rejects the whole update. The floor is checked AGAIN inside the save
 *      transaction, so a slow refresh that verified an older manifest can
 *      never overwrite a newer catalog.
 *
 * `refresh()` is single-flight (concurrent callers share one promise) and
 * `loadCached()` / `refresh()` never interleave.
 *
 * On every load the cached catalog is re-verified with the CURRENT keyset
 * and revoked set, so a tampered database row, a later key revocation or a
 * keyset change drops a cache rather than silently trusting it. (The floor
 * is deliberately NOT applied to the cache at rest: after a force-update
 * manifest the older cache must stay readable. It governs what may be
 * fetched and saved, not what was already verified.)
 *
 * Honest limits: the floor lives in the app's SQLite file, so it is erased by
 * an uninstall / "clear data", and the in-memory fallback store (used only if
 * SQLite cannot be opened) has no persistence at all; the compiled-in
 * `MIN_CATALOG_VERSION` is what bounds those cases once it is set.
 */
import { compareCatalogVersions } from "@golfraven/catalog-tools/manifest-core";
import { utf8DecodeStrict, utf8Encode } from "./bytes";
import type { CatalogCrypto } from "./crypto";
import { MIN_CATALOG_VERSION, type TrustedKey } from "./keys";
import { isBelowMinAppVersion } from "./semver";
import { buildSnapshot, SnapshotParseError, type CatalogSnapshot } from "./snapshot";
import { META_MAX_VERIFIED_VERSION, maxCatalogVersion, readFloor, type CatalogCacheStore, type StoredCatalog } from "./store";
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
  /** Abort the whole request (headers + body) after this long. */
  timeoutMs?: number;
}
export type FetchBytes = (url: string, options: FetchOptions) => Promise<FetchResult>;

/** Default whole-request deadline. */
export const DEFAULT_FETCH_TIMEOUT_MS = 30_000;
/** A shard may be tens of MB on a mobile link. */
export const SHARD_FETCH_TIMEOUT_MS = 120_000;

function originOf(url: string): string | null {
  const m = /^(https?:\/\/[^/?#]+)/i.exec(url);
  return m ? m[1]!.toLowerCase() : null;
}

/**
 * `fetch`-backed implementation, hardened:
 *  - a whole-request timeout (`AbortController`), covering the body read;
 *  - redirects are refused (`redirect: "error"`), and a response that
 *    reports it was redirected, or whose final URL is another origin, is
 *    refused too (RN's XHR-backed `fetch` may ignore the `redirect` option);
 *  - the body is read as a STREAM and cancelled the moment it exceeds
 *    `maxBytes`, where the runtime exposes `response.body` (Node, `expo/fetch`).
 *    Where it does not (RN's default `fetch`), `content-length` is checked up
 *    front and the buffered length afterwards — the timeout still bounds it
 *    `[unverified — device: whether RN 0.86's fetch exposes a body stream]`.
 * Integrity never depends on any of this: every byte is still SHA-256 /
 * signature checked by the caller.
 */
export function createFetchBytes(fetchImpl: typeof fetch): FetchBytes {
  return async (url, options) => {
    const controller = new AbortController();
    const timeoutMs = options.timeoutMs ?? DEFAULT_FETCH_TIMEOUT_MS;
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const headers: Record<string, string> = {};
      if (options.etag) headers["If-None-Match"] = options.etag;
      let res: Response;
      try {
        res = await fetchImpl(url, { headers, redirect: "error", signal: controller.signal });
      } catch (err) {
        if (controller.signal.aborted) throw new Error(`${url}: timed out after ${timeoutMs} ms`);
        throw err;
      }
      if (res.redirected) throw new Error(`${url}: redirected (refused)`);
      if (res.url && originOf(res.url) !== originOf(url)) throw new Error(`${url}: final URL ${res.url} is another origin (refused)`);
      if (res.status === 304) return { status: 304, bytes: new Uint8Array(0), etag: res.headers.get("etag") };
      const len = Number(res.headers.get("content-length") ?? "0");
      if (len > options.maxBytes) {
        void res.body?.cancel().catch(() => undefined); // release the connection; never read it
        throw new Error(`${url}: content-length ${len} exceeds ${options.maxBytes}`);
      }
      const etag = res.headers.get("etag");
      try {
        const reader = res.body?.getReader();
        if (!reader) {
          const buf = new Uint8Array(await res.arrayBuffer());
          if (buf.length > options.maxBytes) throw new Error(`${url}: body ${buf.length} bytes exceeds ${options.maxBytes}`);
          return { status: res.status, bytes: buf, etag };
        }
        const chunks: Uint8Array[] = [];
        let total = 0;
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          total += value.length;
          if (total > options.maxBytes) {
            await reader.cancel().catch(() => undefined);
            throw new Error(`${url}: body exceeds ${options.maxBytes} bytes (stream cancelled)`);
          }
          chunks.push(value);
        }
        const bytes = new Uint8Array(total);
        let off = 0;
        for (const c of chunks) {
          bytes.set(c, off);
          off += c.length;
        }
        return { status: res.status, bytes, etag };
      } catch (err) {
        if (controller.signal.aborted) throw new Error(`${url}: timed out after ${timeoutMs} ms`);
        throw err;
      }
    } finally {
      clearTimeout(timer);
    }
  };
}

export const fetchBytes: FetchBytes = createFetchBytes((input, init) => fetch(input, init));

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
  /** A compiled-in floor (default `MIN_CATALOG_VERSION`, empty = none). */
  compiledMinCatalogVersion?: string;
}

const META_REVOKED = "revokedKids";
const META_UPDATE_REQUIRED = "updateRequired";

type Trust = { ok: true; revoked: Set<string>; floor: string | null } | { ok: false; issue: VerifyIssue };

function trustCorrupt(what: string): { ok: false; issue: VerifyIssue } {
  return { ok: false, issue: { code: "TRUST_STATE_CORRUPT", message: `${what} is unreadable; refusing every catalog until the app data is reset` } };
}

/** Parses the persisted revoked set. `null` = unreadable (NOT empty). */
function parseRevoked(raw: string | null): Set<string> | null {
  if (raw === null) return new Set();
  try {
    const arr: unknown = JSON.parse(raw);
    if (!Array.isArray(arr) || !arr.every((x): x is string => typeof x === "string")) return null;
    return new Set(arr);
  } catch {
    return null;
  }
}

export class CatalogManager {
  private loaded = false;
  private state: CatalogState = { snapshot: null, cacheDropped: null, updateRequired: null, outOfDateBanner: false, lastOutcome: null };
  private readonly fetchImpl: FetchBytes;
  private readonly now: () => Date;
  private inflight: Promise<RefreshOutcome> | null = null;
  private chain: Promise<unknown> = Promise.resolve();

  constructor(private readonly opts: CatalogManagerOptions) {
    this.fetchImpl = opts.fetchBytes ?? fetchBytes;
    this.now = opts.now ?? (() => new Date());
  }

  getState(): CatalogState {
    return this.state;
  }

  /** Runs `fn` after everything queued before it; never concurrently. */
  private exclusive<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.chain.then(fn, fn);
    this.chain = run.catch(() => undefined);
    return run;
  }

  /** The install's trust state: the revoked set and the effective floor
   * (persisted high-water mark, or the compiled-in minimum if higher). */
  private async readTrust(): Promise<Trust> {
    const { store } = this.opts;
    const revoked = parseRevoked(await store.readMeta(META_REVOKED));
    if (revoked === null) return trustCorrupt("the persisted revoked-key set");
    const persisted = readFloor(await store.readMeta(META_MAX_VERIFIED_VERSION));
    if (persisted.kind === "corrupt") return trustCorrupt("the persisted catalog version floor");
    let floor = persisted.kind === "ok" ? persisted.version : null;
    const compiled = this.opts.compiledMinCatalogVersion ?? MIN_CATALOG_VERSION;
    if (compiled !== "") {
      if (readFloor(compiled).kind !== "ok") return trustCorrupt("the compiled-in minimum catalog version");
      floor = floor === null ? compiled : maxCatalogVersion(floor, compiled);
    }
    return { ok: true, revoked, floor };
  }

  /** Raises the persisted floor to `version` (atomic; never lowers it). */
  private async raiseFloor(version: string): Promise<void> {
    await this.opts.store.updateMeta(META_MAX_VERIFIED_VERSION, (cur) => {
      const f = readFloor(cur);
      if (f.kind === "corrupt") return undefined; // never silently heal an unreadable floor
      if (f.kind === "ok" && compareCatalogVersions(f.version, version) >= 0) return undefined;
      return version;
    });
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

  /** The stored requirement as written (not filtered by this build's version). */
  private async readStoredRequirement(): Promise<UpdateRequired | null> {
    const raw = await this.opts.store.readMeta(META_UPDATE_REQUIRED);
    if (!raw) return null;
    try {
      const o = JSON.parse(raw) as Partial<UpdateRequired>;
      if (typeof o.minAppVersion === "string" && typeof o.catalogVersion === "string") {
        return { minAppVersion: o.minAppVersion, catalogVersion: o.catalogVersion };
      }
    } catch {
      /* fall through */
    }
    return null;
  }

  /** The requirement that applies to THIS build: a newer build of the app
   * clears a stale one. */
  private async readUpdateRequired(): Promise<UpdateRequired | null> {
    const r = await this.readStoredRequirement();
    return r && isBelowMinAppVersion(this.opts.appVersion, r.minAppVersion) ? r : null;
  }

  /** Loads and re-verifies whatever is cached. Never touches the network. */
  loadCached(): Promise<CatalogState> {
    return this.exclusive(() => this.loadCachedNow());
  }

  private async loadCachedNow(): Promise<CatalogState> {
    const revoked = parseRevoked(await this.opts.store.readMeta(META_REVOKED));
    const stored = await this.opts.store.loadCatalog();
    let snapshot: CatalogSnapshot | null = null;
    let cacheDropped: VerifyIssue[] | null = null;
    if (revoked === null) {
      // Cannot tell which keys are revoked, so no cache can be trusted.
      if (stored) cacheDropped = [trustCorrupt("the persisted revoked-key set").issue];
    } else if (stored) {
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

  /** Fetch + verify + apply. Never throws; every failure is an outcome.
   * Single-flight: a caller that arrives while a refresh is running gets
   * that refresh's promise (and outcome), not a second concurrent run. */
  refresh(): Promise<RefreshOutcome> {
    if (this.inflight) return this.inflight;
    const run = this.exclusive(() => this.refreshNow()).finally(() => {
      this.inflight = null;
    });
    this.inflight = run;
    return run;
  }

  private async refreshNow(): Promise<RefreshOutcome> {
    const { baseUrl, store, crypto } = this.opts;
    if (baseUrl === null) return this.finish({ kind: "disabled" });
    const root = `${baseUrl.replace(/\/+$/, "")}/catalog/v1/`;

    try {
      if (!this.loaded) await this.loadCachedNow();
      // 0. Trust state. Unreadable => refuse everything.
      const trust = await this.readTrust();
      if (!trust.ok) return this.rejected([trust.issue]);
      let revoked = trust.revoked;
      const floor = trust.floor;
      let stored = await store.loadCatalog();
      let cachedUsable = this.state.snapshot !== null && stored !== null;
      let cachedVersion = cachedUsable ? this.state.snapshot!.catalogVersion : null;

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

      // 1. Verify the whole envelope against the FLOOR, never the cache.
      const verified = verifyCatalogEnvelope(
        { manifest: mRes.bytes, manifestSig: sRes.bytes, versions: vRes.bytes, versionsSig: vsRes.bytes },
        {
          crypto,
          trustedKeys: this.opts.trustedKeys,
          revokedKids: revoked,
          supportedContractMajor: this.opts.supportedContractMajor,
          minCatalogVersion: floor ?? undefined,
        },
      );
      if (!verified.ok) return this.rejected(verified.issues);
      const { manifest } = verified.value;

      // 2. Raise the persisted floor on EVERY verified manifest, before
      //    anything else can drop the cache or end the refresh early.
      await this.raiseFloor(manifest.catalogVersion);

      // 3. Honour revokedKids[] (monotonic union, one atomic update).
      let grew = false;
      if (manifest.revokedKids.length > 0) {
        await store.updateMeta(META_REVOKED, (cur) => {
          const set = parseRevoked(cur);
          if (set === null) return undefined; // unreadable: never overwrite
          const before = set.size;
          for (const k of manifest.revokedKids) set.add(k);
          return set.size === before ? undefined : JSON.stringify([...set].sort());
        });
        const after = parseRevoked(await store.readMeta(META_REVOKED));
        if (after !== null && after.size !== revoked.size) {
          grew = true;
          revoked = after;
        }
      }
      if (grew) {
        // A revocation learned here may invalidate the cache that is on screen
        // (including one signed by the very kid just revoked): re-verify it
        // and decide everything below from what survives.
        await this.loadCachedNow();
        stored = await store.loadCatalog();
        cachedUsable = this.state.snapshot !== null && stored !== null;
        cachedVersion = cachedUsable ? this.state.snapshot!.catalogVersion : null;
      }

      // 4. Force update: keep the cache, download nothing.
      if (isBelowMinAppVersion(this.opts.appVersion, manifest.minAppVersion)) {
        const info: UpdateRequired = { minAppVersion: manifest.minAppVersion, catalogVersion: manifest.catalogVersion };
        const existing = await this.readStoredRequirement();
        // Never replace a requirement set by a NEWER manifest with an older one.
        if (!existing || compareCatalogVersions(manifest.catalogVersion, existing.catalogVersion) >= 0) {
          await store.writeMeta(META_UPDATE_REQUIRED, JSON.stringify(info));
        }
        const reloaded = await this.loadCachedNow();
        return this.finish({ kind: "update_required", ...info }, { snapshot: reloaded.snapshot, cacheDropped: reloaded.cacheDropped, updateRequired: reloaded.updateRequired ?? info, outOfDateBanner: false });
      }
      // This build satisfies the manifest. A stored requirement is cleared only
      // by a manifest at least as new as the one that set it: replaying an
      // older (or the cached) manifest must not clear a newer requirement.
      const requirement = await this.readStoredRequirement();
      if (!requirement || compareCatalogVersions(manifest.catalogVersion, requirement.catalogVersion) >= 0) {
        await store.deleteMeta(META_UPDATE_REQUIRED);
      }
      const updateRequired = await this.readUpdateRequired();

      // Same version already cached (and still trusted): nothing to download.
      if (cachedVersion !== null && compareCatalogVersions(manifest.catalogVersion, cachedVersion) === 0) {
        const saved = await store.saveCatalog({ ...stored!, etag: mRes.etag ?? stored!.etag, fetchedAt: this.now().toISOString() }, { catalogVersion: cachedVersion });
        if (!saved) return this.rejected([{ code: "CATALOG_VERSION_ROLLBACK", message: `the persisted floor is above the cached "${cachedVersion}"` }]);
        return this.finish({ kind: "up_to_date", catalogVersion: cachedVersion }, { updateRequired, outOfDateBanner: false });
      }

      // 5. Download + check every shard before replacing anything.
      const shardTexts = new Map<string, string>();
      const queue = [...manifest.shards];
      const failure: { v: ShardIssue | null } = { v: null };
      const worker = async (): Promise<void> => {
        for (;;) {
          const entry = queue.shift();
          if (!entry || failure.v) return;
          let res: FetchResult;
          try {
            res = await this.fetchImpl(`${root}${entry.path}`, { maxBytes: Math.min(entry.bytes + 1, SHARD_HARD_MAX), timeoutMs: SHARD_FETCH_TIMEOUT_MS });
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

      // The floor is re-checked INSIDE the save transaction: something newer
      // may have been saved while the shards were downloading.
      const saved = await store.saveCatalog(next, { catalogVersion: manifest.catalogVersion });
      if (!saved) {
        const reloaded = await this.loadCachedNow();
        return this.finish(
          { kind: "rejected", issues: [{ code: "CATALOG_VERSION_ROLLBACK", message: `"${manifest.catalogVersion}" is older than a catalog verified while it downloaded; not saved` }] },
          { snapshot: reloaded.snapshot, cacheDropped: reloaded.cacheDropped, outOfDateBanner: false },
        );
      }
      return this.finish({ kind: "updated", from: cachedVersion, to: manifest.catalogVersion }, { snapshot, cacheDropped: null, updateRequired, outOfDateBanner: false });
    } catch (err) {
      return this.finish({ kind: "network_error", message: err instanceof Error ? err.message : String(err) });
    }
  }
}
