// supabase/functions/_shared/catalog/import-handler.ts
//
// The pure, dependency-injected core of the `import-catalog` Edge
// Function (build plan §3.3: "pulls the manifest from the public URL,
// verifies the Ed25519 signature against its compiled kid keyset, and
// imports it, including the full ID ledger into app.catalog_id_ledger").
// Every I/O dependency (network fetch, DB reads/writes via `ImporterRepo`)
// is injected, so this is unit-testable with fakes
// (supabase/tests/unit/import-handler.test.ts), same discipline as
// evidence/handler.ts.
//
// ⛔ REWRITE (P3e round 2 gate, M4: "fetch and verify ALL artifacts
// before opening the transaction"). Round 1's `runCatalogImport` did its
// OWN fetching from INSIDE the caller's `withSystemCatalogImport`
// transaction — every slow network round trip held the write
// transaction's locks/timeouts open the whole time. Split into two
// phases, called separately by `import-catalog/index.ts`:
//   1. `fetchAndVerifyArtifact` — ALL network I/O and ALL cryptographic
//      verification, no `ImporterRepo`, no transaction. Its one DB-ish
//      dependency (looking up a registered signing key) is injected as a
//      plain function, so this phase never touches a write transaction
//      either — `import-catalog/index.ts` supplies one backed by a
//      short, separate, already-committed read (see that file's own
//      `getSigningKeyReadOnly`).
//   2. `applyImportPlan` — pure DB writes from an already-verified plan,
//      no network, called INSIDE `withSystemCatalogImport`. Fast by
//      construction (H3: set-based upserts, not per-row writes for the
//      directory tables — see `ImporterRepo#catalog.upsertFacilities`
//      etc., privileged.ts).
//
// SCOPE (restated from 0023_catalog_import.sql's own header, updated for
// H2): "pull + verify + ledger import" plus, as of P3e round 2 (H2: "no
// re-scope — implement it"), the REAL directory shards
// (`facilities/<region>.json`, `trails.json`, `designers.json` —
// `_shared/catalog/directory-artifact.ts`'s own header). Geometry and
// roster-membership import remain genuinely out of scope — see that
// module's header for exactly why (the artifact carries no geometry
// payload at all; roster import is a larger, distinct feature).
// AT 18's own "stub→verified promotion re-scores the affected plays" is
// ALSO not attempted this round — a known, named gap (see the P3e
// handback report) — this importer applies the ledger's own stub/verified
// transitions faithfully, but does not walk existing `app.play` rows to
// re-score them on a promotion.

import {
  canonicalStringify,
  MANIFEST_DOMAIN,
  VERSIONS_DOMAIN,
  parseCatalogManifest,
  parseManifestSignature,
  parseVersionsArray,
  parseVersionsSignature,
  parseStrictJson,
  compareCatalogVersions,
  type CatalogManifest,
  type ManifestSignature,
  type VersionEntry,
  type VersionsSignature,
} from "./manifest-artifact.ts";
import { parseIdLedger, firstMintedVersion, latestVerifiedVersion, type LedgerEntry } from "./ledger-artifact.ts";
import { parseFacilitiesShard, parseTrailsShard, parseDesignersShard, type ParsedFacility, type ParsedRosterMember, type ParsedTrail, type ParsedDesigner } from "./directory-artifact.ts";
import { verifyArtifactSignature } from "./signature.ts";
import { checkArtifactBaseUrl } from "./import-config.ts";
import type { ImporterRepo, ImporterSigningKeyRow, LedgerBaseRow, LedgerStateRow, RosterVersionInput } from "../types.ts";

export interface CatalogImportConfig {
  /** e.g. "https://golfraven.example/catalog/v1" — no trailing slash. */
  artifactBaseUrl: string;
  allowedHosts: readonly string[];
  /** Bounded network fetch caps (task instruction: "network fetch of the
   * catalog bounded, with explicit size caps") — generous enough for a
   * real manifest/version-history/ledger shard, far below "unbounded". */
  maxManifestBytes?: number;
  maxSignatureBytes?: number;
  maxVersionsBytes?: number;
  maxShardBytes?: number;
  /** How far into the future a `generatedAt`/`publishedAt` may be before
   * it is rejected as far-future/forged (task instruction: "reject
   * far-future versions") — clock skew tolerance, not a real allowance
   * for a future-dated release. */
  maxClockSkewMs?: number;
}

const DEFAULT_MAX_MANIFEST_BYTES = 256 * 1024;
const DEFAULT_MAX_SIGNATURE_BYTES = 4 * 1024;
const DEFAULT_MAX_VERSIONS_BYTES = 2 * 1024 * 1024;
const DEFAULT_MAX_SHARD_BYTES = 16 * 1024 * 1024;
const DEFAULT_MAX_CLOCK_SKEW_MS = 24 * 60 * 60 * 1000;
// M4: every network fetch gets its own hard deadline — a slow/stalled
// artifact host must never hang this function indefinitely.
const FETCH_TIMEOUT_MS = 15_000;

/** Injected: fetches `url`, refusing to buffer past `maxBytes` (the same
 * "bound a network read before trusting Content-Length" discipline
 * http.ts's own `readJsonBody` already uses for a request body). The
 * REAL implementation (import-catalog/index.ts) streams a `Response`
 * body with `AbortSignal.timeout` and `redirect: "error"` (M4); a unit
 * test supplies a fake that returns fixture bytes directly. Must reject
 * (throw) rather than silently truncate on an oversized response. */
export type FetchBytes = (url: string, maxBytes: number) => Promise<Uint8Array>;

/** Injected: looks up a registered signing key WITHOUT opening (or
 * requiring) any write transaction — `import-catalog/index.ts` backs
 * this with a short, separate read (see that file's own
 * `getSigningKeyReadOnly`), so `fetchAndVerifyArtifact` (this module) can
 * run entirely before `withSystemCatalogImport` ever opens (M4). */
export type GetSigningKey = (kid: string) => Promise<ImporterSigningKeyRow | null>;

/** Injected: verifies an Ed25519 signature — real default IS
 * `verifyArtifactSignature` (catalog/signature.ts, standard base64 — the
 * REAL P1 artifact signature format, P3e round 2 gate B1), injected
 * rather than called directly so a unit test can fake "always true"/
 * "always false" without generating a real keypair for every fixture. */
export type VerifySignatureFn = (input: { publicKeyB64Url: string; signatureB64Url: string; payload: string }) => Promise<boolean>;

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes.slice().buffer);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function parseJsonBytes(bytes: Uint8Array, label: string): { ok: true; value: unknown } | { ok: false; issue: string } {
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return { ok: false, issue: `${label}: not valid UTF-8` };
  }
  try {
    // P3e round 2 gate, LOW: P1's own strict parser (duplicate-key /
    // __proto__ / -0 rejection), not bare JSON.parse — see
    // manifest-artifact.ts's own parseStrictJson doc.
    return { ok: true, value: parseStrictJson(text) };
  } catch (err) {
    return { ok: false, issue: `${label}: ${err instanceof Error ? err.message : String(err)}` };
  }
}

export interface VerifiedArtifactPlan {
  ok: true;
  manifest: CatalogManifest;
  versions: VersionEntry[];
  ledgerBytes: Uint8Array | null; // present iff manifest.shards names "id-ledger.json"
  facilityShards: { path: string; bytes: Uint8Array }[]; // every "facilities/*.json" shard
  trailsBytes: Uint8Array | null;
  designersBytes: Uint8Array | null;
}
export interface RejectedArtifact {
  ok: false;
  reason: string;
}

/** Phase 1 (M4): fetches and verifies EVERY artifact this importer reads
 * — manifest, versions, and every shard it will apply — before returning.
 * No `ImporterRepo`, no transaction. Ordering matters: the manifest's own
 * signature must verify BEFORE any shard is even fetched (mirrors
 * `tools/catalog/src/sign.ts#verifyArtifact`'s own documented order:
 * "Read shards only after the signature verifies"). */
export async function fetchAndVerifyArtifact(
  config: CatalogImportConfig,
  fetchBytes: FetchBytes,
  getSigningKey: GetSigningKey,
  verifySignature: VerifySignatureFn = verifyArtifactSignature,
  now: Date = new Date(),
): Promise<VerifiedArtifactPlan | RejectedArtifact> {
  const urlCheck = checkArtifactBaseUrl(config.artifactBaseUrl, config.allowedHosts);
  if (!urlCheck.ok) return { ok: false, reason: `artifact_base_url_${urlCheck.reason}` };

  const maxManifestBytes = config.maxManifestBytes ?? DEFAULT_MAX_MANIFEST_BYTES;
  const maxSignatureBytes = config.maxSignatureBytes ?? DEFAULT_MAX_SIGNATURE_BYTES;
  const maxVersionsBytes = config.maxVersionsBytes ?? DEFAULT_MAX_VERSIONS_BYTES;
  const maxShardBytes = config.maxShardBytes ?? DEFAULT_MAX_SHARD_BYTES;
  const maxClockSkewMs = config.maxClockSkewMs ?? DEFAULT_MAX_CLOCK_SKEW_MS;
  const base = config.artifactBaseUrl.replace(/\/+$/, "");

  // ---- 1. manifest.json + manifest.sig.json ----
  const manifestBytes = await fetchBytes(`${base}/manifest.json`, maxManifestBytes);
  const manifestParsed = parseJsonBytes(manifestBytes, "manifest.json");
  if (!manifestParsed.ok) return { ok: false, reason: manifestParsed.issue };
  const manifestResult = parseCatalogManifest(manifestParsed.value);
  if (!manifestResult.ok) return { ok: false, reason: manifestResult.issue };
  const manifest: CatalogManifest = manifestResult.value;

  const manifestSigBytes = await fetchBytes(`${base}/manifest.sig.json`, maxSignatureBytes);
  const manifestSigParsed = parseJsonBytes(manifestSigBytes, "manifest.sig.json");
  if (!manifestSigParsed.ok) return { ok: false, reason: manifestSigParsed.issue };
  const manifestSigResult = parseManifestSignature(manifestSigParsed.value);
  if (!manifestSigResult.ok) return { ok: false, reason: manifestSigResult.issue };
  const manifestSig: ManifestSignature = manifestSigResult.value;

  const computedManifestSha = await sha256Hex(manifestBytes);
  if (computedManifestSha !== manifestSig.manifestSha) return { ok: false, reason: "catalog_forged" };
  if (manifestSig.catalogVersion !== manifest.catalogVersion) return { ok: false, reason: "catalog_forged" };
  if (manifestSig.contractVersion !== manifest.contractVersion) return { ok: false, reason: "catalog_forged" };
  if (manifestSig.kid !== manifest.kid) return { ok: false, reason: "catalog_forged" };
  if (manifest.revokedKids.includes(manifest.kid)) return { ok: false, reason: "catalog_forged" };
  if (Date.parse(manifest.generatedAt) - now.getTime() > maxClockSkewMs) return { ok: false, reason: "catalog_forged" };

  const manifestKey = await getSigningKey(manifestSig.kid);
  // ⛔ FIX (P3e round 2 gate, LOW nit): "report an unregistered kid as
  // catalog_forged" — distinct from a REGISTERED-but-revoked kid
  // (catalog_stale, matching AT 15's own convention): a kid this
  // verifier has never heard of is not "a release we used to trust,"
  // it's a signature we have no basis to trust AT ALL.
  if (!manifestKey) return { ok: false, reason: "catalog_forged" };
  if (manifestKey.revokedAt) return { ok: false, reason: "catalog_stale" };
  const manifestStatementBytes = new TextEncoder().encode(
    MANIFEST_DOMAIN + canonicalStringify({ catalogVersion: manifestSig.catalogVersion, contractVersion: manifestSig.contractVersion, kid: manifestSig.kid, manifestSha: manifestSig.manifestSha }),
  );
  const manifestSigOk = await verifySignature({ publicKeyB64Url: manifestKey.publicKeyB64Url, signatureB64Url: manifestSig.sig, payload: new TextDecoder().decode(manifestStatementBytes) });
  if (!manifestSigOk) return { ok: false, reason: "catalog_forged" };

  // ---- 2. versions.json + versions.sig.json ----
  const versionsBytes = await fetchBytes(`${base}/versions.json`, maxVersionsBytes);
  const versionsParsed = parseJsonBytes(versionsBytes, "versions.json");
  if (!versionsParsed.ok) return { ok: false, reason: versionsParsed.issue };
  const versionsResult = parseVersionsArray(versionsParsed.value);
  if (!versionsResult.ok) return { ok: false, reason: versionsResult.issue };
  const versions: VersionEntry[] = versionsResult.value;
  if (versions.length === 0) return { ok: false, reason: "versions.json: empty" };

  const versionsSigBytes = await fetchBytes(`${base}/versions.sig.json`, maxSignatureBytes);
  const versionsSigParsed = parseJsonBytes(versionsSigBytes, "versions.sig.json");
  if (!versionsSigParsed.ok) return { ok: false, reason: versionsSigParsed.issue };
  const versionsSigResult = parseVersionsSignature(versionsSigParsed.value);
  if (!versionsSigResult.ok) return { ok: false, reason: versionsSigResult.issue };
  const versionsSig: VersionsSignature = versionsSigResult.value;

  const computedVersionsSha = await sha256Hex(versionsBytes);
  if (computedVersionsSha !== versionsSig.versionsSha) return { ok: false, reason: "catalog_forged" };

  // M3: a manifest listing the kid that signed versions.json as revoked is
  // self-inconsistent — hard reject (mirrors the manifest.kid check above
  // and tools/catalog/src/sign.ts#verifyArtifact).
  if (manifest.revokedKids.includes(versionsSig.kid)) return { ok: false, reason: "catalog_forged" };
  const versionsKey = await getSigningKey(versionsSig.kid);
  if (!versionsKey) return { ok: false, reason: "catalog_forged" };
  if (versionsKey.revokedAt) return { ok: false, reason: "catalog_stale" };
  const versionsStatementBytes = new TextEncoder().encode(VERSIONS_DOMAIN + canonicalStringify({ kid: versionsSig.kid, versionsSha: versionsSig.versionsSha }));
  const versionsSigOk = await verifySignature({ publicKeyB64Url: versionsKey.publicKeyB64Url, signatureB64Url: versionsSig.sig, payload: new TextDecoder().decode(versionsStatementBytes) });
  if (!versionsSigOk) return { ok: false, reason: "catalog_forged" };

  const lastEntry = versions[versions.length - 1]!;
  if (lastEntry.version !== manifest.catalogVersion || lastEntry.kid !== manifest.kid) {
    return { ok: false, reason: "catalog_forged" };
  }
  for (let i = 1; i < versions.length; i++) {
    if (compareCatalogVersions(versions[i]!.version, versions[i - 1]!.version) <= 0) {
      return { ok: false, reason: "catalog_forged" };
    }
  }
  for (const v of versions) {
    if (Date.parse(v.publishedAt) - now.getTime() > maxClockSkewMs) return { ok: false, reason: "catalog_forged" };
  }

  // ---- 3. Shards — only AFTER the manifest's own signature verifies
  // (mirrors tools/catalog/src/sign.ts#verifyArtifact's own documented
  // order). Every shard's bytes are hash/size-checked against the
  // SIGNED manifest.shards[] entry — covered transitively by the
  // manifest's own signature, no per-shard signature needed. ----
  async function fetchShard(path: string): Promise<Uint8Array | { ok: false; reason: string }> {
    const entry = manifest.shards.find((s) => s.path === path);
    if (!entry) return { ok: false, reason: `manifest.json: no shard entry for "${path}"` };
    const bytes = await fetchBytes(`${base}/${path}`, Math.min(entry.bytes + 4096, maxShardBytes));
    if (bytes.length !== entry.bytes) return { ok: false, reason: "catalog_forged" };
    const actualSha = await sha256Hex(bytes);
    if (actualSha !== entry.sha256) return { ok: false, reason: "catalog_forged" };
    return bytes;
  }

  let ledgerBytes: Uint8Array | null = null;
  if (manifest.shards.some((s) => s.path === "id-ledger.json")) {
    const r = await fetchShard("id-ledger.json");
    if (!(r instanceof Uint8Array)) return r;
    ledgerBytes = r;
  }

  const facilityShardPaths = manifest.shards.map((s) => s.path).filter((p) => p.startsWith("facilities/"));
  const facilityShards: { path: string; bytes: Uint8Array }[] = [];
  for (const path of facilityShardPaths) {
    const r = await fetchShard(path);
    if (!(r instanceof Uint8Array)) return r;
    facilityShards.push({ path, bytes: r });
  }

  let trailsBytes: Uint8Array | null = null;
  if (manifest.shards.some((s) => s.path === "trails.json")) {
    const r = await fetchShard("trails.json");
    if (!(r instanceof Uint8Array)) return r;
    trailsBytes = r;
  }

  let designersBytes: Uint8Array | null = null;
  if (manifest.shards.some((s) => s.path === "designers.json")) {
    const r = await fetchShard("designers.json");
    if (!(r instanceof Uint8Array)) return r;
    designersBytes = r;
  }

  return { ok: true, manifest, versions, ledgerBytes, facilityShards, trailsBytes, designersBytes };
}

export interface CatalogImportOutcome {
  ok: boolean;
  reason?: string;
  versionsImported?: number;
  ledgerEntriesApplied?: number;
  facilitiesApplied?: number;
  coursesApplied?: number;
  holesApplied?: number;
  rosterVersionsApplied?: number;
  /** AT 18: courses queued for re-scoring because the ledger promoted them stub->verified. */
  promotedCourses?: number;
  /** AT 18: kept courses queued because they gained a split sibling. */
  splitCourses?: number;
  trailsApplied?: number;
  designersApplied?: number;
  currentVersion?: number;
  ledgerShardPresent?: boolean;
  /** H3: the current version already existed — nothing re-applied. */
  alreadyImported?: boolean;
}

/** Phase 2 (M4): applies an already-verified plan — pure DB writes, no
 * network. `plan` MUST come from a `fetchAndVerifyArtifact` call that
 * returned `ok: true`; this function does not re-verify anything (that
 * already happened in phase 1). */
export async function applyImportPlan(plan: VerifiedArtifactPlan, repo: ImporterRepo): Promise<CatalogImportOutcome> {
  const { manifest, versions } = plan;

  // ---- import every version entry (idempotent) ----
  const results = new Map<string, { version: number; wasNew: boolean }>();
  for (const v of versions) {
    const isCurrent = v.version === manifest.catalogVersion;
    const contractVersion = isCurrent ? String(manifest.contractVersion) : "unknown";
    const imported = await repo.catalog.importVersion({ siteVersion: v.version, contractVersion, sha256: v.sha256, kid: v.kid, publishedAt: v.publishedAt });
    results.set(v.version, imported);
  }
  const versionsImported = [...results.values()].filter((r) => r.wasNew).length;
  const currentImport = results.get(manifest.catalogVersion)!;

  // M3: record every kid this VERIFIED manifest revokes (append-only,
  // app.catalog_kid_revocation — never broadens catalog_signing_key's own
  // grant). Done before the early exit: a re-served manifest's
  // revocations are idempotent no-ops, and a first sight always records.
  await repo.catalog.recordRevokedKids(manifest.revokedKids, manifest.catalogVersion);

  // H3: "exit early when the manifest sha has already been imported." A
  // site version is immutable (importVersion rejects a same-version/
  // different-sha), and one import is one atomic transaction — so a
  // CURRENT version that already existed means this exact artifact was
  // already fully applied; skip the ledger/directory work entirely.
  if (!currentImport.wasNew) {
    return { ok: true, versionsImported, ledgerEntriesApplied: 0, facilitiesApplied: 0, coursesApplied: 0, holesApplied: 0, rosterVersionsApplied: 0, promotedCourses: 0, splitCourses: 0, trailsApplied: 0, designersApplied: 0, currentVersion: currentImport.version, ledgerShardPresent: plan.ledgerBytes !== null, alreadyImported: true };
  }

  // ---- id-ledger.json shard (build plan line 823) — M3: fail closed on
  // a conflicting re-write of already-stored ledger state, never
  // silently keep the first write. ----
  let ledgerEntriesApplied = 0;
  let promotedCourseIds: string[] = [];
  let splitKeptIds: string[] = [];
  if (plan.ledgerBytes) {
    const shardParsed = parseJsonBytes(plan.ledgerBytes, "id-ledger.json");
    if (!shardParsed.ok) return { ok: false, reason: shardParsed.issue };
    const ledgerResult = parseIdLedger(shardParsed.value);
    if (!ledgerResult.ok) return { ok: false, reason: ledgerResult.issue };

    const siteVersionMap = new Map<string, number>();
    for (const row of await repo.catalog.listSiteVersions()) siteVersionMap.set(row.siteVersion, row.version);
    for (const [siteVersion, r] of results) siteVersionMap.set(siteVersion, r.version);

    const baseRows: LedgerBaseRow[] = [];
    const stateRows: LedgerStateRow[] = [];
    for (const entry of ledgerResult.value.entries) {
      const firstVersionStr = firstMintedVersion(entry, compareCatalogVersions);
      const firstVersionInt = siteVersionMap.get(firstVersionStr);
      if (firstVersionInt === undefined) {
        return { ok: false, reason: `id-ledger.json: entry "${entry.id}" references unknown catalogVersion "${firstVersionStr}"` };
      }
      baseRows.push({ id: entry.id, kind: entry.kind, firstCatalogVersionInt: firstVersionInt });

      let verifiedInVersionInt: number | null = null;
      const verifiedStr = latestVerifiedVersion(entry, compareCatalogVersions);
      if (verifiedStr) {
        const mapped = siteVersionMap.get(verifiedStr);
        if (mapped === undefined) {
          return { ok: false, reason: `id-ledger.json: entry "${entry.id}" references unknown catalogVersion "${verifiedStr}"` };
        }
        verifiedInVersionInt = mapped;
      }
      stateRows.push({ id: entry.id, status: entry.status ?? "stub", tombstoned: entry.tombstoned, mergedInto: entry.mergedInto, verifiedInVersionInt, splitSiblings: entry.splitSiblings });
    }

    // ⛔ FIX (P3e round 2 gate, M3): "fail closed when a signed ledger
    // conflicts with stored state: a different merged_into, or a
    // tombstone reversal." Checked BEFORE any write this pass makes —
    // every entry's claim is compared against what's ALREADY on file
    // (from a PRIOR import), and a genuine conflict rejects the WHOLE
    // import rather than silently keeping the first write for that one
    // entry while applying everything else.
    const conflict = await repo.catalog.findLedgerConflict(stateRows);
    if (conflict) return { ok: false, reason: conflict };

    if (baseRows.length > 0) {
      // AT 18: promotion detection runs BEFORE ensureLedgerIdsExist — that
      // call inserts every id it has never seen as a `stub`, so a brand-new
      // course this very ledger mints already-verified would otherwise look
      // like a stub being promoted. (Such a course has no plays to re-score
      // anyway.) Only a course whose stored status was `stub` BEFORE this
      // import and whose incoming entry is `verified` is a promotion.
      promotedCourseIds = await repo.catalog.findStubPromotions(stateRows);
      await repo.catalog.ensureLedgerIdsExist(baseRows);
      // Newly split siblings likewise; both only ENQUEUE work (migration
      // 0026's backlog) — the re-scoring itself runs in the bounded drain
      // pass, never inside this transaction.
      splitKeptIds = await repo.catalog.applySplits(stateRows);
      await repo.catalog.applyLedgerState(stateRows);
      ledgerEntriesApplied = stateRows.length;
    }
  }

  // ---- H2: the real directory shards (facilities/courses, trails,
  // designers) — set-based (H3). ----
  let facilitiesApplied = 0;
  let coursesApplied = 0;
  let holesApplied = 0;
  let rosterVersionsApplied = 0;
  let designersApplied = 0;
  const currentVersionInt = currentImport.version;

  if (plan.designersBytes) {
    const parsed = parseJsonBytes(plan.designersBytes, "designers.json");
    if (!parsed.ok) return { ok: false, reason: parsed.issue };
    const r = parseDesignersShard(parsed.value);
    if (!r.ok) return { ok: false, reason: r.issue };
    await repo.catalog.upsertDesigners(r.value.map((d: ParsedDesigner) => ({ id: d.id, name: d.name, catalogVersionInt: currentVersionInt })));
    designersApplied = r.value.length;
  }

  let trailsApplied = 0;
  let trailsForRosters: ParsedTrail[] = [];
  if (plan.trailsBytes) {
    const parsed = parseJsonBytes(plan.trailsBytes, "trails.json");
    if (!parsed.ok) return { ok: false, reason: parsed.issue };
    const r = parseTrailsShard(parsed.value);
    if (!r.ok) return { ok: false, reason: r.issue };
    await repo.catalog.upsertTrails(r.value.map((t: ParsedTrail) => ({ id: t.id, slug: t.slug, name: t.name, catalogVersionInt: currentVersionInt })));
    trailsApplied = r.value.length;
    trailsForRosters = r.value;
  }

  for (const shard of plan.facilityShards) {
    const parsed = parseJsonBytes(shard.bytes, shard.path);
    if (!parsed.ok) return { ok: false, reason: parsed.issue };
    const r = parseFacilitiesShard(parsed.value);
    if (!r.ok) return { ok: false, reason: r.issue };
    const facilities: ParsedFacility[] = r.value;
    await repo.catalog.upsertFacilities(
      facilities.map((f) => ({ id: f.id, slug: f.slug, region: f.region, tz: f.tz, name: f.name ?? f.slug, verificationStatus: f.verificationStatus, catalogVersionInt: currentVersionInt })),
    );
    const courses = facilities.flatMap((f) =>
      f.courses.map((c) => ({
        id: c.id,
        facilityId: f.id,
        designerId: c.designerId,
        // app.catalog_course.name is NOT NULL — fall back to the
        // facility's own name/slug when the artifact omits one. `holes`
        // is NOT imported: catalog_course has no such column (hole
        // COUNT lives as catalog_hole rows, whose ids this artifact
        // does not carry).
        name: c.name ?? f.name ?? f.slug,
        holes: c.holes,
        // H2's own chosen reading (directory-artifact.ts's own note):
        // Course carries no verification field of its own in this
        // artifact — a course's verification_status mirrors its
        // FACILITY's.
        verificationStatus: f.verificationStatus,
        closed: c.closed,
        catalogVersionInt: currentVersionInt,
      })),
    );
    await repo.catalog.upsertCourses(courses);
    // R3: Course.holesDetail -> catalog_hole (hole ids ARE in the ledger).
    const holes = facilities.flatMap((f) => f.courses.flatMap((c) => c.holesDetail.map((h) => ({ id: h.id, courseId: c.id, number: h.number, catalogVersionInt: currentVersionInt }))));
    await repo.catalog.upsertHoles(holes);
    facilitiesApplied += facilities.length;
    coursesApplied += courses.length;
    holesApplied += holes.length;
  }

  // R3: roster versions/members — AFTER facilities, courses and holes (FKs).
  if (trailsForRosters.length > 0) {
    const rosters = trailsForRosters.flatMap(rostersOf);
    await repo.catalog.upsertRosters(rosters);
    rosterVersionsApplied = rosters.length;
  }

  // AT 18: queue the re-score work (set-based, idempotent).
  await repo.catalog.enqueueRescore(promotedCourseIds, "promotion", currentVersionInt);
  await repo.catalog.enqueueRescore(splitKeptIds, "split", currentVersionInt);

  return {
    ok: true,
    versionsImported,
    ledgerEntriesApplied,
    facilitiesApplied,
    coursesApplied,
    holesApplied,
    rosterVersionsApplied,
    promotedCourses: promotedCourseIds.length,
    splitCourses: splitKeptIds.length,
    trailsApplied,
    designersApplied,
    currentVersion: currentImport.version,
    ledgerShardPresent: plan.ledgerBytes !== null,
  };
}

/** Thrown inside the transaction to ROLL BACK a post-write rejection
 * (ledger conflict, malformed shard) — `applyImportPlan` returns
 * `{ok:false}` after possibly having written version rows already, and
 * committing those would let a retry hit the "already imported" early
 * exit and wrongly succeed. */
class ImportRejected extends Error {
  constructor(public readonly reason: string) {
    super(reason);
  }
}

/** The one correct way to run phase 2: `applyImportPlan` inside the
 * caller's transaction wrapper, rolled back on any `{ok:false}`. */
export async function applyImportPlanAtomically(plan: VerifiedArtifactPlan, withTransaction: <T>(op: (repo: ImporterRepo) => Promise<T>) => Promise<T>): Promise<CatalogImportOutcome> {
  try {
    return await withTransaction(async (repo) => {
      const outcome = await applyImportPlan(plan, repo);
      if (!outcome.ok) throw new ImportRejected(outcome.reason ?? "import_rejected");
      return outcome;
    });
  } catch (err) {
    if (err instanceof ImportRejected) return { ok: false, reason: err.reason };
    throw err;
  }
}

function physicalKey(m: ParsedRosterMember): string {
  switch (m.unit) {
    case "facility":
      return `f:${m.facilityId}`;
    case "hole":
      return `c:${m.courseId}`;
    case "course":
      return "anyOf" in m ? `c:${[...m.anyOf].sort().join(",")}` : `c:${m.courseId}`;
  }
}

/** R3: flattens one trail's roster versions into persistable rows, and
 * derives `removed_on` (0002's own note: "derived by the import function,
 * null while still a member of the latest version"): a member of version
 * k whose physical stop (facility / course set — §4.3: re-typing is not a
 * drop) has no counterpart in version k+1 is removed on k+1's
 * effectiveFrom. */
function rostersOf(trail: ParsedTrail): RosterVersionInput[] {
  const versions = [...trail.rosterVersions].sort((a, b) => a.version - b.version);
  return versions.map((rv, idx) => {
    const next = versions.slice(idx + 1, idx + 2).at(0);
    const nextKeys = next ? new Set(next.members.map(physicalKey)) : null;
    return {
      trailId: trail.id,
      version: rv.version,
      effectiveFrom: rv.effectiveFrom,
      completionUnit: rv.completionUnit,
      markerUnit: rv.markerUnit,
      completionRule: rv.completionRule,
      markerRule: rv.markerRule,
      trackingStartsOn: rv.trackingStartsOn,
      members: rv.members.map((m) => ({
        unit: m.unit,
        courseId: m.unit === "course" ? ("anyOf" in m ? null : m.courseId) : m.unit === "hole" ? m.courseId : null,
        anyOfCourseIds: m.unit === "course" && "anyOf" in m ? m.anyOf : null,
        facilityId: m.unit === "facility" ? m.facilityId : null,
        holeId: m.unit === "hole" ? m.holeId : null,
        stopOrder: m.stopOrder,
        removedOn: nextKeys && !nextKeys.has(physicalKey(m)) ? next!.effectiveFrom : null,
      })),
    };
  });
}

export { parseIdLedger };
export type { LedgerEntry };
