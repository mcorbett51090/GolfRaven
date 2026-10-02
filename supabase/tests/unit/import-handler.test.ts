// supabase/tests/unit/import-handler.test.ts
//
// ⛔ REWRITE (P3e round 2 gate, M4: "fetch and verify ALL artifacts
// before opening the transaction"). `runCatalogImport` no longer exists
// — import-handler.ts now splits into `fetchAndVerifyArtifact` (network
// + crypto, no ImporterRepo) and `applyImportPlan` (pure DB writes from
// an already-verified plan, no network). `runImport` below is a local
// test-only helper that chains the two, so the shape of every existing
// test stays close to what it asserted before — the split itself is
// exercised directly by the two dedicated describe blocks further down.
import { describe, expect, it, vi } from "vitest";
import { applyImportPlan, fetchAndVerifyArtifact, type CatalogImportConfig, type CatalogImportOutcome, type FetchBytes, type GetSigningKey, type RejectedArtifact } from "../../functions/_shared/catalog/import-handler.js";
import { makeFakeImporterRepo, makeFakeImporterState } from "./fake-importer-repo.js";
import { buildSignedArtifact, generateKeypair, jsonBytes } from "./catalog-artifact-fixtures.js";
import type { ImporterRepo } from "../../functions/_shared/types.js";

const BASE_URL = "https://golfraven.example/catalog/v1";
const ALLOWED_HOSTS = ["golfraven.example"];
const NOW = new Date("2026-09-25T00:00:00.000Z");

const FAC_ID = "fac_01ARZ3NDEKTSV4RRFFQ69G5FAV";
const CRS_ID = "crs_01ARZ3NDEKTSV4RRFFQ69G5FBW";

function ledgerFixture() {
  return {
    entries: {
      [FAC_ID]: { id: FAC_ID, status: "verified", transitions: [{ type: "minted", catalogVersion: "20260901-aaaaaaa" }, { type: "verified", catalogVersion: "20260925-bbbbbbb" }] },
      [CRS_ID]: { id: CRS_ID, status: "stub", transitions: [{ type: "minted", catalogVersion: "20260925-bbbbbbb" }] },
    },
  };
}

async function buildHappyArtifact(kid: string, privateKey: CryptoKey) {
  const ledgerBytes = jsonBytes(ledgerFixture());
  return buildSignedArtifact({
    privateKey,
    kid,
    contractVersion: 1,
    catalogVersion: "20260925-bbbbbbb",
    minAppVersion: "1.0.0",
    revokedKids: [],
    generatedAt: NOW.toISOString(),
    versionHistory: [
      { version: "20260901-aaaaaaa", publishedAt: "2026-09-01T00:00:00.000Z", kid, sha256: "a".repeat(64) },
      { version: "20260925-bbbbbbb", publishedAt: NOW.toISOString(), kid, sha256: "b".repeat(64) },
    ],
    shards: [{ path: "id-ledger.json", bytes: ledgerBytes }],
  });
}

function fetcherFor(artifact: Awaited<ReturnType<typeof buildHappyArtifact>>): FetchBytes {
  return vi.fn(async (url: string) => {
    if (url.endsWith("/manifest.json")) return artifact.manifestBytes;
    if (url.endsWith("/manifest.sig.json")) return artifact.manifestSigBytes;
    if (url.endsWith("/versions.json")) return artifact.versionsBytes;
    if (url.endsWith("/versions.sig.json")) return artifact.versionsSigBytes;
    for (const [path, bytes] of artifact.shardsByPath) {
      if (url.endsWith(`/${path}`)) return bytes;
    }
    throw new Error(`fetcherFor: unexpected url ${url}`);
  });
}

function getSigningKeyFor(repo: ImporterRepo): GetSigningKey {
  return (kid) => repo.catalog.getSigningKey(kid);
}

/** Chains phase 1 (`fetchAndVerifyArtifact`) and phase 2
 * (`applyImportPlan`) — the same two calls `import-catalog/index.ts`
 * makes in production, just without the transaction boundary between
 * them a real entrypoint puts there (M4's own point: phase 1 must run
 * BEFORE any transaction opens at all). */
async function runImport(config: CatalogImportConfig, repo: ImporterRepo, fetchBytes: FetchBytes, getSigningKey: GetSigningKey): Promise<CatalogImportOutcome | RejectedArtifact> {
  const plan = await fetchAndVerifyArtifact(config, fetchBytes, getSigningKey);
  if (!plan.ok) return plan;
  return applyImportPlan(plan, repo);
}

async function setupHappyPath() {
  const { privateKey, publicKeyB64Url } = await generateKeypair();
  const artifact = await buildHappyArtifact("kid-1", privateKey);
  const state = makeFakeImporterState(NOW);
  state.signingKeys.set("kid-1", { kid: "kid-1", publicKeyB64Url, revokedAt: null });
  const repo = makeFakeImporterRepo(state);
  const fetchBytes = fetcherFor(artifact);
  return { state, repo, fetchBytes };
}

describe("import-catalog — happy path", () => {
  it("imports the version history and the ledger shard", async () => {
    const { state, repo, fetchBytes } = await setupHappyPath();
    const outcome = await runImport({ artifactBaseUrl: BASE_URL, allowedHosts: ALLOWED_HOSTS }, repo, fetchBytes, getSigningKeyFor(repo));

    expect(outcome.ok).toBe(true);
    if (!outcome.ok) throw new Error("unreachable");
    expect(outcome.versionsImported).toBe(2);
    expect(outcome.ledgerEntriesApplied).toBe(2);
    expect(outcome.ledgerShardPresent).toBe(true);
    expect(state.versions).toHaveLength(2);
    expect(state.versions.find((v) => v.siteVersion === "20260925-bbbbbbb")!.contractVersion).toBe("1"); // the CURRENT entry gets the real contractVersion
    expect(state.versions.find((v) => v.siteVersion === "20260901-aaaaaaa")!.contractVersion).toBe("unknown"); // a historical entry's contractVersion is unknown, never fabricated

    const facRow = state.ledger.get(FAC_ID)!;
    expect(facRow.kind).toBe("facility");
    expect(facRow.status).toBe("verified");
    const crsRow = state.ledger.get(CRS_ID)!;
    expect(crsRow.kind).toBe("course");
    expect(crsRow.status).toBe("stub");
  });

  it("is idempotent — a second import of the SAME artifact makes no new writes", async () => {
    const { state, repo, fetchBytes } = await setupHappyPath();
    await runImport({ artifactBaseUrl: BASE_URL, allowedHosts: ALLOWED_HOSTS }, repo, fetchBytes, getSigningKeyFor(repo));
    const outcome2 = await runImport({ artifactBaseUrl: BASE_URL, allowedHosts: ALLOWED_HOSTS }, repo, fetchBytes, getSigningKeyFor(repo));

    expect(outcome2.ok).toBe(true);
    if (!outcome2.ok) throw new Error("unreachable");
    expect(outcome2.versionsImported).toBe(0); // both site_versions already on file
    expect(state.versions).toHaveLength(2); // no duplicate rows
  });

  // ⛔ REPLACES the old, now-FALSE "never fabricates data beyond the
  // ledger shard" boundary test (P3e round 2 gate, H2: "Owner policy is
  // full product first, so implement it; there is no re-scope"). H2
  // explicitly implements catalog_facility/catalog_course import —
  // asserting the write methods are ABSENT would now pin the wrong
  // thing. See the "H2: directory shards" describe block below for the
  // positive coverage.
  it("H2: ImporterRepo now DOES carry the directory upsert methods (facilities/courses/trails/designers) — the old 'not implemented' boundary no longer holds", async () => {
    const { repo } = await setupHappyPath();
    expect(typeof repo.catalog.upsertFacilities).toBe("function");
    expect(typeof repo.catalog.upsertCourses).toBe("function");
    expect(typeof repo.catalog.upsertTrails).toBe("function");
    expect(typeof repo.catalog.upsertDesigners).toBe("function");
  });
});

describe("import-catalog — rejections", () => {
  it("rejects with catalog_forged when the signing kid is not registered (LOW nit: unregistered != revoked)", async () => {
    const { privateKey } = await generateKeypair();
    const artifact = await buildHappyArtifact("unregistered-kid", privateKey);
    const state = makeFakeImporterState(NOW); // no signing keys registered
    const repo = makeFakeImporterRepo(state);
    const outcome = await runImport({ artifactBaseUrl: BASE_URL, allowedHosts: ALLOWED_HOSTS }, repo, fetcherFor(artifact), getSigningKeyFor(repo));
    expect(outcome.ok).toBe(false);
    if (outcome.ok) throw new Error("unreachable");
    expect(outcome.reason).toBe("catalog_forged");
  });

  it("rejects with catalog_stale when the signing kid is revoked (distinct from an unregistered kid, above)", async () => {
    const { privateKey, publicKeyB64Url } = await generateKeypair();
    const artifact = await buildHappyArtifact("revoked-kid", privateKey);
    const state = makeFakeImporterState(NOW);
    state.signingKeys.set("revoked-kid", { kid: "revoked-kid", publicKeyB64Url, revokedAt: "2026-09-01T00:00:00.000Z" });
    const repo = makeFakeImporterRepo(state);
    const outcome = await runImport({ artifactBaseUrl: BASE_URL, allowedHosts: ALLOWED_HOSTS }, repo, fetcherFor(artifact), getSigningKeyFor(repo));
    expect(outcome.ok).toBe(false);
    if (outcome.ok) throw new Error("unreachable");
    expect(outcome.reason).toBe("catalog_stale");
  });

  it("rejects with catalog_forged when the manifest signature was made by a DIFFERENT key than the one registered under that kid", async () => {
    const { privateKey } = await generateKeypair();
    const { publicKeyB64Url: wrongPublicKey } = await generateKeypair();
    const artifact = await buildHappyArtifact("kid-1", privateKey);
    const state = makeFakeImporterState(NOW);
    state.signingKeys.set("kid-1", { kid: "kid-1", publicKeyB64Url: wrongPublicKey, revokedAt: null });
    const repo = makeFakeImporterRepo(state);
    const outcome = await runImport({ artifactBaseUrl: BASE_URL, allowedHosts: ALLOWED_HOSTS }, repo, fetcherFor(artifact), getSigningKeyFor(repo));
    expect(outcome.ok).toBe(false);
    if (outcome.ok) throw new Error("unreachable");
    expect(outcome.reason).toBe("catalog_forged");
  });

  it("rejects with catalog_forged when the manifest bytes were tampered with after signing (sha mismatch)", async () => {
    const { state, repo, fetchBytes } = await setupHappyPath();
    const tamperedFetch: FetchBytes = vi.fn(async (url: string, maxBytes: number) => {
      const real = await fetchBytes(url, maxBytes);
      if (url.endsWith("/manifest.json")) {
        // Flip a byte — still valid JSON-shaped bytes are not required
        // since parseCatalogManifest would just reject malformed JSON
        // too, but tampering the CONTENT (not just corrupting JSON) is
        // the more interesting attack: re-serialize with an extra,
        // otherwise-harmless field changed.
        const text = new TextDecoder().decode(real).replace('"minAppVersion": "1.0.0"', '"minAppVersion": "9.9.9"');
        return new TextEncoder().encode(text);
      }
      return real;
    });
    const outcome = await runImport({ artifactBaseUrl: BASE_URL, allowedHosts: ALLOWED_HOSTS }, repo, tamperedFetch, getSigningKeyFor(repo));
    expect(outcome.ok).toBe(false);
    if (outcome.ok) throw new Error("unreachable");
    expect(outcome.reason).toBe("catalog_forged");
    expect(state.versions).toHaveLength(0); // nothing imported on a forged manifest
  });

  it("rejects with catalog_forged when generatedAt is far in the future", async () => {
    const { privateKey, publicKeyB64Url } = await generateKeypair();
    const farFuture = new Date(NOW.getTime() + 30 * 24 * 60 * 60 * 1000).toISOString();
    const ledgerBytes = jsonBytes(ledgerFixture());
    const artifact = await buildSignedArtifact({
      privateKey,
      kid: "kid-1",
      contractVersion: 1,
      catalogVersion: "20260925-bbbbbbb",
      minAppVersion: "1.0.0",
      revokedKids: [],
      generatedAt: farFuture,
      versionHistory: [{ version: "20260925-bbbbbbb", publishedAt: NOW.toISOString(), kid: "kid-1", sha256: "b".repeat(64) }],
      shards: [{ path: "id-ledger.json", bytes: ledgerBytes }],
    });
    const state = makeFakeImporterState(NOW);
    state.signingKeys.set("kid-1", { kid: "kid-1", publicKeyB64Url, revokedAt: null });
    const repo = makeFakeImporterRepo(state);
    const outcome = await runImport({ artifactBaseUrl: BASE_URL, allowedHosts: ALLOWED_HOSTS }, repo, fetcherFor(artifact), getSigningKeyFor(repo));
    expect(outcome.ok).toBe(false);
    if (outcome.ok) throw new Error("unreachable");
    expect(outcome.reason).toBe("catalog_forged");
  });

  it("rejects with catalog_forged when a manifest declares itself signed by a kid it also lists as revoked (self-inconsistent)", async () => {
    const { privateKey, publicKeyB64Url } = await generateKeypair();
    const ledgerBytes = jsonBytes(ledgerFixture());
    const artifact = await buildSignedArtifact({
      privateKey,
      kid: "kid-1",
      contractVersion: 1,
      catalogVersion: "20260925-bbbbbbb",
      minAppVersion: "1.0.0",
      revokedKids: ["kid-1"],
      generatedAt: NOW.toISOString(),
      versionHistory: [{ version: "20260925-bbbbbbb", publishedAt: NOW.toISOString(), kid: "kid-1", sha256: "b".repeat(64) }],
      shards: [{ path: "id-ledger.json", bytes: ledgerBytes }],
    });
    const state = makeFakeImporterState(NOW);
    state.signingKeys.set("kid-1", { kid: "kid-1", publicKeyB64Url, revokedAt: null });
    const repo = makeFakeImporterRepo(state);
    const outcome = await runImport({ artifactBaseUrl: BASE_URL, allowedHosts: ALLOWED_HOSTS }, repo, fetcherFor(artifact), getSigningKeyFor(repo));
    expect(outcome.ok).toBe(false);
    if (outcome.ok) throw new Error("unreachable");
    expect(outcome.reason).toBe("catalog_forged");
  });

  it("refuses to fetch anything when the configured base URL's host is not allow-listed", async () => {
    const { repo, fetchBytes } = await setupHappyPath();
    const outcome = await runImport({ artifactBaseUrl: "https://evil.example/catalog/v1", allowedHosts: ALLOWED_HOSTS }, repo, fetchBytes, getSigningKeyFor(repo));
    expect(outcome.ok).toBe(false);
    if (outcome.ok) throw new Error("unreachable");
    expect(outcome.reason).toBe("artifact_base_url_host_not_allowed");
    expect(fetchBytes).not.toHaveBeenCalled();
  });

  it("refuses a non-https base URL", async () => {
    const { repo, fetchBytes } = await setupHappyPath();
    const outcome = await runImport({ artifactBaseUrl: "http://golfraven.example/catalog/v1", allowedHosts: ALLOWED_HOSTS }, repo, fetchBytes, getSigningKeyFor(repo));
    expect(outcome.ok).toBe(false);
    if (outcome.ok) throw new Error("unreachable");
    expect(outcome.reason).toBe("artifact_base_url_not_https");
  });

  // ⛔ M6 (P3e round 2 gate): P1's own ledger schema types a transition's
  // `catalogVersion` as `z.string().min(1)` — NOT necessarily a site
  // version this catalog knows. It must never reject a signed import; the
  // entry falls back to the IMPORTING version's own int and the fact is
  // logged. (This test used to assert the opposite — the old reject.)
  it.each(["20200101-0000000", "an arbitrary string, not a site version at all"])("imports a ledger entry whose transition names an unknown catalogVersion (%s), falling back to the importing version", async (arbitrary) => {
    const { privateKey, publicKeyB64Url } = await generateKeypair();
    const ledger = { entries: { [FAC_ID]: { id: FAC_ID, transitions: [{ type: "minted", catalogVersion: arbitrary }, { type: "verified", catalogVersion: arbitrary }] } } };
    const ledgerBytes = jsonBytes(ledger);
    const artifact = await buildSignedArtifact({
      privateKey,
      kid: "kid-1",
      contractVersion: 1,
      catalogVersion: "20260925-bbbbbbb",
      minAppVersion: "1.0.0",
      revokedKids: [],
      generatedAt: NOW.toISOString(),
      versionHistory: [{ version: "20260925-bbbbbbb", publishedAt: NOW.toISOString(), kid: "kid-1", sha256: "b".repeat(64) }],
      shards: [{ path: "id-ledger.json", bytes: ledgerBytes }],
    });
    const state = makeFakeImporterState(NOW);
    state.signingKeys.set("kid-1", { kid: "kid-1", publicKeyB64Url, revokedAt: null });
    const repo = makeFakeImporterRepo(state);
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const outcome = await runImport({ artifactBaseUrl: BASE_URL, allowedHosts: ALLOWED_HOSTS }, repo, fetcherFor(artifact), getSigningKeyFor(repo));
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) throw new Error("unreachable");
    expect(outcome.ledgerEntriesApplied).toBe(1);
    const importingInt = state.versions.find((v) => v.siteVersion === "20260925-bbbbbbb")!.version;
    expect(state.ledger.get(FAC_ID)).toMatchObject({ firstCatalogVersion: importingInt, verifiedInVersion: importingInt });
    expect(warn).toHaveBeenCalled(); // logged, not silent
    warn.mockRestore();
  });
});

// ⛔ NEW (P3e round 2 gate, H2: "Import catalog_facility / catalog_course
// (and trail/hole where the emitter publishes them)... there is no
// re-scope").
describe("import-catalog — H2: directory shards (facilities/courses/trails/designers)", () => {
  const DSG_ID = "dsg_01ARZ3NDEKTSV4RRFFQ69G5FCX";

  async function buildArtifactWithDirectory(kid: string, privateKey: CryptoKey) {
    // A self-contained ledger fixture (NOT the top-level ledgerFixture()
    // — that one's facility entry mints under "20260901-aaaaaaa", a
    // historical version this artifact's own versionHistory (below)
    // never lists, since this describe block only ever signs ONE
    // release).
    const ledgerBytes = jsonBytes({
      entries: {
        [FAC_ID]: { id: FAC_ID, status: "verified", transitions: [{ type: "minted", catalogVersion: "20260925-bbbbbbb" }] },
      },
    });
    const facilitiesBytes = jsonBytes([
      {
        id: FAC_ID,
        slug: "example-facility",
        region: "US-TN",
        tz: "America/Chicago",
        name: "Example Facility",
        verification: { status: "play-verified" },
        courses: [{ id: CRS_ID, name: "Example Course", holes: 18, closed: false, designers: [DSG_ID] }],
      },
    ]);
    const trailsBytes = jsonBytes([{ id: "trl_01ARZ3NDEKTSV4RRFFQ69G5FDY", slug: "example-trail", name: "Example Trail" }]);
    const designersBytes = jsonBytes([{ id: DSG_ID, name: "Example Designer" }]);
    return buildSignedArtifact({
      privateKey,
      kid,
      contractVersion: 1,
      catalogVersion: "20260925-bbbbbbb",
      minAppVersion: "1.0.0",
      revokedKids: [],
      generatedAt: NOW.toISOString(),
      versionHistory: [{ version: "20260925-bbbbbbb", publishedAt: NOW.toISOString(), kid, sha256: "b".repeat(64) }],
      shards: [
        { path: "id-ledger.json", bytes: ledgerBytes },
        { path: "facilities/us.json", bytes: facilitiesBytes },
        { path: "trails.json", bytes: trailsBytes },
        { path: "designers.json", bytes: designersBytes },
      ],
    });
  }

  async function setupDirectory() {
    const { privateKey, publicKeyB64Url } = await generateKeypair();
    const artifact = await buildArtifactWithDirectory("kid-1", privateKey);
    const state = makeFakeImporterState(NOW);
    state.signingKeys.set("kid-1", { kid: "kid-1", publicKeyB64Url, revokedAt: null });
    const repo = makeFakeImporterRepo(state);
    return { state, repo, fetchBytes: fetcherFor(artifact) };
  }

  it("imports facilities, courses, trails and designers from their real shard paths, set-based (H3)", async () => {
    const { state, repo, fetchBytes } = await setupDirectory();
    const outcome = await runImport({ artifactBaseUrl: BASE_URL, allowedHosts: ALLOWED_HOSTS }, repo, fetchBytes, getSigningKeyFor(repo));
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) throw new Error("unreachable");
    expect(outcome.facilitiesApplied).toBe(1);
    expect(outcome.coursesApplied).toBe(1);
    expect(outcome.trailsApplied).toBe(1);
    expect(outcome.designersApplied).toBe(1);

    const fac = state.facilities.get(FAC_ID)!;
    expect(fac.slug).toBe("example-facility");
    expect(fac.tz).toBe("America/Chicago");
    expect(fac.verificationStatus).toBe("play-verified");

    const crs = state.courses.get(CRS_ID)!;
    expect(crs.facilityId).toBe(FAC_ID);
    expect(crs.designerId).toBe(DSG_ID);
    // H2's own documented reading: a course carries no verification field
    // of its own in this artifact — it mirrors its FACILITY's.
    expect(crs.verificationStatus).toBe("play-verified");

    expect(state.trails.size).toBe(1);
    expect(state.designers.size).toBe(1);
  });

  it("a re-import of the SAME directory shard is idempotent (upsert, not duplicate rows)", async () => {
    const { state, repo, fetchBytes } = await setupDirectory();
    await runImport({ artifactBaseUrl: BASE_URL, allowedHosts: ALLOWED_HOSTS }, repo, fetchBytes, getSigningKeyFor(repo));
    await runImport({ artifactBaseUrl: BASE_URL, allowedHosts: ALLOWED_HOSTS }, repo, fetchBytes, getSigningKeyFor(repo));
    expect(state.facilities.size).toBe(1);
    expect(state.courses.size).toBe(1);
  });
});

// ⛔ NEW (P3e round 2 gate, B1: "Add an interop test that signs with the
// REAL tools/catalog signer (signManifest/signVersions, the emit-catalog
// output) and imports it. Your self-signed fixtures hid this."). Every
// OTHER test in this file signs through catalog-artifact-fixtures.ts's
// own hand-rolled (but now B1-fixed, standard-base64) signer — this
// block instead calls the ACTUAL `tools/catalog/src/sign.ts` functions
// the real `emit-catalog` CLI uses, over Node's own `node:crypto`
// KeyObject (not Web Crypto), proving wire compatibility with the real
// P1 package rather than with this test suite's own re-derivation of its
// wire format.
describe("import-catalog — B1 interop: the REAL tools/catalog/src/sign.ts signer", () => {
  it("imports an artifact signed by the real signManifest/signVersions functions", async () => {
    const nodeCrypto = await import("node:crypto");
    const { signManifest, signVersions } = await import("../../../tools/catalog/src/sign.js");
    const { canonicalStringify: realCanonicalStringify } = await import("../../../tools/catalog/src/manifest.js");
    const { bytesToBase64Url } = await import("../../functions/_shared/catalog/signature.js");

    const { publicKey, privateKey } = nodeCrypto.generateKeyPairSync("ed25519");
    // Ed25519 SPKI DER is a fixed 12-byte ASN.1 header followed by the
    // raw 32-byte public key — slicing the last 32 bytes is the standard
    // way to recover the raw key Web Crypto's `importKey("raw", ...)`
    // (signature.ts's own verifier) expects, matching
    // `app.catalog_signing_key.public_key_b64url`'s own storage
        // convention (a raw key export, never PEM/SPKI).
    const spki = publicKey.export({ type: "spki", format: "der" }) as Buffer;
    const rawPublicKey = new Uint8Array(spki.subarray(spki.length - 32));
    const publicKeyB64Url = bytesToBase64Url(rawPublicKey);

    const kid = "real-signer-kid";
    const catalogVersion = "20260925-cafe001";
    // A fixture with THIS test's own catalogVersion so its transitions
    // resolve against the versions.json this test signs.
    const ledger = {
      entries: {
        [FAC_ID]: { id: FAC_ID, status: "verified", transitions: [{ type: "minted", catalogVersion }] },
      },
    };
    const realLedgerBytes = Buffer.from(realCanonicalStringify(ledger), "utf8");

    const manifestForStatement = { contractVersion: 1, catalogVersion, kid };
    const manifestBody = {
      contractVersion: 1,
      catalogVersion,
      minAppVersion: "1.0.0",
      kid,
      revokedKids: [] as string[],
      generatedAt: NOW.toISOString(),
      shards: [{ path: "id-ledger.json", sha256: nodeCrypto.createHash("sha256").update(realLedgerBytes).digest("hex"), bytes: realLedgerBytes.length }],
    };
    const manifestBytes = Buffer.from(realCanonicalStringify(manifestBody), "utf8");
    const manifestSig = signManifest(manifestForStatement, manifestBytes, privateKey);
    const manifestSigBytes = Buffer.from(realCanonicalStringify(manifestSig), "utf8");

    const versionHistory = [{ version: catalogVersion, publishedAt: NOW.toISOString(), kid, sha256: nodeCrypto.createHash("sha256").update(manifestBytes).digest("hex") }];
    const versionsBytes = Buffer.from(realCanonicalStringify(versionHistory), "utf8");
    const versionsSig = signVersions(versionsBytes, kid, privateKey);
    const versionsSigBytes = Buffer.from(realCanonicalStringify(versionsSig), "utf8");

    const state = makeFakeImporterState(NOW);
    state.signingKeys.set(kid, { kid, publicKeyB64Url, revokedAt: null });
    const repo = makeFakeImporterRepo(state);

    const fetchBytes: FetchBytes = async (url: string) => {
      if (url.endsWith("/manifest.json")) return new Uint8Array(manifestBytes);
      if (url.endsWith("/manifest.sig.json")) return new Uint8Array(manifestSigBytes);
      if (url.endsWith("/versions.json")) return new Uint8Array(versionsBytes);
      if (url.endsWith("/versions.sig.json")) return new Uint8Array(versionsSigBytes);
      if (url.endsWith("/id-ledger.json")) return new Uint8Array(realLedgerBytes);
      throw new Error(`unexpected url ${url}`);
    };

    const outcome = await runImport({ artifactBaseUrl: BASE_URL, allowedHosts: ALLOWED_HOSTS }, repo, fetchBytes, getSigningKeyFor(repo));
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) throw new Error(`import rejected: ${outcome.reason}`);
    expect(outcome.versionsImported).toBe(1);
    expect(outcome.ledgerEntriesApplied).toBe(1);
    const facRow = state.ledger.get(FAC_ID)!;
    expect(facRow.status).toBe("verified");
  });
});

// ⛔ NEW (P3e round 2 gate, H3: "Add a scale test at ~40k ledger ids
// plus the directory. It must finish well inside the 12s
// transaction_timeout; report the measured time."). This unit-level
// version exercises the SET-BASED upsert code path (applyImportPlan's
// own batched `ensureLedgerIdsExist`/`applyLedgerState`/`upsertFacilities`
// calls — one call per shard, never per row) against the in-memory fake,
// which proves the CODE PATH never falls back to a per-row loop at the
// import-handler.ts layer and reports a wall-clock figure for this
// environment — it is NOT a substitute for the real-Postgres timing
// claim H3 asks for (that needs a live `transaction_timeout`-bound
// connection, which only the Deno integration suite
// (import-catalog.deno.test.ts) can genuinely exercise; see that file's
// own H3 scale test for the number that actually matters).
describe("import-catalog — H3: scale (unit-level, in-memory)", () => {
  it("imports ~40,000 ledger ids in well under a second against the fake repo", async () => {
    const { privateKey, publicKeyB64Url } = await generateKeypair();
    const N = 40_000;
    // Crockford base32 (the real ULID alphabet — no I/L/O/U, matching
    // ledger-artifact.ts's own `ID_RE`), NOT plain base36 — base36's
    // `.toUpperCase()` output can contain I/L/O/U, which the real id
    // regex rejects.
    const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    function crockfordId(n: number): string {
      let out = "";
      let v = n;
      for (let i = 0; i < 26; i++) {
        out = CROCKFORD[v % 32] + out;
        v = Math.floor(v / 32);
      }
      return out;
    }
    const entries: Record<string, unknown> = {};
    for (let i = 0; i < N; i++) {
      const id = `fac_${crockfordId(i)}`;
      entries[id] = { id, status: "stub", transitions: [{ type: "minted", catalogVersion: "20260925-bbbbbbb" }] };
    }
    const ledgerBytes = jsonBytes({ entries });
    const artifact = await buildSignedArtifact({
      privateKey,
      kid: "kid-1",
      contractVersion: 1,
      catalogVersion: "20260925-bbbbbbb",
      minAppVersion: "1.0.0",
      revokedKids: [],
      generatedAt: NOW.toISOString(),
      versionHistory: [{ version: "20260925-bbbbbbb", publishedAt: NOW.toISOString(), kid: "kid-1", sha256: "b".repeat(64) }],
      shards: [{ path: "id-ledger.json", bytes: ledgerBytes }],
    });
    const state = makeFakeImporterState(NOW);
    state.signingKeys.set("kid-1", { kid: "kid-1", publicKeyB64Url, revokedAt: null });
    const repo = makeFakeImporterRepo(state);
    const fetchBytes = fetcherFor(artifact);

    const started = performance.now();
    const outcome = await runImport({ artifactBaseUrl: BASE_URL, allowedHosts: ALLOWED_HOSTS }, repo, fetchBytes, getSigningKeyFor(repo));
    const elapsedMs = performance.now() - started;

    expect(outcome.ok).toBe(true);
    if (!outcome.ok) throw new Error("unreachable");
    expect(outcome.ledgerEntriesApplied).toBe(N);
    // eslint-disable-next-line no-console
    console.log(`H3 scale test (unit, fake repo, ${N} ledger ids): ${elapsedMs.toFixed(1)}ms`);
    expect(elapsedMs).toBeLessThan(5_000);
  }, 20_000);
});

// ⛔ NEW (P3e round 2 gate, M3 + H3 early exit).
describe("import-catalog — M3: ledger conflicts and revoked kids", () => {
  async function importTwo(second: (v1: string, v2: string, kid: string, privateKey: CryptoKey) => Promise<Awaited<ReturnType<typeof buildSignedArtifact>>>) {
    const { privateKey, publicKeyB64Url } = await generateKeypair();
    const kid = "kid-m3";
    const SURV_A = "fac_01ARZ3NDEKTSV4RRFFQ69G5FA1";
    const SURV_B = "fac_01ARZ3NDEKTSV4RRFFQ69G5FA2";
    const MERGED = "fac_01ARZ3NDEKTSV4RRFFQ69G5FA3";
    const v1 = "20260901-1111111";
    const v2 = "20260925-2222222";
    const state = makeFakeImporterState(NOW);
    state.signingKeys.set(kid, { kid, publicKeyB64Url, revokedAt: null });
    const repo = makeFakeImporterRepo(state);
    const first = await buildSignedArtifact({
      privateKey, kid, contractVersion: 1, catalogVersion: v1, minAppVersion: "1.0.0", revokedKids: [], generatedAt: NOW.toISOString(),
      versionHistory: [{ version: v1, publishedAt: "2026-09-01T00:00:00.000Z", kid, sha256: "a".repeat(64) }],
      shards: [{ path: "id-ledger.json", bytes: jsonBytes({ entries: {
        [SURV_A]: { id: SURV_A, status: "verified", transitions: [{ type: "minted", catalogVersion: v1 }] },
        [MERGED]: { id: MERGED, status: "verified", tombstoned: true, mergedInto: SURV_A, transitions: [{ type: "minted", catalogVersion: v1 }, { type: "merged", catalogVersion: v1 }] },
      } }) }],
    });
    const o1 = await runImport({ artifactBaseUrl: BASE_URL, allowedHosts: ALLOWED_HOSTS }, repo, fetcherFor(first), getSigningKeyFor(repo));
    expect(o1.ok).toBe(true);
    const art2 = await second(v1, v2, kid, privateKey);
    const o2 = await runImport({ artifactBaseUrl: BASE_URL, allowedHosts: ALLOWED_HOSTS }, repo, fetcherFor(art2), getSigningKeyFor(repo));
    return { state, o2, ids: { SURV_A, SURV_B, MERGED, v1, v2 } };
  }

  it("a later ledger claiming a DIFFERENT mergedInto is rejected (fail closed), stored value unchanged", async () => {
    const { state, o2, ids } = await importTwo(async (v1, v2, kid, privateKey) =>
      buildSignedArtifact({
        privateKey, kid, contractVersion: 1, catalogVersion: v2, minAppVersion: "1.0.0", revokedKids: [], generatedAt: NOW.toISOString(),
        versionHistory: [
          { version: v1, publishedAt: "2026-09-01T00:00:00.000Z", kid, sha256: "a".repeat(64) },
          { version: v2, publishedAt: NOW.toISOString(), kid, sha256: "b".repeat(64) },
        ],
        shards: [{ path: "id-ledger.json", bytes: jsonBytes({ entries: {
          ["fac_01ARZ3NDEKTSV4RRFFQ69G5FA1"]: { id: "fac_01ARZ3NDEKTSV4RRFFQ69G5FA1", status: "verified", transitions: [{ type: "minted", catalogVersion: v1 }] },
          ["fac_01ARZ3NDEKTSV4RRFFQ69G5FA2"]: { id: "fac_01ARZ3NDEKTSV4RRFFQ69G5FA2", status: "verified", transitions: [{ type: "minted", catalogVersion: v2 }] },
          ["fac_01ARZ3NDEKTSV4RRFFQ69G5FA3"]: { id: "fac_01ARZ3NDEKTSV4RRFFQ69G5FA3", status: "verified", tombstoned: true, mergedInto: "fac_01ARZ3NDEKTSV4RRFFQ69G5FA2", transitions: [{ type: "minted", catalogVersion: v1 }, { type: "merged", catalogVersion: v2 }] },
        } }) }],
      }),
    );
    expect(o2.ok).toBe(false);
    if (o2.ok) throw new Error("unreachable");
    expect(o2.reason).toContain(ids.MERGED);
    expect(state.ledger.get(ids.MERGED)!.mergedInto).toBe(ids.SURV_A);
  });

  it("a later ledger reversing a tombstone is rejected", async () => {
    const { o2, ids } = await importTwo(async (v1, v2, kid, privateKey) =>
      buildSignedArtifact({
        privateKey, kid, contractVersion: 1, catalogVersion: v2, minAppVersion: "1.0.0", revokedKids: [], generatedAt: NOW.toISOString(),
        versionHistory: [
          { version: v1, publishedAt: "2026-09-01T00:00:00.000Z", kid, sha256: "a".repeat(64) },
          { version: v2, publishedAt: NOW.toISOString(), kid, sha256: "b".repeat(64) },
        ],
        shards: [{ path: "id-ledger.json", bytes: jsonBytes({ entries: {
          ["fac_01ARZ3NDEKTSV4RRFFQ69G5FA1"]: { id: "fac_01ARZ3NDEKTSV4RRFFQ69G5FA1", status: "verified", transitions: [{ type: "minted", catalogVersion: v1 }] },
          ["fac_01ARZ3NDEKTSV4RRFFQ69G5FA3"]: { id: "fac_01ARZ3NDEKTSV4RRFFQ69G5FA3", status: "verified", transitions: [{ type: "minted", catalogVersion: v1 }] },
        } }) }],
      }),
    );
    expect(o2.ok).toBe(false);
    if (o2.ok) throw new Error("unreachable");
    expect(o2.reason).toContain(ids.MERGED);
  });

  it("an identical re-assertion of the same merge is NOT a conflict (and a later release still imports)", async () => {
    const { o2 } = await importTwo(async (v1, v2, kid, privateKey) =>
      buildSignedArtifact({
        privateKey, kid, contractVersion: 1, catalogVersion: v2, minAppVersion: "1.0.0", revokedKids: [], generatedAt: NOW.toISOString(),
        versionHistory: [
          { version: v1, publishedAt: "2026-09-01T00:00:00.000Z", kid, sha256: "a".repeat(64) },
          { version: v2, publishedAt: NOW.toISOString(), kid, sha256: "b".repeat(64) },
        ],
        shards: [{ path: "id-ledger.json", bytes: jsonBytes({ entries: {
          ["fac_01ARZ3NDEKTSV4RRFFQ69G5FA1"]: { id: "fac_01ARZ3NDEKTSV4RRFFQ69G5FA1", status: "verified", transitions: [{ type: "minted", catalogVersion: v1 }] },
          ["fac_01ARZ3NDEKTSV4RRFFQ69G5FA3"]: { id: "fac_01ARZ3NDEKTSV4RRFFQ69G5FA3", status: "verified", tombstoned: true, mergedInto: "fac_01ARZ3NDEKTSV4RRFFQ69G5FA1", transitions: [{ type: "minted", catalogVersion: v1 }, { type: "merged", catalogVersion: v1 }] },
        } }) }],
      }),
    );
    expect(o2.ok).toBe(true);
  });

  it("a manifest whose revokedKids names the kid that signed versions.json is a hard reject", async () => {
    const { privateKey, publicKeyB64Url } = await generateKeypair();
    const state = makeFakeImporterState(NOW);
    state.signingKeys.set("kid-1", { kid: "kid-1", publicKeyB64Url, revokedAt: null });
    const repo = makeFakeImporterRepo(state);
    const artifact = await buildSignedArtifact({
      privateKey, kid: "kid-1", contractVersion: 1, catalogVersion: "20260925-bbbbbbb", minAppVersion: "1.0.0", revokedKids: ["kid-1"], generatedAt: NOW.toISOString(),
      versionHistory: [{ version: "20260925-bbbbbbb", publishedAt: NOW.toISOString(), kid: "kid-1", sha256: "b".repeat(64) }], shards: [],
    });
    const o = await runImport({ artifactBaseUrl: BASE_URL, allowedHosts: ALLOWED_HOSTS }, repo, fetcherFor(artifact), getSigningKeyFor(repo));
    expect(o.ok).toBe(false);
  });

  it("a verified manifest's revokedKids are RECORDED, and a later import signed by a recorded-revoked kid is rejected as catalog_stale", async () => {
    const { privateKey, publicKeyB64Url } = await generateKeypair();
    const k2 = await generateKeypair();
    const state = makeFakeImporterState(NOW);
    state.signingKeys.set("kid-good", { kid: "kid-good", publicKeyB64Url: k2.publicKeyB64Url, revokedAt: null });
    state.signingKeys.set("kid-old", { kid: "kid-old", publicKeyB64Url, revokedAt: null });
    const repo = makeFakeImporterRepo(state);
    const a1 = await buildSignedArtifact({
      privateKey: k2.privateKey, kid: "kid-good", contractVersion: 1, catalogVersion: "20260925-bbbbbbb", minAppVersion: "1.0.0", revokedKids: ["kid-old"], generatedAt: NOW.toISOString(),
      versionHistory: [{ version: "20260925-bbbbbbb", publishedAt: NOW.toISOString(), kid: "kid-good", sha256: "b".repeat(64) }], shards: [],
    });
    expect((await runImport({ artifactBaseUrl: BASE_URL, allowedHosts: ALLOWED_HOSTS }, repo, fetcherFor(a1), getSigningKeyFor(repo))).ok).toBe(true);
    expect(state.revokedKids.has("kid-old")).toBe(true);
    const a2 = await buildSignedArtifact({
      privateKey, kid: "kid-old", contractVersion: 1, catalogVersion: "20260926-ccccccc", minAppVersion: "1.0.0", revokedKids: [], generatedAt: NOW.toISOString(),
      versionHistory: [{ version: "20260926-ccccccc", publishedAt: NOW.toISOString(), kid: "kid-old", sha256: "c".repeat(64) }], shards: [],
    });
    const o2 = await runImport({ artifactBaseUrl: BASE_URL, allowedHosts: ALLOWED_HOSTS }, repo, fetcherFor(a2), getSigningKeyFor(repo));
    expect(o2.ok).toBe(false);
    if (o2.ok) throw new Error("unreachable");
    expect(o2.reason).toBe("catalog_stale");
  });
});

describe("import-catalog — H3: early exit when the version is already imported", () => {
  it("a re-import of the same artifact reports alreadyImported and applies nothing", async () => {
    const { repo, fetchBytes } = await setupHappyPath();
    await runImport({ artifactBaseUrl: BASE_URL, allowedHosts: ALLOWED_HOSTS }, repo, fetchBytes, getSigningKeyFor(repo));
    const second = await runImport({ artifactBaseUrl: BASE_URL, allowedHosts: ALLOWED_HOSTS }, repo, fetchBytes, getSigningKeyFor(repo));
    expect(second.ok).toBe(true);
    if (!second.ok) throw new Error("unreachable");
    expect((second as { alreadyImported?: boolean }).alreadyImported).toBe(true);
    expect((second as { ledgerEntriesApplied?: number }).ledgerEntriesApplied).toBe(0);
  });
});

// ⛔ NEW (P3e round 2 gate, LOW): a conflicting split_from fails closed, like M3.
describe("import-catalog — split_from conflicts fail closed (like M3)", () => {
  it("an import claiming a DIFFERENT kept course for an already-split sibling is rejected, whole", async () => {
    const state = makeFakeImporterState(NOW);
    const repo = makeFakeImporterRepo(state);
    state.ledger.set("crs_sib", { id: "crs_sib", kind: "course", status: "verified", mergedInto: null, tombstonedAt: null, firstCatalogVersion: 1, verifiedInVersion: 1, splitFrom: "crs_keptA" });
    const conflict = await repo.catalog.findLedgerConflict([
      { id: "crs_keptB", status: "verified", tombstoned: false, mergedInto: null, verifiedInVersionInt: 1, splitSiblings: ["crs_sib"] },
    ]);
    expect(conflict).toContain("already on file as split from \"crs_keptA\"");
  });

  it("the SAME kept course re-asserting an already-recorded split is not a conflict", async () => {
    const state = makeFakeImporterState(NOW);
    const repo = makeFakeImporterRepo(state);
    state.ledger.set("crs_sib", { id: "crs_sib", kind: "course", status: "verified", mergedInto: null, tombstonedAt: null, firstCatalogVersion: 1, verifiedInVersion: 1, splitFrom: "crs_keptA" });
    expect(await repo.catalog.findLedgerConflict([{ id: "crs_keptA", status: "verified", tombstoned: false, mergedInto: null, verifiedInVersionInt: 1, splitSiblings: ["crs_sib"] }])).toBeNull();
  });

  it("two kept courses claiming one sibling inside a single ledger is a conflict", async () => {
    const repo = makeFakeImporterRepo(makeFakeImporterState(NOW));
    const conflict = await repo.catalog.findLedgerConflict([
      { id: "crs_a", status: "verified", tombstoned: false, mergedInto: null, verifiedInVersionInt: 1, splitSiblings: ["crs_sib"] },
      { id: "crs_b", status: "verified", tombstoned: false, mergedInto: null, verifiedInVersionInt: 1, splitSiblings: ["crs_sib"] },
    ]);
    expect(conflict).toContain("claimed by both");
  });
});

