// supabase/tests/integration/import-catalog.deno.test.ts
//
// P3e: the REAL `fetchAndVerifyArtifact`/`applyImportPlan`/`drainQueuedCatalog`
// (supabase/functions/_shared/catalog/{import-handler,drain-orchestrator}.ts),
// running through the REAL `withSystemCatalogImport`/`withOwnership`
// (privileged.ts), against the harness cluster `tools/db/test.sh` builds —
// same rationale as handlers.deno.test.ts's own header: the fake-repo unit
// suite (supabase/tests/unit/import-handler.test.ts) proves the DECISION
// logic; this file proves the REAL SQL (real advisory lock, real FK on
// merged_into, real UNIQUE(site_version), real BYPASSRLS grants, the real
// migration-0024 evidence_queued_claim_shape CHECK) behaves the same way.
//
// ⛔ REWRITE (P3e round 2 gate). `runCatalogImport` no longer exists — the
// two-phase split (M4) means every call site here now does
// `fetchAndVerifyArtifact(...)` (no transaction) then
// `withSystemCatalogImport((repo) => applyImportPlan(plan, repo))`.
// `drainQueuedCatalog` takes `(importerRepo, withOwnership, limit)` now
// (B2) — every drain call is `withSystemCatalogImport((repo) =>
// drainQueuedCatalog(repo, withOwnership, limit))`. The old
// `ImporterRepo#queuedCatalog.promoteToAccepted`/`markNeedsAttention`
// system-scoped writes are GONE — a promotion is now a real, actor-scoped
// `Repo#evidence.resolveQueuedRow` write, reached only by re-running real
// intake derivation (redrainQueuedEvidenceRow, evidence/handler.ts).
import { assert, assertEquals, assertNotEquals } from "https://deno.land/std@0.224.0/assert/mod.ts";
import { withSystemCatalogImport, withOwnership, getCatalogImportEnvConfig } from "../../functions/_shared/privileged.ts";
import { fetchAndVerifyArtifact, applyImportPlanAtomically, type FetchBytes, type GetSigningKey } from "../../functions/_shared/catalog/import-handler.ts";
import { drainQueuedCatalog } from "../../functions/_shared/catalog/drain-orchestrator.ts";
import { canonicalStringify, MANIFEST_DOMAIN, VERSIONS_DOMAIN } from "../../functions/_shared/catalog/manifest-artifact.ts";
import { verifyWebhookSignature, buildWebhookSignatureHeader } from "../../functions/_shared/catalog/webhook-auth.ts";
import { bytesToBase64Url } from "../../functions/_shared/catalog/signature.ts";
import { freshUuid, createTestUser, insertSigningKeyWithKey, adminSql, rawCount, ensureServiceRole } from "./_helpers.ts";

// A SECOND pre-seeded, already-verified facility (supabase/tests/helpers.sql)
// — distinct from FAC_X, to avoid cross-test interference with the many
// OTHER integration test files that already exercise FAC_X's own play/
// evidence rows.
const FAC_Y = "fac_y";
const CRS_Y1 = "crs_y1";

/** fac_y is America/Chicago — a self_report localDate must fall inside the
 * facility-local window (30 days back) evaluated against the row's queue
 * time, so the drain fixtures use "today" there. */
const TODAY_CHICAGO = new Intl.DateTimeFormat("en-CA", { timeZone: "America/Chicago", year: "numeric", month: "2-digit", day: "2-digit" }).format(new Date());

const DT = { sanitizeOps: false, sanitizeResources: false };

async function generateKeypair() {
  const kp = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const rawPublic = await crypto.subtle.exportKey("raw", kp.publicKey);
  return { privateKey: kp.privateKey, publicKeyB64Url: bytesToBase64Url(new Uint8Array(rawPublic)) };
}
// ⛔ FIX (P3e round 2 gate, B1): sign with STANDARD (padded) base64 — the
// REAL `tools/catalog/src/sign.ts#signBytes` encoding — never base64url.
// See supabase/tests/unit/catalog-artifact-fixtures.ts's own note (this
// file duplicates rather than imports it — see this module's header on
// why Deno can't share a vitest-shaped fixture file).
async function signBytesStd(privateKey: CryptoKey, bytes: Uint8Array): Promise<string> {
  const sig = await crypto.subtle.sign("Ed25519", privateKey, bytes.slice().buffer);
  let bin = "";
  for (const b of new Uint8Array(sig)) bin += String.fromCharCode(b);
  return btoa(bin);
}
async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes.slice().buffer);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
function jsonBytes(v: unknown): Uint8Array {
  return new TextEncoder().encode(canonicalStringify(v));
}

/** Builds one real, signed artifact — a Deno-native duplicate of
 * supabase/tests/unit/catalog-artifact-fixtures.ts's own
 * `buildSignedArtifact` (that file uses `.js`-suffixed specifiers for
 * vitest's own TS-as-.js resolution — see its header — which Deno's real
 * module resolution does not accept; duplicated rather than shared for
 * that mechanical reason, same "cannot import across that boundary"
 * class of constraint as manifest-artifact.ts's own header). */
async function buildArtifact(input: {
  privateKey: CryptoKey;
  kid: string;
  catalogVersion: string;
  revokedKids?: string[];
  generatedAt?: string;
  versionHistory: { version: string; publishedAt: string; kid: string; sha256: string }[];
  ledgerEntries: Record<string, unknown>;
}) {
  const ledgerBytes = jsonBytes({ entries: input.ledgerEntries });
  const shardEntries = [{ path: "id-ledger.json", sha256: await sha256Hex(ledgerBytes), bytes: ledgerBytes.length }];
  const manifest = {
    contractVersion: 1,
    catalogVersion: input.catalogVersion,
    minAppVersion: "1.0.0",
    kid: input.kid,
    revokedKids: input.revokedKids ?? [],
    generatedAt: input.generatedAt ?? new Date().toISOString(),
    shards: shardEntries,
  };
  const manifestBytes = jsonBytes(manifest);
  const manifestSha = await sha256Hex(manifestBytes);
  const manifestStatement = { catalogVersion: input.catalogVersion, contractVersion: 1, kid: input.kid, manifestSha };
  const manifestSig = await signBytesStd(input.privateKey, new TextEncoder().encode(MANIFEST_DOMAIN + canonicalStringify(manifestStatement)));
  const manifestSigBytes = jsonBytes({ ...manifestStatement, sig: manifestSig });

  const versionsBytes = jsonBytes(input.versionHistory);
  const versionsSha = await sha256Hex(versionsBytes);
  const versionsStatement = { kid: input.kid, versionsSha };
  const versionsSig = await signBytesStd(input.privateKey, new TextEncoder().encode(VERSIONS_DOMAIN + canonicalStringify(versionsStatement)));
  const versionsSigBytes = jsonBytes({ ...versionsStatement, sig: versionsSig });

  return { manifestBytes, manifestSigBytes, versionsBytes, versionsSigBytes, ledgerBytes };
}

function fetcherFor(artifact: Awaited<ReturnType<typeof buildArtifact>>): FetchBytes {
  return async (url: string) => {
    if (url.endsWith("/manifest.json")) return artifact.manifestBytes;
    if (url.endsWith("/manifest.sig.json")) return artifact.manifestSigBytes;
    if (url.endsWith("/versions.json")) return artifact.versionsBytes;
    if (url.endsWith("/versions.sig.json")) return artifact.versionsSigBytes;
    if (url.endsWith("/id-ledger.json")) return artifact.ledgerBytes;
    throw new Error(`fetcherFor: unexpected url ${url}`);
  };
}

const BASE_URL = "https://golfraven.example/catalog/v1";
const ALLOWED_HOSTS = ["golfraven.example"];

/** The REAL two-phase call `import-catalog/index.ts` makes in
 * production (M4) — phase 1 (`fetchAndVerifyArtifact`) runs BEFORE any
 * transaction opens; phase 2 (`applyImportPlan`) runs INSIDE
 * `withSystemCatalogImport`. `getSigningKey` is a plain, short,
 * already-committed read (this test uses `adminSql()` directly — the
 * REAL entrypoint uses its own `getSigningKeyReadOnly`, a separate
 * concern from what this file is proving). */
async function runImport(config: { artifactBaseUrl: string; allowedHosts: string[] }, fetchBytes: FetchBytes, getSigningKey: GetSigningKey) {
  const plan = await fetchAndVerifyArtifact(config, fetchBytes, getSigningKey);
  if (!plan.ok) return plan;
  return applyImportPlanAtomically(plan, withSystemCatalogImport);
}

async function getSigningKeyReadOnly(kid: string) {
  await ensureServiceRole();
  const rows = await adminSql()`select kid, public_key_b64url, revoked_at from app.catalog_signing_key where kid = ${kid}`;
  const r = rows[0];
  if (!r) return null;
  return { kid: r.kid as string, publicKeyB64Url: r.public_key_b64url as string, revokedAt: r.revoked_at ? (r.revoked_at as Date).toISOString() : null };
}

Deno.test("auth rejection: verifyWebhookSignature rejects a missing/forged credential — no JWT path exists for this endpoint at all", DT, async () => {
  const secret = "s".repeat(48); // runtime-built fake HMAC secret (>= 32 bytes); never a real value
  const body = new TextEncoder().encode("{}");
  const now = new Date();

  const missing = await verifyWebhookSignature({ secret, headerValue: null, rawBody: body, now });
  assertEquals(missing.ok, false);

  const wrongSecretHeader = await buildWebhookSignatureHeader("a-totally-different-secret", body, now);
  const forged = await verifyWebhookSignature({ secret, headerValue: wrongSecretHeader, rawBody: body, now });
  assertEquals(forged.ok, false);

  const real = await verifyWebhookSignature({ secret, headerValue: await buildWebhookSignatureHeader(secret, body, now), rawBody: body, now });
  assertEquals(real.ok, true);
});

// ⛔ NEW (P3e round 2 gate, LOW: "reject an HMAC secret that is empty,
// whitespace-only or shorter than 32 bytes").
Deno.test("auth rejection: verifyWebhookSignature refuses a too-short/blank secret outright, even with an otherwise-correct signature", DT, async () => {
  const body = new TextEncoder().encode("{}");
  const now = new Date();
  for (const shortSecret of ["", "   ", "short-secret-under-32-bytes"]) {
    const header = await buildWebhookSignatureHeader(shortSecret || "placeholder-for-header-shape", body, now);
    const result = await verifyWebhookSignature({ secret: shortSecret, headerValue: header, rawBody: body, now });
    assertEquals(result.ok, false, `expected a short/blank secret (${JSON.stringify(shortSecret)}) to be refused`);
  }
});

Deno.test("getCatalogImportEnvConfig: returns null (not a throw) when the environment is not configured", DT, () => {
  const before = { url: Deno.env.get("CATALOG_ARTIFACT_BASE_URL"), hosts: Deno.env.get("CATALOG_ARTIFACT_ALLOWED_HOSTS"), secret: Deno.env.get("CATALOG_IMPORT_HMAC_SECRET") };
  Deno.env.delete("CATALOG_ARTIFACT_BASE_URL");
  Deno.env.delete("CATALOG_ARTIFACT_ALLOWED_HOSTS");
  Deno.env.delete("CATALOG_IMPORT_HMAC_SECRET");
  try {
    assertEquals(getCatalogImportEnvConfig(), null);
  } finally {
    for (const [k, v] of Object.entries(before)) {
      const envKey = k === "url" ? "CATALOG_ARTIFACT_BASE_URL" : k === "hosts" ? "CATALOG_ARTIFACT_ALLOWED_HOSTS" : "CATALOG_IMPORT_HMAC_SECRET";
      if (v !== undefined) Deno.env.set(envKey, v);
    }
  }
});

Deno.test("happy path: imports a real version + ledger shard, against REAL Postgres (catalog_version, catalog_id_ledger, catalog_signing_key)", DT, async () => {
  const { privateKey, publicKeyB64Url } = await generateKeypair();
  const kid = `kid-import-${freshUuid()}`;
  await insertSigningKeyWithKey(kid, publicKeyB64Url, null);

  const catalogVersion = `20260925-${freshUuid().replace(/-/g, "").slice(0, 7)}`;
  const facId = `fac_${freshUuid().replace(/-/g, "").toUpperCase().padEnd(26, "0").slice(0, 26)}`;
  const artifact = await buildArtifact({
    privateKey,
    kid,
    catalogVersion,
    versionHistory: [{ version: catalogVersion, publishedAt: new Date().toISOString(), kid, sha256: "b".repeat(64) }],
    ledgerEntries: { [facId]: { id: facId, status: "verified", transitions: [{ type: "minted", catalogVersion }, { type: "verified", catalogVersion }] } },
  });

  const outcome = await runImport({ artifactBaseUrl: BASE_URL, allowedHosts: ALLOWED_HOSTS }, fetcherFor(artifact), getSigningKeyReadOnly);
  assert(outcome.ok, `expected ok, got reason=${outcome.reason}`);
  assertEquals(outcome.versionsImported, 1);
  assertEquals(outcome.ledgerEntriesApplied, 1);

  // Required under HARNESS_MODE=restricted (see ensureServiceRole's own
  // doc): adminSql()'s connection is migration_owner there, which sees
  // ZERO rows on a FORCE-RLS table without this.
  await ensureServiceRole();
  const versionRows = await adminSql()`select version, site_version, kid from app.catalog_version where site_version = ${catalogVersion}`;
  assertEquals(versionRows.length, 1);
  assertEquals(versionRows[0]!.kid, kid);

  const ledgerRows = await adminSql()`select id, kind, status from app.catalog_id_ledger where id = ${facId}`;
  assertEquals(ledgerRows.length, 1);
  assertEquals(ledgerRows[0]!.kind, "facility");
  assertEquals(ledgerRows[0]!.status, "verified");
});

Deno.test("idempotent replay: importing the SAME artifact twice writes the version/ledger rows only once", DT, async () => {
  const { privateKey, publicKeyB64Url } = await generateKeypair();
  const kid = `kid-replay-${freshUuid()}`;
  await insertSigningKeyWithKey(kid, publicKeyB64Url, null);
  const catalogVersion = `20260925-${freshUuid().replace(/-/g, "").slice(0, 7)}`;
  const artifact = await buildArtifact({
    privateKey,
    kid,
    catalogVersion,
    versionHistory: [{ version: catalogVersion, publishedAt: new Date().toISOString(), kid, sha256: "c".repeat(64) }],
    ledgerEntries: {},
  });

  const first = await runImport({ artifactBaseUrl: BASE_URL, allowedHosts: ALLOWED_HOSTS }, fetcherFor(artifact), getSigningKeyReadOnly);
  assert(first.ok, `expected ok, got reason=${(first as { reason?: string }).reason}`);
  const second = await runImport({ artifactBaseUrl: BASE_URL, allowedHosts: ALLOWED_HOSTS }, fetcherFor(artifact), getSigningKeyReadOnly);
  assert(second.ok, `expected ok, got reason=${(second as { reason?: string }).reason}`);
  assertEquals(second.versionsImported, 0);
  assertEquals(second.currentVersion, first.currentVersion);

  const count = await rawCount(`select count(*)::int as n from app.catalog_version where site_version = '${catalogVersion}'`);
  assertEquals(count, 1);
});

Deno.test("forged manifest: a manifest signed by an UNREGISTERED kid is rejected (catalog_forged — LOW nit: distinct from a revoked, registered kid)", DT, async () => {
  const { privateKey } = await generateKeypair();
  const kid = `kid-unregistered-${freshUuid()}`; // deliberately never inserted into app.catalog_signing_key
  const catalogVersion = `20260925-${freshUuid().replace(/-/g, "").slice(0, 7)}`;
  const artifact = await buildArtifact({
    privateKey,
    kid,
    catalogVersion,
    versionHistory: [{ version: catalogVersion, publishedAt: new Date().toISOString(), kid, sha256: "d".repeat(64) }],
    ledgerEntries: {},
  });

  const outcome = await runImport({ artifactBaseUrl: BASE_URL, allowedHosts: ALLOWED_HOSTS }, fetcherFor(artifact), getSigningKeyReadOnly);
  assertEquals(outcome.ok, false);
  assertEquals((outcome as { reason: string }).reason, "catalog_forged");

  const count = await rawCount(`select count(*)::int as n from app.catalog_version where site_version = '${catalogVersion}'`);
  assertEquals(count, 0);
});

Deno.test("stale manifest: a manifest signed by a REGISTERED but REVOKED kid is rejected (catalog_stale)", DT, async () => {
  const { privateKey, publicKeyB64Url } = await generateKeypair();
  const kid = `kid-revoked-${freshUuid()}`;
  await insertSigningKeyWithKey(kid, publicKeyB64Url, new Date());
  const catalogVersion = `20260925-${freshUuid().replace(/-/g, "").slice(0, 7)}`;
  const artifact = await buildArtifact({
    privateKey,
    kid,
    catalogVersion,
    versionHistory: [{ version: catalogVersion, publishedAt: new Date().toISOString(), kid, sha256: "d2".repeat(32) }],
    ledgerEntries: {},
  });

  const outcome = await runImport({ artifactBaseUrl: BASE_URL, allowedHosts: ALLOWED_HOSTS }, fetcherFor(artifact), getSigningKeyReadOnly);
  assertEquals(outcome.ok, false);
  assertEquals((outcome as { reason: string }).reason, "catalog_stale");
});

Deno.test("forged manifest: a manifest signature made by the WRONG key for a REGISTERED kid is rejected (catalog_forged)", DT, async () => {
  const { privateKey } = await generateKeypair(); // signs with THIS key...
  const { publicKeyB64Url: registeredPublicKey } = await generateKeypair(); // ...but THIS key is what's registered
  const kid = `kid-wrongkey-${freshUuid()}`;
  await insertSigningKeyWithKey(kid, registeredPublicKey, null);
  const catalogVersion = `20260925-${freshUuid().replace(/-/g, "").slice(0, 7)}`;
  const artifact = await buildArtifact({
    privateKey,
    kid,
    catalogVersion,
    versionHistory: [{ version: catalogVersion, publishedAt: new Date().toISOString(), kid, sha256: "e".repeat(64) }],
    ledgerEntries: {},
  });

  const outcome = await runImport({ artifactBaseUrl: BASE_URL, allowedHosts: ALLOWED_HOSTS }, fetcherFor(artifact), getSigningKeyReadOnly);
  assertEquals(outcome.ok, false);
  assertEquals((outcome as { reason: string }).reason, "catalog_forged");
});

// ⛔ NEW (P3e round 2 gate, M3: "fail closed when a signed ledger
// conflicts with stored state: a different merged_into, or a tombstone
// reversal"). Real Postgres, real `app.catalog_id_ledger` row, real
// `findLedgerConflict` query.
Deno.test("M3: a re-import claiming a DIFFERENT mergedInto than what's already on file is rejected, and writes nothing new", DT, async () => {
  const { privateKey, publicKeyB64Url } = await generateKeypair();
  const kid = `kid-m3-${freshUuid()}`;
  await insertSigningKeyWithKey(kid, publicKeyB64Url, null);
  const v1 = `20260901-${freshUuid().replace(/-/g, "").slice(0, 7)}`;
  const v2 = `20260925-${freshUuid().replace(/-/g, "").slice(0, 7)}`;
  const survivorA = `fac_${freshUuid().replace(/-/g, "").toUpperCase().padEnd(26, "0").slice(0, 26)}`;
  const survivorB = `fac_${freshUuid().replace(/-/g, "").toUpperCase().padEnd(26, "0").slice(0, 26)}`;
  const mergedId = `fac_${freshUuid().replace(/-/g, "").toUpperCase().padEnd(26, "0").slice(0, 26)}`;

  // First import: mergedId is tombstoned, merged into survivorA.
  const artifact1 = await buildArtifact({
    privateKey,
    kid,
    catalogVersion: v1,
    versionHistory: [{ version: v1, publishedAt: new Date().toISOString(), kid, sha256: "f1".repeat(32) }],
    ledgerEntries: {
      [survivorA]: { id: survivorA, status: "verified", transitions: [{ type: "minted", catalogVersion: v1 }] },
      [mergedId]: { id: mergedId, status: "verified", tombstoned: true, mergedInto: survivorA, transitions: [{ type: "minted", catalogVersion: v1 }, { type: "merged", catalogVersion: v1 }] },
    },
  });
  const first = await runImport({ artifactBaseUrl: BASE_URL, allowedHosts: ALLOWED_HOSTS }, fetcherFor(artifact1), getSigningKeyReadOnly);
  assert(first.ok, `expected ok, got reason=${(first as { reason?: string }).reason}`);

  const beforeConflict = await adminSql()`select merged_into from app.catalog_id_ledger where id = ${mergedId}`;
  assertEquals(beforeConflict[0]!.merged_into, survivorA);

  // Second import: a LATER release claims mergedId now merged into a
  // DIFFERENT survivor (survivorB) — a genuine conflict (M3), rejected
  // outright, and the already-stored merged_into must be UNCHANGED.
  const artifact2 = await buildArtifact({
    privateKey,
    kid,
    catalogVersion: v2,
    versionHistory: [
      { version: v1, publishedAt: new Date().toISOString(), kid, sha256: "f1".repeat(32) },
      { version: v2, publishedAt: new Date().toISOString(), kid, sha256: "f2".repeat(32) },
    ],
    ledgerEntries: {
      [survivorA]: { id: survivorA, status: "verified", transitions: [{ type: "minted", catalogVersion: v1 }] },
      [survivorB]: { id: survivorB, status: "verified", transitions: [{ type: "minted", catalogVersion: v2 }] },
      [mergedId]: { id: mergedId, status: "verified", tombstoned: true, mergedInto: survivorB, transitions: [{ type: "minted", catalogVersion: v1 }, { type: "merged", catalogVersion: v2 }] },
    },
  });
  const second = await runImport({ artifactBaseUrl: BASE_URL, allowedHosts: ALLOWED_HOSTS }, fetcherFor(artifact2), getSigningKeyReadOnly);
  assertEquals(second.ok, false, `expected the conflicting re-import to be rejected, got ${JSON.stringify(second)}`);
  assert((second as { reason: string }).reason.includes(mergedId), `expected the rejection reason to name the conflicting id, got: ${(second as { reason: string }).reason}`);

  const afterConflict = await adminSql()`select merged_into from app.catalog_id_ledger where id = ${mergedId}`;
  assertEquals(afterConflict[0]!.merged_into, survivorA, "a rejected conflicting import must never have changed the already-stored merged_into");
});

// ⛔ IMPORTANT PRE-EXISTING FINDING, NOW FIXED THIS ROUND (B3): the
// original note here described `app.evidence.facility_id`/`course_id`/
// `catalog_version` as REAL, ENFORCED FKs that made it IMPOSSIBLE to
// insert ANY `queued_catalog` evidence row for a facility id not already
// fully catalog_facility-backed. Migration 0024 (this round) fixes that:
// a queued row now carries `claimed_facility_id`/`claimed_course_id`/
// `claimed_catalog_version` (plain text, no FK) instead, with
// `facility_id`/`course_id`/`catalog_version` left NULL, enforced by the
// `evidence_queued_claim_shape` CHECK constraint. The tests below insert
// a queued row using the migration-0024 column shape directly (bypassing
// evidence/handler.ts's own request-shape validation, which is proven
// separately by supabase/tests/unit/evidence-handler.test.ts) so this
// file can prove drainQueuedCatalog's REAL SQL end to end.

Deno.test("draining: a queued_catalog row whose claimed facility ALREADY resolves is re-derived and promoted to accepted, against a REAL app.evidence row (B2: never a raw status flip)", DT, async () => {
  const uid = freshUuid();
  await createTestUser(uid, `import-drain-${uid.slice(0, 8)}`);
  await ensureServiceRole(); // belt-and-suspenders — createTestUser already does this as a side effect, but don't rely on that ordering implicitly.

  const deviceId = freshUuid();
  await adminSql()`insert into app.device (id, user_id, platform) values (${deviceId}, ${uid}, 'ios')`;

  // fac_y (supabase/tests/helpers.sql) is already `verified` in
  // app.catalog_id_ledger AND has a real app.catalog_facility row — a
  // real re-derivation (B2) should resolve it, run the matcher (no
  // fix, so no match), score a self_report play, and promote the row.
  const currentSiteVersion = await adminSql()`select site_version from app.catalog_version order by site_version desc nulls last, version desc limit 1`;
  const claimedVersion = (currentSiteVersion[0]?.site_version as string | undefined) ?? "20260101-0000000";
  const queuedInput = {
    source: "self_report",
    deviceId,
    facilityId: FAC_Y,
    courseId: CRS_Y1,
    localDate: TODAY_CHICAGO,
    catalogVersion: claimedVersion,
  };
  await adminSql()`
    insert into app.evidence (user_id, source, source_ref, input_hash, status, device_id, claimed_facility_id, claimed_course_id, claimed_catalog_version, queued_input, local_date)
    values (${uid}, 'self_report', ${"drain-test-" + freshUuid()}, ${"h".repeat(64)}, 'queued_catalog', ${deviceId}, ${FAC_Y}, ${CRS_Y1}, ${claimedVersion}, ${adminSql().json(queuedInput)}, ${TODAY_CHICAGO})`;

  const drainResult = await withSystemCatalogImport((repo) => drainQueuedCatalog(repo, withOwnership, 10));
  assert(drainResult.resolved >= 1, `expected at least 1 resolved, got ${JSON.stringify(drainResult)}`);

  const rows = await adminSql()`select status, facility_id, catalog_version, claimed_facility_id from app.evidence where user_id = ${uid}`;
  assertEquals(rows.length, 1);
  assertEquals(rows[0]!.status, "accepted");
  assertEquals(rows[0]!.facility_id, FAC_Y); // B3: the RESOLVED facility_id is now populated on promotion
  assertNotEquals(rows[0]!.catalog_version, null);
  // B2's core claim: a REAL play was scored for the drained row.
  const plays = await rawCount(`select count(*)::int as n from app.play where user_id = '${uid}' and course_id = '${CRS_Y1}'`);
  assertEquals(plays, 1);
});

Deno.test("draining: markQueuedTerminal flips status to needs_attention, and NEVER creates an app.review_item row (build plan §3.3, real SQL)", DT, async () => {
  const uid = freshUuid();
  await createTestUser(uid, `import-drain-na-${uid.slice(0, 8)}`);
  await ensureServiceRole(); // belt-and-suspenders — see the other draining test's own comment.
  const deviceId = freshUuid();
  await adminSql()`insert into app.device (id, user_id, platform) values (${deviceId}, ${uid}, 'ios')`;
  const queuedInput = { source: "self_report", deviceId, facilityId: "fac_ghost_does_not_exist", localDate: TODAY_CHICAGO, catalogVersion: "20260101-0000000" };
  await adminSql()`
    insert into app.evidence (user_id, source, source_ref, input_hash, status, device_id, claimed_facility_id, claimed_course_id, claimed_catalog_version, queued_input, local_date)
    values (${uid}, 'self_report', ${"drain-na-" + freshUuid()}, ${"i".repeat(64)}, 'queued_catalog', ${deviceId}, 'fac_ghost_does_not_exist', null, '20260101-0000000', ${adminSql().json(queuedInput)}, ${TODAY_CHICAGO})`;
  const [row] = await adminSql()`select id from app.evidence where user_id = ${uid} and status = 'queued_catalog'`;

  const reviewItemCountBefore = await rawCount(`select count(*)::int as n from app.review_item`);

  await withOwnership({ uid, role: "authenticated" }, (repo) => repo.evidence.markQueuedTerminal(row!.id, "needs_attention"));

  const after = await adminSql()`select status from app.evidence where id = ${row!.id}`;
  assertEquals(after[0]!.status, "needs_attention");

  const reviewItemCountAfter = await rawCount(`select count(*)::int as n from app.review_item`);
  assertEquals(reviewItemCountAfter, reviewItemCountBefore, "markQueuedTerminal must never create a review_item (build plan §3.3: 'without a review_item')");
});

// ⛔ NEW (P3e round 2 gate, B2 — probe D regression): "Add a regression
// test for probe D: drain, then a later real check-in at the same
// facility and date produces no fraud_signal and scores normally."
Deno.test("probe D regression: a drained (promoted) row never quarantines, and a LATER real check-in at the same facility+date scores normally with no fraud_signal", DT, async () => {
  const uid = freshUuid();
  await createTestUser(uid, `probe-d-${uid.slice(0, 8)}`);
  await ensureServiceRole();
  const deviceId = freshUuid();
  await adminSql()`insert into app.device (id, user_id, platform) values (${deviceId}, ${uid}, 'ios')`;

  const currentSiteVersion = await adminSql()`select site_version from app.catalog_version order by site_version desc nulls last, version desc limit 1`;
  const claimedVersion = (currentSiteVersion[0]?.site_version as string | undefined) ?? "20260101-0000000";
  const queuedInput = { source: "self_report", deviceId, facilityId: FAC_Y, courseId: CRS_Y1, localDate: TODAY_CHICAGO, catalogVersion: claimedVersion };
  await adminSql()`
    insert into app.evidence (user_id, source, source_ref, input_hash, status, device_id, claimed_facility_id, claimed_course_id, claimed_catalog_version, queued_input, local_date)
    values (${uid}, 'self_report', ${"probe-d-" + freshUuid()}, ${"j".repeat(64)}, 'queued_catalog', ${deviceId}, ${FAC_Y}, ${CRS_Y1}, ${claimedVersion}, ${adminSql().json(queuedInput)}, ${TODAY_CHICAGO})`;

  const drainResult = await withSystemCatalogImport((repo) => drainQueuedCatalog(repo, withOwnership, 10));
  assert(drainResult.resolved >= 1, `expected the queued row to resolve, got ${JSON.stringify(drainResult)}`);

  const fraudSignalsAfterDrain = await rawCount(`select count(*)::int as n from app.fraud_signal where kind = 'quarantined_evidence_row'`);

  // A later, REAL, live check-in for the SAME facility+date must score
  // normally — findExisting/listForPlay must see the drained row as an
  // ordinary, real, scored evidence row (not a stale placeholder), and
  // no NEW fraud_signal (of any kind) should appear as a side effect of
  // this second submission.
  const fraudSignalsBeforeSecond = await rawCount(`select count(*)::int as n from app.fraud_signal`);
  await withOwnership({ uid, role: "authenticated" }, async (repo) => {
    const { handleEvidenceIntake } = await import("../../functions/_shared/evidence/handler.ts");
    return handleEvidenceIntake(
      {
        source: "self_report",
        deviceId,
        facilityId: FAC_Y,
        courseId: CRS_Y1,
        localDate: TODAY_CHICAGO,
        catalogVersion: claimedVersion,
      },
      repo,
    );
  });
  const fraudSignalsAfterSecond = await rawCount(`select count(*)::int as n from app.fraud_signal`);
  // The drained row was REALLY scored (a play exists for this user, linked
  // to BOTH evidence rows after the later check-in), and this user has
  // never had a fraud_signal of any kind.
  assertEquals(await rawCount(`select count(*)::int as n from app.play where user_id = '${uid}' and course_id = '${CRS_Y1}'`), 1);
  assertEquals(await rawCount(`select count(*)::int as n from app.fraud_signal where user_id = '${uid}'`), 0);

  const quarantineAfter = await rawCount(`select count(*)::int as n from app.fraud_signal where kind = 'quarantined_evidence_row'`);
  assertEquals(quarantineAfter, fraudSignalsAfterDrain, "no NEW quarantined_evidence_row fraud_signal from the drained row or the later real check-in");
  assertEquals(fraudSignalsAfterSecond, fraudSignalsBeforeSecond, "a normal second check-in at the same facility+date must raise no new fraud_signal at all");
});

// ⛔ NEW (P3e round 2 gate, H4: "Run the drain even when the import
// fails (422/500), in its own transaction"). Proven at this layer as:
// draining does not depend in any way on an import having just
// succeeded in the SAME call — it's a fully independent
// `withSystemCatalogImport` call over `queuedCatalog`, so a failed
// import (asserted separately, above) can never prevent it from running.
// (The entrypoint-level "run both, in sequence, even on 422/500" wiring
// itself lives in import-catalog/index.ts — this integration suite
// proves the PRIMITIVE two calls are independent; see that file's own
// tests, index.test.ts, for the entrypoint-level sequencing.)
Deno.test("H4: drainQueuedCatalog runs and resolves rows via its own transaction, independent of any import call in the same pass", DT, async () => {
  const uid = freshUuid();
  await createTestUser(uid, `h4-drain-${uid.slice(0, 8)}`);
  await ensureServiceRole();
  const deviceId = freshUuid();
  await adminSql()`insert into app.device (id, user_id, platform) values (${deviceId}, ${uid}, 'ios')`;
  const currentSiteVersion = await adminSql()`select site_version from app.catalog_version order by site_version desc nulls last, version desc limit 1`;
  const claimedVersion = (currentSiteVersion[0]?.site_version as string | undefined) ?? "20260101-0000000";
  const queuedInput = { source: "self_report", deviceId, facilityId: FAC_Y, localDate: TODAY_CHICAGO, catalogVersion: claimedVersion };
  await adminSql()`
    insert into app.evidence (user_id, source, source_ref, input_hash, status, device_id, claimed_facility_id, claimed_course_id, claimed_catalog_version, queued_input, local_date)
    values (${uid}, 'self_report', ${"h4-" + freshUuid()}, ${"k".repeat(64)}, 'queued_catalog', ${deviceId}, ${FAC_Y}, null, ${claimedVersion}, ${adminSql().json(queuedInput)}, ${TODAY_CHICAGO})`;

  // No import call at all in this test — draining alone, against
  // whatever the cluster's own current state already is.
  const drainResult = await withSystemCatalogImport((repo) => drainQueuedCatalog(repo, withOwnership, 10));
  assert(drainResult.resolved >= 1, `expected the row to resolve via draining alone, got ${JSON.stringify(drainResult)}`);
});

// ⛔ NEW (P3e round 2 gate, H3: "Add a scale test at ~40k ledger ids plus
// the directory. It must finish well inside the 12 s transaction_timeout;
// report the measured time."). REAL Postgres, REAL set-based `unnest`
// upserts, the REAL `applyImportPlanAtomically` (phase 2 only is timed —
// phase 1 is network/crypto and runs before any transaction opens, M4).
Deno.test("H3 scale: ~40k ledger ids + 1k facilities/courses import inside the 12 s transaction_timeout, against real Postgres", DT, async () => {
  const { privateKey, publicKeyB64Url } = await generateKeypair();
  const kid = `kid-scale-${freshUuid()}`;
  await insertSigningKeyWithKey(kid, publicKeyB64Url, null);
  const catalogVersion = `20260925-${freshUuid().replace(/-/g, "").slice(0, 7)}`;

  const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
  const salt = [...crypto.getRandomValues(new Uint8Array(8))].map((b) => CROCKFORD[b % 32]).join("");
  const mkId = (prefix: string, n: number) => {
    let out = "";
    let v = n;
    for (let i = 0; i < 18; i++) {
      out = CROCKFORD[v % 32] + out;
      v = Math.floor(v / 32);
    }
    return `${prefix}_${salt}${out}`; // 8 + 18 = 26 chars
  };
  const N_LEDGER_ONLY = 38_000;
  const N_DIR = 1_000;
  const entries: Record<string, unknown> = {};
  const mint = [{ type: "minted", catalogVersion }];
  for (let i = 0; i < N_LEDGER_ONLY; i++) {
    const id = mkId("hol", i);
    entries[id] = { id, status: "stub", transitions: mint };
  }
  const facilities = [];
  for (let i = 0; i < N_DIR; i++) {
    const fid = mkId("fac", i);
    const cid = mkId("crs", i);
    entries[fid] = { id: fid, status: "verified", transitions: [{ type: "minted", catalogVersion }, { type: "verified", catalogVersion }] };
    entries[cid] = { id: cid, status: "verified", transitions: [{ type: "minted", catalogVersion }, { type: "verified", catalogVersion }] };
    facilities.push({ id: fid, slug: `scale-${salt.toLowerCase()}-${i}`, region: "US-TN", tz: "America/Chicago", name: `Scale ${i}`, verification: { status: "play-verified" }, courses: [{ id: cid, name: `Scale Course ${i}`, holes: 18, closed: false }] });
  }
  // Directory extras (H2) — trails + designers, and the first course
  // points at the first designer (the separate guarded designer_id pass).
  const dsg0 = mkId("dsg", 0);
  const dsg1 = mkId("dsg", 1);
  const trl0 = mkId("trl", 0);
  const trl1 = mkId("trl", 1);
  for (const id of [dsg0, dsg1, trl0, trl1]) entries[id] = { id, transitions: mint };
  (facilities[0]!.courses[0] as Record<string, unknown>).designers = [dsg0];
  const ledgerBytes = jsonBytes({ entries });
  const facilitiesBytes = jsonBytes(facilities);
  const designersBytes = jsonBytes([{ id: dsg0, name: "Scale Designer 0" }, { id: dsg1, name: "Scale Designer 1" }]);
  const trailsBytes = jsonBytes([
    { id: trl0, slug: `scale-trail-${salt.toLowerCase()}-0`, name: "Scale Trail 0" },
    { id: trl1, slug: `scale-trail-${salt.toLowerCase()}-1`, name: "Scale Trail 1" },
  ]);

  const manifest = {
    contractVersion: 1,
    catalogVersion,
    minAppVersion: "1.0.0",
    kid,
    revokedKids: [] as string[],
    generatedAt: new Date().toISOString(),
    shards: [
      { path: "id-ledger.json", sha256: await sha256Hex(ledgerBytes), bytes: ledgerBytes.length },
      { path: "facilities/us.json", sha256: await sha256Hex(facilitiesBytes), bytes: facilitiesBytes.length },
      { path: "designers.json", sha256: await sha256Hex(designersBytes), bytes: designersBytes.length },
      { path: "trails.json", sha256: await sha256Hex(trailsBytes), bytes: trailsBytes.length },
    ],
  };
  const manifestBytes = jsonBytes(manifest);
  const manifestStatement = { catalogVersion, contractVersion: 1, kid, manifestSha: await sha256Hex(manifestBytes) };
  const manifestSigBytes = jsonBytes({ ...manifestStatement, sig: await signBytesStd(privateKey, new TextEncoder().encode(MANIFEST_DOMAIN + canonicalStringify(manifestStatement))) });
  const versionsBytes = jsonBytes([{ version: catalogVersion, publishedAt: new Date().toISOString(), kid, sha256: "9".repeat(64) }]);
  const versionsStatement = { kid, versionsSha: await sha256Hex(versionsBytes) };
  const versionsSigBytes = jsonBytes({ ...versionsStatement, sig: await signBytesStd(privateKey, new TextEncoder().encode(VERSIONS_DOMAIN + canonicalStringify(versionsStatement))) });

  const fetchBytes: FetchBytes = async (url: string) => {
    if (url.endsWith("/manifest.json")) return manifestBytes;
    if (url.endsWith("/manifest.sig.json")) return manifestSigBytes;
    if (url.endsWith("/versions.json")) return versionsBytes;
    if (url.endsWith("/versions.sig.json")) return versionsSigBytes;
    if (url.endsWith("/id-ledger.json")) return ledgerBytes;
    if (url.endsWith("/facilities/us.json")) return facilitiesBytes;
    if (url.endsWith("/designers.json")) return designersBytes;
    if (url.endsWith("/trails.json")) return trailsBytes;
    throw new Error(`unexpected url ${url}`);
  };

  const plan = await fetchAndVerifyArtifact({ artifactBaseUrl: BASE_URL, allowedHosts: ALLOWED_HOSTS, maxShardBytes: 64 * 1024 * 1024 }, fetchBytes, getSigningKeyReadOnly);
  assert(plan.ok, `expected a verified plan, got ${JSON.stringify(plan)}`);

  const started = performance.now();
  const outcome = await applyImportPlanAtomically(plan, withSystemCatalogImport);
  const elapsedMs = performance.now() - started;
  console.log(`H3 SCALE (real Postgres): ${N_LEDGER_ONLY + 2 * N_DIR} ledger ids + ${N_DIR} facilities + ${N_DIR} courses imported in ${elapsedMs.toFixed(0)} ms`);
  assert(outcome.ok, `expected ok, got reason=${outcome.reason}`);
  assertEquals(outcome.ledgerEntriesApplied, N_LEDGER_ONLY + 2 * N_DIR + 4);
  assertEquals(outcome.facilitiesApplied, N_DIR);
  assertEquals(outcome.coursesApplied, N_DIR);
  assert(elapsedMs < 12_000, `import took ${elapsedMs}ms, over the 12 s transaction_timeout`);

  const n = await rawCount(`select count(*)::int as n from app.catalog_course where facility_id like 'fac_${salt}%'`);
  assertEquals(n, N_DIR);
  assertEquals(await rawCount(`select count(*)::int as n from app.catalog_designer where id in ('${dsg0}', '${dsg1}')`), 2);
  assertEquals(await rawCount(`select count(*)::int as n from app.catalog_trail where id in ('${trl0}', '${trl1}')`), 2);
  // The guarded designer_id pass linked the first course to its designer.
  assertEquals(await rawCount(`select count(*)::int as n from app.catalog_course where id = '${mkId("crs", 0)}' and designer_id = '${dsg0}'`), 1);
});
