// supabase/tests/integration/_publisher.ts
//
// Shared fixture for the catalog integration tests: a REAL Ed25519 publisher
// that builds a signed artifact (manifest, versions, shards) and imports it
// through the REAL two-phase pipeline. Not a test file itself (no
// `.deno.test.ts` suffix), so `deno test` only loads it as a module.
import { assert } from "https://deno.land/std@0.224.0/assert/mod.ts";
import { withOwnership, withSystemCatalogImport } from "../../functions/_shared/privileged.ts";
import { finalizeScoringForKey } from "../../functions/_shared/evidence/handler.ts";
import { deriveFix } from "../../functions/_shared/evidence/derive-fix.ts";
import type { Repo } from "../../functions/_shared/types.ts";
import { fetchAndVerifyArtifact, applyImportPlanAtomically, type FetchBytes } from "../../functions/_shared/catalog/import-handler.ts";
import { canonicalStringify, MANIFEST_DOMAIN, VERSIONS_DOMAIN } from "../../functions/_shared/catalog/manifest-artifact.ts";
import { bytesToBase64Url } from "../../functions/_shared/catalog/signature.ts";
import { adminSql, createTestUser, ensureServiceRole, freshUuid, insertSigningKeyWithKey } from "./_helpers.ts";

export const BASE_URL = "https://golfraven.example/catalog/v1";
export const ALLOWED_HOSTS = ["golfraven.example"];
const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

export function todayChicago(): string {
  return new Intl.DateTimeFormat("en-CA", { timeZone: "America/Chicago", year: "numeric", month: "2-digit", day: "2-digit" }).format(new Date());
}

/** Unique ids per test run (the cluster is shared with every other test file). */
export function ids() {
  const salt = [...crypto.getRandomValues(new Uint8Array(20))].map((b) => CROCKFORD[b % 32]).join("");
  const mk = (prefix: string, n: string) => `${prefix}_${salt}${n}`; // 20 + 6 = 26
  return {
    fac: mk("fac", "000001"),
    k: mk("crs", "00000K"),
    s: mk("crs", "00000S"),
    trl: mk("trl", "000001"),
    hol1: mk("hol", "000001"),
    hol2: mk("hol", "000002"),
    mk,
    salt,
  };
}

export async function generateKeypair() {
  const kp = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const raw = await crypto.subtle.exportKey("raw", kp.publicKey);
  return { privateKey: kp.privateKey, publicKeyB64Url: bytesToBase64Url(new Uint8Array(raw)) };
}
async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const d = await crypto.subtle.digest("SHA-256", bytes.slice().buffer);
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
async function signStd(privateKey: CryptoKey, text: string): Promise<string> {
  const sig = await crypto.subtle.sign("Ed25519", privateKey, new TextEncoder().encode(text));
  let bin = "";
  for (const b of new Uint8Array(sig)) bin += String.fromCharCode(b);
  return btoa(bin);
}
export const jsonBytes = (v: unknown) => new TextEncoder().encode(canonicalStringify(v));

export interface BuiltRelease {
  fetchBytes: FetchBytes;
  /** The exact `manifestSig` a client would lift from this release's `manifest.sig.json`. */
  manifestSig: { kid: string; contractVersion: number; manifestSha: string; sig: string };
}

export class Publisher {
  private history: { version: string; publishedAt: string; kid: string; sha256: string }[] = [];
  constructor(private privateKey: CryptoKey, private kid: string) {}

  /** Builds + signs one release WITHOUT importing it. */
  async build(version: string, shardFiles: Record<string, unknown>): Promise<BuiltRelease> {
    if (!this.history.some((h) => h.version === version)) this.history.push({ version, publishedAt: new Date().toISOString(), kid: this.kid, sha256: "a".repeat(63) + String(this.history.length) });
    const bytesByPath = new Map<string, Uint8Array>();
    for (const [path, value] of Object.entries(shardFiles)) bytesByPath.set(path, jsonBytes(value));
    const shards = [];
    for (const [path, bytes] of bytesByPath) shards.push({ path, sha256: await sha256Hex(bytes), bytes: bytes.length });
    const manifestBytes = jsonBytes({ contractVersion: 1, catalogVersion: version, minAppVersion: "1.0.0", kid: this.kid, revokedKids: [], generatedAt: new Date().toISOString(), shards });
    const mStmt = { catalogVersion: version, contractVersion: 1, kid: this.kid, manifestSha: await sha256Hex(manifestBytes) };
    const sig = await signStd(this.privateKey, MANIFEST_DOMAIN + canonicalStringify(mStmt));
    const manifestSigBytes = jsonBytes({ ...mStmt, sig });
    const versionsBytes = jsonBytes(this.history);
    const vStmt = { kid: this.kid, versionsSha: await sha256Hex(versionsBytes) };
    const versionsSigBytes = jsonBytes({ ...vStmt, sig: await signStd(this.privateKey, VERSIONS_DOMAIN + canonicalStringify(vStmt)) });
    const fetchBytes: FetchBytes = async (url: string) => {
      if (url.endsWith("/manifest.json")) return manifestBytes;
      if (url.endsWith("/manifest.sig.json")) return manifestSigBytes;
      if (url.endsWith("/versions.json")) return versionsBytes;
      if (url.endsWith("/versions.sig.json")) return versionsSigBytes;
      for (const [p, b] of bytesByPath) if (url.endsWith(`/${p}`)) return b;
      throw new Error(`unexpected url ${url}`);
    };
    return { fetchBytes, manifestSig: { kid: this.kid, contractVersion: 1, manifestSha: mStmt.manifestSha, sig } };
  }

  /** Imports an already-built release (real two-phase pipeline). */
  async apply(release: BuiltRelease) {
    const getKey = async (kid: string) => {
      await ensureServiceRole();
      const rows = await adminSql()`select kid, public_key_b64url, revoked_at from app.catalog_signing_key where kid = ${kid}`;
      const r = rows[0];
      return r ? { kid: r.kid as string, publicKeyB64Url: r.public_key_b64url as string, revokedAt: r.revoked_at ? (r.revoked_at as Date).toISOString() : null } : null;
    };
    const plan = await fetchAndVerifyArtifact({ artifactBaseUrl: BASE_URL, allowedHosts: ALLOWED_HOSTS }, release.fetchBytes, getKey);
    assert(plan.ok, `plan rejected: ${JSON.stringify(plan)}`);
    const outcome = await applyImportPlanAtomically(plan, withSystemCatalogImport);
    assert(outcome.ok, `import rejected: ${outcome.reason}`);
    return outcome;
  }

  /** Signs + imports one release. */
  async publish(version: string, shardFiles: Record<string, unknown>) {
    return this.apply(await this.build(version, shardFiles));
  }
}

export async function newPublisher() {
  const { privateKey, publicKeyB64Url } = await generateKeypair();
  const kid = `kid-promo-${freshUuid()}`;
  await insertSigningKeyWithKey(kid, publicKeyB64Url, null);
  return new Publisher(privateKey, kid);
}

export const mint = (v: string) => [{ type: "minted", catalogVersion: v }];
export const facilityShard = (i: ReturnType<typeof ids>, status: string, courses: unknown[]) => [
  { id: i.fac, slug: `promo-${i.salt.toLowerCase()}`, region: "US-TN", tz: "America/Chicago", name: "Promo Facility", verification: { status }, courses },
];

/** Gives an imported course a real polygon (the artifact carries none) so
 * the (derived-fix) tier is the ONLY thing standing between the stub-era
 * score and the promoted one. */
export async function giveCoursePolygon(courseId: string) {
  await ensureServiceRole();
  const d = 0.001;
  await adminSql()`
    update app.catalog_course set geometry_kind = 'polygon',
      boundary = ST_SetSRID(ST_MakePolygon(ST_MakeLine(ARRAY[
        ST_MakePoint(${-86.7816 - d}, ${36.1467 - d}), ST_MakePoint(${-86.7816 + d}, ${36.1467 - d}),
        ST_MakePoint(${-86.7816 + d}, ${36.1467 + d}), ST_MakePoint(${-86.7816 - d}, ${36.1467 + d}),
        ST_MakePoint(${-86.7816 - d}, ${36.1467 - d})])), 4326)
    where id = ${courseId}`;
}

export type Actor = { uid: string; role: "authenticated" };
export async function newUser(label: string): Promise<Actor> {
  const uid = freshUuid();
  await createTestUser(uid, `promo-${label}-${uid.slice(0, 8)}`);
  return { uid, role: "authenticated" };
}

/** A dwell round (2 h apart, both fixes live+attested, inside a polygon) the
 * way live intake would have stored it, with the course's tier AS OF NOW —
 * including `integrity.fixCoords` (the raw coordinates intake now keeps so a
 * re-pick can re-run the matcher). `vendor: true` adds a mapped sensor-
 * provenance vendor round beside it: the combination that makes the play
 * money-TRUE as long as it is NOT a user pick. */
export async function seedDwellInRepo(repo: Repo, facilityId: string, courseId: string, tier: "unverified" | "play-verified", opts: { vendor?: boolean; holes?: 9 | 18; withCoords?: boolean } = {}) {
  const localDate = todayChicago();
  const noonUtcMs = Date.parse(`${localDate}T17:00:00Z`); // 12:00 Chicago (CDT/CST both keep this on the same local day)
  const mk = (fixId: string, capturedAt: number) =>
    deriveFix({
      fix: { fixId, accuracyMeters: 10, capturedAt, simulated: false, foreground: true, fromApp: true },
      resolvedFacilityId: facilityId,
      localDate,
      match: { verificationTier: tier, geometryKind: "polygon", insideBuffer: true },
      consumedToken: { attestationGrade: "attested", challengeKind: "live" },
    });
  const inId = `in${freshUuid().slice(0, 8)}`;
  const outId = `out${freshUuid().slice(0, 8)}`;
  const device = await repo.device.ensureOwn(null, "ios");
  const sourceRef = `dwell-${freshUuid()}`;
  await repo.evidence.insertIdempotent({
    kind: "resolved", sourceRef, inputHash: `hash-${sourceRef}`, source: "foreground_dwell", facilityId, courseId,
    startedAt: null, endedAt: null, localDate,
    summary: { localDate, checkinFix: mk(inId, noonUtcMs), checkoutFix: mk(outId, noonUtcMs + 120 * 60_000), apartMinutes: 120, holes: opts.holes ?? 18 },
    // What live intake stores for a course that can still be re-picked (a stub / a split family).
    integrity: opts.withCoords === false ? {} : { fixCoords: { [inId]: { lat: 36.1467, lng: -86.7816 }, [outId]: { lat: 36.1468, lng: -86.7817 } } },
    cosignal: {}, attestationGrade: "attested", matcherVersion: null, catalogVersion: null, status: "accepted", deviceId: device.id,
  });
  if (opts.vendor) {
    const ref = `vendor-${freshUuid()}`;
    await repo.evidence.insertIdempotent({
      kind: "resolved", sourceRef: ref, inputHash: `hash-${ref}`, source: "arccos", facilityId, courseId,
      startedAt: null, endedAt: null, localDate, summary: { localDate, vendorCourseMapped: true, sensorProvenance: true },
      integrity: {}, cosignal: {}, attestationGrade: "unattestable", matcherVersion: null, catalogVersion: null, status: "accepted", deviceId: device.id,
    });
  }
  return finalizeScoringForKey(repo, facilityId, courseId, localDate);
}

/** A dwell round (2 h apart, both fixes live+attested, inside a polygon) the
 * way live intake would have stored it, with the course's tier AS OF NOW.
 * `vendor: true` adds a mapped sensor-provenance vendor round beside it: the
 * combination that makes the play money-TRUE as long as it is NOT a user pick. */
export async function seedDwellAndScore(actor: Actor, facilityId: string, courseId: string, tier: "unverified" | "play-verified", opts: { vendor?: boolean; holes?: 9 | 18; withCoords?: boolean } = {}) {
  return withOwnership(actor, (repo) => seedDwellInRepo(repo, facilityId, courseId, tier, opts));
}

export const playScore = async (uid: string, courseId: string) => {
  await ensureServiceRole();
  const rows = await adminSql()`select score_badge, score_monetary, money, status, course_disambiguated_by, id from app.play where user_id = ${uid} and course_id = ${courseId}`;
  return rows[0] ? { badge: Number(rows[0].score_badge), monetary: Number(rows[0].score_monetary), money: Boolean(rows[0].money), status: rows[0].status as string, pick: rows[0].course_disambiguated_by as string | null, id: rows[0].id as string } : null;
};
export const uniqueCourses = (actor: Actor) => withOwnership(actor, (repo) => repo.play.uniqueCourseCount());

/** The cluster is shared and the backlog is global: close every OPEN rescore backlog
 * row left by an earlier test so a drain pass only ever sees the row(s) the current
 * test creates (a pass takes the oldest open rows first). Call at the START of a test
 * that drains the backlog. */
export async function closeStaleBacklog() {
  await ensureServiceRole();
  await adminSql()`update app.catalog_rescore_backlog set done_at = now() where done_at is null`;
}
