// supabase/tests/integration/_helpers.ts
//
// P3c gate round 2, item 0 (required first): "Add a Deno integration
// suite that runs the REAL privileged.ts and the handlers against the
// harness cluster that tools/db/test.sh builds." Every *.deno.test.ts
// file in this directory imports this module for its DB connection and
// fixture helpers.
//
// Connection contract (set by tools/db/test-deno-integration.sh, which
// tools/db/test.sh calls the same way it already calls
// test-replay-concurrency.sh / test-money-path-concurrency.sh — see that
// script's own header): PGHOST/PGPORT/PGUSER/PGDATABASE are the standard
// libpq env vars, already pointed at the SAME live throwaway cluster/
// database the pgTAP matrix and the two concurrency scripts just ran
// against (helpers.sql's fixtures — fac_x/crs_x1/trl_t, player A/B,
// etc. — are already seeded by the time this suite runs, and are reused
// directly rather than re-created).
//
// `privileged.ts` (supabase/functions/_shared/privileged.ts) reads its
// OWN connection string from `Deno.env.get("SUPABASE_DB_URL")` — never
// PGHOST/PGPORT directly — so this module derives one from the PG* env
// vars and sets it before any test imports privileged.ts. The derived
// URL is deliberately host-less (`postgres:///$PGDATABASE`): postgres.js
// (the driver privileged.ts imports) falls back to `PGHOST`/`PGPORT`/
// `PGUSER` from the environment when the URL string itself carries no
// host — confirmed this session against a real throwaway cluster (a URL
// WITH a host, even a percent-encoded unix-socket path, either fails
// `new URL(...)` outright or survives un-decoded and is then dialed as a
// literal TCP hostname; the host-less form is the only shape that
// reaches postgres.js's own env-var fallback, which is what correctly
// resolves the unix-socket directory `PGHOST` holds here).
const PGHOST = Deno.env.get("PGHOST");
const PGPORT = Deno.env.get("PGPORT");
const PGUSER = Deno.env.get("PGUSER");
const PGDATABASE = Deno.env.get("PGDATABASE");
if (!PGHOST || !PGPORT || !PGUSER || !PGDATABASE) {
  throw new Error(
    "supabase/tests/integration/_helpers.ts: PGHOST, PGPORT, PGUSER and PGDATABASE must all be set — run via tools/db/test-deno-integration.sh (or tools/db/test.sh), never `deno test` directly against this directory.",
  );
}
if (!Deno.env.get("SUPABASE_DB_URL")) {
  Deno.env.set("SUPABASE_DB_URL", `postgres:///${PGDATABASE}`);
}
// Edge role (PR2). `EDGE_DB_MODE` itself is set by tools/db/test-deno-integration.sh (it runs this whole suite
// once per mode); privileged.ts is the only reader of it. The edge pool connects as the provisioned `edge_gateway`
// login: same host-less shape as above (the host and port come from PGHOST/PGPORT), the user named in the URL's query. The
// harness cluster authenticates with `trust`; when tools/db/test.sh passes the throwaway password it generated at
// runtime (EDGE_GATEWAY_TEST_PASSWORD, never a literal anywhere in the repo) it is handed to the client the way a
// libpq client would receive it (PGPASSWORD), and ignored by `trust`.
if (!Deno.env.get("GOLFRAVEN_EDGE_DB_URL")) {
  const edgePassword = Deno.env.get("EDGE_GATEWAY_TEST_PASSWORD");
  // `new URL("postgres://user:pw@/db")` is invalid (userinfo with an empty host), and postgres.js v3.4.5 reads a password
  // ONLY from the URL's userinfo or PGPASSWORD (a `?password=` / `?pass=` query parameter is not an option -- it is sent to
  // the server as a startup parameter and refused: `unrecognized configuration parameter`). The host-less URL therefore
  // carries only the user and database; the socket directory comes from PGHOST, and the throwaway password (when
  // tools/db/test.sh generated one) goes in PGPASSWORD, which a `trust` cluster simply never asks for.
  if (edgePassword && !Deno.env.get("PGPASSWORD")) Deno.env.set("PGPASSWORD", edgePassword);
  Deno.env.set("GOLFRAVEN_EDGE_DB_URL", `postgres:///${PGDATABASE}?user=edge_gateway`);
}

import postgres from "https://deno.land/x/postgresjs@v3.4.5/mod.js";
import type { Actor } from "../../functions/_shared/types.ts";

type AdminSql = ReturnType<typeof postgres>;

let _admin: AdminSql | null = null;

/** A single persistent (max: 1) raw admin connection — `SET ROLE
 * service_role` once, so every fixture write below runs with the SAME
 * BYPASSRLS privilege `privileged.ts` itself uses, exactly mirroring how
 * `tools/db/test.sh` seeds `supabase/tests/helpers.sql` (`SET ROLE
 * service_role;` then the fixture file, in ONE psql session) in EITHER
 * harness mode. This is test-fixture plumbing ONLY — real assertions
 * always go through `withOwnership`/the real handlers, never this
 * connection. */
export function adminSql(): AdminSql {
  if (_admin) return _admin;
  _admin = postgres({
    host: PGHOST,
    port: Number(PGPORT),
    username: PGUSER,
    database: PGDATABASE,
    max: 1,
    prepare: false,
  });
  return _admin;
}

let _roleSet = false;
/** Exported so a test file can run its OWN raw `adminSql()` template-tag
 * queries (not just through `rawCount`/`rawEvidenceRow`, which already
 * call this internally) and still see real data under
 * HARNESS_MODE=restricted. Necessary, not merely tidy: under `restricted`,
 * `adminSql()`'s connection is `migration_owner` — NOSUPERUSER, no
 * BYPASSRLS, and no client-role RLS policy of its own — so a raw SELECT
 * against a FORCE-RLS table (nearly all of `app.*`) silently returns ZERO
 * rows (RLS filters, it doesn't error) unless this has switched the
 * session to `service_role` first. Masked entirely under
 * HARNESS_MODE=superuser (`postgres` is a true superuser and bypasses RLS
 * regardless of role) — a real bug this session's own restricted-mode run
 * caught, in a test file's verification query, not in product code. */
export async function ensureServiceRole(): Promise<void> {
  if (_roleSet) return;
  await adminSql()`set role service_role`;
  _roleSet = true;
}

let _rawOwner: AdminSql | null = null;

/** A SEPARATE persistent connection that NEVER switches role — stays as
 * the raw connecting `$DBUSER` (`postgres`, a true superuser, under
 * HARNESS_MODE=superuser; `migration_owner`, NOSUPERUSER but the TABLE
 * OWNER, under HARNESS_MODE=restricted). Needed for fixture tables
 * `service_role` has NO write grant on at all by design (this round's own
 * fix: `app.catalog_signing_key` is SELECT-only for service_role — see
 * 0019's own comment) — table ownership alone does not bypass FORCE ROW
 * LEVEL SECURITY (only a true superuser or a BYPASSRLS-attributed role
 * does), so even `migration_owner` needs the SAME self-granting
 * temporary-policy dance 0016/0017/0019 themselves already use for this
 * exact shape of problem (`withTemporaryOwnerAccess` below). */
function rawOwnerSql(): AdminSql {
  if (_rawOwner) return _rawOwner;
  _rawOwner = postgres({
    host: PGHOST,
    port: Number(PGPORT),
    username: PGUSER,
    database: PGDATABASE,
    max: 1,
    prepare: false,
  });
  return _rawOwner;
}

/** Runs `fn` with a TEMPORARY, CURRENT_USER-scoped `FOR ALL USING(true)
 * WITH CHECK(true)` policy on `schemaTable` (e.g. "app.catalog_signing_key")
 * — the exact pattern 0016/0017/0019's own migrations use to seed a row
 * into a FORCE-RLS table with no policy for the connecting role, via
 * `rawOwnerSql()` (never `service_role`, which has no write grant here at
 * all). Always drops the policy and revokes the grant afterward, even on
 * failure. */
async function withTemporaryOwnerAccess<T>(schemaTable: string, fn: (sql: AdminSql) => Promise<T>): Promise<T> {
  const sql = rawOwnerSql();
  const policyName = `integration_suite_temp_${schemaTable.replace(/\W/g, "_")}`;
  await sql.unsafe(`grant insert, update, delete on ${schemaTable} to current_user`);
  await sql.unsafe(`create policy ${policyName} on ${schemaTable} for all to current_user using (true) with check (true)`);
  try {
    return await fn(sql);
  } finally {
    await sql.unsafe(`drop policy if exists ${policyName} on ${schemaTable}`);
    await sql.unsafe(`revoke insert, update, delete on ${schemaTable} from current_user`);
  }
}

export function freshUuid(): string {
  return crypto.randomUUID();
}

export function makeActor(uid: string): Actor {
  return { uid, role: "authenticated" };
}

/** Inserts a fresh `auth.users` row (+ `app.profile`) — every fresh test
 * actor needs one before ANY `app.*` FK to `auth.users` can be satisfied;
 * no `Repo` method creates one (in production this is Supabase Auth's
 * own job, entirely outside this round's scope). */
export async function createTestUser(uid: string, label: string): Promise<void> {
  await ensureServiceRole();
  const sql = adminSql();
  await sql`insert into auth.users (id, email) values (${uid}, ${label + "@integration.test"})`;
  // app.profile.handle is CHECK (handle ~ '^[a-z0-9_]{3,20}$') — `label`
  // (used freely for the email above) is NOT handle-shaped (hyphens,
  // arbitrary length), so a short, deterministic, always-valid handle is
  // derived from the uid itself instead — this suite never reads a
  // profile's handle back, it only needs the row to exist (app.profile
  // has no FK anything else here relies on, but keeping a real row here
  // mirrors what a real signup produces, same as helpers.sql's own
  // fixtures).
  const handle = `u${uid.replace(/-/g, "").slice(0, 19)}`;
  await sql`insert into app.profile (user_id, handle) values (${uid}, ${handle})`;
}

/** A second catalog course at the ALREADY-seeded `fac_x` facility
 * (`supabase/tests/helpers.sql`) — used by the "facility-level evidence
 * visible to a SECOND course's play on the same day" repro (item 1). No
 * `Repo` method can create one (catalog import is out of scope) — a raw
 * admin insert, same shape as `supabase/tests/matrix/13_evidence_intake.sql`'s
 * own `crs_geom1`/`crs_radius1` fixtures. */
export async function createCourseAtFacX(courseId: string): Promise<void> {
  await ensureServiceRole();
  const sql = adminSql();
  await sql`insert into app.catalog_id_ledger (id, kind, status, first_catalog_version) values (${courseId}, 'course', 'verified', 1)`;
  await sql`insert into app.catalog_course (id, facility_id, name, verification_status, catalog_version) values (${courseId}, 'fac_x', ${"Integration Test " + courseId}, 'play-verified', 1)`;
}

/** Same as `createCourseAtFacX`, but with a REAL radius geometry centered
 * on `NASHVILLE` (below) — a course `Repo#catalog.matchFix` (privileged.ts's
 * own `ST_DWithin` query) resolves `insideBuffer: true` for a fix AT that
 * point, and `false` far away. Used by the end-to-end presence_signal
 * tests in handlers.deno.test.ts — `supabase/tests/matrix/13_evidence_intake.sql`'s
 * own `crs_geom1`/`crs_radius1` fixtures don't survive into this suite's
 * run (that pgTAP file's whole BEGIN...ROLLBACK wrapper discards them),
 * so this suite creates its own. */
export async function createCourseWithRadiusAtFacX(courseId: string, radiusM = 200): Promise<void> {
  await ensureServiceRole();
  const sql = adminSql();
  await sql`insert into app.catalog_id_ledger (id, kind, status, first_catalog_version) values (${courseId}, 'course', 'verified', 1)`;
  await sql`
    insert into app.catalog_course (id, facility_id, name, verification_status, geometry_kind, radius_center, radius_m, catalog_version)
    values (${courseId}, 'fac_x', ${"Integration Test " + courseId}, 'play-verified', 'radius',
      ST_SetSRID(ST_MakePoint(${NASHVILLE.lng}, ${NASHVILLE.lat}), 4326), ${radiusM}, 1)`;
}

/** A course with a REAL polygon boundary (a small square centered on
 * `NASHVILLE`) — packages/rules' own `isQualityCoSignalFix`
 * (internal/classify.ts) requires `geometryKind === "polygon"`
 * specifically for a fix to ever count as a presence co-signal; a
 * radius-fallback course (`createCourseWithRadiusAtFacX` above) can
 * never produce `presence_signal: true`, by design, REGARDLESS of
 * `insideBuffer` — this suite's own end-to-end "real co-signal" tests
 * need this shape, not the radius one. */
export async function createCourseWithPolygonAtFacX(courseId: string): Promise<void> {
  await ensureServiceRole();
  const sql = adminSql();
  await sql`insert into app.catalog_id_ledger (id, kind, status, first_catalog_version) values (${courseId}, 'course', 'verified', 1)`;
  const d = 0.001; // ~100m at this latitude — plenty of margin around NASHVILLE for the ST_DWithin(+50m) buffer
  await sql`
    insert into app.catalog_course (id, facility_id, name, verification_status, geometry_kind, boundary, catalog_version)
    values (${courseId}, 'fac_x', ${"Integration Test " + courseId}, 'play-verified', 'polygon',
      ST_SetSRID(ST_MakePolygon(ST_MakeLine(ARRAY[
        ST_MakePoint(${NASHVILLE.lng - d}, ${NASHVILLE.lat - d}),
        ST_MakePoint(${NASHVILLE.lng + d}, ${NASHVILLE.lat - d}),
        ST_MakePoint(${NASHVILLE.lng + d}, ${NASHVILLE.lat + d}),
        ST_MakePoint(${NASHVILLE.lng - d}, ${NASHVILLE.lat + d}),
        ST_MakePoint(${NASHVILLE.lng - d}, ${NASHVILLE.lat - d})
      ])), 4326), 1)`;
}

/** A fresh `app.catalog_version` row (+ optional signing key), so a
 * single test file can exercise the AT 8/AT 15 skew-window and
 * revoked-kid paths without perturbing `fac_x`'s own catalog_version=1
 * row (`supabase/tests/helpers.sql`) other tests in this same run may
 * still be relying on as "current". */
export async function insertCatalogVersion(version: number, publishedAt: Date, kid: string): Promise<void> {
  await ensureServiceRole();
  await adminSql()`insert into app.catalog_version (version, site_version, contract_version, sha256, kid, published_at) values (${version}, ${siteVersionFor(version)}, 'v1', ${"s".repeat(64)}, ${kid}, ${publishedAt.toISOString()})`;
}

/** P3e round 2 gate (H1): intake takes the SITE version string
 * (yyyymmdd-gitsha7), resolved via `catalog_version.site_version`, and
 * "current" is the greatest site_version. This derives one for an
 * integer fixture version such that ORDER BY site_version matches
 * ORDER BY version (2030-01-01 + n days, n in the hex suffix) and never
 * collides with a real import's own 2026 dates. `siteVersionFor(1)` is
 * the value supabase/tests/helpers.sql seeds on version 1. */
export function siteVersionFor(n: number): string {
  const d = new Date(Date.UTC(2030, 0, 1) + n * 24 * 60 * 60 * 1000);
  const ymd = `${d.getUTCFullYear()}${String(d.getUTCMonth() + 1).padStart(2, "0")}${String(d.getUTCDate()).padStart(2, "0")}`;
  return `${ymd}-${n.toString(16).padStart(7, "0")}`;
}
export const SEED_SITE_VERSION = siteVersionFor(1);

/** Unlike every other fixture helper in this file, this one does NOT go
 * through `service_role` — 0019's own fix (P3c gate round 2, "Conditions
 * on the BYPASSRLS design") narrowed `service_role` to SELECT-only on
 * `app.catalog_signing_key`, on purpose (see that migration's own
 * comment). Uses `withTemporaryOwnerAccess` instead — the SAME
 * self-granting pattern 0016/0017/0019 themselves use to seed a FORCE-RLS
 * table with no policy for the connecting role. */
export async function insertSigningKey(kid: string, revokedAt: Date | null): Promise<void> {
  await withTemporaryOwnerAccess("app.catalog_signing_key", (sql) =>
    sql`insert into app.catalog_signing_key (kid, public_key_b64url, revoked_at) values (${kid}, 'AAAA', ${revokedAt ? revokedAt.toISOString() : null})`,
  );
}

/** Same as `insertSigningKey`, but with a REAL, caller-supplied Ed25519
 * public key (unlike `insertSigningKey`'s own fixed `'AAAA'` placeholder,
 * which is fine for the AT 8/AT 15 skew tests — they never reach real
 * signature verification — but useless for import-catalog.deno.test.ts,
 * which DOES verify a real signature against a real registered key). */
export async function insertSigningKeyWithKey(kid: string, publicKeyB64Url: string, revokedAt: Date | null): Promise<void> {
  await withTemporaryOwnerAccess("app.catalog_signing_key", (sql) =>
    sql`insert into app.catalog_signing_key (kid, public_key_b64url, revoked_at) values (${kid}, ${publicKeyB64Url}, ${revokedAt ? revokedAt.toISOString() : null})`,
  );
}

/** Row counts / column reads a test needs to assert against directly
 * (never through a `Repo` method — those are what's under test). */
export async function rawEvidenceRow(id: string): Promise<Record<string, unknown> | null> {
  await ensureServiceRole();
  const rows = await adminSql()`select * from app.evidence where id = ${id}`;
  return rows[0] ?? null;
}

export async function rawCount(sqlText: string): Promise<number> {
  await ensureServiceRole();
  const rows = await adminSql().unsafe(sqlText);
  return Number((rows[0] as Record<string, unknown>)?.n ?? (rows[0] as Record<string, unknown>)?.count ?? 0);
}

export const FAC_X = "fac_x";
export const CRS_X1 = "crs_x1";
export const NASHVILLE = { lat: 36.1467, lng: -86.7816 };
