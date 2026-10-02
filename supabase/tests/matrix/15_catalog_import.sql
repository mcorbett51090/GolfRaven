-- 15_catalog_import.sql
-- P3e: the `import-catalog` Edge Function (build plan §3.3). Every
-- SQL-level claim 0023_catalog_import.sql's own header makes, proven
-- directly — this migration adds no new table, no new SECURITY DEFINER
-- function and no new grant (its own header explains why), so this file
-- is deliberately small: it exists to catch a REGRESSION in those three
-- "did not change" claims, not to cover new surface area 01_rls_enabled.sql
-- / 02_grants_trust.sql's own table-agnostic checks don't already reach.

BEGIN;
SELECT plan(33);

-- Every INSERT below needs service_role's own BYPASSRLS + full DML grant
-- (app.catalog_version has no INSERT policy for any other role — same
-- reasoning supabase/tests/helpers.sql's own header gives for seeding its
-- fixtures as service_role). Introspection cells (has_column/col_is_null,
-- information_schema/pg_catalog reads) don't need a role switch, but
-- switching once, up front, keeps this file's own read/write ordering
-- simple rather than toggling roles mid-file.
SELECT tests.authenticate_as('service_role', '{}'::jsonb);

-- ============================================================================
-- 1. app.catalog_version.site_version: present, nullable, UNIQUE.
-- ============================================================================
SELECT has_column('app', 'catalog_version', 'site_version', 'catalog_version has a site_version column');
SELECT col_is_null('app', 'catalog_version', 'site_version', 'site_version is nullable (existing fixtures insert NULL — 0023''s own header)');

SELECT is(
  (
    SELECT count(*)::int FROM pg_constraint c
    JOIN pg_class t ON t.oid = c.conrelid
    JOIN pg_namespace n ON n.oid = t.relnamespace
    WHERE n.nspname = 'app' AND t.relname = 'catalog_version'
      AND c.conname = 'catalog_version_site_version_key' AND c.contype = 'u'
  ),
  1,
  'catalog_version.site_version has its own UNIQUE constraint (catalog_version_site_version_key)'
);

-- Two pre-existing fixture rows may both carry NULL site_version (multiple
-- NULLs are distinct under UNIQUE) — proven by helpers.sql's own version=1
-- row already having been inserted successfully by the time this file
-- runs, PLUS one more NULL-site_version row inserted right here.
INSERT INTO app.catalog_version (version, contract_version, sha256, kid, published_at)
VALUES (9001, 'v-test', repeat('c', 64), 'kid-test', now()), (9004, 'v-test', repeat('f', 64), 'kid-test', now());
SELECT is(
  (SELECT count(*)::int FROM app.catalog_version WHERE site_version IS NULL),
  2,
  'two NULL-site_version rows coexist under the UNIQUE constraint (the seeded row now carries a real site_version)'
);

-- Must-fail cell: two rows with the SAME non-null site_version are
-- rejected.
INSERT INTO app.catalog_version (version, site_version, contract_version, sha256, kid, published_at)
VALUES (9002, '20260925-0000001', 'v-test', repeat('d', 64), 'kid-test', now());
SELECT throws_ok(
  $$INSERT INTO app.catalog_version (version, site_version, contract_version, sha256, kid, published_at)
    VALUES (9003, '20260925-0000001', 'v-test', repeat('e', 64), 'kid-test', now())$$,
  '23505',
  NULL,
  'a duplicate non-null site_version is rejected by the UNIQUE constraint (must-fail cell)'
);

-- ============================================================================
-- 2. app.catalog_signing_key stays SELECT-only for service_role — 0023's
--    own header claims this grant was NOT broadened to support import
--    -catalog. Prove it directly (a regression guard, not new coverage:
--    13_evidence_intake.sql already proves anon/authenticated get nothing
--    at all on this table; this cell is specifically about service_role).
-- ============================================================================
SELECT is(
  (
    SELECT array_agg(DISTINCT privilege_type::text ORDER BY privilege_type::text)
    FROM information_schema.role_table_grants
    WHERE table_schema = 'app' AND table_name = 'catalog_signing_key' AND grantee = 'service_role'
  ),
  ARRAY['SELECT'],
  'service_role holds ONLY SELECT on catalog_signing_key — import-catalog never broadened this grant'
);

-- Must-fail cell: service_role genuinely cannot INSERT here (still
-- authenticated as service_role from this file's own top).
SELECT throws_ok(
  $$INSERT INTO app.catalog_signing_key (kid, public_key_b64url) VALUES ('should-fail', 'AAAA')$$,
  '42501',
  NULL,
  'service_role cannot INSERT into catalog_signing_key (must-fail cell, proves the grant claim is real, not merely a listing)'
);

-- ============================================================================
-- 3. 0024 (P3e round 2 gate, B3): queued_catalog claim columns + CHECK.
-- ============================================================================
SELECT has_column('app', 'evidence', 'claimed_facility_id', 'evidence.claimed_facility_id exists (B3)');
SELECT has_column('app', 'evidence', 'claimed_course_id', 'evidence.claimed_course_id exists (B3)');
SELECT has_column('app', 'evidence', 'claimed_catalog_version', 'evidence.claimed_catalog_version exists (B3)');
SELECT has_column('app', 'evidence', 'queued_input', 'evidence.queued_input exists (B3)');

SELECT is(
  (SELECT count(*)::int FROM pg_constraint c JOIN pg_class t ON t.oid = c.conrelid JOIN pg_namespace n ON n.oid = t.relnamespace
   WHERE n.nspname = 'app' AND t.relname = 'evidence' AND c.conname = 'evidence_queued_claim_shape' AND c.contype = 'c'),
  1,
  'evidence_queued_claim_shape CHECK exists'
);

-- Must-fail: a queued_catalog row may NOT carry a resolved facility_id.
SELECT throws_ok(
  $$INSERT INTO app.evidence (user_id, source, source_ref, input_hash, status, local_date, facility_id, claimed_facility_id)
    VALUES ('00000000-0000-0000-0000-00000000000a', 'self_report', 'q-resolved-facility', repeat('a', 64), 'queued_catalog', current_date, 'fac_x', 'fac_ghost')$$,
  '23514', NULL,
  'a queued_catalog row with a resolved facility_id is rejected (must-fail cell)'
);
-- Must-fail: a queued_catalog row must carry claimed_facility_id.
SELECT throws_ok(
  $$INSERT INTO app.evidence (user_id, source, source_ref, input_hash, status, local_date)
    VALUES ('00000000-0000-0000-0000-00000000000a', 'self_report', 'q-no-claim', repeat('b', 64), 'queued_catalog', current_date)$$,
  '23514', NULL,
  'a queued_catalog row with no claimed_facility_id is rejected (must-fail cell)'
);
-- The point of B3: a queued row for a facility id that exists NOWHERE
-- inserts fine even with the deferred FKs forced immediate (the pgTAP
-- txn never COMMITs, so without this a COMMIT-time deferred-FK failure
-- would be invisible — the hazard the gate named).
SET CONSTRAINTS ALL IMMEDIATE;
SELECT lives_ok(
  $$INSERT INTO app.evidence (user_id, source, source_ref, input_hash, status, local_date, claimed_facility_id, claimed_catalog_version, queued_input)
    VALUES ('00000000-0000-0000-0000-00000000000a', 'self_report', 'q-ok', repeat('c', 64), 'queued_catalog', current_date, 'fac_does_not_exist', '20991231-abcdef0', '{"k":1}'::jsonb)$$,
  'a queued_catalog row for a facility id absent from the catalog inserts (no FK blocks it) — B3'
);
SET CONSTRAINTS ALL DEFERRED;

SELECT ok(
  EXISTS (SELECT 1 FROM pg_enum e JOIN pg_type t ON t.oid = e.enumtypid JOIN pg_namespace n ON n.oid = t.typnamespace
          WHERE n.nspname = 'app' AND t.typname = 'evidence_status' AND e.enumlabel = 'unknown_id'),
  'evidence_status has the terminal unknown_id label (M1)'
);

-- queued_input is server-only: never in the player-facing view.
SELECT hasnt_column('api', 'my_evidence', 'queued_input', 'api.my_evidence does NOT expose queued_input');
SELECT has_column('api', 'my_evidence', 'claimed_facility_id', 'api.my_evidence exposes the player''s own claimed_facility_id');

-- ============================================================================
-- 4. 0025 (M3): app.catalog_kid_revocation — INSERT/SELECT-only, FORCE RLS.
-- ============================================================================
SELECT is(
  (SELECT array_agg(DISTINCT privilege_type::text ORDER BY privilege_type::text)
   FROM information_schema.role_table_grants
   WHERE table_schema = 'app' AND table_name = 'catalog_kid_revocation' AND grantee = 'service_role'),
  ARRAY['INSERT', 'SELECT'],
  'service_role holds ONLY INSERT+SELECT on catalog_kid_revocation (append-only)'
);
SELECT is(
  (SELECT relforcerowsecurity FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'app' AND c.relname = 'catalog_kid_revocation'),
  true,
  'catalog_kid_revocation has FORCE ROW LEVEL SECURITY'
);
INSERT INTO app.catalog_kid_revocation (kid, first_revoked_in_catalog_version) VALUES ('kid-rev-test', '20260925-0000001');
SELECT throws_ok($$UPDATE app.catalog_kid_revocation SET kid = 'x' WHERE kid = 'kid-rev-test'$$, '42501', NULL, 'service_role cannot UPDATE a recorded revocation (must-fail cell)');
SELECT throws_ok($$DELETE FROM app.catalog_kid_revocation WHERE kid = 'kid-rev-test'$$, '42501', NULL, 'service_role cannot DELETE a recorded revocation (must-fail cell)');

-- ============================================================================
-- 5. 0024 (P3e round 3, R1): export + delete coverage for the new columns.
-- ============================================================================
INSERT INTO auth.users (id, email) VALUES ('00000000-0000-0000-0000-0000000e1501', 'queued-export@example.test');
INSERT INTO app.profile (user_id, handle) VALUES ('00000000-0000-0000-0000-0000000e1501', 'queuedexport');
INSERT INTO app.evidence (user_id, source, source_ref, input_hash, status, local_date, claimed_facility_id, claimed_course_id, claimed_catalog_version, queued_input)
VALUES ('00000000-0000-0000-0000-0000000e1501', 'self_report', 'q-export', repeat('d', 64), 'queued_catalog', current_date, 'fac_future', 'crs_future', '20991231-abcdef0', '{"facilityId":"fac_future","localDate":"2099-12-31"}'::jsonb);

SELECT is(
  (private.export_my_data('00000000-0000-0000-0000-0000000e1501'::uuid) -> 'evidence' -> 0 ->> 'claimed_facility_id'),
  'fac_future',
  'export_my_data returns the caller''s own queued claim (claimed_facility_id)'
);
SELECT is(
  (private.export_my_data('00000000-0000-0000-0000-0000000e1501'::uuid) -> 'evidence' -> 0 -> 'queued_input' ->> 'localDate'),
  '2099-12-31',
  'export_my_data returns the caller''s own raw queued submission (queued_input) — their own data'
);
-- 0024's replacement must not have undone P3d round 3 (S1): the two
-- narrowed columns stay out, and the audit_log block keeps no subject_id.
SELECT ok(
  NOT ((private.export_my_data('00000000-0000-0000-0000-00000000000a'::uuid) -> 'purchase_evidence' -> 0) ? 'ref_id')
  AND NOT ((private.export_my_data('00000000-0000-0000-0000-00000000000a'::uuid) -> 'audit_log' -> 0) ? 'subject_id'),
  'export_my_data (0024) still excludes purchase_evidence.ref_id and audit_log.subject_id (P3d S1 not regressed)'
);
SELECT private.delete_my_data('00000000-0000-0000-0000-0000000e1501'::uuid);
SELECT is(
  (SELECT count(*)::int FROM app.evidence WHERE user_id = '00000000-0000-0000-0000-0000000e1501'),
  0,
  'delete_my_data removes the user''s queued rows, claimed_* and queued_input with them'
);

-- ============================================================================
-- 6. 0026 (P3e round 3): catalog_course.holes + the AT 18 re-score backlog.
-- ============================================================================
SELECT has_column('app', 'catalog_course', 'holes', 'catalog_course.holes exists (declared hole count)');
SELECT throws_ok(
  $$INSERT INTO app.catalog_course (id, facility_id, name, holes, catalog_version) VALUES ('crs_x1', 'fac_x', 'dup', 0, 1)$$,
  '23514', NULL,
  'catalog_course.holes must be positive when set (must-fail cell)'
);
SELECT is(
  (SELECT array_agg(DISTINCT privilege_type::text ORDER BY privilege_type::text)
   FROM information_schema.role_table_grants
   WHERE table_schema = 'app' AND table_name = 'catalog_rescore_backlog' AND grantee = 'service_role'),
  ARRAY['INSERT', 'SELECT', 'UPDATE'],
  'service_role holds ONLY SELECT+INSERT+UPDATE on catalog_rescore_backlog (never DELETE — a finished row is the idempotency record)'
);
SELECT is(
  (SELECT relforcerowsecurity FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'app' AND c.relname = 'catalog_rescore_backlog'),
  true,
  'catalog_rescore_backlog has FORCE ROW LEVEL SECURITY'
);
INSERT INTO app.catalog_rescore_backlog (course_id, reason, catalog_version) VALUES ('crs_x1', 'promotion', 1);
SELECT throws_ok(
  $$INSERT INTO app.catalog_rescore_backlog (course_id, reason, catalog_version) VALUES ('crs_x1', 'promotion', 1)$$,
  '23505', NULL,
  'one backlog row per (course, reason, catalog version) — a replayed import cannot re-queue (must-fail cell)'
);
SELECT throws_ok(
  $$INSERT INTO app.catalog_rescore_backlog (course_id, reason, catalog_version) VALUES ('crs_x1', 'bogus', 1)$$,
  '23514', NULL,
  'reason is constrained to promotion|split (must-fail cell)'
);
SELECT throws_ok(
  $$DELETE FROM app.catalog_rescore_backlog WHERE course_id = 'crs_x1'$$,
  '42501', NULL,
  'service_role cannot DELETE a backlog row (must-fail cell)'
);

SELECT * FROM finish();
ROLLBACK;
