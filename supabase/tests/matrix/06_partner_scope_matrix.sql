-- 06_partner_scope_matrix.sql
-- build plan §4.7.7 must-fail cells (docs/golf-trails/02-build-plan.md:
-- 1328-1393) that are testable at the DB/RLS/grant level in this stage.
-- Many §4.7.7 rows describe Edge Function behaviour (e.g. "staff@X attests
-- at Y -> 403", "a sixth wrong PIN -> 429") that has no DB-level
-- equivalent without the (out-of-scope-this-stage) Edge Function code —
-- those are left as TODOs, cited by line number, at the end of this file.
-- What IS tested here: the `private.has_facility_scope` /
-- `has_trail_scope` functions those Edge Functions are specified to call
-- (§4.7 item 4, line 1292-1294), and the api views/RLS built on them.

BEGIN;
SELECT plan(27);

-- Actor uuids (see supabase/tests/helpers.sql).
-- staff_x        = 00000000-0000-0000-0000-1000000000a1
-- staff_x_revoked= 00000000-0000-0000-0000-1000000000a2
-- staff_y        = 00000000-0000-0000-0000-1000000000a3
-- manager_x      = 00000000-0000-0000-0000-2000000000b1
-- manager_x_revoked=00000000-0000-0000-0000-2000000000b2
-- operator_t     = 00000000-0000-0000-0000-3000000000c1
-- operator_t_revoked=00000000-0000-0000-0000-3000000000c2
-- admin          = 00000000-0000-0000-0000-4000000000d0

-- ---------------------------------------------------------------------------
-- has_facility_scope / has_trail_scope (§4.7 item 4, line 1288-1296).
-- ---------------------------------------------------------------------------
SELECT ok(
  private.has_facility_scope('00000000-0000-0000-0000-1000000000a1'::uuid, 'fac_x'),
  'staff@X has facility scope on X'
);
SELECT ok(
  NOT private.has_facility_scope('00000000-0000-0000-0000-1000000000a1'::uuid, 'fac_y'),
  'staff@X has NO facility scope on Y (line 1333: staff@X attests at Y -> 403)'
);
SELECT ok(
  NOT private.has_facility_scope('00000000-0000-0000-0000-1000000000a2'::uuid, 'fac_x'),
  'REVOKED staff@X has no facility scope, even though the row is still there (line 1334)'
);
SELECT ok(
  NOT private.has_facility_scope('00000000-0000-0000-0000-2000000000b2'::uuid, 'fac_x'),
  'REVOKED manager@X has no facility scope (line 1343: any /v1/partner/* with a still-valid JWT -> 403)'
);
SELECT ok(
  private.has_trail_scope('00000000-0000-0000-0000-3000000000c1'::uuid, 'trl_t'),
  'operator@T has trail scope on T'
);
SELECT ok(
  NOT private.has_trail_scope('00000000-0000-0000-0000-3000000000c2'::uuid, 'trl_t'),
  'REVOKED operator@T has no trail scope (line 1343)'
);
-- operator's trail scope reaches a facility only via facility_programme
-- (fac_x participates in trl_t; fac_y does not) — this is the mechanism
-- api.facility_qr / special_marker_stock etc. rely on for operator reads.
SELECT ok(
  private.has_facility_scope('00000000-0000-0000-0000-3000000000c1'::uuid, 'fac_x'),
  'operator@T has facility scope on X (X participates in T via facility_programme)'
);
SELECT ok(
  NOT private.has_facility_scope('00000000-0000-0000-0000-3000000000c1'::uuid, 'fac_y'),
  'operator@T has NO facility scope on Y (Y does not participate in T)'
);
SELECT ok(
  private.is_admin('00000000-0000-0000-0000-4000000000d0'::uuid),
  'admin is recognised by private.is_admin'
);

-- ---------------------------------------------------------------------------
-- attestation: "staff@X reads attestation rows (any, incl. their own
-- attests) through any view -> 0 rows" (line 1365, G3-06).
-- ---------------------------------------------------------------------------
-- authenticated has USAGE on schema `app` (0001, S2 fix — SECURITY
-- INVOKER RPC functions need it) and a SELECT grant on app.attestation
-- (0009), so the denial here is RLS alone, not a schema/table-privilege
-- error: `attestation_select_own_player` only matches
-- `player_user_id = auth.uid()`, which staff@X's own uid never satisfies.
SELECT tests.authenticate_as('authenticated', tests.claims('00000000-0000-0000-0000-1000000000a1'::uuid));
SELECT is(
  (SELECT count(*)::int FROM app.attestation),
  0,
  'staff@X reads app.attestation -> 0 rows (RLS: no policy matches a non-owner, not even their own attests)'
);
SELECT tests.clear_actor();

-- staff_shift_log — "staff and managers of that facility" (line 842, 1366).
SELECT tests.authenticate_as('authenticated', tests.claims('00000000-0000-0000-0000-1000000000a1'::uuid));
SELECT is(
  (SELECT count(*)::int FROM api.staff_shift_log),
  1,
  'staff@X sees facility X''s shift-log row via api.staff_shift_log'
);
SELECT tests.clear_actor();

SELECT tests.authenticate_as('authenticated', tests.claims('00000000-0000-0000-0000-1000000000a3'::uuid));
SELECT is(
  (SELECT count(*)::int FROM api.staff_shift_log),
  0,
  'staff@Y sees 0 rows via api.staff_shift_log (facility X is out of scope, line 1367)'
);
SELECT tests.clear_actor();

-- staff_activity — "manager@X reads api.staff_activity | only facility X's
-- rows, no player id or handle" (line 843, 1368).
SELECT tests.authenticate_as('authenticated', tests.claims('00000000-0000-0000-0000-2000000000b1'::uuid));
SELECT is(
  (SELECT count(*)::int FROM api.staff_activity),
  1,
  'manager@X sees facility X''s staff_activity row'
);
SELECT tests.clear_actor();
SELECT is(
  (SELECT array_agg(column_name::text) FROM information_schema.columns
   WHERE table_schema = 'app' AND table_name = 'staff_activity'
     AND column_name::text IN ('user_id', 'player_id', 'handle')),
  NULL,
  'app.staff_activity carries no player id or handle column at all (line 843)'
);

-- special_marker_availability — "status rows only; no count, no user id"
-- (line 1390).
SELECT is(
  (SELECT array_agg(column_name::text) FROM information_schema.columns
   WHERE table_schema = 'api' AND table_name = 'special_marker_availability'
     AND column_name::text IN ('on_hand', 'user_id')),
  NULL,
  'api.special_marker_availability exposes no on_hand count and no user_id'
);

-- signin_provider_token — "Player reads any signin_provider_token row,
-- including their own | denied (no policy)" (line 1393).
SELECT tests.authenticate_as('authenticated', tests.claims('00000000-0000-0000-0000-00000000000a'::uuid));
SELECT throws_ok(
  'SELECT count(*) FROM app.signin_provider_token',
  '42501',
  NULL,
  'player A cannot read app.signin_provider_token, even their own row (no policy)'
);
SELECT tests.clear_actor();

-- ---------------------------------------------------------------------------
-- k-anonymity: "no row is written when cohort_n < 10" is a hard CHECK, so
-- even a service-role bulk write can't create a sub-10 rollup row.
-- ---------------------------------------------------------------------------
SELECT throws_ok(
  $$INSERT INTO app.operator_rollup (trail_id, month, metric, value, cohort_n) VALUES ('trl_t', current_date, 'x', 1, 9)$$,
  '23514',
  NULL,
  'app.operator_rollup rejects cohort_n < 10 at the CHECK constraint (k-anonymity, line 1255)'
);
SELECT throws_ok(
  $$INSERT INTO app.sponsor_rollup (sponsorship_id, month, metric, value, cohort_n) VALUES ('d0000000-0000-0000-0000-000000000001', current_date, 'x', 1, 9)$$,
  '23514',
  NULL,
  'app.sponsor_rollup rejects cohort_n < 10 at the CHECK constraint'
);

-- partner_role_rank ordering — "a role strictly below the grantor's"
-- (line 839, 1341).
SELECT ok(
  private.partner_role_rank('staff') < private.partner_role_rank('manager')
  AND private.partner_role_rank('manager') < private.partner_role_rank('operator'),
  'partner_role_rank orders staff < manager < operator, so an invite can be checked strictly-below'
);

-- attestation self-attest guard — "a staff member can never attest their
-- own player account" (§4.5, line 990) enforced as a hard CHECK.
SELECT throws_ok(
  $$INSERT INTO app.attestation (facility_id, staff_user_id, player_user_id, player_pseudonym, kind, token_jti)
    VALUES ('fac_x', '00000000-0000-0000-0000-1000000000a1', '00000000-0000-0000-0000-1000000000a1', 'x', 'presence', 'jti-self')$$,
  '23514',
  NULL,
  'a staff member cannot be recorded attesting their own player account (CHECK, line 990/1360/1385)'
);

-- ---------------------------------------------------------------------------
-- B1 (gate round 2): PUBLIC has EXECUTE on nothing in app/api/private —
-- the exact defect the default-privilege fix in 0001_schemas.sql closes.
-- ---------------------------------------------------------------------------
SELECT is(
  (
    SELECT count(*)::int FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname IN ('app', 'api', 'private') AND has_function_privilege('public', p.oid, 'EXECUTE')
  ),
  0,
  'PUBLIC has EXECUTE on no function in app/api/private (B1)'
);

-- ---------------------------------------------------------------------------
-- B7 (gate round 2): the two must-fail cells the gate named explicitly.
-- ---------------------------------------------------------------------------
SELECT tests.authenticate_as('authenticated', tests.claims('00000000-0000-0000-0000-3000000000c1'::uuid));
SELECT is(
  (SELECT count(*)::int FROM api.staff_shift_log),
  0,
  'operator@T reads api.staff_shift_log -> 0 rows (B7: it is player-identifying; operator must never see it)'
);
SELECT tests.clear_actor();

SELECT tests.authenticate_as('authenticated', tests.claims('00000000-0000-0000-0000-1000000000a1'::uuid));
SELECT is(
  (SELECT count(*)::int FROM api.staff_activity),
  0,
  'staff@X reads api.staff_activity -> 0 rows (B7: reader is manager/operator only, not staff)'
);
SELECT tests.clear_actor();

-- ---------------------------------------------------------------------------
-- S5 additions.
-- ---------------------------------------------------------------------------
-- anon calling any private.* function is denied outright.
SELECT tests.authenticate_as('anon', '{}'::jsonb);
SELECT throws_ok(
  $$SELECT private.is_admin('00000000-0000-0000-0000-00000000000a'::uuid)$$,
  '42501',
  NULL,
  'anon cannot EXECUTE private.is_admin (or any private.* function)'
);
SELECT tests.clear_actor();

-- a user_metadata write attempt: authenticated has no UPDATE grant on
-- auth.users at all (§4.7 item 4: roles never come from user_metadata,
-- which "the user can write via auth.updateUser" — the DB-level backstop
-- is that no client role can write auth.users directly through this
-- schema regardless).
SELECT tests.authenticate_as('authenticated', tests.claims('00000000-0000-0000-0000-00000000000a'::uuid));
SELECT throws_ok(
  $$UPDATE auth.users SET raw_user_meta_data = '{"role":"admin"}'::jsonb WHERE id = auth.uid()$$,
  '42501',
  NULL,
  'authenticated cannot write auth.users.raw_user_meta_data (no grant) — role can never be self-elevated via user_metadata'
);
SELECT tests.clear_actor();

-- private.rate_limit_bucket: RLS enabled+forced, no client policy.
SELECT ok(
  (SELECT relrowsecurity AND relforcerowsecurity FROM pg_class c
   JOIN pg_namespace n ON n.oid = c.relnamespace
   WHERE n.nspname = 'private' AND c.relname = 'rate_limit_bucket'),
  'private.rate_limit_bucket has RLS enabled and forced'
);
SELECT tests.authenticate_as('authenticated', tests.claims('00000000-0000-0000-0000-00000000000a'::uuid));
SELECT throws_ok(
  'SELECT count(*) FROM private.rate_limit_bucket',
  '42501',
  NULL,
  'authenticated cannot read private.rate_limit_bucket at all (has USAGE on schema private, but no table grant and no RLS policy)'
);
SELECT tests.clear_actor();

SELECT * FROM finish();
ROLLBACK;

-- TODO (Edge-Function-level §4.7.7 cells — out of this stage's scope,
-- "Edge Functions (Deno)" / "attestation verification code" / "scorePlay"
-- are explicitly excluded; each needs the named function's business logic,
-- not just DB grants/RLS):
--   line 1332  "player calls update evidence / insert into play / update
--               play set score_monetary=1 -> denied" — covered at the DB
--               layer by 0009's REVOKE (see 02_grants_trust.sql); the
--               Edge Function's own validation is untested here.
--   line 1333  staff@X attests at Y -> 403 (partner-attest)
--   line 1339  staff@X redeems an offer for a facility not their own with
--              a valid player QR -> 403 (partner-offers-redeem)
--   line 1345  player uploads 6 MB / PDF / SVG -> 413/415 (POST /v1/receipts
--              MIME/size sniffing)
--   line 1346  EXIF stripped from an uploaded JPEG (POST /v1/receipts)
--   line 1361  manager@X invites an account on the same device as their
--              own -> the invite completes, first attest -> held_review
--   lines 1372-1414 (v5/v6 course-QR, entitlement redemption, rate limits,
--              sign-in linking): all require the corresponding Edge
--              Function (checkin-token, marker-scan, course-qr,
--              partner-entitlements-redeem, me-signin-methods).
