-- 12_guc_session_reuse.sql
--
-- ⛔ FIX (HIGH-1 regression, post-P3a re-gate round 3): "after
-- delete_my_data, every play-linked offer_code/entitlement write on that
-- connection fails." Repro: (1) insert a play-linked offer_code; (2) run
-- delete_my_data(<other user>) and COMMIT; (3) insert the next
-- play-linked offer_code -- it fails in offer_code_play_guard;
-- `UPDATE app.entitlement SET state = state` fails the same way.
--
-- Mechanism: `set_config(name, value, true)` ("is_local") only reverts at
-- the end of the ENCLOSING TRANSACTION -- confirmed empirically this
-- round (a throwaway scratch cluster, outside this repo): releasing a
-- SAVEPOINT does NOT trigger the reversion (the value stays visible,
-- unchanged, for the rest of the STILL-OPEN outer transaction); only a
-- real COMMIT of the outer transaction does. Once that transaction
-- commits, `current_setting('app.delete_my_data.target_user_id', true)`
-- reads '' (Postgres's own placeholder default for a custom GUC that has
-- ever been SET LOCAL in this session -- NOT NULL, and NOT the last real
-- value) for the REST OF THE SESSION, until set again. PostgREST/
-- Supavisor reuse connections across unrelated requests, so this is a
-- real, live production bug, not a test-harness artifact: private.
-- offer_code_play_guard/entitlement_play_guard's own re-read runs AS
-- private_definer, and EVERY candidate SELECT policy for that role on
-- app.offer_code/app.entitlement/app.play is OR'd together (Postgres
-- evaluates all of them; it does not short-circuit past one that
-- errors) -- the OLDER policies in 0016_private_definer.sql cast
-- current_setting(...) straight to ::uuid with no nullif() guard, so
-- `''::uuid` raises `invalid input syntax for type uuid: ""` the moment
-- ANY later play-linked write touches that table on the SAME connection,
-- regardless of which function actually triggered the read. Fixed by
-- wrapping every such cast in nullif(current_setting(...), '') (see
-- 0016_private_definer.sql's own header note on this, right above
-- pd_delete_admin_user_user_id) -- nullif('', '') is NULL, and
-- NULL::uuid is simply NULL, never an error, so the fail-closed
-- behaviour (no rows visible with no real target set) is unchanged; only
-- the ERROR is gone. tools/db/verify-function-inventory.mjs's new check
-- (#7) fails the build if any RLS policy anywhere regresses to an
-- unwrapped current_setting(.
--
-- ⛔ Deliberately its OWN file, not folded into 09/11: reproducing the
-- bug needs a REAL COMMIT of the enclosing transaction (a SAVEPOINT
-- release does not trigger the reversion, confirmed above) -- which
-- means every fixture THIS file creates before that COMMIT is PERMANENT
-- in the scratch database for the rest of this test.sh run, not undone
-- by the usual trailing ROLLBACK the way every other matrix file's data
-- is. Kept to the absolute minimum for exactly that reason (one
-- throwaway user, deleted immediately, nothing else) -- everything that
-- actually PROVES the fix runs afterward, inside its own fresh
-- BEGIN/ROLLBACK, and is undone normally.
-- A single plan() for the WHOLE file, called once, up front -- pgTAP's
-- own bookkeeping lives in a session-scoped temp table, which (unlike an
-- ordinary table's uncommitted rows) survives this file's own mid-file
-- COMMIT just fine, so one plan()/finish() pair correctly spans both of
-- this file's transactions.
BEGIN;
SELECT plan(11);

SELECT tests.authenticate_as('service_role', '{}'::jsonb);

-- Player I: a throwaway user with no data beyond its own auth.users row,
-- purely to produce a real delete_my_data(...) call whose own
-- target_user_id (and friends) GUC then reverts to the '' placeholder
-- once THIS transaction commits, immediately below.
SELECT lives_ok(
  $$INSERT INTO auth.users (id, email) VALUES ('00000000-0000-0000-0000-100000000099', 'player-i@example.test')$$,
  'setup: a throwaway user for the GUC-session-reuse repro (permanent in this scratch DB for the rest of this run -- see this file''s own header)'
);
SELECT lives_ok(
  $$SELECT private.delete_my_data('00000000-0000-0000-0000-100000000099'::uuid)$$,
  'setup: delete_my_data on the throwaway user -- sets app.delete_my_data.target_user_id (and friends) LOCALLY for this transaction'
);

-- THE COMMIT: this is what actually reproduces the bug -- everything
-- above this point in THIS FILE is now permanent for the rest of this
-- test.sh run (see this file's own header note). Nothing below this line
-- depends on it being undone.
COMMIT;

-- Confirm, directly, that the placeholder GUC now reads '' (not NULL,
-- not the deleted user's real id) -- the exact state PostgREST/Supavisor
-- connection reuse leaves behind, and the precondition the rest of this
-- file's assertions actually need to be testing the right thing.
DO $$
DECLARE
  v_val text;
BEGIN
  v_val := current_setting('app.delete_my_data.target_user_id', true);
  IF v_val IS DISTINCT FROM '' THEN
    RAISE EXCEPTION 'precondition failed: expected the leftover placeholder GUC to read '''' after commit, got %', v_val;
  END IF;
END
$$;
SELECT pass('precondition confirmed: app.delete_my_data.target_user_id reads '''' (the leftover placeholder, not NULL or a stale real value) after the enclosing transaction committed -- SHOW/current_setting agree');

-- ---------------------------------------------------------------------------
-- THE ACTUAL REGRESSION TEST: a play-linked offer_code insert, and an
-- entitlement state update, on the SAME connection, must both succeed
-- with the '' placeholder in place. Fresh transaction -- everything from
-- here on IS rolled back normally at the end of this file, same as every
-- other matrix file.
-- ---------------------------------------------------------------------------
BEGIN;

-- ⛔ FIX (this file, HARNESS_MODE=restricted failure): tests.authenticate_as
-- (supabase/tests/shim.sql) does `SET LOCAL ROLE <p_role>` -- is_local,
-- the EXACT SAME "reverts at the enclosing transaction's COMMIT, not at
-- RESET" semantics this whole file exists to test for the
-- delete_my_data GUC. The first BEGIN block's own `tests.authenticate_as
-- ('service_role', ...)` call (above) therefore reverted at THIS file's
-- own mid-file COMMIT, back to whatever role the session actually
-- connected as -- harmless under HARNESS_MODE=superuser (that's
-- `postgres`, a real superuser, which bypasses RLS/grants regardless of
-- the active ROLE), but under HARNESS_MODE=restricted that is
-- `migration_owner` (NOSUPERUSER NOBYPASSRLS), so every INSERT/UPDATE
-- below correctly started failing RLS/grants once the actor silently
-- reverted -- confirmed empirically this round. Re-authenticate as
-- service_role for THIS (fresh, still-open) transaction explicitly,
-- rather than relying on the first block's now-expired grant.
SELECT tests.authenticate_as('service_role', '{}'::jsonb);

SELECT lives_ok(
  $$SET CONSTRAINTS app.offer_code_play_guard_trg, app.entitlement_play_guard_trg IMMEDIATE$$,
  'setup: check the play guards immediately for the rest of this file, so each write below actually exercises private.offer_code_play_guard/entitlement_play_guard''s own re-read at statement time, not at a commit this file never reaches'
);
SELECT lives_ok(
  $$INSERT INTO auth.users (id, email) VALUES ('00000000-0000-0000-0000-100000000003', 'player-h@example.test')$$,
  'setup: player H''s auth.users row'
);
SELECT lives_ok(
  $$INSERT INTO app.play (id, user_id, course_id, facility_id, play_date, policy_version, status)
    VALUES ('48000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-100000000003',
            'crs_x1', 'fac_x', current_date - 1, 'v1', 'confirmed')$$,
  'setup: a play row for player H, held_review=false'
);
SELECT lives_ok(
  $$INSERT INTO app.offer_code (id, offer_id, user_id, facility_id, state, play_id)
    VALUES ('75000000-0000-0000-0000-000000000001', '60000000-0000-0000-0000-000000000002',
            '00000000-0000-0000-0000-100000000003', 'fac_x', 'earned', '48000000-0000-0000-0000-000000000001')$$,
  'HIGH-1 FIXED: a play-linked offer_code insert succeeds on the SAME connection after an earlier delete_my_data call committed and left the target_user_id GUC at the '''' placeholder (repro step 3 -- was: "invalid input syntax for type uuid: """ from offer_code_play_guard''s own re-read)'
);
SELECT lives_ok(
  $$INSERT INTO app.entitlement (id, user_id, kind, trail_id, state, play_id)
    VALUES ('56000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-100000000003',
            'special_marker', 'trl_t', 'redeemable', '48000000-0000-0000-0000-000000000001')$$,
  'setup: a play-linked entitlement for player H'
);
SELECT lives_ok(
  $$UPDATE app.entitlement SET state = state WHERE id = '56000000-0000-0000-0000-000000000001'$$,
  'HIGH-1 FIXED: UPDATE app.entitlement SET state = state (the repro''s own second failing statement) also succeeds -- fires entitlement_play_guard''s re-read the same way'
);

-- Should-fix note (no fix needed -- "the pre-existing garbage-GUC case
-- raises only in the caller's own session"): a GENUINELY garbage
-- (non-empty, non-uuid) value is a DIFFERENT, caller-side bug --
-- nullif(x, '') only swallows the EMPTY-STRING placeholder shape, not an
-- arbitrary bad value, so this must still raise. SET LOCAL semantics
-- (is_local = true) scope it to THIS transaction alone; it is undone by
-- this file's own trailing ROLLBACK below, same as everything else in
-- this block -- never visible to another session, and not something
-- nullif(...,'') is meant to (or does) mask.
SELECT lives_ok(
  $$SELECT set_config('app.delete_my_data.target_user_id', 'not-a-uuid-at-all', true)$$,
  'setup: a genuinely garbage (non-empty, non-uuid) GUC value -- simulates a caller bug, NOT the leftover-'''' -placeholder shape this round''s fix targets'
);
SELECT throws_ok(
  $$UPDATE app.entitlement SET state = state WHERE id = '56000000-0000-0000-0000-000000000001'$$,
  '22P02',
  NULL,
  'a genuinely garbage GUC value still raises (22P02, invalid_text_representation) -- confirms nullif(...,'''') is narrowly scoped to the empty-string placeholder and does not mask an unrelated caller-side bug; this is accepted as-is, no fix needed (post-P3a re-gate round 3)'
);

SELECT tests.clear_actor();
SELECT * FROM finish();
ROLLBACK;
