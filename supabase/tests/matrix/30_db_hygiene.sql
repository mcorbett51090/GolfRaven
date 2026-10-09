-- 30_db_hygiene.sql
-- 0050_db_hygiene.sql: (1) the six batched purge definers take their batch once (S1.1b gate L-4) and kept everything else; (2) the InitPlan form of the partner-binding conjunct;
-- (3) the S2a gate NIT: the pepper epoch table refuses a future-dated rotation, and the previous-pepper selection is pinned to max(effective_from).
-- The timing proof under STALE planner statistics cannot be a pgTAP cell (VACUUM cannot run inside a transaction): it is the Deno cell "0050: with STALE planner statistics" in
-- supabase/tests/integration/retention-purge.deno.test.ts. The behaviour of each purge (bounds, floors, grants, counts) stays proved where it always was: matrices 16 and 20.
-- Every group is its own BEGIN ... ROLLBACK; no secret: the peppers are filler built at run time, the vectors were computed OUTSIDE the database (see 24_course_qr_marker_scan.sql).

SELECT plan(38);

-- ----------------------------------------------------------------------------
-- 1. The six purge definers: identity, owner and exposure unchanged; the batch is taken once
-- ----------------------------------------------------------------------------
SELECT is((SELECT count(*)::int FROM pg_proc p WHERE p.pronamespace = 'private'::regnamespace AND p.proname LIKE 'purge\_%'), 12, 'the twelve purge definers exist (the six of 0033 / 0040 / 0050 and the six partner purges of 0054; a thirteenth would have to be given the same treatment)');
SELECT is((SELECT count(*)::int FROM pg_proc p WHERE p.pronamespace = 'private'::regnamespace AND p.proname LIKE 'purge\_%'
             AND p.prosecdef AND p.proowner = 'private_definer'::regrole AND p.proconfig = ARRAY['search_path=""']), 12, 'all twelve: SECURITY DEFINER, owned by private_definer, search_path = ''''');
SELECT is((SELECT count(*)::int FROM pg_proc p WHERE p.pronamespace = 'private'::regnamespace AND p.proname LIKE 'purge\_%'
             AND (p.prosrc ~ '\mIN \(\s*SELECT' OR p.prosrc ~* 'WITH\s+\w+\s+AS\s+MATERIALIZED')), 0, 'none of the six keeps the per-row-rescanned IN (SELECT ... LIMIT) shape (or the MATERIALIZED / USING shape 0050 measured and rejected)');
SELECT is((SELECT array_agg(p.proname::text ORDER BY p.proname) FROM pg_proc p WHERE p.pronamespace = 'private'::regnamespace AND p.proname LIKE 'purge\_%' AND p.prosrc ~ '= ANY \(ARRAY\('),
          ARRAY['purge_consumed_nonce', 'purge_fix_coords', 'purge_partner_challenges', 'purge_partner_credentials', 'purge_partner_enrolment_tokens', 'purge_partner_invites', 'purge_partner_sessions', 'purge_partner_sign_in_failures', 'purge_signin_email_proofs', 'purge_signin_revocation_queue'],
  'the ten single-key purges take the batch as an InitPlan array: = ANY (ARRAY(SELECT key ... LIMIT n))');
SELECT is((SELECT array_agg(p.proname::text ORDER BY p.proname) FROM pg_proc p WHERE p.pronamespace = 'private'::regnamespace AND p.proname LIKE 'purge\_%' AND p.prosrc ~ 'FOR v_row IN'),
          ARRAY['purge_install_link_tombstones', 'purge_rate_limit_buckets'], 'the two composite-key purges read the batch once and delete by primary key in a loop');
SELECT is((SELECT count(*)::int FROM pg_proc p WHERE p.pronamespace = 'private'::regnamespace AND p.proname LIKE 'purge\_%' AND regexp_replace(p.prosrc, '--[^\n]*', '', 'g') ~ '\mctid\M'), 0, 'no purge uses ctid (private_definer holds column-level SELECT only on install_link_account)');
-- the batch bound and the retention floors are still in the bodies
SELECT is((SELECT count(*)::int FROM pg_proc p WHERE p.pronamespace = 'private'::regnamespace AND p.proname IN ('purge_consumed_nonce', 'purge_rate_limit_buckets', 'purge_signin_email_proofs', 'purge_signin_revocation_queue')
             AND p.prosrc ~ 'v_limit constant int := 5000' AND p.prosrc ~ 'LIMIT v_limit'), 4, 'the four SQL-bounded purges still carry their constant 5000 bound');
SELECT is((SELECT count(*)::int FROM pg_proc p WHERE p.proname = 'purge_consumed_nonce' AND p.prosrc ~ 'interval ''7 days'''), 1, 'the nonce purge keeps its 7-day floor');
SELECT is((SELECT count(*)::int FROM pg_proc p WHERE p.proname = 'purge_rate_limit_buckets' AND p.prosrc ~ 'interval ''2 days'''), 1, 'the bucket purge keeps its 2-day floor');
SELECT is((SELECT count(*)::int FROM pg_proc p WHERE p.proname = 'purge_signin_email_proofs' AND p.prosrc ~ 'interval ''1 hour''' AND p.prosrc ~ 'app\.signin\.proof_purge'), 1, 'the proof purge keeps its one-hour floor and its purge window');
SELECT is((SELECT count(*)::int FROM pg_proc p WHERE p.proname = 'purge_install_link_tombstones' AND p.prosrc ~ 'interval ''24 months''' AND p.prosrc ~ '100000'), 1, 'the tombstone purge keeps its 24-month retention and its 1..100000 argument check');
SELECT is((SELECT count(*)::int FROM pg_proc p WHERE p.proname = 'purge_fix_coords' AND p.prosrc ~ 'app\.edge\.purge_fix_coords' AND p.prosrc ~ 'between 7 and 30 days'), 1, 'the fix-coordinate purge keeps its purge window and its 7..30 day argument check');
-- grants: exactly as before (service_role + edge_system for the five that run from the retention step / import; nobody else)
SELECT is((SELECT array_agg(p.proname::text || ':' || r.n ORDER BY p.proname, r.n)
           FROM pg_proc p CROSS JOIN (VALUES ('anon'), ('authenticated'), ('edge_actor'), ('edge_gateway'), ('edge_partner')) AS r(n)
           WHERE p.pronamespace = 'private'::regnamespace AND p.proname LIKE 'purge\_%' AND has_function_privilege(r.n, p.oid, 'EXECUTE')), NULL, 'no client role, no edge_actor, no edge_gateway and no edge_partner may EXECUTE any purge');
SELECT is((SELECT array_agg(p.proname::text ORDER BY p.proname) FROM pg_proc p WHERE p.pronamespace = 'private'::regnamespace AND p.proname LIKE 'purge\_%' AND has_function_privilege('edge_system', p.oid, 'EXECUTE')),
          ARRAY['purge_consumed_nonce', 'purge_fix_coords', 'purge_install_link_tombstones', 'purge_partner_challenges', 'purge_partner_credentials', 'purge_partner_enrolment_tokens', 'purge_partner_invites', 'purge_partner_sessions', 'purge_partner_sign_in_failures', 'purge_rate_limit_buckets', 'purge_signin_email_proofs', 'purge_signin_revocation_queue'], 'edge_system may EXECUTE all twelve (the six as before and the six of 0054)');
SELECT is((SELECT array_agg(p.proname::text ORDER BY p.proname) FROM pg_proc p WHERE p.pronamespace = 'private'::regnamespace AND p.proname LIKE 'purge\_%' AND has_function_privilege('service_role', p.oid, 'EXECUTE')),
          ARRAY['purge_consumed_nonce', 'purge_install_link_tombstones', 'purge_rate_limit_buckets', 'purge_signin_email_proofs', 'purge_signin_revocation_queue'], 'service_role may EXECUTE the five it could before (never purge_fix_coords, never a partner purge)');
SELECT is((SELECT count(*)::int FROM pg_proc p WHERE p.pronamespace = 'private'::regnamespace AND p.proname LIKE 'purge\_%' AND p.proacl::text ~ '(^\{|,)=X/'), 0, 'PUBLIC has EXECUTE on none of the twelve');
-- the registry rows are untouched by 0050 (the notes name 0033 / 0040 / 0041, never 0050)
SELECT is((SELECT count(*)::int FROM private.function_inventory WHERE schema_name = 'private' AND function_name LIKE 'purge\_%' AND note LIKE '%0050%'), 0, 'private.function_inventory is unchanged for the purges: 0050 rewrote bodies only');

-- the composite-key purge deletes by the WHOLE key: an expired window and the current window of the SAME bucket key are two rows, and only the expired one goes
BEGIN;
SET LOCAL ROLE private_definer;
INSERT INTO private.rate_limit_bucket (bucket_key, window_start, count) VALUES ('m27:composite', now() - interval '5 days', 1), ('m27:composite', now(), 1);
RESET ROLE;
GRANT edge_system TO CURRENT_USER WITH INHERIT FALSE, SET TRUE;
SET LOCAL ROLE edge_system;
SELECT cmp_ok(private.purge_rate_limit_buckets(), '>=', 1, 'composite key: the purge removes the expired window of a bucket key');
RESET ROLE;
SET LOCAL ROLE private_definer;
SELECT is((SELECT count(*)::int FROM private.rate_limit_bucket WHERE bucket_key = 'm27:composite' AND window_start > now() - interval '1 hour'), 1, 'composite key: ... and the CURRENT window of the same bucket key survives (it is a different primary key)');
SELECT is((SELECT count(*)::int FROM private.rate_limit_bucket WHERE bucket_key = 'm27:composite'), 1, 'composite key: ... and the expired one is gone');
RESET ROLE;
ROLLBACK;

-- ----------------------------------------------------------------------------
-- 2. The InitPlan form of the partner-binding conjunct
-- ----------------------------------------------------------------------------
SELECT cmp_ok((SELECT count(*)::int FROM pg_policy pol WHERE pol.polroles = ARRAY['private_definer'::regrole::oid]
                 AND coalesce(pg_get_expr(pol.polqual, pol.polrelid), '') || ' ' || coalesce(pg_get_expr(pol.polwithcheck, pol.polrelid), '') LIKE '%SELECT private.partner_binding_kind()%'),
              '>=', 118, 'at least the 118 policies 0047 section 8c closed (plus 0048''s two alarm policies) carry the InitPlan form');
SELECT is((SELECT count(*)::int FROM pg_policy pol WHERE pol.polname = 'pd_signin_proof_select' AND pg_get_expr(pol.polqual, pol.polrelid) LIKE '%( SELECT private.partner_binding_kind() AS partner_binding_kind) IS DISTINCT FROM ''partner''::text%'), 1,
          'pd_signin_proof_select (the purge window of the proof table): the InitPlan form, still a top-level trailing conjunct');
SELECT is((SELECT count(*)::int FROM pg_policy pol WHERE pol.polname = 'pd_signin_proof_select' AND pg_get_expr(pol.polqual, pol.polrelid) LIKE '%current_setting(''app.signin.proof_purge''%'), 1, 'and it still reads the purge window it always did (only the conjunct changed)');
SELECT is((SELECT count(*)::int FROM private.definer_policy_allowlist al JOIN pg_policy pol ON pol.polname = al.policy_name JOIN pg_class c ON c.oid = pol.polrelid AND c.relname = al.table_name
             JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = al.schema_name
             WHERE al.using_expr IS DISTINCT FROM pg_get_expr(pol.polqual, pol.polrelid) OR al.with_check_expr IS DISTINCT FROM pg_get_expr(pol.polwithcheck, pol.polrelid)), 0, 'every allow-list snapshot equals its live policy expression');

-- ----------------------------------------------------------------------------
-- 3a. The pepper epoch CHECK: a pepper cannot take effect after it was recorded
-- ----------------------------------------------------------------------------
SELECT is((SELECT pg_get_constraintdef(c.oid) FROM pg_constraint c WHERE c.conrelid = 'app.course_pin_pepper_epoch'::regclass AND c.conname = 'course_pin_pepper_epoch_effective_not_future'), 'CHECK ((effective_from <= recorded_at))', 'the constraint exists and says effective_from <= recorded_at');
SELECT is((SELECT convalidated FROM pg_constraint c WHERE c.conrelid = 'app.course_pin_pepper_epoch'::regclass AND c.conname = 'course_pin_pepper_epoch_effective_not_future'), true, 'and it is validated (not NOT VALID)');
BEGIN;
SET LOCAL ROLE service_role;
SELECT throws_ok($$INSERT INTO app.course_pin_pepper_epoch (effective_from) VALUES (now() + interval '1 minute')$$, '23514', NULL, 'MUST FAIL: the operator''s INSERT of a future effective_from (the default recorded_at is now) is refused');
SELECT throws_ok($$INSERT INTO app.course_pin_pepper_epoch (effective_from) VALUES (now() + interval '1 day')$$, '23514', NULL, 'MUST FAIL: a day ahead (a wrong timezone, a typo) is refused too');
SELECT throws_ok($$INSERT INTO app.course_pin_pepper_epoch (effective_from, recorded_at) VALUES (timestamptz '2030-01-01 00:00:01+00', timestamptz '2030-01-01 00:00:00+00')$$, '23514', NULL, 'MUST FAIL: one second after an explicit recorded_at is refused (the boundary is exact)');
SELECT lives_ok($$INSERT INTO app.course_pin_pepper_epoch (effective_from, recorded_at) VALUES (timestamptz '2030-01-01 00:00:00+00', timestamptz '2030-01-01 00:00:00+00')$$, 'control: effective_from = recorded_at is allowed (the documented procedure, VALUES (now()), writes exactly that)');
SELECT lives_ok($$INSERT INTO app.course_pin_pepper_epoch (effective_from) VALUES (now())$$, 'control: the documented procedure itself, INSERT ... (effective_from) VALUES (now()), is allowed');
SELECT lives_ok($$INSERT INTO app.course_pin_pepper_epoch (effective_from) VALUES (now() - interval '30 minutes')$$, 'control: a past effective_from (a back-dated rotation) is allowed');
RESET ROLE;
ROLLBACK;

-- ----------------------------------------------------------------------------
-- 3b. The previous-pepper selection takes max(effective_from), not min (S2a gate NIT; mutant q09)
-- ----------------------------------------------------------------------------
-- vectors for fac_x 2030-01-02 epoch 0 under the pepper repeat('p', 40) / repeat('q', 40), computed OUTSIDE the database (24_course_qr_marker_scan.sql 3c): 9072 / 6623.
-- Two rotations: the first took effect 2 hours ago, the latest 30 minutes ago. An instant ONE HOUR ago is after the first and before the latest: under max it is before the latest rotation, so the
-- PREVIOUS pepper judges it; under min it would be after the earliest, so the CURRENT pepper would.
BEGIN;
INSERT INTO vault.secrets (name, secret) VALUES ('course_pin_pepper', repeat('p', 40)), ('course_pin_pepper_previous', repeat('q', 40));
SET LOCAL ROLE service_role;
INSERT INTO app.course_pin_pepper_epoch (effective_from) VALUES (now() - interval '2 hours'), (now() - interval '30 minutes');
RESET ROLE;
SET LOCAL ROLE private_definer;
SELECT is(private.course_pin_matches('fac_x', '2030-01-02', 0, '6623', now() - interval '1 hour'), true, 'two rotations: an instant between them is judged under the PREVIOUS pepper (max(effective_from) is the latest rotation)');
SELECT is(private.course_pin_matches('fac_x', '2030-01-02', 0, '9072', now() - interval '1 hour'), false, 'two rotations: ... and the current pepper''s PIN is not what was displayed then (min(effective_from) would have said it was)');
SELECT is(private.course_pin_matches('fac_x', '2030-01-02', 0, '6623', now() - interval '3 hours'), true, 'control: an instant before BOTH rotations is judged under the previous pepper');
SELECT is(private.course_pin_matches('fac_x', '2030-01-02', 0, '9072', now() - interval '10 minutes'), true, 'control: an instant after BOTH rotations is judged under the current pepper');
SELECT is(private.course_pin_matches('fac_x', '2030-01-02', 0, '6623', now() - interval '10 minutes'), false, 'control: ... and the previous pepper''s PIN does not verify there');
RESET ROLE;
ROLLBACK;
SELECT is((SELECT count(*)::int FROM pg_proc p WHERE p.proname = 'course_pin_matches' AND p.prosrc ~ 'pg_catalog\.max\(e\.effective_from\)' AND p.prosrc !~ 'pg_catalog\.min\('), 1, 'and the source says max(effective_from), with no min');

SELECT * FROM finish();
