-- 20_retention_hygiene_purges.sql
-- 0040_retention_hygiene_purges.sql (edge role PR4c): the two TTL hygiene purges (private.purge_consumed_nonce, private.purge_rate_limit_buckets) are
-- granted to edge_system, and those two plus the two sign-in purges (private.purge_signin_email_proofs, private.purge_signin_revocation_queue) are
-- bounded to 5000 rows per call. Proved here, in the harness session (every group is its own BEGIN ... ROLLBACK; the roles are switched with
-- SET LOCAL ROLE after a temporary, rolled-back membership grant, the 16_edge_role.sql cell 709 pattern), so the file leaves nothing behind:
--   1. WHO may execute what: edge_system and service_role can run the two hygiene purges; edge_actor (unbound, bound as a user, bound as a system
--      delegate), anon and authenticated cannot (42501 on the real call, not only on has_function_privilege); the two sign-in purges kept their grants;
--   2. each purge removes ONLY expired rows: a live nonce tombstone (not yet 7 days past its expiry, an attestation tombstone younger than 7 days, one
--      with a future expiry, one a minute inside the floor) and a current-window rate-limit row survive, the expired ones go, and a second call is idempotent;
--   3. the `<uid>:me-delete:user` bucket private.delete_my_data keeps (so a retry of the same deletion stays limited) IS removed by the purge once its
--      window is more than a day past, and not before;
--   4. every purge is BOUNDED: with 5003 expired rows a call removes exactly 5000, the next the rest, the next nothing;
--   5. the layered defences, each alone: the nonce purge's 7-day floor and the proof purge's one-hour floor are enforced by the function body AND by
--      the private_definer policy, so a cell that widens the policy proves the body keeps the live row (a mutant of the body is otherwise masked).
-- No secret in this file: ids are synthetic constants starting 5a5a2000-, keys and hashes are filler.

SELECT plan(63);

CREATE FUNCTION pg_temp.can_exec(p_role text, p_names text[]) RETURNS int LANGUAGE sql STABLE AS $f$
  SELECT count(*)::int FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
  WHERE n.nspname = 'private' AND p.proname = ANY (p_names) AND has_function_privilege(p_role, p.oid, 'EXECUTE')
$f$;

-- ----------------------------------------------------------------------------
-- 1. Privileges: by name, per role
-- ----------------------------------------------------------------------------
SELECT is(pg_temp.can_exec('edge_system', ARRAY['purge_consumed_nonce', 'purge_rate_limit_buckets']), 2, 'privileges: edge_system CAN run both hygiene purges (the owner-approved grant, 0040)');
SELECT is(pg_temp.can_exec('service_role', ARRAY['purge_consumed_nonce', 'purge_rate_limit_buckets']), 2, 'privileges: service_role still can (unchanged)');
SELECT is(pg_temp.can_exec('edge_actor', ARRAY['purge_consumed_nonce', 'purge_rate_limit_buckets']), 0, 'privileges: edge_actor can NOT run either');
SELECT is(pg_temp.can_exec('anon', ARRAY['purge_consumed_nonce', 'purge_rate_limit_buckets']), 0, 'privileges: anon can NOT run either');
SELECT is(pg_temp.can_exec('authenticated', ARRAY['purge_consumed_nonce', 'purge_rate_limit_buckets']), 0, 'privileges: authenticated can NOT run either');
SELECT is(pg_temp.can_exec('edge_system', ARRAY['purge_signin_email_proofs', 'purge_signin_revocation_queue']), 2, 'privileges: the two sign-in purges kept edge_system ...');
SELECT is(pg_temp.can_exec('service_role', ARRAY['purge_signin_email_proofs', 'purge_signin_revocation_queue']), 2, 'privileges: ... and service_role ...');
SELECT is(pg_temp.can_exec('edge_actor', ARRAY['purge_signin_email_proofs', 'purge_signin_revocation_queue'])
        + pg_temp.can_exec('anon', ARRAY['purge_signin_email_proofs', 'purge_signin_revocation_queue'])
        + pg_temp.can_exec('authenticated', ARRAY['purge_signin_email_proofs', 'purge_signin_revocation_queue']), 0, 'privileges: ... and gained nobody');
SELECT is((SELECT count(*)::int FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
           WHERE n.nspname = 'private' AND p.proname IN ('purge_consumed_nonce', 'purge_rate_limit_buckets', 'purge_signin_email_proofs', 'purge_signin_revocation_queue')
             AND p.prosecdef AND pg_get_userbyid(p.proowner) = 'private_definer' AND 'search_path=""' = ANY (p.proconfig)), 4,
  'structure: all four are SECURITY DEFINER, owned by private_definer, with search_path = ''''');
SELECT is((SELECT p.prorettype::regtype::text FROM pg_proc p WHERE p.oid = 'private.purge_rate_limit_buckets()'::regprocedure), 'integer', 'structure: purge_rate_limit_buckets returns the count (int), since 0040');
SELECT is((SELECT p.prorettype::regtype::text FROM pg_proc p WHERE p.oid = 'private.purge_consumed_nonce()'::regprocedure), 'bigint', 'structure: purge_consumed_nonce still returns bigint');
-- the ONE new grant: edge_system holds EXECUTE on exactly two functions in schema private beyond what the inventory said before 0040 (the rest is the
-- inventory gate's job; this is the by-name statement of it)
SELECT is((SELECT array_agg(p.proname::text ORDER BY p.proname COLLATE "C") FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
           WHERE n.nspname = 'private' AND p.proname LIKE 'purge\_%' AND has_function_privilege('edge_system', p.oid, 'EXECUTE')),
  ARRAY['purge_consumed_nonce', 'purge_fix_coords', 'purge_install_link_tombstones', 'purge_partner_challenges', 'purge_partner_credentials', 'purge_partner_enrolment_tokens', 'purge_partner_invites', 'purge_partner_sessions', 'purge_partner_sign_in_failures', 'purge_rate_limit_buckets', 'purge_signin_email_proofs', 'purge_signin_revocation_queue'],
  'privileges: edge_system can run exactly the twelve purges (the four retention classes, the two hygiene purges of 0040 and the six partner purges of 0054), nothing else named purge_*');

-- ----------------------------------------------------------------------------
-- 2. Real calls by role: refused for edge_actor (unbound, user-bound, delegate-bound), anon, authenticated; allowed for edge_system and service_role
-- ----------------------------------------------------------------------------
BEGIN;
GRANT edge_actor TO CURRENT_USER WITH INHERIT FALSE, SET TRUE; -- rolled back; a restricted harness role may not SET ROLE edge_actor otherwise
SET LOCAL ROLE edge_actor;
SELECT throws_ok($$SELECT private.purge_consumed_nonce()$$, '42501', 'permission denied for function purge_consumed_nonce', 'edge_actor (unbound) cannot run purge_consumed_nonce');
SELECT throws_ok($$SELECT private.purge_rate_limit_buckets()$$, '42501', 'permission denied for function purge_rate_limit_buckets', 'edge_actor (unbound) cannot run purge_rate_limit_buckets');
ROLLBACK;

BEGIN;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
INSERT INTO auth.users (id, email) VALUES ('5a5a2000-0000-0000-0000-0000000000a1', 'p20-a@purge.test') ON CONFLICT (id) DO NOTHING;
RESET ROLE;
GRANT edge_actor TO CURRENT_USER WITH INHERIT FALSE, SET TRUE;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('5a5a2000-0000-0000-0000-0000000000a1')$$, 'edge_actor: bind a user');
SELECT throws_ok($$SELECT private.purge_consumed_nonce()$$, '42501', 'permission denied for function purge_consumed_nonce', 'edge_actor (bound as a user) cannot run purge_consumed_nonce');
SELECT throws_ok($$SELECT private.purge_rate_limit_buckets()$$, '42501', 'permission denied for function purge_rate_limit_buckets', 'edge_actor (bound as a user) cannot run purge_rate_limit_buckets');
ROLLBACK;

BEGIN;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
INSERT INTO auth.users (id, email) VALUES ('5a5a2000-0000-0000-0000-0000000000a2', 'p20-b@purge.test') ON CONFLICT (id) DO NOTHING;
INSERT INTO app.evidence (id, user_id, source, source_ref, input_hash, local_date, status, claimed_facility_id, claimed_course_id, claimed_catalog_version, queued_input)
VALUES ('5a5a2000-0000-0000-0000-00000000e001', '5a5a2000-0000-0000-0000-0000000000a2', 'foreground_checkin', 'p20-queued', 'h-p20', current_date, 'queued_catalog', 'fac_x', 'crs_x1', '20300102-0000001', '{"k": "v"}'::jsonb);
RESET ROLE;
GRANT edge_system TO CURRENT_USER WITH INHERIT FALSE, SET TRUE;
GRANT edge_actor TO CURRENT_USER WITH INHERIT FALSE, SET TRUE;
SET LOCAL ROLE edge_system;
SELECT is(private.bind_delegate_for_queued_evidence('5a5a2000-0000-0000-0000-00000000e001'), '5a5a2000-0000-0000-0000-0000000000a2'::uuid, 'delegate: edge_system binds the owner of the queued row');
SET LOCAL ROLE edge_actor;
SELECT is(private.actor_uid(), '5a5a2000-0000-0000-0000-0000000000a2'::uuid, 'delegate: as edge_actor the transaction is bound to the row owner (a system delegate)');
SELECT throws_ok($$SELECT private.purge_consumed_nonce()$$, '42501', 'permission denied for function purge_consumed_nonce', 'edge_actor (delegate-bound) cannot run purge_consumed_nonce');
SELECT throws_ok($$SELECT private.purge_rate_limit_buckets()$$, '42501', 'permission denied for function purge_rate_limit_buckets', 'edge_actor (delegate-bound) cannot run purge_rate_limit_buckets');
ROLLBACK;

BEGIN;
SELECT tests.authenticate_as('anon', '{}'::jsonb);
SELECT throws_ok($$SELECT private.purge_consumed_nonce()$$, '42501', NULL, 'anon cannot run purge_consumed_nonce');
SELECT throws_ok($$SELECT private.purge_rate_limit_buckets()$$, '42501', NULL, 'anon cannot run purge_rate_limit_buckets');
RESET ROLE;
SELECT tests.authenticate_as('authenticated', tests.claims('5a5a2000-0000-0000-0000-0000000000a1'));
SELECT throws_ok($$SELECT private.purge_consumed_nonce()$$, '42501', NULL, 'authenticated cannot run purge_consumed_nonce');
SELECT throws_ok($$SELECT private.purge_rate_limit_buckets()$$, '42501', NULL, 'authenticated cannot run purge_rate_limit_buckets');
RESET ROLE;
ROLLBACK;

BEGIN;
GRANT edge_system TO CURRENT_USER WITH INHERIT FALSE, SET TRUE;
SET LOCAL ROLE edge_system;
SELECT lives_ok($$SELECT private.purge_consumed_nonce()$$, 'edge_system CAN run purge_consumed_nonce');
SELECT lives_ok($$SELECT private.purge_rate_limit_buckets()$$, 'edge_system CAN run purge_rate_limit_buckets');
RESET ROLE;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT lives_ok($$SELECT private.purge_consumed_nonce()$$, 'service_role still can run purge_consumed_nonce');
SELECT lives_ok($$SELECT private.purge_rate_limit_buckets()$$, 'service_role still can run purge_rate_limit_buckets');
RESET ROLE;
ROLLBACK;

-- ----------------------------------------------------------------------------
-- 3. purge_consumed_nonce removes ONLY expired tombstones
-- ----------------------------------------------------------------------------
BEGIN;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT count(*) AS pre FROM private.consumed_nonce WHERE COALESCE(expires_at, consumed_at) < now() - interval '7 days' \gset
INSERT INTO private.consumed_nonce (nonce_hash, source, consumed_at, expires_at) VALUES
  ('m20-old-exp',     'checkin_challenge', now() - interval '31 days', now() - interval '8 days'),            -- 8 days past its source expiry: purged
  ('m20-live-recent', 'checkin_challenge', now() - interval '31 days', now() - interval '1 hour'),            -- consumed 31 days ago but expired 1 hour ago: kept (the cutoff is expiry-based)
  ('m20-live-future', 'checkin_challenge', now() - interval '1 minute', now() + interval '5 minutes'),        -- not yet expired: kept
  ('m20-live-edge',   'checkin_challenge', now() - interval '30 days', now() - interval '6 days 23 hours');   -- a hour inside the floor: kept
INSERT INTO private.consumed_nonce (nonce_hash, source, consumed_at) VALUES
  ('m20-old-att',  'attestation', now() - interval '8 days'),   -- no stored expiry: consumed_at, 8 days ago: purged
  ('m20-live-att', 'attestation', now() - interval '1 day');    -- consumed yesterday: kept
RESET ROLE;
GRANT edge_system TO CURRENT_USER WITH INHERIT FALSE, SET TRUE;
SET LOCAL ROLE edge_system;
SELECT is(private.purge_consumed_nonce(), (:pre + 2)::bigint, 'purge_consumed_nonce (as edge_system): removes exactly the two expired tombstones (and any other expired row already in the table)');
SELECT is(private.purge_consumed_nonce(), 0::bigint, 'purge_consumed_nonce: idempotent (a second call removes nothing)');
RESET ROLE;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT array_agg(nonce_hash ORDER BY nonce_hash) FROM private.consumed_nonce WHERE nonce_hash LIKE 'm20-%'), ARRAY['m20-live-att', 'm20-live-edge', 'm20-live-future', 'm20-live-recent'],
  'purge_consumed_nonce: the four LIVE tombstones survive (recent, future expiry, an hour inside the floor, a day-old attestation) and the two expired ones are gone');
RESET ROLE;
ROLLBACK;

-- ----------------------------------------------------------------------------
-- 4. purge_rate_limit_buckets removes ONLY windows older than 2 days; and the kept <uid>:me-delete:user bucket goes once its window is past
-- ----------------------------------------------------------------------------
BEGIN;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
INSERT INTO auth.users (id, email) VALUES ('5a5a2000-0000-0000-0000-0000000000b1', 'p20-c@purge.test') ON CONFLICT (id) DO NOTHING;
RESET ROLE;
SET LOCAL ROLE private_definer;
SELECT count(*) AS pre_rl FROM private.rate_limit_bucket WHERE window_start < now() - interval '2 days' \gset
INSERT INTO private.rate_limit_bucket (bucket_key, window_start, count) VALUES
  ('m20:old',                 now() - interval '3 days',          4),   -- purged
  ('m20:old-day',             now() - interval '2 days 1 hour',   4),   -- purged
  ('m20:edge-day',            now() - interval '1 day 23 hours',  4),   -- a window that ended a day ago: kept
  ('m20:current',             now(),                              1),   -- the current window: kept
  ('m20:current-hour',        date_trunc('hour', now()),          1);   -- the current hour's window: kept
RESET ROLE;
GRANT edge_system TO CURRENT_USER WITH INHERIT FALSE, SET TRUE;
SET LOCAL ROLE edge_system;
SELECT is(private.purge_rate_limit_buckets(), :pre_rl + 2, 'purge_rate_limit_buckets (as edge_system): removes exactly the two windows older than 2 days (and any other already in the table)');
SELECT is(private.purge_rate_limit_buckets(), 0, 'purge_rate_limit_buckets: idempotent');
RESET ROLE;
SET LOCAL ROLE private_definer;
SELECT is((SELECT array_agg(bucket_key ORDER BY bucket_key) FROM private.rate_limit_bucket WHERE bucket_key LIKE 'm20:%'), ARRAY['m20:current', 'm20:current-hour', 'm20:edge-day'],
  'purge_rate_limit_buckets: the current-window rows and the window that ended a day ago survive');
RESET ROLE;
ROLLBACK;

BEGIN;
-- the real flow: an account hits its me-delete and evidence limits, deletes itself (delete_my_data keeps ONLY the me-delete bucket), the window passes
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
INSERT INTO auth.users (id, email) VALUES ('5a5a2000-0000-0000-0000-0000000000c1', 'p20-d@purge.test') ON CONFLICT (id) DO NOTHING;
SELECT private.hit_rate_limit('5a5a2000-0000-0000-0000-0000000000c1:me-delete:user', interval '1 day', 5);
SELECT private.hit_rate_limit('5a5a2000-0000-0000-0000-0000000000c1:evidence', interval '1 hour', 60);
SELECT private.delete_my_data('5a5a2000-0000-0000-0000-0000000000c1');
RESET ROLE;
SET LOCAL ROLE private_definer;
SELECT is((SELECT array_agg(bucket_key) FROM private.rate_limit_bucket WHERE bucket_key LIKE '5a5a2000-0000-0000-0000-0000000000c1:%'), ARRAY['5a5a2000-0000-0000-0000-0000000000c1:me-delete:user'],
  'me-delete bucket: delete_my_data keeps ONLY the deleted account''s <uid>:me-delete:user bucket (the evidence bucket is gone)');
RESET ROLE;
GRANT edge_system TO CURRENT_USER WITH INHERIT FALSE, SET TRUE;
SET LOCAL ROLE edge_system;
SELECT lives_ok($$SELECT private.purge_rate_limit_buckets()$$, 'me-delete bucket: a purge run while its window is current ...');
RESET ROLE;
SET LOCAL ROLE private_definer;
SELECT is((SELECT count(*)::int FROM private.rate_limit_bucket WHERE bucket_key = '5a5a2000-0000-0000-0000-0000000000c1:me-delete:user'), 1, 'me-delete bucket: ... keeps it (a retry of the deletion stays limited)');
-- one day later: its (one-day) window has passed, but the purge keeps a window for 2 days after its START: still there
UPDATE private.rate_limit_bucket SET window_start = now() - interval '1 day 23 hours' WHERE bucket_key = '5a5a2000-0000-0000-0000-0000000000c1:me-delete:user';
RESET ROLE;
SET LOCAL ROLE edge_system;
SELECT lives_ok($$SELECT private.purge_rate_limit_buckets()$$, 'me-delete bucket: a purge run a day after its window ended ...');
RESET ROLE;
SET LOCAL ROLE private_definer;
SELECT is((SELECT count(*)::int FROM private.rate_limit_bucket WHERE bucket_key = '5a5a2000-0000-0000-0000-0000000000c1:me-delete:user'), 1, 'me-delete bucket: ... still keeps it (the window started less than 2 days ago)');
UPDATE private.rate_limit_bucket SET window_start = now() - interval '2 days 1 hour' WHERE bucket_key = '5a5a2000-0000-0000-0000-0000000000c1:me-delete:user';
RESET ROLE;
SET LOCAL ROLE edge_system;
SELECT cmp_ok(private.purge_rate_limit_buckets(), '>=', 1, 'me-delete bucket: a purge run once its window is more than a day past removes it');
RESET ROLE;
SET LOCAL ROLE private_definer;
SELECT is((SELECT count(*)::int FROM private.rate_limit_bucket WHERE bucket_key LIKE '5a5a2000-0000-0000-0000-0000000000c1:%'), 0, 'me-delete bucket: ... and nothing of the deleted account is left in the table');
RESET ROLE;
ROLLBACK;

-- ----------------------------------------------------------------------------
-- 5. BOUNDED: 5003 expired rows -> 5000, then the rest, then nothing; a live row is never touched by any batch
-- ----------------------------------------------------------------------------
-- 5a. consumed_nonce
BEGIN;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT count(*) AS pre_n FROM private.consumed_nonce WHERE COALESCE(expires_at, consumed_at) < now() - interval '7 days' \gset
INSERT INTO private.consumed_nonce (nonce_hash, source, consumed_at, expires_at)
SELECT 'm20-b-' || g, 'checkin_challenge', now() - interval '12 days', now() - interval '10 days' FROM generate_series(1, 5003) g;
INSERT INTO private.consumed_nonce (nonce_hash, source, consumed_at, expires_at) VALUES ('m20-b-live', 'checkin_challenge', now(), now() + interval '5 minutes');
RESET ROLE;
GRANT edge_system TO CURRENT_USER WITH INHERIT FALSE, SET TRUE;
SET LOCAL ROLE edge_system;
SELECT is(private.purge_consumed_nonce(), 5000::bigint, 'bounded: purge_consumed_nonce removes exactly 5000 of 5003 expired tombstones in one call');
SELECT is(private.purge_consumed_nonce(), (:pre_n + 3)::bigint, 'bounded: ... the next call removes the rest');
SELECT is(private.purge_consumed_nonce(), 0::bigint, 'bounded: ... and the next nothing');
RESET ROLE;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT count(*)::int FROM private.consumed_nonce WHERE nonce_hash = 'm20-b-live'), 1, 'bounded: the live tombstone survived every batch');
RESET ROLE;
ROLLBACK;

-- 5b. rate_limit_bucket
BEGIN;
SET LOCAL ROLE private_definer;
SELECT count(*) AS pre_b FROM private.rate_limit_bucket WHERE window_start < now() - interval '2 days' \gset
INSERT INTO private.rate_limit_bucket (bucket_key, window_start, count) SELECT 'm20:b:' || g, now() - interval '5 days', 1 FROM generate_series(1, 5003) g;
INSERT INTO private.rate_limit_bucket (bucket_key, window_start, count) VALUES ('m20:b:live', now(), 1);
RESET ROLE;
GRANT edge_system TO CURRENT_USER WITH INHERIT FALSE, SET TRUE;
SET LOCAL ROLE edge_system;
SELECT is(private.purge_rate_limit_buckets(), 5000, 'bounded: purge_rate_limit_buckets removes exactly 5000 of 5003 expired windows in one call');
SELECT is(private.purge_rate_limit_buckets(), :pre_b + 3, 'bounded: ... the next call removes the rest');
SELECT is(private.purge_rate_limit_buckets(), 0, 'bounded: ... and the next nothing');
RESET ROLE;
SET LOCAL ROLE private_definer;
SELECT is((SELECT count(*)::int FROM private.rate_limit_bucket WHERE bucket_key = 'm20:b:live'), 1, 'bounded: the current-window row survived every batch');
RESET ROLE;
ROLLBACK;

-- 5c. signin_email_proof (rows an hour past their expiry; the live and the just-expired survive)
BEGIN;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
INSERT INTO auth.users (id, email) VALUES
  ('5a5a2000-0000-0000-0000-0000000000d1', 'p20-e@purge.test'),
  ('5a5a2000-0000-0000-0000-0000000000d2', 'p20-f@purge.test') ON CONFLICT (id) DO NOTHING;
RESET ROLE;
SET LOCAL ROLE private_definer;
SELECT count(*) AS pre_p FROM private.signin_email_proof WHERE expires_at < now() - interval '1 hour' \gset
DO $d$
DECLARE v uuid;
BEGIN
  FOR i IN 1..5003 LOOP
    v := gen_random_uuid();
    PERFORM set_config('app.signin.proof_id', v::text, true);
    INSERT INTO private.signin_email_proof (id, caller_user_id, target_user_id, provider, email_hash, sub_hash, created_at, expires_at)
    VALUES (v, '5a5a2000-0000-0000-0000-0000000000d1', '5a5a2000-0000-0000-0000-0000000000d2', 'apple', repeat('a', 64), repeat('b', 64), now() - interval '3 hours', now() - interval '170 minutes');
  END LOOP;
  -- a live proof, and one that expired 20 minutes ago (inside the hour of grace): both must survive
  v := '5a5a2000-0000-0000-0000-00000000f001'; PERFORM set_config('app.signin.proof_id', v::text, true);
  INSERT INTO private.signin_email_proof (id, caller_user_id, target_user_id, provider, email_hash, sub_hash, created_at, expires_at)
  VALUES (v, '5a5a2000-0000-0000-0000-0000000000d1', '5a5a2000-0000-0000-0000-0000000000d2', 'apple', repeat('a', 64), repeat('c', 64), now(), now() + interval '5 minutes');
  v := '5a5a2000-0000-0000-0000-00000000f002'; PERFORM set_config('app.signin.proof_id', v::text, true);
  INSERT INTO private.signin_email_proof (id, caller_user_id, target_user_id, provider, email_hash, sub_hash, created_at, expires_at)
  VALUES (v, '5a5a2000-0000-0000-0000-0000000000d1', '5a5a2000-0000-0000-0000-0000000000d2', 'apple', repeat('a', 64), repeat('d', 64), now() - interval '25 minutes', now() - interval '20 minutes');
  PERFORM set_config('app.signin.proof_id', '', true);
END
$d$;
RESET ROLE;
GRANT edge_system TO CURRENT_USER WITH INHERIT FALSE, SET TRUE;
SET LOCAL ROLE edge_system;
SELECT is(private.purge_signin_email_proofs(), 5000, 'bounded: purge_signin_email_proofs removes exactly 5000 of 5003 stale proofs in one call');
SELECT is(private.purge_signin_email_proofs(), :pre_p + 3, 'bounded: ... the next call removes the rest');
SELECT is(private.purge_signin_email_proofs(), 0, 'bounded: ... and the next nothing');
RESET ROLE;
SET LOCAL ROLE private_definer;
SELECT set_config('app.signin.proof_id', '5a5a2000-0000-0000-0000-00000000f001', true);
SELECT is((SELECT count(*)::int FROM private.signin_email_proof WHERE id = '5a5a2000-0000-0000-0000-00000000f001'), 1, 'bounded: the live proof survived every batch');
SELECT set_config('app.signin.proof_id', '5a5a2000-0000-0000-0000-00000000f002', true);
SELECT is((SELECT count(*)::int FROM private.signin_email_proof WHERE id = '5a5a2000-0000-0000-0000-00000000f002'), 1, 'bounded: ... and so did the proof that expired 20 minutes ago (the hour of grace)');
RESET ROLE;
ROLLBACK;

-- 5d. signin_revocation_queue (finished rows older than the age; a pending row is never purged, however old)
BEGIN;
SET LOCAL ROLE private_definer;
SELECT count(*) AS pre_q FROM private.signin_revocation_queue WHERE status <> 'pending' AND completed_at < now() - interval '30 days' \gset
INSERT INTO private.signin_revocation_queue (provider, source, token_fingerprint, status, created_at, completed_at)
SELECT 'apple', 'unlink', 'm20-q-' || g, 'revoked', now() - interval '50 days', now() - interval '40 days' FROM generate_series(1, 5003) g;
INSERT INTO private.signin_revocation_queue (id, provider, source, token_fingerprint, status, created_at, completed_at) VALUES
  ('5a5a2000-0000-0000-0000-00000000f101', 'apple', 'unlink', 'm20-q-young', 'revoked', now() - interval '6 days', now() - interval '5 days');
INSERT INTO private.signin_revocation_queue (id, provider, source, token_fingerprint, refresh_token_ciphertext, dek_wrapped, kek_id, status, created_at, expires_at) VALUES
  ('5a5a2000-0000-0000-0000-00000000f102', 'apple', 'unlink', 'm20-q-pending', decode('01', 'hex'), decode('02', 'hex'), 'm20-kek', 'pending', now() - interval '100 days', now() + interval '1 hour');
RESET ROLE;
GRANT edge_system TO CURRENT_USER WITH INHERIT FALSE, SET TRUE;
SET LOCAL ROLE edge_system;
SELECT is(private.purge_signin_revocation_queue(interval '30 days'), 5000, 'bounded: purge_signin_revocation_queue removes exactly 5000 of 5003 finished rows in one call');
SELECT is(private.purge_signin_revocation_queue(interval '30 days'), :pre_q + 3, 'bounded: ... the next call removes the rest');
SELECT is(private.purge_signin_revocation_queue(interval '30 days'), 0, 'bounded: ... and the next nothing');
SELECT throws_ok($$SELECT private.purge_signin_revocation_queue(interval '1 hour')$$, '22023', NULL, 'bounded: the age bound still applies (an age under a day is refused)');
RESET ROLE;
SET LOCAL ROLE private_definer;
SELECT is((SELECT array_agg(id::text ORDER BY id) FROM private.signin_revocation_queue WHERE id IN ('5a5a2000-0000-0000-0000-00000000f101', '5a5a2000-0000-0000-0000-00000000f102')),
  ARRAY['5a5a2000-0000-0000-0000-00000000f101', '5a5a2000-0000-0000-0000-00000000f102'], 'bounded: a young finished row and an old PENDING row survived every batch');
RESET ROLE;
ROLLBACK;

-- ----------------------------------------------------------------------------
-- 6. The layered defences, each ALONE (the policy widened inside a rolled-back transaction; the function body must still keep the live row)
--    The verdict is read into a psql variable inside the transaction and asserted after it, because ROLLBACK discards pgTAP's own rows.
-- ----------------------------------------------------------------------------
-- 6a. consumed_nonce: the 7-day floor in the function body
BEGIN;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
INSERT INTO private.consumed_nonce (nonce_hash, source, consumed_at, expires_at) VALUES
  ('m20-l-old',  'checkin_challenge', now() - interval '31 days', now() - interval '8 days'),
  ('m20-l-live', 'checkin_challenge', now() - interval '31 days', now() - interval '1 hour');
RESET ROLE;
ALTER POLICY pd_purge_consumed_nonce_expired ON private.consumed_nonce USING (true);
ALTER POLICY pd_purge_consumed_nonce_expired_r ON private.consumed_nonce USING (true);
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT private.purge_consumed_nonce() >= 1 AS purged_something \gset
SELECT (count(*) FILTER (WHERE nonce_hash = 'm20-l-live') = 1 AND count(*) FILTER (WHERE nonce_hash = 'm20-l-old') = 0) AS good FROM private.consumed_nonce WHERE nonce_hash LIKE 'm20-l-%' \gset
RESET ROLE;
ROLLBACK;
SELECT ok(:'purged_something'::boolean AND :'good'::boolean, 'layered: with the nonce policies widened to true, the function body alone still keeps a tombstone that is not 7 days past its expiry');

-- ... and the policy alone (the body's predicate removed): the policy still confines private_definer to expired rows
BEGIN;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
INSERT INTO private.consumed_nonce (nonce_hash, source, consumed_at, expires_at) VALUES
  ('m20-p-old',  'checkin_challenge', now() - interval '31 days', now() - interval '8 days'),
  ('m20-p-live', 'checkin_challenge', now() - interval '31 days', now() - interval '1 hour');
RESET ROLE;
SET LOCAL ROLE private_definer;
WITH d AS (DELETE FROM private.consumed_nonce WHERE nonce_hash LIKE 'm20-p-%' RETURNING nonce_hash) SELECT (count(*) FILTER (WHERE nonce_hash = 'm20-p-old') = 1 AND count(*) FILTER (WHERE nonce_hash = 'm20-p-live') = 0) AS good FROM d \gset
RESET ROLE;
ROLLBACK;
SELECT ok(:'good'::boolean, 'layered: the nonce policy alone (an unconditional DELETE as private_definer) removes the expired tombstone and can not touch the live one');

-- 6b. signin_email_proof: the one-hour floor in the function body
BEGIN;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
INSERT INTO auth.users (id, email) VALUES
  ('5a5a2000-0000-0000-0000-0000000000e1', 'p20-g@purge.test'),
  ('5a5a2000-0000-0000-0000-0000000000e2', 'p20-h@purge.test') ON CONFLICT (id) DO NOTHING;
RESET ROLE;
SET LOCAL ROLE private_definer;
SELECT set_config('app.signin.proof_id', '5a5a2000-0000-0000-0000-00000000f201', true);
INSERT INTO private.signin_email_proof (id, caller_user_id, target_user_id, provider, email_hash, sub_hash, created_at, expires_at)
VALUES ('5a5a2000-0000-0000-0000-00000000f201', '5a5a2000-0000-0000-0000-0000000000e1', '5a5a2000-0000-0000-0000-0000000000e2', 'apple', repeat('a', 64), repeat('e', 64), now() - interval '3 hours', now() - interval '170 minutes');
SELECT set_config('app.signin.proof_id', '5a5a2000-0000-0000-0000-00000000f202', true);
INSERT INTO private.signin_email_proof (id, caller_user_id, target_user_id, provider, email_hash, sub_hash, created_at, expires_at)
VALUES ('5a5a2000-0000-0000-0000-00000000f202', '5a5a2000-0000-0000-0000-0000000000e1', '5a5a2000-0000-0000-0000-0000000000e2', 'apple', repeat('a', 64), repeat('f', 64), now() - interval '25 minutes', now() - interval '20 minutes');
SELECT set_config('app.signin.proof_id', '', true);
RESET ROLE;
ALTER POLICY pd_signin_proof_select ON private.signin_email_proof USING (true);
ALTER POLICY pd_signin_proof_delete ON private.signin_email_proof USING (true);
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT private.purge_signin_email_proofs() >= 1 AS purged_something \gset
RESET ROLE;
SET LOCAL ROLE private_definer;
SELECT (count(*) FILTER (WHERE id = '5a5a2000-0000-0000-0000-00000000f202') = 1 AND count(*) FILTER (WHERE id = '5a5a2000-0000-0000-0000-00000000f201') = 0) AS good FROM private.signin_email_proof \gset
RESET ROLE;
ROLLBACK;
SELECT ok(:'purged_something'::boolean AND :'good'::boolean, 'layered: with the proof policies widened to true, the function body alone still keeps a proof that expired less than an hour ago');
