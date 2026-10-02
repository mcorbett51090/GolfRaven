-- 18_signin_providers_edge.sql
-- 0035_signin_providers.sql, the EDGE lane: the `_for_actor` wrappers edge_actor calls (no user argument; the bound kind =
-- 'user' actor), the queue's system operations edge_system calls, and what neither role can do. It reconnects as a REAL
-- `edge_gateway` login for the reason 16_edge_role.sql gives (SET ROLE is judged by the session user), so it is its own
-- file and shares nothing with 17_signin_providers.sql but the migration under test.
--
-- THE THREE PHASES (the same as 16)
--   0  (harness role, as service_role)  seed two throw-away users EA / EB with identities, a committed grant for EB, a
--      queued evidence row for EA (the delegate cell) and a run-time-random KEK in the Vault stand-in. COMMITTED: edge
--      transactions run in another session.
--   1  (edge_gateway)                   every assertion; each group is its own BEGIN ... ROLLBACK except the two that need
--      a real COMMIT (session reuse; the queue claimed by edge_system), which say so.
--   2  (harness role)                   removes everything phase 0 and 1 committed.
--
-- No secret in this file: the KEK is gen_random_bytes at run time, the "ciphertexts" are filler (the database never
-- decrypts). Ids are synthetic constants starting 5a5a1800-.

\set QUIET 1
SELECT session_user::text AS harness_user, current_database()::text AS harness_db, substr(md5(random()::text), 1, 12) AS run \gset

-- ============================================================================
-- PHASE 0: seed (committed)
-- ============================================================================
-- pre-clean of the queue rows an aborted earlier run committed (only private_definer holds anything on the queue)
BEGIN;
SET LOCAL ROLE private_definer;
DELETE FROM private.signin_revocation_queue WHERE token_fingerprint IN (md5(decode(repeat('b1', 40), 'hex')), md5(decode(repeat('e1', 40), 'hex')));
COMMIT;
SET ROLE service_role;
BEGIN;
-- pre-clean: a run that aborted before its own phase 2 left these committed (this file must be re-runnable, like 16)
SELECT private.delete_my_data(u.id) FROM auth.users u WHERE u.id IN ('5a5a1800-0000-0000-0000-0000000000ea', '5a5a1800-0000-0000-0000-0000000000eb');
DELETE FROM auth.identities WHERE user_id IN ('5a5a1800-0000-0000-0000-0000000000ea', '5a5a1800-0000-0000-0000-0000000000eb');
DELETE FROM vault.secrets WHERE name = 'siwa_token_kek_e18';
INSERT INTO auth.users (id, email) VALUES
  ('5a5a1800-0000-0000-0000-0000000000ea', 'edge18-ea@signin.test'),
  ('5a5a1800-0000-0000-0000-0000000000eb', 'edge18-eb@signin.test')
ON CONFLICT (id) DO NOTHING; -- auth.users rows are never deleted by this harness, so a re-run finds them
INSERT INTO app.profile (user_id, handle) VALUES
  ('5a5a1800-0000-0000-0000-0000000000ea', 'edge18_ea'),
  ('5a5a1800-0000-0000-0000-0000000000eb', 'edge18_eb');
INSERT INTO auth.identities (provider_id, user_id, identity_data, provider) VALUES
  ('edge18-ea@signin.test', '5a5a1800-0000-0000-0000-0000000000ea', '{"email":"edge18-ea@signin.test"}', 'email'),
  ('edge18-eb@signin.test', '5a5a1800-0000-0000-0000-0000000000eb', '{"email":"edge18-eb@signin.test"}', 'email'),
  ('edge18-g-eb', '5a5a1800-0000-0000-0000-0000000000eb', '{"email":"edge18-eb@signin.test"}', 'google');
INSERT INTO vault.secrets (name, secret) VALUES ('siwa_token_kek_e18', encode(gen_random_bytes(32), 'base64'));
SELECT private.signin_store_token('5a5a1800-0000-0000-0000-0000000000eb', 'google', decode(repeat('b1', 40), 'hex'), decode(repeat('b2', 70), 'hex'), 'e18');
INSERT INTO app.evidence (id, user_id, source, source_ref, input_hash, local_date, status, claimed_facility_id, claimed_course_id, claimed_catalog_version, queued_input) VALUES
  ('5a5a1800-0000-0000-0000-00000000e001', '5a5a1800-0000-0000-0000-0000000000ea', 'foreground_checkin', 'edge18-queued', 'h-e18', current_date, 'queued_catalog', 'fac_x', 'crs_x1', '20300102-0000001', '{"k": "v"}'::jsonb);
COMMIT;
RESET ROLE;

-- ============================================================================
-- PHASE 1: reconnect as the real login
-- ============================================================================
\c :"harness_db" edge_gateway
\set QUIET 1
SELECT plan(83);

-- ----------------------------------------------------------------------------
-- 1. Privileges: who can call what (the inventory check proves the same against the manifest; these are the behaviours)
-- Looked up through pg_proc by name: has_function_privilege('role', 'private.f(...)') would resolve the signature as
-- edge_gateway, which has no USAGE on schema private (and must not).
-- ----------------------------------------------------------------------------
CREATE FUNCTION pg_temp.can_exec(p_role text, p_names text[]) RETURNS int LANGUAGE sql STABLE AS $f$
  SELECT count(*)::int FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
  WHERE n.nspname = 'private' AND p.proname = ANY (p_names) AND has_function_privilege(p_role, p.oid, 'EXECUTE')
$f$;
SELECT is(pg_temp.can_exec('edge_actor', ARRAY['signin_methods_for_actor', 'signin_link_identity_for_actor', 'signin_store_token_for_actor', 'signin_unlink_identity_for_actor', 'signin_enqueue_revocations_for_actor', 'signin_find_account_by_email_for_actor']), 6,
  'privileges: edge_actor can EXECUTE the six _for_actor wrappers');
SELECT is(pg_temp.can_exec('edge_actor', ARRAY['signin_methods', 'signin_link_identity', 'signin_store_token', 'signin_unlink_identity', 'signin_enqueue_revocations', 'claim_signin_revocations', 'complete_signin_revocation', 'purge_signin_revocation_queue', 'signin_bound_user', 'signin_enqueue_internal', 'signin_find_account_by_email']), 0,
  'privileges: edge_actor can EXECUTE NONE of the user-id-taking core functions, the queue operations, the unbound email lookup or the internals (F7)');
SELECT is(pg_temp.can_exec('edge_actor', ARRAY['peek_signin_otp_failures_for_actor', 'reserve_signin_otp_attempt_for_actor', 'release_signin_otp_attempt_for_actor']), 3,
  'privileges (L1): edge_actor can EXECUTE the three OTP-counter _for_actor wrappers');
SELECT is(pg_temp.can_exec('edge_actor', ARRAY['peek_signin_otp_failures', 'reserve_signin_otp_attempt', 'release_signin_otp_attempt']), 0,
  'privileges (L1): edge_actor can EXECUTE NONE of the three OTP-counter CORES (they take no user and check no binding: any connection could reset an address''s counter)');
SELECT is(pg_temp.can_exec('service_role', ARRAY['peek_signin_otp_failures', 'reserve_signin_otp_attempt', 'release_signin_otp_attempt']), 3,
  'privileges (L1): ... service_role, the legacy lane, keeps them');
SELECT is(pg_temp.can_exec('edge_system', ARRAY['signin_methods_for_actor', 'signin_link_identity_for_actor', 'signin_store_token_for_actor', 'signin_unlink_identity_for_actor', 'signin_enqueue_revocations_for_actor', 'signin_methods', 'signin_find_account_by_email', 'signin_find_account_by_email_for_actor', 'peek_signin_otp_failures', 'reserve_signin_otp_attempt', 'release_signin_otp_attempt', 'peek_signin_otp_failures_for_actor', 'reserve_signin_otp_attempt_for_actor', 'release_signin_otp_attempt_for_actor']), 0,
  'privileges: edge_system can EXECUTE none of the user-facing sign-in functions (it is not an actor)');
SELECT is(pg_temp.can_exec('edge_system', ARRAY['claim_signin_revocations', 'complete_signin_revocation', 'purge_signin_revocation_queue', 'get_signin_token_kek']), 4,
  'privileges: edge_system CAN run the queue operations and read the KEK (the drain decrypts)');

-- ----------------------------------------------------------------------------
-- 2. Unbound and the wrong binding kind
-- ----------------------------------------------------------------------------
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT throws_ok($$SELECT * FROM private.signin_methods_for_actor()$$, '42501', 'signin_methods_for_actor: no actor is bound in this transaction', 'unbound: methods_for_actor refuses');
SELECT throws_ok($$SELECT private.signin_link_identity_for_actor('apple', 'x', NULL, false, false)$$, '42501', 'signin_link_identity_for_actor: no actor is bound in this transaction', 'unbound: link_for_actor refuses');
SELECT throws_ok($$SELECT private.signin_store_token_for_actor('apple', decode(repeat('ab', 40), 'hex'), decode(repeat('cd', 70), 'hex'), 'e18')$$, '42501', 'signin_store_token_for_actor: no actor is bound in this transaction', 'unbound: store_token_for_actor refuses');
SELECT throws_ok($$SELECT * FROM private.signin_unlink_identity_for_actor('google')$$, '42501', 'signin_unlink_identity_for_actor: no actor is bound in this transaction', 'unbound: unlink_for_actor refuses');
SELECT throws_ok($$SELECT * FROM private.signin_enqueue_revocations_for_actor()$$, '42501', 'signin_enqueue_revocations_for_actor: no actor is bound in this transaction', 'unbound: enqueue_for_actor refuses');
SELECT throws_ok($$SELECT private.signin_find_account_by_email_for_actor('edge18-eb@signin.test')$$, '42501', 'signin_find_account_by_email_for_actor: no actor is bound in this transaction', 'unbound (F7): the email lookup refuses: an unbound edge_actor learns nothing about which emails hold accounts');
SELECT throws_ok($$SELECT private.peek_signin_otp_failures_for_actor(repeat('0', 64))$$, '42501', 'peek_signin_otp_failures_for_actor: no actor is bound in this transaction', 'unbound (L1): the OTP peek wrapper refuses');
SELECT throws_ok($$SELECT * FROM private.reserve_signin_otp_attempt_for_actor(repeat('0', 64))$$, '42501', 'reserve_signin_otp_attempt_for_actor: no actor is bound in this transaction', 'unbound (L1): ... the reserve wrapper (no address''s attempts can be burned)');
SELECT throws_ok($$SELECT private.release_signin_otp_attempt_for_actor(repeat('0', 64), to_timestamp(floor(extract(epoch FROM now()) / 3600) * 3600))$$, '42501', 'release_signin_otp_attempt_for_actor: no actor is bound in this transaction', 'unbound (L1): ... and the release wrapper (no address''s counter can be reset: release is a decrement)');
SELECT throws_ok($$SELECT private.release_signin_otp_attempt(repeat('0', 64), to_timestamp(floor(extract(epoch FROM now()) / 3600) * 3600))$$, '42501', NULL, 'unbound (L1): the release CORE is not callable by edge_actor at all (permission denied, not a binding check)');
SELECT throws_ok($$SELECT * FROM private.reserve_signin_otp_attempt(repeat('0', 64))$$, '42501', NULL, 'unbound (L1): ... nor the reserve core');
SELECT throws_ok($$SELECT private.peek_signin_otp_failures(repeat('0', 64))$$, '42501', NULL, 'unbound (L1): ... nor the peek core');
ROLLBACK;

BEGIN;
SET LOCAL ROLE edge_system;
SELECT is(private.bind_delegate_for_queued_evidence('5a5a1800-0000-0000-0000-00000000e001'), '5a5a1800-0000-0000-0000-0000000000ea'::uuid, 'delegate: edge_system binds the owner of the queued row as a system delegate');
SET LOCAL ROLE edge_actor;
SELECT throws_ok($$SELECT * FROM private.signin_methods_for_actor()$$, '42501', 'signin_methods_for_actor: a system delegate may not manage sign-in methods', 'delegate: a system delegate binding cannot list sign-in methods');
SELECT throws_ok($$SELECT * FROM private.signin_enqueue_revocations_for_actor()$$, '42501', 'signin_enqueue_revocations_for_actor: a system delegate may not manage sign-in methods', 'delegate: ... nor queue revocations (it is not an account deletion)');
SELECT throws_ok($$SELECT private.signin_link_identity_for_actor('apple', 'x', NULL, false, false)$$, '42501', 'signin_link_identity_for_actor: a system delegate may not manage sign-in methods', 'delegate: ... nor link an identity');
SELECT throws_ok($$SELECT private.signin_find_account_by_email_for_actor('edge18-eb@signin.test')$$, '42501', 'signin_find_account_by_email_for_actor: a system delegate may not manage sign-in methods', 'delegate (F7): ... nor look an email up (only a kind = user binding may)');
SELECT throws_ok($$SELECT private.peek_signin_otp_failures_for_actor(repeat('0', 64))$$, '42501', 'peek_signin_otp_failures_for_actor: a system delegate may not manage sign-in methods', 'delegate (L1): ... nor peek the OTP counter');
SELECT throws_ok($$SELECT * FROM private.reserve_signin_otp_attempt_for_actor(repeat('0', 64))$$, '42501', 'reserve_signin_otp_attempt_for_actor: a system delegate may not manage sign-in methods', 'delegate (L1): ... nor reserve an OTP attempt');
SELECT throws_ok($$SELECT private.release_signin_otp_attempt_for_actor(repeat('0', 64), to_timestamp(floor(extract(epoch FROM now()) / 3600) * 3600))$$, '42501', 'release_signin_otp_attempt_for_actor: a system delegate may not manage sign-in methods', 'delegate (L1): ... nor release one (only a kind = user binding may)');
ROLLBACK;

-- ----------------------------------------------------------------------------
-- 3. The bound actor EA: the whole flow, and nothing of EB's
-- ----------------------------------------------------------------------------
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('5a5a1800-0000-0000-0000-0000000000ea')$$, 'EA: bind');
SELECT is((SELECT count(*)::int FROM private.signin_methods_for_actor()), 1, 'EA: one method (email), none of EB''s two');
SELECT is((SELECT o_provider FROM private.signin_methods_for_actor()), 'email', 'EA: ... the email identity');
SELECT is(private.signin_link_identity_for_actor('apple', 'edge18-a-sub', 'edge18-ea@signin.test', true, false), true, 'EA: links apple to its OWN account (no user argument exists to name another)');
SELECT is(private.signin_link_identity_for_actor('apple', 'edge18-a-sub', 'edge18-ea@signin.test', true, false), false, 'EA: ... idempotent');
SELECT lives_ok($$SELECT private.signin_store_token_for_actor('apple', decode(repeat('e1', 40), 'hex'), decode(repeat('e2', 70), 'hex'), 'e18')$$, 'EA: stores the envelope for its apple identity');
SELECT is((SELECT o_has_token FROM private.signin_methods_for_actor() WHERE o_provider = 'apple'), true, 'EA: methods reports a revocable grant');
SELECT throws_ok($$SELECT private.signin_link_identity_for_actor('apple', 'edge18-a-other', NULL, false, false)$$, '23505', NULL, 'EA: a second, different apple identity is refused');
SELECT throws_ok($$SELECT * FROM private.signin_unlink_identity_for_actor('google')$$, 'P0002', NULL, 'EA: unlinking google fails: EA has no google identity, and EB''s is not reachable through EA');
SELECT is((SELECT count(*)::int FROM private.signin_enqueue_revocations_for_actor()), 1, 'EA: enqueue queues exactly EA''s own grant');
SELECT is((SELECT count(*)::int FROM private.signin_unlink_identity_for_actor('apple')), 1, 'EA: unlink apple (email remains) returns the revocation queue id');
SELECT throws_ok($$SELECT * FROM private.signin_unlink_identity_for_actor('email')$$, '55000', NULL, 'EA: unlinking the last method is refused');
-- raw table access
SELECT is((SELECT count(*)::int FROM app.signin_provider_token WHERE user_id = '5a5a1800-0000-0000-0000-0000000000eb'), 0, 'EA: EB''s grant row is invisible to edge_actor (control below: it can see its own kind of row)');
SELECT throws_ok($$SELECT refresh_token_ciphertext FROM app.signin_provider_token$$, '42501', NULL, 'EA: the ciphertext column is not readable');
SELECT throws_ok($$SELECT dek_wrapped FROM app.signin_provider_token$$, '42501', NULL, 'EA: the wrapped DEK column is not readable');
SELECT throws_ok($$INSERT INTO app.signin_provider_token (user_id, provider, refresh_token_ciphertext, dek_wrapped, kek_id) VALUES ('5a5a1800-0000-0000-0000-0000000000ea', 'apple', '\x00', '\x00', 'e18')$$, '42501', NULL, 'EA: no direct INSERT on the grant table');
SELECT throws_ok($$UPDATE app.signin_provider_token SET kek_id = 'x'$$, '42501', NULL, 'EA: no UPDATE');
SELECT throws_ok($$DELETE FROM app.signin_provider_token$$, '42501', NULL, 'EA: no DELETE');
SELECT throws_ok($$SELECT count(*) FROM private.signin_revocation_queue$$, '42501', NULL, 'EA: the queue table is not readable');
SELECT throws_ok($$INSERT INTO private.signin_revocation_queue (provider, source, token_fingerprint, refresh_token_ciphertext, dek_wrapped, kek_id) VALUES ('apple', 'unlink', 'x', '\x00', '\x00', 'e18')$$, '42501', NULL, 'EA: ... nor writable');
SELECT throws_ok($$SELECT * FROM auth.identities$$, '42501', NULL, 'EA: auth.identities is not readable by edge_actor (only the definers reach it)');
-- the core functions
SELECT throws_ok($$SELECT * FROM private.signin_methods('5a5a1800-0000-0000-0000-0000000000eb')$$, '42501', NULL, 'EA: the user-id-taking core is not callable (no way to ask about EB)');
SELECT throws_ok($$SELECT private.signin_link_identity('5a5a1800-0000-0000-0000-0000000000eb', 'apple', 'x', NULL, false, false)$$, '42501', NULL, 'EA: ... nor link to another account');
SELECT throws_ok($$SELECT * FROM private.signin_unlink_identity('5a5a1800-0000-0000-0000-0000000000eb', 'google')$$, '42501', NULL, 'EA: ... nor unlink another account''s method');
SELECT throws_ok($$SELECT * FROM private.claim_signin_revocations(NULL, 10, 60)$$, '42501', NULL, 'EA: the queue claim is not an actor operation');
-- the no-uid helpers an actor may call
SELECT is(private.signin_find_account_by_email_for_actor('EDGE18-EB@signin.test'), '5a5a1800-0000-0000-0000-0000000000eb'::uuid, 'EA: a BOUND user can look up the account holding an email (the link path needs it; returns only an id)');
SELECT throws_ok($$SELECT private.signin_find_account_by_email('edge18-eb@signin.test')$$, '42501', NULL, 'EA (F7): the unbound core lookup is not callable by an edge_actor at all');
SELECT is((SELECT o_kek_id FROM private.get_signin_token_kek(NULL)), 'e18', 'EA: can read the KEK (R6: the runtime that runs as edge_actor encrypts the grant)');
SELECT is(private.peek_signin_otp_failures_for_actor(repeat('0', 64)), 0, 'EA: a BOUND user can peek the OTP failure counter for a hash (through the wrapper)');
SELECT is((SELECT o_attempts FROM private.reserve_signin_otp_attempt_for_actor(repeat('0', 64))), 1, 'EA: ... and reserve one attempt');
SELECT is((SELECT o_window_start FROM private.reserve_signin_otp_attempt_for_actor(repeat('0', 64))), to_timestamp(floor(extract(epoch FROM now()) / 3600) * 3600), 'EA: ... the reservation reports the hour window it was charged to (L2)');
SELECT is(private.release_signin_otp_attempt_for_actor(repeat('0', 64), to_timestamp(floor(extract(epoch FROM now()) / 3600) * 3600)), 1, 'EA: ... and give one back in that window (2 -> 1)');
SELECT is(private.release_signin_otp_attempt_for_actor(repeat('0', 64), to_timestamp(floor(extract(epoch FROM now()) / 3600) * 3600) - interval '1 hour'), 0, 'EA (L2): a release naming another window moves nothing here');
SELECT is(private.peek_signin_otp_failures_for_actor(repeat('0', 64)), 1, 'EA (L2): ... the current window still holds its 1');
SELECT throws_ok($$SELECT private.peek_signin_otp_failures(repeat('0', 64))$$, '42501', NULL, 'EA (L1): even BOUND, the peek core is not callable by edge_actor (only the wrapper is)');
SELECT throws_ok($$SELECT * FROM private.reserve_signin_otp_attempt(repeat('0', 64))$$, '42501', NULL, 'EA (L1): ... nor the reserve core');
SELECT throws_ok($$SELECT private.release_signin_otp_attempt(repeat('0', 64), to_timestamp(floor(extract(epoch FROM now()) / 3600) * 3600))$$, '42501', NULL, 'EA (L1): ... nor the release core');
ROLLBACK;

-- ----------------------------------------------------------------------------
-- 4. EB's committed grant: an actor never sees it; the queue claimed by edge_system (a real COMMIT)
-- ----------------------------------------------------------------------------
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('5a5a1800-0000-0000-0000-0000000000eb')$$, 'EB: bind');
SELECT is((SELECT count(*)::int FROM private.signin_methods_for_actor()), 2, 'EB: its own two methods');
SELECT is((SELECT o_has_token FROM private.signin_methods_for_actor() WHERE o_provider = 'google'), true, 'EB: ... google with a stored grant');
SELECT is((SELECT count(*)::int FROM app.signin_provider_token), 1, 'EB: through the column grant it sees exactly its own grant row (user_id, provider only)');
SELECT is((SELECT count(*)::int FROM private.signin_enqueue_revocations_for_actor()), 1, 'EB: enqueue (committed below)');
COMMIT;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('5a5a1800-0000-0000-0000-0000000000ea')$$, 'EA: bind in a later transaction on the same connection');
SELECT is(nullif(current_setting('app.signin.target_user_id', true), ''), NULL, 'reuse: after the earlier COMMIT the window GUC reads empty');
SELECT is((SELECT count(*)::int FROM private.signin_methods_for_actor()), 1, 'reuse: the next transaction on the reused connection works and sees only EA''s method');
SELECT is((SELECT count(*)::int FROM app.signin_provider_token), 0, 'EA: EB''s committed grant is still invisible');
ROLLBACK;
BEGIN;
SET LOCAL ROLE edge_system;
CREATE TEMP TABLE claimed18 ON COMMIT DROP AS SELECT * FROM private.claim_signin_revocations(NULL, 100, 60);
SELECT is((SELECT count(*)::int FROM claimed18 WHERE o_provider = 'google' AND o_kek_id = 'e18' AND encode(o_ciphertext, 'hex') = repeat('b1', 40)), 1, 'edge_system: claims EB''s queued grant with its envelope (the drain decrypts it with the KEK)');
SELECT throws_ok($$SELECT * FROM private.signin_methods_for_actor()$$, '42501', NULL, 'edge_system: cannot call a wrapper (EXECUTE is edge_actor only)');
SELECT throws_ok($$SELECT private.signin_find_account_by_email('edge18-eb@signin.test')$$, '42501', NULL, 'edge_system: cannot look up accounts by email');
SELECT throws_ok($$SELECT count(*) FROM private.signin_revocation_queue$$, '42501', NULL, 'edge_system: still cannot read the queue table, only claim from it');
SELECT throws_ok($$SELECT count(*) FROM app.signin_provider_token$$, '42501', NULL, 'edge_system: no privilege at all on the grant table (a PII-registered table, check 12)');
SELECT is(private.complete_signin_revocation((SELECT o_id FROM claimed18 WHERE o_provider = 'google' LIMIT 1), 'revoked', NULL, 30), 'revoked', 'edge_system: records the revocation');
SELECT throws_ok($$SELECT private.purge_signin_revocation_queue(interval '1 hour')$$, '22023', NULL, 'edge_system: the purge age bound applies to it too');
COMMIT;

-- ----------------------------------------------------------------------------
-- 5. Nothing was broadened: the edge allowlist and the grants are what 0031/0032 left, plus nothing for these tables
-- (relations are looked up through pg_class: a 'schema.table'::regclass cast needs USAGE on the schema, which edge_gateway lacks)
-- ----------------------------------------------------------------------------
SELECT is((SELECT count(*)::int FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid JOIN pg_namespace n ON n.oid = c.relnamespace
           WHERE ((n.nspname = 'app' AND c.relname = 'signin_provider_token') OR (n.nspname = 'private' AND c.relname = 'signin_revocation_queue'))
             AND (p.polroles && ARRAY(SELECT oid FROM pg_roles WHERE rolname IN ('edge_actor', 'edge_system')) OR p.polroles @> ARRAY[0]::oid[])), 1,
  'no broadening: exactly ONE policy applies to an edge role on these two tables, and it is 0031''s own select-own policy');
SELECT is((SELECT p.polname FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid JOIN pg_namespace n ON n.oid = c.relnamespace
           WHERE n.nspname = 'app' AND c.relname = 'signin_provider_token' AND p.polroles && ARRAY(SELECT oid FROM pg_roles WHERE rolname = 'edge_actor')),
  'edge_actor_signin_provider_token_select', 'no broadening: ... confirmed by name');
SELECT is((SELECT array_agg(a.attname::text ORDER BY a.attname)
           FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace
           WHERE n.nspname = 'app' AND c.relname = 'signin_provider_token' AND a.attnum > 0 AND NOT a.attisdropped AND has_column_privilege('edge_actor', a.attrelid, a.attnum, 'SELECT')),
  ARRAY['provider', 'user_id'], 'no broadening: edge_actor''s column grant on the grant table is still exactly (provider, user_id)');

-- No finish(): see 16_edge_role.sql.

-- ============================================================================
-- PHASE 2: cleanup (harness role)
-- ============================================================================
\c :"harness_db" :"harness_user"
SET ROLE service_role;
BEGIN;
SELECT private.delete_my_data(u) FROM unnest(ARRAY['5a5a1800-0000-0000-0000-0000000000ea', '5a5a1800-0000-0000-0000-0000000000eb']::uuid[]) AS u;
DELETE FROM auth.identities WHERE user_id IN ('5a5a1800-0000-0000-0000-0000000000ea', '5a5a1800-0000-0000-0000-0000000000eb');
DELETE FROM vault.secrets WHERE name = 'siwa_token_kek_e18';
DELETE FROM private.rate_limit_bucket WHERE bucket_key = 'signin-otp-fail:' || repeat('0', 64);
COMMIT;
RESET ROLE;
-- the queue rows this file committed: only private_definer holds anything on the table, and the migrating role may SET ROLE to it
BEGIN;
SET LOCAL ROLE private_definer;
DELETE FROM private.signin_revocation_queue WHERE token_fingerprint IN (md5(decode(repeat('b1', 40), 'hex')), md5(decode(repeat('e1', 40), 'hex')));
COMMIT;
