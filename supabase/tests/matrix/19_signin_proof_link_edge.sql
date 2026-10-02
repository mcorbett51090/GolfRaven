-- 19_signin_proof_link_edge.sql
-- 0039_signin_proof_bound_link.sql, the EDGE lane: the proof is MINTED by edge_system (private.signin_record_email_proof) in an unbound
-- transaction and REDEEMED by a bound kind = 'user' edge_actor (private.signin_link_identity_with_proof_for_actor), which links the identity and
-- stores its token for the PROOF'S target account, never for the caller. It reconnects as a REAL `edge_gateway` login for the reason
-- 16_edge_role.sql gives (SET ROLE is judged by the session user), so it is its own file; the structure, the RLS scoping, the purge and
-- the account deletion are 19_signin_proof_link.sql.
--
-- THE THREE PHASES (the same as 16 / 18)
--   0  (harness role)  seed throw-away accounts (a caller PC, targets PT / PD / PH, an unrelated PX, and three accounts whose GoTrue sign-in stamp is
--      stale / absent / in the future), three COMMITTED proofs as private_definer (one expired, one already consumed, one for an address that has
--      since changed hands) and a queued evidence row for the delegate cell. COMMITTED: edge transactions run in another session.
--   1  (edge_gateway)  every assertion; each group is its own BEGIN ... ROLLBACK except the committed flow (a real COMMIT between mint and redeem).
--   2  (harness role)  removes everything phase 0 and 1 committed.
--
-- THE CORROBORATION. The minter refuses unless auth.users.last_sign_in_at of the TARGET is within 60 seconds of the call: the harness stamps it in
-- phase 0 (GoTrue would, after a verifyOtp), and phase 1 runs a second or two later. [unverified: real GoTrue stamps it for verifyOtp.]
--
-- No secret in this file: the ciphertexts are filler (the database never decrypts), hashes are computed at run time, ids are synthetic constants
-- starting 5a5a1901-.

\set QUIET 1
SELECT session_user::text AS harness_user, current_database()::text AS harness_db \gset

-- ============================================================================
-- PHASE 0: seed (committed)
-- ============================================================================
SET ROLE service_role;
BEGIN;
-- pre-clean: a run that aborted before its own phase 2 left these committed (this file must be re-runnable, like 16 / 18)
SELECT private.delete_my_data(u.id) FROM auth.users u WHERE u.id::text LIKE '5a5a1901-0000-0000-0000-0000000000%';
DELETE FROM auth.identities WHERE user_id::text LIKE '5a5a1901-0000-0000-0000-0000000000%';
INSERT INTO auth.users (id, email) VALUES
  ('5a5a1901-0000-0000-0000-0000000000c1', 'p19e-pc@signin.test'),
  ('5a5a1901-0000-0000-0000-0000000000a1', 'p19e-pt@signin.test'),
  ('5a5a1901-0000-0000-0000-0000000000d1', 'p19e-pd@signin.test'),
  ('5a5a1901-0000-0000-0000-0000000000e1', 'p19e-px@signin.test'),
  ('5a5a1901-0000-0000-0000-0000000000b1', 'p19e-ph@signin.test'),
  ('5a5a1901-0000-0000-0000-000000000051', 'p19e-ps@signin.test'),
  ('5a5a1901-0000-0000-0000-00000000000f', 'p19e-pn@signin.test'),
  ('5a5a1901-0000-0000-0000-0000000000f1', 'p19e-pf@signin.test')
ON CONFLICT (id) DO NOTHING; -- auth.users rows are never deleted by this harness, so a re-run finds them
INSERT INTO app.profile (user_id, handle) VALUES
  ('5a5a1901-0000-0000-0000-0000000000c1', 'p19e_pc'), ('5a5a1901-0000-0000-0000-0000000000a1', 'p19e_pt'), ('5a5a1901-0000-0000-0000-0000000000e1', 'p19e_px');
INSERT INTO auth.identities (provider_id, user_id, identity_data, provider) VALUES
  ('p19e-pc@signin.test', '5a5a1901-0000-0000-0000-0000000000c1', '{"email":"p19e-pc@signin.test"}', 'email'),
  ('p19e-pt@signin.test', '5a5a1901-0000-0000-0000-0000000000a1', '{"email":"p19e-pt@signin.test"}', 'email'),
  ('p19e-pd@signin.test', '5a5a1901-0000-0000-0000-0000000000d1', '{"email":"p19e-pd@signin.test"}', 'email'),
  ('p19e-pd-apple', '5a5a1901-0000-0000-0000-0000000000d1', '{"email":"p19e-pd@signin.test"}', 'apple'),
  ('p19e-px@signin.test', '5a5a1901-0000-0000-0000-0000000000e1', '{"email":"p19e-px@signin.test"}', 'email'),
  ('p19e-px-apple', '5a5a1901-0000-0000-0000-0000000000e1', '{"email":"p19e-px@signin.test"}', 'apple'),
  ('p19e-ph@signin.test', '5a5a1901-0000-0000-0000-0000000000b1', '{"email":"p19e-ph@signin.test"}', 'email');
-- GoTrue's sign-in stamp, as a verifyOtp would have left it (clock_timestamp: as fresh as possible)
UPDATE auth.users SET last_sign_in_at = clock_timestamp() WHERE id IN ('5a5a1901-0000-0000-0000-0000000000a1', '5a5a1901-0000-0000-0000-0000000000d1');
UPDATE auth.users SET last_sign_in_at = clock_timestamp() - interval '10 minutes' WHERE id = '5a5a1901-0000-0000-0000-000000000051';
UPDATE auth.users SET last_sign_in_at = NULL WHERE id = '5a5a1901-0000-0000-0000-00000000000f';
UPDATE auth.users SET last_sign_in_at = clock_timestamp() + interval '10 minutes' WHERE id = '5a5a1901-0000-0000-0000-0000000000f1';
INSERT INTO app.evidence (id, user_id, source, source_ref, input_hash, local_date, status, claimed_facility_id, claimed_course_id, claimed_catalog_version, queued_input) VALUES
  ('5a5a1901-0000-0000-0000-00000000e001', '5a5a1901-0000-0000-0000-0000000000e1', 'foreground_checkin', 'edge19-queued', 'h-e19', current_date, 'queued_catalog', 'fac_x', 'crs_x1', '20300102-0000001', '{"k": "v"}'::jsonb);
COMMIT;
RESET ROLE;
-- three committed proofs, written the only way a proof can be: as private_definer with the window open on the row's id
BEGIN;
SET LOCAL ROLE private_definer;
SELECT set_config('app.signin.proof_id', '5a5a1901-0000-0000-0000-00000000e0e1', true);
INSERT INTO private.signin_email_proof (id, caller_user_id, target_user_id, email_hash, provider, sub_hash, created_at, expires_at)
VALUES ('5a5a1901-0000-0000-0000-00000000e0e1', '5a5a1901-0000-0000-0000-0000000000c1', '5a5a1901-0000-0000-0000-0000000000a1',
        encode(sha256(convert_to('p19e-pt@signin.test', 'UTF8')), 'hex'), 'apple', encode(sha256(convert_to('apple:p19e-sub-exp', 'UTF8')), 'hex'), now() - interval '20 minutes', now() - interval '15 minutes');
SELECT set_config('app.signin.proof_id', '5a5a1901-0000-0000-0000-00000000e0e2', true);
INSERT INTO private.signin_email_proof (id, caller_user_id, target_user_id, email_hash, provider, sub_hash, created_at, expires_at, consumed_at)
VALUES ('5a5a1901-0000-0000-0000-00000000e0e2', '5a5a1901-0000-0000-0000-0000000000c1', '5a5a1901-0000-0000-0000-0000000000a1',
        encode(sha256(convert_to('p19e-pt@signin.test', 'UTF8')), 'hex'), 'apple', encode(sha256(convert_to('apple:p19e-sub-used', 'UTF8')), 'hex'), now(), now() + interval '5 minutes', now());
SELECT set_config('app.signin.proof_id', '5a5a1901-0000-0000-0000-00000000e0e3', true);
INSERT INTO private.signin_email_proof (id, caller_user_id, target_user_id, email_hash, provider, sub_hash, created_at, expires_at)
VALUES ('5a5a1901-0000-0000-0000-00000000e0e3', '5a5a1901-0000-0000-0000-0000000000c1', '5a5a1901-0000-0000-0000-0000000000b1',
        encode(sha256(convert_to('p19e-ph-old@signin.test', 'UTF8')), 'hex'), 'apple', encode(sha256(convert_to('apple:p19e-sub-old', 'UTF8')), 'hex'), now(), now() + interval '5 minutes');
-- and one STALE proof (expired 2 hours 55 minutes ago): the next committed mint removes it
SELECT set_config('app.signin.proof_id', '5a5a1901-0000-0000-0000-00000000e0e4', true);
INSERT INTO private.signin_email_proof (id, caller_user_id, target_user_id, email_hash, provider, sub_hash, created_at, expires_at)
VALUES ('5a5a1901-0000-0000-0000-00000000e0e4', '5a5a1901-0000-0000-0000-0000000000c1', '5a5a1901-0000-0000-0000-0000000000a1',
        encode(sha256(convert_to('p19e-pt@signin.test', 'UTF8')), 'hex'), 'apple', encode(sha256(convert_to('apple:p19e-sub-stale', 'UTF8')), 'hex'), now() - interval '3 hours', now() - interval '2 hours 55 minutes');
SELECT set_config('app.signin.proof_id', '', true);
COMMIT;

-- ============================================================================
-- PHASE 1: reconnect as the real login
-- ============================================================================
\c :"harness_db" edge_gateway
\set QUIET 1
SELECT plan(78);

-- helpers (session-level temp functions): privileges by name, a sha256 hex, and the two calls under test with one-line arguments
CREATE FUNCTION pg_temp.can_exec(p_role text, p_names text[]) RETURNS int LANGUAGE sql STABLE AS $f$
  SELECT count(*)::int FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
  WHERE n.nspname = 'private' AND p.proname = ANY (p_names) AND has_function_privilege(p_role, p.oid, 'EXECUTE')
$f$;
CREATE FUNCTION pg_temp.h(p_text text) RETURNS text LANGUAGE sql IMMUTABLE AS $f$ SELECT encode(sha256(convert_to(p_text, 'UTF8')), 'hex') $f$;
-- plpgsql, not sql: a SQL function's body is checked at CREATE time, and edge_gateway has no USAGE on schema private (and must not)
CREATE FUNCTION pg_temp.mint(p_caller uuid, p_target uuid, p_email text, p_sub text, p_provider text DEFAULT 'apple') RETURNS uuid LANGUAGE plpgsql AS $f$
BEGIN
  RETURN private.signin_record_email_proof(p_caller, p_target, pg_temp.h(lower(btrim(p_email))), p_provider, pg_temp.h(p_provider || ':' || p_sub));
END
$f$;
CREATE FUNCTION pg_temp.link(p_sub text, p_email text DEFAULT 'p19e-pt@signin.test', p_provider text DEFAULT 'apple', p_verified boolean DEFAULT true, p_relay boolean DEFAULT false, p_pid uuid DEFAULT NULL) RETURNS boolean LANGUAGE plpgsql AS $f$
BEGIN
  RETURN private.signin_link_identity_with_proof_for_actor(coalesce(p_pid, current_setting('p19.pid')::uuid), p_provider, p_sub, p_email, p_verified, p_relay,
                                                           decode(repeat('e1', 40), 'hex'), decode(repeat('e2', 70), 'hex'), 'e19');
END
$f$;

-- ----------------------------------------------------------------------------
-- 1. Privileges: who can call what, and what nobody can touch
-- ----------------------------------------------------------------------------
SELECT is(pg_temp.can_exec('edge_actor', ARRAY['signin_record_email_proof', 'purge_signin_email_proofs']), 0,
  'privileges: edge_actor can NOT mint a proof, nor run the purge (the per-user lane never writes the proof table)');
SELECT is(pg_temp.can_exec('edge_actor', ARRAY['signin_link_identity_with_proof_for_actor']), 1, 'privileges: ... it can redeem one, through the bound-actor definer only');
SELECT is(pg_temp.can_exec('edge_system', ARRAY['signin_record_email_proof', 'purge_signin_email_proofs']), 2, 'privileges: edge_system can mint and purge');
SELECT is(pg_temp.can_exec('edge_system', ARRAY['signin_link_identity_with_proof_for_actor']), 0, 'privileges: ... but can not redeem (it is not an actor)');
SELECT is(pg_temp.can_exec('service_role', ARRAY['signin_record_email_proof', 'signin_link_identity_with_proof_for_actor']), 0, 'privileges: service_role (the legacy lane) can do neither');
-- (the relation is looked up through pg_class: a 'schema.table'::regclass cast needs USAGE on the schema, which edge_gateway lacks)
SELECT is((SELECT count(*)::int FROM (VALUES ('edge_gateway'), ('edge_actor'), ('edge_system')) r(n)
           CROSS JOIN (SELECT c.oid FROM pg_class c JOIN pg_namespace ns ON ns.oid = c.relnamespace WHERE ns.nspname = 'private' AND c.relname = 'signin_email_proof') t
           WHERE has_any_column_privilege(r.n, t.oid, 'SELECT,INSERT,UPDATE,REFERENCES') OR has_table_privilege(r.n, t.oid, 'DELETE,TRUNCATE,TRIGGER')), 0,
  'privileges: no edge role holds any privilege on the proof table');

-- ----------------------------------------------------------------------------
-- 2. The minter refuses: wrong role, bound transaction, bad arguments, the email binding, the GoTrue corroboration
-- ----------------------------------------------------------------------------
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT throws_ok($$SELECT pg_temp.mint('5a5a1901-0000-0000-0000-0000000000c1', '5a5a1901-0000-0000-0000-0000000000a1', 'p19e-pt@signin.test', 'p19e-sub-a')$$, '42501', NULL,
  'mint: an UNBOUND edge_actor cannot mint (permission denied: not granted to it)');
SELECT lives_ok($$SELECT private.bind_actor('5a5a1901-0000-0000-0000-0000000000c1')$$, 'mint: bind the caller PC');
SELECT throws_ok($$SELECT pg_temp.mint('5a5a1901-0000-0000-0000-0000000000c1', '5a5a1901-0000-0000-0000-0000000000a1', 'p19e-pt@signin.test', 'p19e-sub-a')$$, '42501', NULL,
  'mint: a BOUND edge_actor cannot mint either');
SELECT throws_ok($$SELECT * FROM private.signin_email_proof$$, '42501', NULL, 'mint: edge_actor cannot read the proof table');
SELECT throws_ok($$INSERT INTO private.signin_email_proof (caller_user_id, target_user_id, email_hash, provider, sub_hash, expires_at) VALUES ('5a5a1901-0000-0000-0000-0000000000c1', '5a5a1901-0000-0000-0000-0000000000a1', repeat('a', 64), 'apple', repeat('b', 64), now() + interval '5 minutes')$$, '42501', NULL,
  'mint: ... nor insert a proof of its own');
SELECT throws_ok($$UPDATE private.signin_email_proof SET consumed_at = NULL$$, '42501', NULL, 'mint: ... nor un-consume one');
SELECT throws_ok($$DELETE FROM private.signin_email_proof$$, '42501', NULL, 'mint: ... nor delete one');
SET LOCAL ROLE edge_system;
SELECT throws_ok($$SELECT pg_temp.mint('5a5a1901-0000-0000-0000-0000000000c1', '5a5a1901-0000-0000-0000-0000000000a1', 'p19e-pt@signin.test', 'p19e-sub-a')$$, '42501', 'signin_record_email_proof: a proof cannot be minted inside an actor-bound transaction',
  'mint: edge_system cannot mint inside a transaction that already has an actor bound (SET ROLE edge_system does not escape the binding)');
ROLLBACK;

BEGIN;
SET LOCAL ROLE edge_system;
SELECT is(private.bind_delegate_for_queued_evidence('5a5a1901-0000-0000-0000-00000000e001'), '5a5a1901-0000-0000-0000-0000000000e1'::uuid, 'mint: edge_system binds a system delegate');
SELECT throws_ok($$SELECT pg_temp.mint('5a5a1901-0000-0000-0000-0000000000c1', '5a5a1901-0000-0000-0000-0000000000a1', 'p19e-pt@signin.test', 'p19e-sub-a')$$, '42501', 'signin_record_email_proof: a proof cannot be minted inside an actor-bound transaction',
  'mint: ... a delegate binding is a binding too');
ROLLBACK;

BEGIN;
SET LOCAL ROLE edge_system;
SELECT throws_ok($$SELECT * FROM private.signin_email_proof$$, '42501', NULL, 'mint: edge_system cannot read the proof table (check 12: no privilege on a PII-registered table)');
SELECT throws_ok($$INSERT INTO private.signin_email_proof (caller_user_id, target_user_id, email_hash, provider, sub_hash, expires_at) VALUES ('5a5a1901-0000-0000-0000-0000000000c1', '5a5a1901-0000-0000-0000-0000000000a1', repeat('a', 64), 'apple', repeat('b', 64), now() + interval '5 minutes')$$, '42501', NULL,
  'mint: ... nor write it directly: the minter definer is the only writer');
SELECT throws_ok($$SELECT private.signin_record_email_proof(NULL, '5a5a1901-0000-0000-0000-0000000000a1', repeat('a', 64), 'apple', repeat('b', 64))$$, '22023', 'signin_record_email_proof: invalid caller, target, provider or hash', 'mint: a NULL caller is refused');
SELECT throws_ok($$SELECT private.signin_record_email_proof('5a5a1901-0000-0000-0000-0000000000c1', '5a5a1901-0000-0000-0000-0000000000a1', 'not-a-hash', 'apple', repeat('b', 64))$$, '22023', 'signin_record_email_proof: invalid caller, target, provider or hash', 'mint: a malformed email hash is refused');
SELECT throws_ok($$SELECT private.signin_record_email_proof('5a5a1901-0000-0000-0000-0000000000c1', '5a5a1901-0000-0000-0000-0000000000a1', repeat('a', 64), 'apple', repeat('B', 64))$$, '22023', 'signin_record_email_proof: invalid caller, target, provider or hash', 'mint: a malformed subject hash is refused');
SELECT throws_ok($$SELECT private.signin_record_email_proof('5a5a1901-0000-0000-0000-0000000000c1', '5a5a1901-0000-0000-0000-0000000000a1', repeat('a', 64), 'facebook', repeat('b', 64))$$, '22023', 'signin_record_email_proof: invalid caller, target, provider or hash', 'mint: only apple and google are providers');
SELECT throws_ok($$SELECT pg_temp.mint('5a5a1901-0000-0000-0000-0000000000a1', '5a5a1901-0000-0000-0000-0000000000a1', 'p19e-pt@signin.test', 'p19e-sub-a')$$, '22023', 'signin_record_email_proof: a proof is for ANOTHER account (the caller is the target)', 'mint: caller = target is refused (a proof is cross-account)');
SELECT throws_ok($$SELECT pg_temp.mint('5a5a1901-0000-0000-0000-0000000000ff', '5a5a1901-0000-0000-0000-0000000000a1', 'p19e-pt@signin.test', 'p19e-sub-a')$$, 'P0002', 'signin_record_email_proof: no such caller', 'mint: an unknown caller is refused');
SELECT throws_ok($$SELECT pg_temp.mint('5a5a1901-0000-0000-0000-0000000000c1', '5a5a1901-0000-0000-0000-0000000000ff', 'p19e-pt@signin.test', 'p19e-sub-a')$$, 'P0002', 'signin_record_email_proof: no such target account', 'mint: an unknown target is refused');
SELECT throws_ok($$SELECT pg_temp.mint('5a5a1901-0000-0000-0000-0000000000c1', '5a5a1901-0000-0000-0000-0000000000a1', 'p19e-pc@signin.test', 'p19e-sub-a')$$, '28000', 'email_proof_refused: the proven address is not the target account''s address',
  'mint: the email binding is the DATABASE''s: a proof of the CALLER''s own address cannot be minted against the target');
SELECT throws_ok($$SELECT pg_temp.mint('5a5a1901-0000-0000-0000-0000000000c1', '5a5a1901-0000-0000-0000-000000000051', 'p19e-ps@signin.test', 'p19e-sub-a')$$, '28000', 'email_proof_refused: the target account has no sign-in within the last 60 seconds to corroborate the proof',
  'mint: a target whose GoTrue sign-in stamp is 10 minutes old is refused (no verifyOtp just happened)');
SELECT throws_ok($$SELECT pg_temp.mint('5a5a1901-0000-0000-0000-0000000000c1', '5a5a1901-0000-0000-0000-00000000000f', 'p19e-pn@signin.test', 'p19e-sub-a')$$, '28000', 'email_proof_refused: the target account has no sign-in within the last 60 seconds to corroborate the proof',
  'mint: ... one that has never signed in (NULL) is refused');
SELECT throws_ok($$SELECT pg_temp.mint('5a5a1901-0000-0000-0000-0000000000c1', '5a5a1901-0000-0000-0000-0000000000f1', 'p19e-pf@signin.test', 'p19e-sub-a')$$, '28000', 'email_proof_refused: the target account has no sign-in within the last 60 seconds to corroborate the proof',
  'mint: ... and one stamped 10 minutes in the FUTURE is refused too (the window is symmetric around now, not open-ended)');
SELECT lives_ok($$SELECT pg_temp.mint('5a5a1901-0000-0000-0000-0000000000c1', '5a5a1901-0000-0000-0000-0000000000a1', '  P19E-PT@signin.test ', 'p19e-sub-a')$$,
  'mint: the fresh, correctly-bound proof IS minted (the helper normalises the address before hashing, as the Edge code does)');
ROLLBACK;

-- ----------------------------------------------------------------------------
-- 3. Redeeming: unbound and delegate refusals
-- ----------------------------------------------------------------------------
BEGIN;
SET LOCAL ROLE edge_system;
SELECT set_config('p19.pid', pg_temp.mint('5a5a1901-0000-0000-0000-0000000000c1', '5a5a1901-0000-0000-0000-0000000000a1', 'p19e-pt@signin.test', 'p19e-sub-a')::text, true);
SET LOCAL ROLE edge_actor;
SELECT throws_ok($$SELECT pg_temp.link('p19e-sub-a')$$, '42501', 'signin_link_identity_with_proof_for_actor: no actor is bound in this transaction', 'redeem: an UNBOUND edge_actor cannot redeem a proof');
ROLLBACK;

BEGIN;
SET LOCAL ROLE edge_system;
SELECT set_config('p19.pid', pg_temp.mint('5a5a1901-0000-0000-0000-0000000000c1', '5a5a1901-0000-0000-0000-0000000000a1', 'p19e-pt@signin.test', 'p19e-sub-a')::text, true);
SELECT is(private.bind_delegate_for_queued_evidence('5a5a1901-0000-0000-0000-00000000e001'), '5a5a1901-0000-0000-0000-0000000000e1'::uuid, 'redeem: a delegate binding (kind = system_delegate) is made after the proof was minted');
SET LOCAL ROLE edge_actor;
SELECT throws_ok($$SELECT pg_temp.link('p19e-sub-a')$$, '42501', 'signin_link_identity_with_proof_for_actor: a system delegate may not manage sign-in methods', 'redeem: a system DELEGATE cannot redeem a proof');
ROLLBACK;

-- ----------------------------------------------------------------------------
-- 4. Redeeming: every binding is checked, in the database, and the link lands on the TARGET
-- ----------------------------------------------------------------------------
BEGIN;
SET LOCAL ROLE edge_system;
SELECT set_config('p19.pid', pg_temp.mint('5a5a1901-0000-0000-0000-0000000000c1', '5a5a1901-0000-0000-0000-0000000000a1', 'p19e-pt@signin.test', 'p19e-sub-a')::text, true);
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('5a5a1901-0000-0000-0000-0000000000c1')$$, 'redeem: bind the caller PC');
SELECT throws_ok($$SELECT pg_temp.link('p19e-sub-b')$$, '28000', 'email_proof_refused: that proof was issued for a different identity', 'redeem: a proof minted for Apple sub A cannot link sub B');
SELECT throws_ok($$SELECT pg_temp.link('p19e-sub-a', 'p19e-pt@signin.test', 'google')$$, '28000', 'email_proof_refused: that proof was issued for a different identity', 'redeem: ... nor the same subject under another provider');
SELECT throws_ok($$SELECT pg_temp.link('p19e-sub-a', 'p19e-pc@signin.test')$$, '28000', 'email_proof_refused: that proof was issued for a different address', 'redeem: a proof for the target''s address cannot link an identity that carries another address');
SELECT throws_ok($$SELECT pg_temp.link('p19e-sub-a', 'p19e-pt@signin.test', 'apple', false)$$, '22023', NULL, 'redeem: an UNVERIFIED email is never the proof path');
SELECT throws_ok($$SELECT pg_temp.link('p19e-sub-a', 'p19e-pt@signin.test', 'apple', true, true)$$, '22023', NULL, 'redeem: a PRIVATE-RELAY address is never the proof path');
SELECT throws_ok($$SELECT pg_temp.link('p19e-sub-a', 'p19e-pt@signin.test', 'apple', true, false, gen_random_uuid())$$, '28000', 'email_proof_refused: no such proof', 'redeem: a proof id that does not exist is refused');
SELECT throws_ok($$SELECT private.signin_link_identity_with_proof_for_actor(NULL, 'apple', 'p19e-sub-a', 'p19e-pt@signin.test', true, false, decode(repeat('e1', 40), 'hex'), decode(repeat('e2', 70), 'hex'), 'e19')$$, '22023', NULL, 'redeem: a NULL proof id is refused');
SELECT throws_ok($$SELECT private.signin_link_identity_with_proof_for_actor(current_setting('p19.pid')::uuid, 'apple', 'p19e-sub-a', 'p19e-pt@signin.test', true, false, decode('abcd', 'hex'), decode(repeat('e2', 70), 'hex'), 'e19')$$, '22023', NULL,
  'redeem: a too-short ciphertext is refused by the token store, and (it is one transaction) the proof stays unconsumed');
SELECT is(pg_temp.link('p19e-sub-a'), true, 'redeem: the correctly bound proof links the identity (created = true)');
SELECT is((SELECT count(*)::int FROM private.signin_methods_for_actor()), 1, 'redeem: ... and the CALLER''s own methods are still just the one (email): the identity did NOT land on the caller');
SELECT is((SELECT count(*)::int FROM private.signin_methods_for_actor() WHERE o_provider = 'apple'), 0, 'redeem: ... no apple on the caller');
SELECT throws_ok($$SELECT pg_temp.link('p19e-sub-a')$$, '28000', 'email_proof_refused: that proof was already used', 'redeem: REPLAY: the same proof again is refused (single use)');
ROLLBACK;

-- another caller cannot redeem a proof issued to PC
BEGIN;
SET LOCAL ROLE edge_system;
SELECT set_config('p19.pid', pg_temp.mint('5a5a1901-0000-0000-0000-0000000000c1', '5a5a1901-0000-0000-0000-0000000000a1', 'p19e-pt@signin.test', 'p19e-sub-a')::text, true);
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('5a5a1901-0000-0000-0000-0000000000e1')$$, 'redeem: bind an UNRELATED caller PX');
SELECT throws_ok($$SELECT pg_temp.link('p19e-sub-a')$$, '28000', 'email_proof_refused: that proof was issued to another caller', 'redeem: a proof is redeemable only by the caller it was issued to');
ROLLBACK;

-- the three proofs seeded (committed) in phase 0: expired, already consumed, address changed hands
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('5a5a1901-0000-0000-0000-0000000000c1')$$, 'redeem: bind the caller PC');
SELECT throws_ok($$SELECT pg_temp.link('p19e-sub-exp', 'p19e-pt@signin.test', 'apple', true, false, '5a5a1901-0000-0000-0000-00000000e0e1')$$, '28000', 'email_proof_refused: that proof has expired', 'redeem: an EXPIRED proof is refused');
SELECT throws_ok($$SELECT pg_temp.link('p19e-sub-used', 'p19e-pt@signin.test', 'apple', true, false, '5a5a1901-0000-0000-0000-00000000e0e2')$$, '28000', 'email_proof_refused: that proof was already used', 'redeem: a CONSUMED proof (one still inside its lifetime) is refused');
SELECT throws_ok($$SELECT pg_temp.link('p19e-sub-old', 'p19e-ph-old@signin.test', 'apple', true, false, '5a5a1901-0000-0000-0000-00000000e0e3')$$, '28000', 'email_proof_refused: the proven address no longer belongs to the target account',
  'redeem: a proof for an address that has since CHANGED HANDS (the target''s auth.users.email is no longer it) is refused');
SELECT throws_ok($$SELECT pg_temp.link('p19e-sub-stale', 'p19e-pt@signin.test', 'apple', true, false, '5a5a1901-0000-0000-0000-00000000e0e4')$$, '28000', 'email_proof_refused: that proof has expired',
  'redeem: (control for the retention cell below) the hour-stale proof is still there and refused as expired, until a mint commits');
ROLLBACK;

-- ----------------------------------------------------------------------------
-- 5. The §3.4 rules are the legacy path's: duplicate identity, one Apple per account
-- ----------------------------------------------------------------------------
BEGIN;
SET LOCAL ROLE edge_system;
SELECT set_config('p19.pid', pg_temp.mint('5a5a1901-0000-0000-0000-0000000000c1', '5a5a1901-0000-0000-0000-0000000000d1', 'p19e-pd@signin.test', 'p19e-sub-other')::text, true);
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('5a5a1901-0000-0000-0000-0000000000c1')$$, 'rules: bind the caller PC');
SELECT throws_ok($$SELECT pg_temp.link('p19e-sub-other', 'p19e-pd@signin.test')$$, '23505', 'provider_already_linked: this account already has a different apple identity',
  'rules: a DIFFERENT Apple identity on a target that already has one is refused (one Apple per account)');
ROLLBACK;
BEGIN;
SET LOCAL ROLE edge_system;
SELECT set_config('p19.pid', pg_temp.mint('5a5a1901-0000-0000-0000-0000000000c1', '5a5a1901-0000-0000-0000-0000000000d1', 'p19e-pd@signin.test', 'p19e-pd-apple')::text, true);
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('5a5a1901-0000-0000-0000-0000000000c1')$$, 'rules: bind the caller PC');
SELECT is(pg_temp.link('p19e-pd-apple', 'p19e-pd@signin.test'), false, 'rules: the SAME identity the target already holds links as created = false (idempotent: no duplicate row)');
ROLLBACK;
BEGIN;
SET LOCAL ROLE edge_system;
SELECT set_config('p19.pid', pg_temp.mint('5a5a1901-0000-0000-0000-0000000000c1', '5a5a1901-0000-0000-0000-0000000000a1', 'p19e-pt@signin.test', 'p19e-px-apple')::text, true);
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('5a5a1901-0000-0000-0000-0000000000c1')$$, 'rules: bind the caller PC');
SELECT throws_ok($$SELECT pg_temp.link('p19e-px-apple')$$, '23505', 'identity_conflict: that identity belongs to another account', 'rules: an identity that belongs to ANOTHER account (PX) is never moved, proof or not');
ROLLBACK;

-- ----------------------------------------------------------------------------
-- 6. The committed flow: mint and redeem in different transactions, then look at both accounts
-- ----------------------------------------------------------------------------
BEGIN;
SET LOCAL ROLE edge_system;
SELECT set_config('p19.pid', pg_temp.mint('5a5a1901-0000-0000-0000-0000000000c1', '5a5a1901-0000-0000-0000-0000000000a1', 'p19e-pt@signin.test', 'p19e-sub-c')::text, false);
COMMIT;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('5a5a1901-0000-0000-0000-0000000000e1')$$, 'flow: bind PX in a later transaction on the reused connection');
SELECT throws_ok($$SELECT pg_temp.link('p19e-sub-c')$$, '28000', 'email_proof_refused: that proof was issued to another caller', 'flow: the committed proof is not redeemable by PX');
ROLLBACK;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('5a5a1901-0000-0000-0000-0000000000c1')$$, 'flow: bind PC (the caller the proof was issued to)');
SELECT throws_ok($$SELECT pg_temp.link('p19e-sub-stale', 'p19e-pt@signin.test', 'apple', true, false, '5a5a1901-0000-0000-0000-00000000e0e4')$$, '28000', 'email_proof_refused: no such proof',
  'retention: the committed mint removed the proof that was an hour past its expiry (it is no longer there, not merely expired)');
SELECT throws_ok($$SELECT pg_temp.link('p19e-sub-exp', 'p19e-pt@signin.test', 'apple', true, false, '5a5a1901-0000-0000-0000-00000000e0e1')$$, '28000', 'email_proof_refused: that proof has expired',
  'retention: ... and one only 15 minutes past its expiry was NOT removed (the minter touches only what is an hour stale)');
SELECT is(nullif(current_setting('app.signin.proof_id', true), ''), NULL, 'flow (session reuse): the proof-id window GUC reads empty in a transaction that follows a COMMIT');
SELECT is(pg_temp.link('p19e-sub-c'), true, 'flow: PC redeems the committed proof: the identity is created');
COMMIT;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('5a5a1901-0000-0000-0000-0000000000a1')$$, 'flow: bind the TARGET PT');
SELECT is((SELECT count(*)::int FROM private.signin_methods_for_actor()), 2, 'flow: the TARGET now has two methods (email and apple): the identity landed on the account whose mailbox was proven');
SELECT is((SELECT o_has_token FROM private.signin_methods_for_actor() WHERE o_provider = 'apple'), true, 'flow: ... and the provider grant was stored for the TARGET (revocable)');
SELECT is((SELECT o_subject FROM private.signin_methods_for_actor() WHERE o_provider = 'apple'), 'p19e-sub-c', 'flow: ... under the Apple subject the proof was minted for');
SELECT is((SELECT count(*)::int FROM private.signin_unlink_identity_for_actor('apple')), 1, 'last-method rule: the target can unlink the new apple method while email remains, and its revocation is queued');
SELECT throws_ok($$SELECT * FROM private.signin_unlink_identity_for_actor('email')$$, '55000', NULL, 'last-method rule: ... and the last method still cannot be unlinked (the proof path does not weaken rule 4)');
ROLLBACK;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('5a5a1901-0000-0000-0000-0000000000c1')$$, 'flow: bind the CALLER PC');
SELECT is((SELECT count(*)::int FROM private.signin_methods_for_actor() WHERE o_provider = 'apple'), 0, 'flow: the caller has NO apple identity (it was never linked to actor_uid())');
SELECT is((SELECT count(*)::int FROM private.signin_methods_for_actor()), 1, 'flow: ... and no new method of any kind');
SELECT throws_ok($$SELECT pg_temp.link('p19e-sub-c')$$, '28000', 'email_proof_refused: that proof was already used', 'flow: REPLAY of the redeemed proof, in a later transaction, is refused');
ROLLBACK;

-- ----------------------------------------------------------------------------
-- 7. Nothing was broadened
-- ----------------------------------------------------------------------------
SELECT is((SELECT count(*)::int FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid JOIN pg_namespace n ON n.oid = c.relnamespace
           WHERE n.nspname = 'private' AND c.relname = 'signin_email_proof'
             AND (p.polroles && ARRAY(SELECT oid FROM pg_roles WHERE rolname IN ('edge_actor', 'edge_system')) OR p.polroles @> ARRAY[0]::oid[])), 0,
  'no broadening: NO policy on the proof table applies to an edge role or to PUBLIC');
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
SELECT private.delete_my_data(u.id) FROM auth.users u WHERE u.id::text LIKE '5a5a1901-0000-0000-0000-0000000000%';
DELETE FROM auth.identities WHERE user_id::text LIKE '5a5a1901-0000-0000-0000-0000000000%';
COMMIT;
RESET ROLE;
