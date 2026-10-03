-- 19_signin_proof_link_edge.sql
-- 0039_signin_proof_bound_link.sql + 0041_signin_proof_hardening.sql, the EDGE lane: the proof is MINTED by edge_signin_minter (private.signin_record_email_proof;
-- 0041 moved EXECUTE there from edge_system, and bound the proof to the GoTrue session verifyOtp created) in an unbound
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
-- THE CORROBORATION. The minter refuses unless auth.users.last_sign_in_at of the TARGET is within 60 seconds of the call, AND unless auth.sessions holds a
-- session with the given id for the TARGET created within 60 seconds (0041, (b)): the harness stamps both in phase 0 (GoTrue would, after a verifyOtp), and
-- phase 1 runs a second or two later. [unverified: real GoTrue stamps last_sign_in_at and creates the session row for verifyOtp.] One session mints at most
-- ONE proof (a unique index), so every committed mint here has a session of its own; the rolled-back ones reuse the session of their account.
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
  ('5a5a1901-0000-0000-0000-0000000000f1', 'p19e-pf@signin.test'),
  ('5a5a1901-0000-0000-0000-0000000000b2', 'p19e-i@signin.test'),
  ('5a5a1901-0000-0000-0000-0000000000b3', 'p19e-' || chr(304) || 'j@signin.test')
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
  ('p19e-ph@signin.test', '5a5a1901-0000-0000-0000-0000000000b1', '{"email":"p19e-ph@signin.test"}', 'email'),
  ('p19e-i@signin.test', '5a5a1901-0000-0000-0000-0000000000b2', '{"email":"p19e-i@signin.test"}', 'email'),
  ('p19e-' || chr(304) || 'j@signin.test', '5a5a1901-0000-0000-0000-0000000000b3', jsonb_build_object('email', 'p19e-' || chr(304) || 'j@signin.test'), 'email');
-- GoTrue's sign-in stamp, as a verifyOtp would have left it (clock_timestamp: as fresh as possible)
UPDATE auth.users SET last_sign_in_at = clock_timestamp() WHERE id IN ('5a5a1901-0000-0000-0000-0000000000a1', '5a5a1901-0000-0000-0000-0000000000d1', '5a5a1901-0000-0000-0000-0000000000b2', '5a5a1901-0000-0000-0000-0000000000b3', '5a5a1901-0000-0000-0000-0000000000e1');
-- the GoTrue sessions a verifyOtp would have created (0041, (b)): fresh ones for PT / PD / PI / PJ / PX, an old one and a future-dated one for PT
DELETE FROM auth.sessions WHERE user_id::text LIKE '5a5a1901-0000-0000-0000-0000000000%';
INSERT INTO auth.sessions (id, user_id, created_at) VALUES
  ('5a5a1901-0000-0000-0000-0000000005a1', '5a5a1901-0000-0000-0000-0000000000a1', clock_timestamp()),
  ('5a5a1901-0000-0000-0000-0000000005a2', '5a5a1901-0000-0000-0000-0000000000a1', clock_timestamp()),
  ('5a5a1901-0000-0000-0000-0000000005a3', '5a5a1901-0000-0000-0000-0000000000a1', clock_timestamp() - interval '10 minutes'),
  ('5a5a1901-0000-0000-0000-0000000005a4', '5a5a1901-0000-0000-0000-0000000000a1', clock_timestamp() + interval '10 minutes'),
  ('5a5a1901-0000-0000-0000-0000000005d1', '5a5a1901-0000-0000-0000-0000000000d1', clock_timestamp()),
  ('5a5a1901-0000-0000-0000-0000000005b2', '5a5a1901-0000-0000-0000-0000000000b2', clock_timestamp()),
  ('5a5a1901-0000-0000-0000-0000000005b3', '5a5a1901-0000-0000-0000-0000000000b3', clock_timestamp()),
  ('5a5a1901-0000-0000-0000-0000000005e1', '5a5a1901-0000-0000-0000-0000000000e1', clock_timestamp());
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
SELECT plan(127);

-- helpers (session-level temp functions): privileges by name, a sha256 hex, and the two calls under test with one-line arguments
CREATE FUNCTION pg_temp.can_exec(p_role text, p_names text[]) RETURNS int LANGUAGE sql STABLE AS $f$
  SELECT count(*)::int FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
  WHERE n.nspname = 'private' AND p.proname = ANY (p_names) AND has_function_privilege(p_role, p.oid, 'EXECUTE')
$f$;
CREATE FUNCTION pg_temp.h(p_text text) RETURNS text LANGUAGE sql IMMUTABLE AS $f$ SELECT encode(sha256(convert_to(p_text, 'UTF8')), 'hex') $f$;
-- plpgsql, not sql: a SQL function's body is checked at CREATE time, and edge_gateway has no USAGE on schema private (and must not)
-- 0041: the address and the subject go in RAW (the database normalises and hashes them); the session defaults to the account's own fresh one
CREATE FUNCTION pg_temp.mint(p_caller uuid, p_target uuid, p_email text, p_sub text, p_provider text DEFAULT 'apple', p_session uuid DEFAULT NULL) RETURNS uuid LANGUAGE plpgsql AS $f$
BEGIN
  RETURN private.signin_record_email_proof(p_caller, p_target, p_email, p_provider, p_sub,
    coalesce(p_session, CASE p_target WHEN '5a5a1901-0000-0000-0000-0000000000a1'::uuid THEN '5a5a1901-0000-0000-0000-0000000005a1'::uuid
                                       WHEN '5a5a1901-0000-0000-0000-0000000000d1'::uuid THEN '5a5a1901-0000-0000-0000-0000000005d1'::uuid
                                       WHEN '5a5a1901-0000-0000-0000-0000000000b2'::uuid THEN '5a5a1901-0000-0000-0000-0000000005b2'::uuid
                                       WHEN '5a5a1901-0000-0000-0000-0000000000b3'::uuid THEN '5a5a1901-0000-0000-0000-0000000005b3'::uuid
                                       ELSE gen_random_uuid() END));
END
$f$;
-- whether a mint / a link succeeds, as a boolean (the refusal itself is not the point of the normalisation cells: that both sides agree is)
-- Each probe is its own sub-transaction that is ROLLED BACK (the marker exception), so a success does not consume the session or the proof: the next probe
-- on the same account is judged on its address alone, and a `false` can only mean the address was refused.
CREATE FUNCTION pg_temp.mint_ok(p_caller uuid, p_target uuid, p_email text, p_sub text) RETURNS boolean LANGUAGE plpgsql AS $f$
BEGIN
  PERFORM pg_temp.mint(p_caller, p_target, p_email, p_sub);
  RAISE EXCEPTION 'probe ok' USING ERRCODE = 'P0001';
EXCEPTION WHEN SQLSTATE '28000' THEN
  RETURN false;
WHEN SQLSTATE 'P0001' THEN
  RETURN true;
END
$f$;
CREATE FUNCTION pg_temp.link_ok(p_sub text, p_email text) RETURNS boolean LANGUAGE plpgsql AS $f$
BEGIN
  PERFORM pg_temp.link(p_sub, p_email);
  RAISE EXCEPTION 'probe ok' USING ERRCODE = 'P0001';
EXCEPTION WHEN SQLSTATE '28000' THEN
  RETURN false;
WHEN SQLSTATE 'P0001' THEN
  RETURN true;
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
SELECT is(pg_temp.can_exec('edge_system', ARRAY['signin_record_email_proof']), 0, 'privileges (0041, L1): edge_system can NOT mint (the drain, queue, import and retention lanes run as it)');
SELECT is(pg_temp.can_exec('edge_system', ARRAY['purge_signin_email_proofs']), 1, 'privileges: ... it can still purge (system work)');
SELECT is(pg_temp.can_exec('edge_signin_minter', ARRAY['signin_record_email_proof']), 1, 'privileges (0041): edge_signin_minter can mint');
SELECT is(pg_temp.can_exec('edge_signin_minter', ARRAY['purge_signin_email_proofs', 'signin_link_identity_with_proof_for_actor', 'bind_actor', 'actor_uid', 'delete_my_data_for_actor', 'signin_methods_for_actor', 'hit_system_rate_limit']), 0,
  'privileges (0041): ... and nothing else: not the purge, not the redeemer, not the binder, not a sign-in or rate-limit function');
SELECT is(pg_temp.can_exec('edge_system', ARRAY['signin_link_identity_with_proof_for_actor']), 0, 'privileges: edge_system can not redeem (it is not an actor)');
SELECT is(pg_temp.can_exec('service_role', ARRAY['signin_record_email_proof', 'signin_link_identity_with_proof_for_actor']), 0, 'privileges: service_role (the legacy lane) can do neither');
-- (the relation is looked up through pg_class: a 'schema.table'::regclass cast needs USAGE on the schema, which edge_gateway lacks)
SELECT is((SELECT count(*)::int FROM (VALUES ('edge_gateway'), ('edge_actor'), ('edge_system'), ('edge_signin_minter')) r(n)
           CROSS JOIN (SELECT c.oid FROM pg_class c JOIN pg_namespace ns ON ns.oid = c.relnamespace WHERE ns.nspname = 'private' AND c.relname = 'signin_email_proof') t
           WHERE has_any_column_privilege(r.n, t.oid, 'SELECT,INSERT,UPDATE,REFERENCES') OR has_table_privilege(r.n, t.oid, 'DELETE,TRUNCATE,TRIGGER')), 0,
  'privileges: no edge role (the minter included) holds any privilege on the proof table');

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
SELECT throws_ok($$SELECT pg_temp.mint('5a5a1901-0000-0000-0000-0000000000c1', '5a5a1901-0000-0000-0000-0000000000a1', 'p19e-pt@signin.test', 'p19e-sub-a')$$, '42501', NULL,
  'mint (0041, L1): edge_system can no longer mint, bound or not (permission denied: the EXECUTE was moved to the minter role)');
SET LOCAL ROLE edge_signin_minter;
SELECT throws_ok($$SELECT pg_temp.mint('5a5a1901-0000-0000-0000-0000000000c1', '5a5a1901-0000-0000-0000-0000000000a1', 'p19e-pt@signin.test', 'p19e-sub-a')$$, '42501', 'signin_record_email_proof: a proof cannot be minted inside an actor-bound transaction',
  'mint: the MINTER cannot mint inside a transaction that already has an actor bound (SET ROLE edge_signin_minter does not escape the binding: "no actor bound" holds under the new role)');
ROLLBACK;

-- an unbound edge_system transaction (the shape of the drain, queue, import and retention lanes): every statement a lane runs is judged against edge_system
BEGIN;
SET LOCAL ROLE edge_system;
SELECT throws_ok($$SELECT pg_temp.mint('5a5a1901-0000-0000-0000-0000000000c1', '5a5a1901-0000-0000-0000-0000000000a1', 'p19e-pt@signin.test', 'p19e-sub-a')$$, '42501', NULL,
  'mint (0041, L1): an UNBOUND edge_system transaction (a drain / queue / import / retention lane) cannot mint: permission denied');
ROLLBACK;

BEGIN;
SET LOCAL ROLE edge_system;
SELECT is(private.bind_delegate_for_queued_evidence('5a5a1901-0000-0000-0000-00000000e001'), '5a5a1901-0000-0000-0000-0000000000e1'::uuid, 'mint: edge_system binds a system delegate');
SET LOCAL ROLE edge_signin_minter;
SELECT throws_ok($$SELECT pg_temp.mint('5a5a1901-0000-0000-0000-0000000000c1', '5a5a1901-0000-0000-0000-0000000000a1', 'p19e-pt@signin.test', 'p19e-sub-a')$$, '42501', 'signin_record_email_proof: a proof cannot be minted inside an actor-bound transaction',
  'mint: ... a delegate binding is a binding too');
SET LOCAL ROLE edge_actor;
SELECT throws_ok($$SELECT pg_temp.mint('5a5a1901-0000-0000-0000-0000000000c1', '5a5a1901-0000-0000-0000-0000000000a1', 'p19e-pt@signin.test', 'p19e-sub-a')$$, '42501', NULL,
  'mint: a system DELEGATE acting as the row''s owner (edge_actor after the delegate bind) cannot mint either');
ROLLBACK;

-- the minter holds nothing else (the catalog says so in 19_signin_proof_link.sql; these are the behaviours)
BEGIN;
SET LOCAL ROLE edge_signin_minter;
SELECT throws_ok($$SELECT * FROM private.signin_email_proof$$, '42501', NULL, 'minter: it cannot read the proof table');
SELECT throws_ok($$INSERT INTO private.signin_email_proof (caller_user_id, target_user_id, email_hash, provider, sub_hash, expires_at) VALUES ('5a5a1901-0000-0000-0000-0000000000c1', '5a5a1901-0000-0000-0000-0000000000a1', repeat('a', 64), 'apple', repeat('b', 64), now() + interval '5 minutes')$$, '42501', NULL,
  'minter: ... nor write it directly (only the definer writes it)');
SELECT throws_ok($$SELECT count(*) FROM app.play$$, '42501', NULL, 'minter: it cannot read app.play');
SELECT throws_ok($$SELECT count(*) FROM app.profile$$, '42501', NULL, 'minter: ... nor app.profile');
SELECT throws_ok($$SELECT count(*) FROM auth.users$$, '42501', NULL, 'minter: ... nor auth.users');
SELECT throws_ok($$SELECT count(*) FROM auth.sessions$$, '42501', NULL, 'minter: ... nor auth.sessions (the session id is a secret it never sees)');
SELECT throws_ok($$SELECT count(*) FROM private.actor_binding$$, '42501', NULL, 'minter: ... nor private.actor_binding');
SELECT throws_ok($$SELECT private.purge_signin_email_proofs()$$, '42501', NULL, 'minter: it cannot run the purge');
SELECT throws_ok($$SELECT private.bind_actor('5a5a1901-0000-0000-0000-0000000000c1')$$, '42501', NULL, 'minter: it cannot bind an actor');
SELECT throws_ok($$SELECT private.signin_link_identity_with_proof_for_actor(gen_random_uuid(), 'apple', 's', 'p19e-pt@signin.test', true, false, decode(repeat('e1', 40), 'hex'), decode(repeat('e2', 70), 'hex'), 'e19')$$, '42501', NULL, 'minter: ... nor redeem a proof');
SELECT throws_ok($$SELECT private.hit_system_rate_limit('p19e', interval '1 minute', 5)$$, '42501', NULL, 'minter: ... nor call any other private function');
SELECT throws_ok($$CREATE TABLE public.zz_minter_t (a int)$$, '42501', NULL, 'minter: it can create nothing');
SELECT throws_ok($$SET LOCAL ROLE service_role$$, '42501', NULL, 'minter: SET ROLE service_role is refused (edge_gateway is not a member)');
SELECT throws_ok($$SET LOCAL ROLE authenticated$$, '42501', NULL, 'minter: ... SET ROLE authenticated');
SELECT throws_ok($$SET LOCAL ROLE private_definer$$, '42501', NULL, 'minter: ... SET ROLE private_definer');
SELECT throws_ok($$SET LOCAL ROLE postgres$$, '42501', NULL, 'minter: ... SET ROLE postgres');
-- KNOWN LIMIT (R6, edge-role-design.md 12.1): SET ROLE is judged by the SESSION user (edge_gateway), which is a member of all three roles, so a statement that can
-- issue SET ROLE (or set_config('role', ...)) reaches the minter from any lane, and edge_actor from the minter. The minter role removes the capability from
-- the lanes as a PRIVILEGE; what stops a role-switching injection from minting is the session binding (the next group), not the role. This cell pins the limit
-- so a reader does not take the role for more than it is.
SELECT lives_ok($$SET LOCAL ROLE edge_actor$$, 'KNOWN LIMIT (R6): from the minter, SET ROLE edge_actor works (edge_gateway holds SET on all the edge roles); the role is not a barrier against a role-switching statement');
ROLLBACK;

BEGIN;
SET LOCAL ROLE edge_system;
SELECT throws_ok($$SELECT * FROM private.signin_email_proof$$, '42501', NULL, 'mint: edge_system cannot read the proof table (check 12: no privilege on a PII-registered table)');
SELECT throws_ok($$INSERT INTO private.signin_email_proof (caller_user_id, target_user_id, email_hash, provider, sub_hash, expires_at) VALUES ('5a5a1901-0000-0000-0000-0000000000c1', '5a5a1901-0000-0000-0000-0000000000a1', repeat('a', 64), 'apple', repeat('b', 64), now() + interval '5 minutes')$$, '42501', NULL,
  'mint: ... nor write it directly: the minter definer is the only writer');
SET LOCAL ROLE edge_signin_minter;
SELECT throws_ok($$SELECT private.signin_record_email_proof(NULL, '5a5a1901-0000-0000-0000-0000000000a1', 'p19e-pt@signin.test', 'apple', 'p19e-sub-a', '5a5a1901-0000-0000-0000-0000000005a1')$$, '22023', 'signin_record_email_proof: invalid caller, target, provider, address or subject', 'mint: a NULL caller is refused');
SELECT throws_ok($$SELECT private.signin_record_email_proof('5a5a1901-0000-0000-0000-0000000000c1', '5a5a1901-0000-0000-0000-0000000000a1', '   ', 'apple', 'p19e-sub-a', '5a5a1901-0000-0000-0000-0000000005a1')$$, '22023', 'signin_record_email_proof: invalid caller, target, provider, address or subject', 'mint: a blank address is refused');
SELECT throws_ok($$SELECT private.signin_record_email_proof('5a5a1901-0000-0000-0000-0000000000c1', '5a5a1901-0000-0000-0000-0000000000a1', 'p19e-pt@signin.test', 'apple', ' ', '5a5a1901-0000-0000-0000-0000000005a1')$$, '22023', 'signin_record_email_proof: invalid caller, target, provider, address or subject', 'mint: a blank subject is refused');
SELECT throws_ok($$SELECT private.signin_record_email_proof('5a5a1901-0000-0000-0000-0000000000c1', '5a5a1901-0000-0000-0000-0000000000a1', 'p19e-pt@signin.test', 'apple', 'p19e-sub-a', NULL)$$, '22023', 'signin_record_email_proof: a session id is required', 'mint (0041, b): a NULL session id is refused');
SELECT throws_ok($$SELECT private.signin_record_email_proof('5a5a1901-0000-0000-0000-0000000000c1', '5a5a1901-0000-0000-0000-0000000000a1', 'p19e-pt@signin.test', 'facebook', 'p19e-sub-a', '5a5a1901-0000-0000-0000-0000000005a1')$$, '22023', 'signin_record_email_proof: invalid caller, target, provider, address or subject', 'mint: only apple and google are providers');
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
SELECT throws_ok($$SELECT pg_temp.mint('5a5a1901-0000-0000-0000-0000000000c1', '5a5a1901-0000-0000-0000-0000000000a1', 'p19e-pt@signin.test', 'p19e-sub-a', 'apple', gen_random_uuid())$$, '28000', 'email_proof_refused: the target account has no session of that id created within the last 60 seconds to bind the proof to',
  'mint (0041, b): a session id that does not exist is refused: an injected mint cannot guess the id of the victim''s session');
SELECT throws_ok($$SELECT pg_temp.mint('5a5a1901-0000-0000-0000-0000000000c1', '5a5a1901-0000-0000-0000-0000000000a1', 'p19e-pt@signin.test', 'p19e-sub-a', 'apple', '5a5a1901-0000-0000-0000-0000000005e1')$$, '28000', 'email_proof_refused: the target account has no session of that id created within the last 60 seconds to bind the proof to',
  'mint (0041, b): a REAL fresh session that belongs to ANOTHER account (PX) is refused: the session must be the target''s');
SELECT throws_ok($$SELECT pg_temp.mint('5a5a1901-0000-0000-0000-0000000000c1', '5a5a1901-0000-0000-0000-0000000000a1', 'p19e-pt@signin.test', 'p19e-sub-a', 'apple', '5a5a1901-0000-0000-0000-0000000005a3')$$, '28000', 'email_proof_refused: the target account has no session of that id created within the last 60 seconds to bind the proof to',
  'mint (0041, b): the target''s own session created 10 minutes ago is refused (it is not the one verifyOtp just created)');
SELECT throws_ok($$SELECT pg_temp.mint('5a5a1901-0000-0000-0000-0000000000c1', '5a5a1901-0000-0000-0000-0000000000a1', 'p19e-pt@signin.test', 'p19e-sub-a', 'apple', '5a5a1901-0000-0000-0000-0000000005a4')$$, '28000', 'email_proof_refused: the target account has no session of that id created within the last 60 seconds to bind the proof to',
  'mint (0041, b): ... and one dated 10 minutes in the FUTURE is refused too');
SELECT lives_ok($$SELECT pg_temp.mint('5a5a1901-0000-0000-0000-0000000000c1', '5a5a1901-0000-0000-0000-0000000000a1', '  P19E-PT@signin.test ', 'p19e-sub-a')$$,
  'mint: the fresh, correctly-bound proof IS minted (the address is normalised, lower(btrim()), IN THE DATABASE)');
SELECT throws_ok($$SELECT pg_temp.mint('5a5a1901-0000-0000-0000-0000000000c1', '5a5a1901-0000-0000-0000-0000000000a1', 'p19e-pt@signin.test', 'p19e-sub-a2')$$, '28000', 'email_proof_refused: that session already minted a proof',
  'mint (0041, b): ONE session mints at most ONE proof (a second mint on the same session, same transaction, is refused)');

ROLLBACK;

-- ----------------------------------------------------------------------------
-- 3. Redeeming: unbound and delegate refusals
-- ----------------------------------------------------------------------------
BEGIN;
SET LOCAL ROLE edge_signin_minter;
SELECT set_config('p19.pid', pg_temp.mint('5a5a1901-0000-0000-0000-0000000000c1', '5a5a1901-0000-0000-0000-0000000000a1', 'p19e-pt@signin.test', 'p19e-sub-a')::text, true);
SET LOCAL ROLE edge_actor;
SELECT throws_ok($$SELECT pg_temp.link('p19e-sub-a')$$, '42501', 'signin_link_identity_with_proof_for_actor: no actor is bound in this transaction', 'redeem: an UNBOUND edge_actor cannot redeem a proof');
ROLLBACK;

BEGIN;
SET LOCAL ROLE edge_signin_minter;
SELECT set_config('p19.pid', pg_temp.mint('5a5a1901-0000-0000-0000-0000000000c1', '5a5a1901-0000-0000-0000-0000000000a1', 'p19e-pt@signin.test', 'p19e-sub-a')::text, true);
SET LOCAL ROLE edge_system;
SELECT is(private.bind_delegate_for_queued_evidence('5a5a1901-0000-0000-0000-00000000e001'), '5a5a1901-0000-0000-0000-0000000000e1'::uuid, 'redeem: a delegate binding (kind = system_delegate) is made after the proof was minted');
SET LOCAL ROLE edge_actor;
SELECT throws_ok($$SELECT pg_temp.link('p19e-sub-a')$$, '42501', 'signin_link_identity_with_proof_for_actor: a system delegate may not manage sign-in methods', 'redeem: a system DELEGATE cannot redeem a proof');
ROLLBACK;

-- ----------------------------------------------------------------------------
-- 4. Redeeming: every binding is checked, in the database, and the link lands on the TARGET
-- ----------------------------------------------------------------------------
BEGIN;
SET LOCAL ROLE edge_signin_minter;
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
SET LOCAL ROLE edge_signin_minter;
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
SET LOCAL ROLE edge_signin_minter;
SELECT set_config('p19.pid', pg_temp.mint('5a5a1901-0000-0000-0000-0000000000c1', '5a5a1901-0000-0000-0000-0000000000d1', 'p19e-pd@signin.test', 'p19e-sub-other')::text, true);
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('5a5a1901-0000-0000-0000-0000000000c1')$$, 'rules: bind the caller PC');
SELECT throws_ok($$SELECT pg_temp.link('p19e-sub-other', 'p19e-pd@signin.test')$$, '23505', 'provider_already_linked: this account already has a different apple identity',
  'rules: a DIFFERENT Apple identity on a target that already has one is refused (one Apple per account)');
ROLLBACK;
BEGIN;
SET LOCAL ROLE edge_signin_minter;
SELECT set_config('p19.pid', pg_temp.mint('5a5a1901-0000-0000-0000-0000000000c1', '5a5a1901-0000-0000-0000-0000000000d1', 'p19e-pd@signin.test', 'p19e-pd-apple')::text, true);
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('5a5a1901-0000-0000-0000-0000000000c1')$$, 'rules: bind the caller PC');
SELECT is(pg_temp.link('p19e-pd-apple', 'p19e-pd@signin.test'), false, 'rules: the SAME identity the target already holds links as created = false (idempotent: no duplicate row)');
ROLLBACK;
BEGIN;
SET LOCAL ROLE edge_signin_minter;
SELECT set_config('p19.pid', pg_temp.mint('5a5a1901-0000-0000-0000-0000000000c1', '5a5a1901-0000-0000-0000-0000000000a1', 'p19e-pt@signin.test', 'p19e-px-apple')::text, true);
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('5a5a1901-0000-0000-0000-0000000000c1')$$, 'rules: bind the caller PC');
SELECT throws_ok($$SELECT pg_temp.link('p19e-px-apple')$$, '23505', 'identity_conflict: that identity belongs to another account', 'rules: an identity that belongs to ANOTHER account (PX) is never moved, proof or not');
ROLLBACK;

-- ----------------------------------------------------------------------------
-- 6. The committed flow: mint and redeem in different transactions, then look at both accounts
-- ----------------------------------------------------------------------------
BEGIN;
SET LOCAL ROLE edge_signin_minter;
SELECT set_config('p19.pid', pg_temp.mint('5a5a1901-0000-0000-0000-0000000000c1', '5a5a1901-0000-0000-0000-0000000000a1', 'p19e-pt@signin.test', 'p19e-sub-c', 'apple', '5a5a1901-0000-0000-0000-0000000005a2')::text, false);
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
-- the committed mint consumed its session: a second mint on it, in a later transaction, is refused (one session, one proof, across transactions)
BEGIN;
SET LOCAL ROLE edge_signin_minter;
SELECT throws_ok($$SELECT pg_temp.mint('5a5a1901-0000-0000-0000-0000000000c1', '5a5a1901-0000-0000-0000-0000000000a1', 'p19e-pt@signin.test', 'p19e-sub-c2', 'apple', '5a5a1901-0000-0000-0000-0000000005a2')$$, '28000', 'email_proof_refused: that session already minted a proof',
  'flow (0041, b): the committed proof keeps its session: the same session cannot mint a second proof in a LATER transaction');
SELECT lives_ok($$SELECT pg_temp.mint('5a5a1901-0000-0000-0000-0000000000c1', '5a5a1901-0000-0000-0000-0000000000a1', 'p19e-pt@signin.test', 'p19e-sub-c3')$$, 'flow: ... while another fresh session of the target (the default one) still mints');
ROLLBACK;

-- ----------------------------------------------------------------------------
-- 6b. L2: ONE normalisation, in the database, for the mint and the redemption (lower(btrim()) then sha256). JavaScript hashes nothing for the proof any more.
--     The cells do not assert what lower() returns (it is locale-dependent): they assert that the mint, the redeemer and a plain SQL expression AGREE.
-- ----------------------------------------------------------------------------
-- spaces and case are normalised away; a tab, a no-break space and a plus tag are NOT (the database's rule, applied identically on both sides)
BEGIN;
SET LOCAL ROLE edge_signin_minter;
SELECT is(pg_temp.mint_ok('5a5a1901-0000-0000-0000-0000000000c1', '5a5a1901-0000-0000-0000-0000000000a1', '   P19E-Pt@Signin.TEST  ', 'p19e-sub-n1'), true,
  'normalisation: surrounding spaces and mixed case are the same address (lower(btrim()))');
SELECT is(pg_temp.mint_ok('5a5a1901-0000-0000-0000-0000000000c1', '5a5a1901-0000-0000-0000-0000000000a1', E'\tp19e-pt@signin.test\t', 'p19e-sub-n2'), false,
  'normalisation: a TAB-wrapped address is NOT the address (btrim strips spaces only; JavaScript trim() would have stripped it: the old mismatch). Refused at the mint, not later at the link');
SELECT is(pg_temp.mint_ok('5a5a1901-0000-0000-0000-0000000000c1', '5a5a1901-0000-0000-0000-0000000000a1', E' p19e-pt@signin.test ', 'p19e-sub-n3'), false,
  'normalisation: ... and so is a NO-BREAK-SPACE-wrapped one (U+00A0)');
SELECT is(pg_temp.mint_ok('5a5a1901-0000-0000-0000-0000000000c1', '5a5a1901-0000-0000-0000-0000000000a1', E'p19e-pt@signin.test ', 'p19e-sub-n3b'), false,
  'normalisation: ... and an EM-SPACE-wrapped one (U+2003)');
SELECT is(pg_temp.mint_ok('5a5a1901-0000-0000-0000-0000000000c1', '5a5a1901-0000-0000-0000-0000000000a1', 'p19e-pt+tag@signin.test', 'p19e-sub-n4'), false,
  'normalisation: plus-addressing is a DIFFERENT address on both sides (the database does not strip +tag, and neither does anything else): refused');
-- the Turkish dotted capital I: whatever lower() does with U+0130 in this database, the mint accepts it exactly when the same expression says the two addresses are equal
SELECT is(pg_temp.mint_ok('5a5a1901-0000-0000-0000-0000000000c1', '5a5a1901-0000-0000-0000-0000000000b2', 'p19e-' || chr(304) || '@signin.test', 'p19e-sub-n5'),
  lower(btrim('p19e-' || chr(304) || '@signin.test')) = lower(btrim('p19e-i@signin.test')),
  'normalisation: U+0130 (I with dot above) against a target stored with an ASCII i: accepted iff lower(btrim()) says they are equal IN THIS DATABASE (no JavaScript opinion)');
SELECT is(pg_temp.mint_ok('5a5a1901-0000-0000-0000-0000000000c1', '5a5a1901-0000-0000-0000-0000000000b2', 'P19E-I@signin.test', 'p19e-sub-n6'), true,
  'normalisation: ... and the ASCII upper-case spelling of the stored address is accepted');
SELECT is(pg_temp.mint_ok('5a5a1901-0000-0000-0000-0000000000c1', '5a5a1901-0000-0000-0000-0000000000b3', 'p19e-' || chr(304) || 'j@signin.test', 'p19e-sub-n7'), true,
  'normalisation: a target whose OWN stored address contains U+0130 is accepted for exactly that address, in any locale (equal strings are equal after any lower())');
SELECT is(pg_temp.mint_ok('5a5a1901-0000-0000-0000-0000000000c1', '5a5a1901-0000-0000-0000-0000000000b3', 'P19E-' || chr(304) || 'J@SIGNIN.TEST', 'p19e-sub-n8'),
  lower(btrim('P19E-' || chr(304) || 'J@SIGNIN.TEST')) = lower(btrim('p19e-' || chr(304) || 'j@signin.test')),
  'normalisation: ... and the upper-cased spelling of it is accepted iff lower(btrim()) agrees');
ROLLBACK;

-- redemption: the same rule, on the address the link carries. Mint with the canonical address; link with variants (PI: it has no Apple identity yet).
BEGIN;
SET LOCAL ROLE edge_signin_minter;
SELECT set_config('p19.pid', pg_temp.mint('5a5a1901-0000-0000-0000-0000000000c1', '5a5a1901-0000-0000-0000-0000000000b2', 'p19e-i@signin.test', 'p19e-sub-r1')::text, true);
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('5a5a1901-0000-0000-0000-0000000000c1')$$, 'normalisation: bind the caller PC');
SELECT is(pg_temp.link_ok('p19e-sub-r1', E'\tp19e-i@signin.test'), false, 'normalisation: a proof for the address cannot link an identity whose address is tab-prefixed (the same rule the mint applied)');
SELECT is(pg_temp.link_ok('p19e-sub-r1', E'p19e-i@signin.test\u00a0'), false, 'normalisation: ... or NBSP-suffixed');
SELECT is(pg_temp.link_ok('p19e-sub-r1', 'p19e-i+tag@signin.test'), false, 'normalisation: ... or plus-tagged');
SELECT is(pg_temp.link_ok(' p19e-sub-r1', 'p19e-i@signin.test'), false, 'normalisation: the SUBJECT is exact bytes on both sides: a leading space is another identity');
SELECT is(pg_temp.link_ok('p19e-sub-r1', '   P19E-I@Signin.Test '), true, 'normalisation: the spaces-and-case variant of the same address links (mint and redeem normalise identically)');
SELECT is(pg_temp.link_ok('p19e-sub-r1', 'p19e-' || chr(304) || '@signin.test'), lower(btrim('p19e-' || chr(304) || '@signin.test')) = lower(btrim('p19e-i@signin.test')),
  'normalisation: U+0130 (I with dot above) on the link: accepted iff lower(btrim()) says it is the minted address in THIS database: the redeemer and the mint share the one rule');
ROLLBACK;
-- an address with U+0130 round-trips mint -> redeem exactly, and an upper-cased spelling is accepted by the redeemer iff the mint would have accepted it
BEGIN;
SET LOCAL ROLE edge_signin_minter;
SELECT set_config('p19.pid', pg_temp.mint('5a5a1901-0000-0000-0000-0000000000c1', '5a5a1901-0000-0000-0000-0000000000b3', 'p19e-' || chr(304) || 'j@signin.test', 'p19e-sub-r2')::text, true);
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('5a5a1901-0000-0000-0000-0000000000c1')$$, 'normalisation: bind the caller PC');
SELECT is(pg_temp.link_ok('p19e-sub-r2', 'P19E-' || chr(304) || 'J@SIGNIN.TEST'),
  lower(btrim('P19E-' || chr(304) || 'J@SIGNIN.TEST')) = lower(btrim('p19e-' || chr(304) || 'j@signin.test')),
  'normalisation: U+0130 address minted for the exact spelling and redeemed with an upper-cased one: it links iff lower(btrim()) says the two are the same address (never half-done otherwise)');
ROLLBACK;

-- ----------------------------------------------------------------------------
-- 7. Nothing was broadened
-- ----------------------------------------------------------------------------
SELECT is((SELECT count(*)::int FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid JOIN pg_namespace n ON n.oid = c.relnamespace
           WHERE n.nspname = 'private' AND c.relname = 'signin_email_proof'
             AND (p.polroles && ARRAY(SELECT oid FROM pg_roles WHERE rolname IN ('edge_actor', 'edge_system', 'edge_signin_minter')) OR p.polroles @> ARRAY[0]::oid[])), 0,
  'no broadening: NO policy on the proof table applies to an edge role (the minter included) or to PUBLIC');
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
DELETE FROM auth.sessions WHERE user_id::text LIKE '5a5a1901-0000-0000-0000-0000000000%';
COMMIT;
RESET ROLE;
