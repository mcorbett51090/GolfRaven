-- 25_partner_auth_spine_edge.sql
-- P5.1a S1.1a (0047), the edge_partner lane, run as a REAL `edge_gateway` login that SET LOCAL ROLEs into `edge_partner` / `edge_partner_minter` / `edge_actor`
-- (read 21_device_platform_claim.sql: `SET ROLE` is judged by the SESSION user, so every assertion lives in the edge_gateway session, reached by `\c`).
-- The structure, the semantics and the catalog sweeps are 25_partner_auth_spine.sql (run as the harness, which can seed and read FORCE-RLS tables).
--
--   * the binder (private.bind_partner_session) from the real lane: a good hash binds; an unknown, malformed, expired-idle and expired-absolute hash are the SAME refusal;
--     a second bind in one transaction is refused; partner_binding() / partner_binding_kind() read the binding back (the Edge's post-bind assertion);
--   * edge_partner holds NO privilege on any relation (the binder, not a table grant, is the only way in); it cannot bind a user and cannot reach the authorize seam;
--   * the minter cannot execute the binder (it executes nothing in S1.1a), and holds no table privilege either;
--   * the user lane sees nothing of a partner binding (edge_actor under it: actor_uid() NULL);
--   * a POOLED connection: partner then user then partner then user binds on one backend, one per transaction, each clean (the stale row of the previous transaction is
--     never honoured, and a user bind clears the previous partner's session_id so the CHECK holds).
--
-- This file COMMITS two credentials and three sessions (for staff_x, a helpers.sql principal) in phase 0; 25_partner_auth_spine_edge_cleanup.sql (the next file, run by the
-- harness) deletes them and proves they are gone. All new ids start ee24e000-. Test hashes are random per run (nothing here is a secret, but nothing is a constant either).

\set QUIET 1
SELECT session_user::text AS harness_user, current_database()::text AS harness_db \gset

-- ============================================================================
-- PHASE 0: seed (harness role, a temporary CURRENT_USER policy on the FORCE-RLS tables; committed)
-- ============================================================================
GRANT SELECT, INSERT, UPDATE, DELETE ON app.partner_credential, app.partner_session TO CURRENT_USER;
CREATE POLICY zz24e_cred ON app.partner_credential FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz24e_sess ON app.partner_session FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
SELECT encode(digest(gen_random_uuid()::text, 'sha256'), 'hex') AS h_ok,
       encode(digest(gen_random_uuid()::text, 'sha256'), 'hex') AS h_idle,
       encode(digest(gen_random_uuid()::text, 'sha256'), 'hex') AS h_abs,
       encode(digest(gen_random_uuid()::text, 'sha256'), 'hex') AS h_unknown \gset
-- the INSERT guards (S1.1a gate M2) refuse a back-dated session: switched off for the seeding only, switched back on right after (the cleanup file proves they are on)
ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_insert_guard_trg;
INSERT INTO app.partner_credential (id, user_id, credential_id, public_key, alg)
VALUES ('ee24e000-0000-0000-0000-0000000000c1', '00000000-0000-0000-0000-1000000000a1', decode(repeat('e1', 32), 'hex'), decode(repeat('e2', 77), 'hex'), -7);
INSERT INTO app.partner_session (id, token_hash, user_id, credential_id, aal, created_at, last_seen_at, expires_at, mint_kind, mint_nonce_hash,
                                 mint_authenticator_data, mint_client_data_json, mint_signature)
VALUES ('ee24e000-0000-0000-0000-0000000000a1', :'h_ok', '00000000-0000-0000-0000-1000000000a1', 'ee24e000-0000-0000-0000-0000000000c1', 1, now() - interval '1 hour', now(), now() + interval '8 hours',
        'sign_in', decode(repeat('e3', 32), 'hex'), decode(repeat('04', 40), 'hex'), convert_to('{}', 'UTF8'), decode(repeat('05', 70), 'hex')),
       ('ee24e000-0000-0000-0000-0000000000a2', :'h_idle', '00000000-0000-0000-0000-1000000000a1', 'ee24e000-0000-0000-0000-0000000000c1', 1, now() - interval '1 hour', now() - interval '31 minutes', now() + interval '8 hours',
        'sign_in', decode(repeat('e4', 32), 'hex'), decode(repeat('04', 40), 'hex'), convert_to('{}', 'UTF8'), decode(repeat('05', 70), 'hex')),
       ('ee24e000-0000-0000-0000-0000000000a3', :'h_abs', '00000000-0000-0000-0000-1000000000a1', 'ee24e000-0000-0000-0000-0000000000c1', 1, now() - interval '9 hours', now(), now() - interval '1 minute',
        'sign_in', decode(repeat('e5', 32), 'hex'), decode(repeat('04', 40), 'hex'), convert_to('{}', 'UTF8'), decode(repeat('05', 70), 'hex'));
ALTER TABLE app.partner_session ENABLE TRIGGER partner_session_insert_guard_trg;
DROP POLICY zz24e_cred ON app.partner_credential;
DROP POLICY zz24e_sess ON app.partner_session;
REVOKE SELECT, INSERT, UPDATE, DELETE ON app.partner_credential, app.partner_session FROM CURRENT_USER;

-- ============================================================================
-- PHASE 1: reconnect as the real login
-- ============================================================================
\c :"harness_db" edge_gateway
\set QUIET 1
SELECT plan(34);

-- 1. unbound: the read-backs are empty
BEGIN;
SET LOCAL ROLE edge_partner;
SELECT is((SELECT count(*)::int FROM private.partner_binding()), 0, 'unbound: partner_binding() returns no row');
SELECT is(private.partner_binding_kind(), NULL::text, 'unbound: partner_binding_kind() is NULL');
ROLLBACK;

-- 2. the refusals are one refusal
BEGIN;
SET LOCAL ROLE edge_partner;
SELECT throws_ok(format($$SELECT private.bind_partner_session(%L)$$, :'h_unknown'), '28000', 'partner_session_refused', 'an unknown hash is refused');
ROLLBACK;
BEGIN;
SET LOCAL ROLE edge_partner;
SELECT throws_ok($$SELECT private.bind_partner_session('not-a-hash')$$, '28000', 'partner_session_refused', 'a malformed hash is refused identically');
ROLLBACK;
BEGIN;
SET LOCAL ROLE edge_partner;
SELECT throws_ok($$SELECT private.bind_partner_session(NULL)$$, '28000', 'partner_session_refused', 'a NULL hash is refused identically');
ROLLBACK;
BEGIN;
SET LOCAL ROLE edge_partner;
SELECT throws_ok(format($$SELECT private.bind_partner_session(%L)$$, :'h_idle'), '28000', 'partner_session_refused', 'an idle-expired session is refused identically (31 minutes against the 30 of staff)');
ROLLBACK;
BEGIN;
SET LOCAL ROLE edge_partner;
SELECT throws_ok(format($$SELECT private.bind_partner_session(%L)$$, :'h_abs'), '28000', 'partner_session_refused', 'an absolute-expired session is refused identically');
ROLLBACK;

-- 3. a good bind, read back, and what the lane can and cannot do afterwards
BEGIN;
SET LOCAL ROLE edge_partner;
SELECT lives_ok(format($$SELECT private.bind_partner_session(%L)$$, :'h_ok'), 'a live session binds');
SELECT is((SELECT kind FROM private.partner_binding()), 'partner', 'partner_binding() reads back kind partner ...');
SELECT is((SELECT session_id FROM private.partner_binding()), 'ee24e000-0000-0000-0000-0000000000a1'::uuid, '... and the session id');
SELECT is(private.partner_binding_kind(), 'partner', 'partner_binding_kind() reads back partner');
SELECT throws_ok(format($$SELECT private.bind_partner_session(%L)$$, :'h_ok'), '28000', 'partner_session_refused', 'a SECOND bind in the transaction is refused');
SELECT throws_ok($$SELECT * FROM app.partner_session$$, '42501', NULL, 'edge_partner has no SELECT on partner_session');
SELECT throws_ok($$SELECT * FROM app.partner_credential$$, '42501', NULL, '... none on partner_credential');
SELECT throws_ok($$SELECT * FROM app.partner_member$$, '42501', NULL, '... none on partner_member');
SELECT throws_ok($$SELECT * FROM app.profile$$, '42501', NULL, '... none on any player table');
SELECT throws_ok($$SELECT * FROM private.actor_binding$$, '42501', NULL, '... and cannot read the binding table');
SELECT throws_ok($$UPDATE app.partner_session SET revoked_at = now()$$, '42501', NULL, '... cannot write a session');
SELECT throws_ok($$INSERT INTO app.partner_session (id) VALUES (gen_random_uuid())$$, '42501', NULL, '... nor insert one');
SELECT throws_ok($$SELECT private.bind_actor('00000000-0000-0000-0000-1000000000a1')$$, '42501', NULL, '... cannot bind a USER');
SELECT throws_ok($$SELECT private.partner_authorize('fac_x', NULL, ARRAY['staff']::app.partner_role[], 'A0')$$, '42501', NULL, '... cannot call the authorize seam directly (it is a definer-to-definer function: no EXECUTE for anyone)');
SELECT throws_ok($$SELECT * FROM private.partner_session_by_hash(repeat('0', 64))$$, '42501', NULL, '... nor the toucher''s lookup');
RESET ROLE;
-- the user lane under the partner binding
SET LOCAL ROLE edge_actor;
SELECT is(private.actor_uid(), NULL::uuid, 'edge_actor under a PARTNER binding: actor_uid() is NULL (the user lane sees no actor)');
SELECT is((SELECT count(*)::int FROM app.evidence), 0, '... and reads zero rows of a user table (evidence is the player''s own: staff_x has some)');
RESET ROLE;
ROLLBACK;

-- 4. the minter executes nothing in S1.1a
BEGIN;
SET LOCAL ROLE edge_partner_minter;
SELECT throws_ok(format($$SELECT private.bind_partner_session(%L)$$, :'h_ok'), '42501', NULL, 'edge_partner_minter cannot execute the binder');
SELECT throws_ok($$SELECT * FROM app.partner_session$$, '42501', NULL, '... and holds no table privilege');
ROLLBACK;

-- 5. a POOLED connection: one backend, four transactions, each bound once and cleanly
BEGIN;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'h_ok') AS _b1 \gset
COMMIT;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT is(private.actor_uid(), NULL::uuid, 'pooled: the next transaction on the backend inherits NOTHING from the previous partner binding');
SELECT lives_ok($$SELECT private.bind_actor('00000000-0000-0000-0000-1000000000a1')$$, 'pooled: a USER bind after a PARTNER bind on the same backend succeeds (the stale session_id is cleared)');
SELECT is(private.actor_uid(), '00000000-0000-0000-0000-1000000000a1'::uuid, 'pooled: ... and binds the user');
RESET ROLE;
SET LOCAL ROLE edge_partner;
SELECT is((SELECT kind FROM private.partner_binding()), 'user', 'pooled: partner_binding() tells a user binding apart (kind user)');
SELECT is((SELECT session_id FROM private.partner_binding()), NULL::uuid, 'pooled: ... with no session id');
RESET ROLE;
COMMIT;
BEGIN;
SET LOCAL ROLE edge_partner;
SELECT lives_ok(format($$SELECT private.bind_partner_session(%L)$$, :'h_ok'), 'pooled: a PARTNER bind after a USER bind on the same backend succeeds');
SELECT is((SELECT kind FROM private.partner_binding()), 'partner', 'pooled: ... and reads back partner');
RESET ROLE;
COMMIT;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('00000000-0000-0000-0000-1000000000a1')$$, 'pooled: and a USER bind once more');
RESET ROLE;
COMMIT;

SELECT * FROM finish();
