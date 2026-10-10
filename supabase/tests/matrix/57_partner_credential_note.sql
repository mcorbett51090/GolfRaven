-- 57_partner_credential_note.sql
-- 0079_partner_credential_note.sql (P5 §65): class A0 PATCH of the
-- display-only note on the signed-in person's own credential.

\set QUIET 1
BEGIN;
SELECT plan(14);

GRANT edge_partner, private_definer TO CURRENT_USER WITH SET TRUE;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.partner_credential, app.partner_session TO CURRENT_USER;
ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_insert_guard_trg;
ALTER TABLE app.partner_credential DISABLE TRIGGER partner_credential_insert_guard_trg;
CREATE POLICY zz57_cred ON app.partner_credential FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz57_sess ON app.partner_session FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

CREATE FUNCTION pg_temp.th(p_label text) RETURNS text LANGUAGE sql IMMUTABLE AS $f$
  SELECT md5('s57:' || p_label) || md5('s57b:' || p_label)
$f$;
CREATE FUNCTION pg_temp.mk_cred(p_label text, p_uid uuid) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_credential (user_id, credential_id, public_key, alg)
  VALUES (p_uid, decode(md5('c57:' || p_label) || md5('c57b:' || p_label), 'hex'),
          decode(md5('k57:' || p_label) || md5('k57b:' || p_label), 'hex'), -7)
  RETURNING id
$f$;
CREATE FUNCTION pg_temp.mk_session(p_label text, p_uid uuid, p_cred uuid, p_aal int DEFAULT 1) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_session (token_hash, user_id, credential_id, aal, created_at, last_seen_at, expires_at,
                                   mint_kind, mint_nonce_hash, mint_authenticator_data, mint_client_data_json, mint_signature)
  VALUES (pg_temp.th(p_label), p_uid, p_cred, p_aal, now() - interval '1 hour', now(), now() + interval '7 hours', 'sign_in',
          decode(md5('n57:' || p_label) || md5('n57b:' || p_label), 'hex'), decode(repeat('04', 40), 'hex'),
          convert_to('{}', 'UTF8'), decode(repeat('05', 70), 'hex'))
  RETURNING id
$f$;
CREATE FUNCTION pg_temp.note(p_th text, p_id uuid, p_note text) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r text;
BEGIN
  EXECUTE 'SET LOCAL ROLE edge_partner';
  PERFORM private.bind_partner_session(p_th);
  SELECT o_status INTO r FROM private.partner_credential_note_for_partner(p_id, p_note);
  EXECUTE 'RESET ROLE';
  RETURN r;
END
$f$;
GRANT EXECUTE ON FUNCTION pg_temp.th(text), pg_temp.mk_cred(text, uuid), pg_temp.mk_session(text, uuid, uuid, int),
  pg_temp.note(text, uuid, text) TO PUBLIC;

-- ----------------------------------------------------------------------------
-- 1. Structure / EXECUTE / inventory / policy
-- ----------------------------------------------------------------------------
SELECT ok(
  has_function_privilege('edge_partner', 'private.partner_credential_note_for_partner(uuid, text)'::regprocedure, 'EXECUTE'),
  'privileges: edge_partner CAN run partner_credential_note_for_partner'
);
SELECT is(
  (SELECT count(*)::int FROM pg_proc p WHERE p.proname = 'partner_credential_note_for_partner'
     AND (has_function_privilege('edge_actor', p.oid, 'EXECUTE')
          OR has_function_privilege('edge_system', p.oid, 'EXECUTE')
          OR has_function_privilege('anon', p.oid, 'EXECUTE')
          OR has_function_privilege('authenticated', p.oid, 'EXECUTE')
          OR has_function_privilege('service_role', p.oid, 'EXECUTE'))),
  0,
  'privileges: nobody else may EXECUTE it'
);
SELECT is(
  (SELECT count(*)::int FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
   WHERE n.nspname = 'private' AND p.proname = 'partner_credential_note_for_partner'
     AND p.prosecdef AND p.proowner = 'private_definer'::regrole
     AND p.proconfig = ARRAY['search_path=""']),
  1,
  'structure: SECURITY DEFINER / private_definer / search_path='''''
);
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is(
  (SELECT count(*)::int FROM private.function_inventory
   WHERE function_name = 'partner_credential_note_for_partner' AND expected_edge_partner AND NOT expected_edge_system),
  1,
  'inventory: one edge_partner row'
);
SELECT tests.clear_actor();
SELECT is(
  (SELECT count(*)::int FROM pg_policy pol WHERE pol.polname = 'pd_update_partner_credential_note'),
  1,
  'structure: partner UPDATE(note) policy exists'
);

-- ----------------------------------------------------------------------------
-- 2. Behaviour: set / clear / not_found / overlong / unbound
-- ----------------------------------------------------------------------------
SELECT pg_temp.th('stf') AS th_stf, pg_temp.th('mgr') AS th_mgr \gset
SELECT pg_temp.mk_cred('stf', '00000000-0000-0000-0000-1000000000a1') AS c_stf \gset
SELECT pg_temp.mk_cred('mgr', '00000000-0000-0000-0000-2000000000b1') AS c_mgr \gset
SELECT pg_temp.mk_session('stf', '00000000-0000-0000-0000-1000000000a1', :'c_stf') AS s_stf \gset
SELECT pg_temp.mk_session('mgr', '00000000-0000-0000-0000-2000000000b1', :'c_mgr') AS s_mgr \gset

SELECT is(pg_temp.note(:'th_stf', :'c_stf'::uuid, 'front desk'), 'ok', 'staff sets note on own credential');
SELECT is((SELECT note FROM app.partner_credential WHERE id = :'c_stf'::uuid), 'front desk', '... and the row holds it');

SELECT is(pg_temp.note(:'th_stf', :'c_stf'::uuid, '   '), 'ok', 'whitespace clears the note');
SELECT is((SELECT note FROM app.partner_credential WHERE id = :'c_stf'::uuid), NULL, '... to NULL');

SELECT is(pg_temp.note(:'th_stf', :'c_mgr'::uuid, 'nope'), 'not_found',
  'another person''s credential is not_found (own-only; reach does not apply)');
SELECT is(pg_temp.note(:'th_stf', 'ffffffff-0000-0000-0000-000000000000'::uuid, 'x'), 'not_found',
  'unknown id is the same not_found');

SELECT throws_ok(
  format($t$SELECT pg_temp.note(%L, %L::uuid, %L)$t$, :'th_stf', :'c_stf', repeat('a', 41)),
  '22023',
  NULL,
  'over 40 characters raises 22023'
);

SELECT throws_ok(
  $$SELECT o_status FROM private.partner_credential_note_for_partner('00000000-0000-0000-0000-1000000000a1', 'x')$$,
  '42501',
  NULL,
  'without a partner binding the note write is refused'
);

-- PA-22 widened: list + note writer may touch .note; nothing else in partner_* may
SELECT is(
  (SELECT count(*)::int FROM pg_proc p WHERE p.pronamespace = 'private'::regnamespace
     AND p.proname LIKE 'partner\_%' AND p.prosrc ~* '\mc\.note\M|\.note\M'
     AND p.proname NOT IN ('partner_credential_list_for_partner', 'partner_credential_note_for_partner')),
  0,
  'PA-22: only list + note writer touch the display-only note'
);

SELECT * FROM finish();
ROLLBACK;
