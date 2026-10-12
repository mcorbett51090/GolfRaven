-- 64_partner_credential_note_reach.sql
-- 0086_partner_credential_note_reach.sql (P5 §76): class A0 PATCH of the
-- display-only note on own OR reach-covered credentials.

\set QUIET 1
BEGIN;
SELECT plan(10);

GRANT edge_partner, private_definer TO CURRENT_USER WITH SET TRUE;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.partner_credential, app.partner_session TO CURRENT_USER;
ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_insert_guard_trg;
ALTER TABLE app.partner_credential DISABLE TRIGGER partner_credential_insert_guard_trg;
CREATE POLICY zz64_cred ON app.partner_credential FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz64_sess ON app.partner_session FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

CREATE FUNCTION pg_temp.th(p_label text) RETURNS text LANGUAGE sql IMMUTABLE AS $f$
  SELECT md5('s64:' || p_label) || md5('s64b:' || p_label)
$f$;
CREATE FUNCTION pg_temp.mk_cred(p_label text, p_uid uuid) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_credential (user_id, credential_id, public_key, alg)
  VALUES (p_uid, decode(md5('c64:' || p_label) || md5('c64b:' || p_label), 'hex'),
          decode(md5('k64:' || p_label) || md5('k64b:' || p_label), 'hex'), -7)
  RETURNING id
$f$;
CREATE FUNCTION pg_temp.mk_session(p_label text, p_uid uuid, p_cred uuid, p_aal int DEFAULT 1) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_session (token_hash, user_id, credential_id, aal, created_at, last_seen_at, expires_at,
                                   mint_kind, mint_nonce_hash, mint_authenticator_data, mint_client_data_json, mint_signature)
  VALUES (pg_temp.th(p_label), p_uid, p_cred, p_aal, now() - interval '1 hour', now(), now() + interval '7 hours', 'sign_in',
          decode(md5('n64:' || p_label) || md5('n64b:' || p_label), 'hex'), decode(repeat('04', 40), 'hex'),
          convert_to('{}', 'UTF8'), decode(repeat('05', 70), 'hex'))
  RETURNING id
$f$;
CREATE FUNCTION pg_temp.note(p_id uuid, p_note text) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r text;
BEGIN
  EXECUTE 'SET LOCAL ROLE edge_partner';
  SELECT o_status INTO r FROM private.partner_credential_note_for_partner(p_id, p_note);
  EXECUTE 'RESET ROLE';
  RETURN r;
END
$f$;
GRANT EXECUTE ON FUNCTION pg_temp.th(text), pg_temp.mk_cred(text, uuid), pg_temp.mk_session(text, uuid, uuid, int),
  pg_temp.note(uuid, text) TO PUBLIC;

-- ----------------------------------------------------------------------------
-- 1. Structure: body + policy call reach
-- ----------------------------------------------------------------------------
SELECT ok(
  (SELECT prosrc LIKE '%partner_reach_covers%' FROM pg_proc p
   JOIN pg_namespace n ON n.oid = p.pronamespace
   WHERE n.nspname = 'private' AND p.proname = 'partner_credential_note_for_partner'),
  'structure: note definer body calls partner_reach_covers'
);
SELECT ok(
  (SELECT pg_get_expr(pol.polqual, pol.polrelid) LIKE '%partner_reach_covers%'
   FROM pg_policy pol
   JOIN pg_class c ON c.oid = pol.polrelid
   JOIN pg_namespace n ON n.oid = c.relnamespace
   WHERE n.nspname = 'app' AND c.relname = 'partner_credential'
     AND pol.polname = 'pd_update_partner_credential_note'),
  'structure: UPDATE(note) policy USING calls partner_reach_covers'
);
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT ok(
  (SELECT note LIKE '%reach%' FROM private.function_inventory
   WHERE function_name = 'partner_credential_note_for_partner'),
  'inventory: note mentions reach'
);
SELECT tests.clear_actor();

-- ----------------------------------------------------------------------------
-- 2. Behaviour: manager@X notes staff@X; staff cannot note up; Y out of reach
-- ----------------------------------------------------------------------------
SELECT pg_temp.th('sx') AS th_sx \gset
SELECT pg_temp.th('mx') AS th_mx \gset
SELECT pg_temp.mk_cred('sx', '00000000-0000-0000-0000-1000000000a1') AS c_sx \gset
SELECT pg_temp.mk_cred('mx', '00000000-0000-0000-0000-2000000000b1') AS c_mx \gset
SELECT pg_temp.mk_cred('sy', '00000000-0000-0000-0000-1000000000a3') AS c_sy \gset
SELECT pg_temp.mk_session('sx', '00000000-0000-0000-0000-1000000000a1', :'c_sx') AS s_sx \gset
SELECT pg_temp.mk_session('mx', '00000000-0000-0000-0000-2000000000b1', :'c_mx') AS s_mx \gset

SAVEPOINT reach_ok;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_mx');
RESET ROLE;
SELECT is(pg_temp.note(:'c_sx'::uuid, 'lane 2 iPad'), 'ok',
  'manager@X sets note on staff@X credential (reach covers)');
SELECT is((SELECT note FROM app.partner_credential WHERE id = :'c_sx'::uuid), 'lane 2 iPad',
  '... and the row holds it');
SELECT is(pg_temp.note(:'c_mx'::uuid, 'own desk'), 'ok',
  'manager still sets note on own credential');
SELECT is(pg_temp.note(:'c_sy'::uuid, 'nope'), 'not_found',
  'manager@X cannot note staff@Y (outside reach → not_found)');
ROLLBACK TO SAVEPOINT reach_ok;

SAVEPOINT staff_up;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SELECT is(pg_temp.note(:'c_sx'::uuid, 'mine'), 'ok', 'staff still sets note on own');
SELECT is(pg_temp.note(:'c_mx'::uuid, 'up'), 'not_found',
  'staff cannot note manager credential (reach does not go up)');
ROLLBACK TO SAVEPOINT staff_up;

-- policy allowlist exprs match live
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is(
  (SELECT using_expr LIKE '%partner_reach_covers%' AND with_check_expr LIKE '%partner_reach_covers%'
   FROM private.definer_policy_allowlist
   WHERE policy_name = 'pd_update_partner_credential_note'),
  true,
  'allowlist: UPDATE(note) exprs record partner_reach_covers'
);
SELECT tests.clear_actor();

SELECT * FROM finish();
ROLLBACK;
