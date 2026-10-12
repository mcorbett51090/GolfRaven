-- 67_partner_credential_list_reach.sql
-- 0089_partner_credential_list_reach.sql (P5 §79): class A0 list of
-- credentials for own OR reach-covered person (empty outside reach).

\set QUIET 1
BEGIN;
SELECT plan(11);

GRANT edge_partner, private_definer TO CURRENT_USER WITH SET TRUE;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.partner_credential, app.partner_session TO CURRENT_USER;
ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_insert_guard_trg;
ALTER TABLE app.partner_credential DISABLE TRIGGER partner_credential_insert_guard_trg;
CREATE POLICY zz67_cred ON app.partner_credential FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz67_sess ON app.partner_session FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

CREATE FUNCTION pg_temp.th(p_label text) RETURNS text LANGUAGE sql IMMUTABLE AS $f$
  SELECT md5('s67:' || p_label) || md5('s67b:' || p_label)
$f$;
CREATE FUNCTION pg_temp.mk_cred(p_label text, p_uid uuid) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_credential (user_id, credential_id, public_key, alg)
  VALUES (p_uid, decode(md5('c67:' || p_label) || md5('c67b:' || p_label), 'hex'),
          decode(md5('k67:' || p_label) || md5('k67b:' || p_label), 'hex'), -7)
  RETURNING id
$f$;
CREATE FUNCTION pg_temp.mk_session(p_label text, p_uid uuid, p_cred uuid, p_aal int DEFAULT 1) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_session (token_hash, user_id, credential_id, aal, created_at, last_seen_at, expires_at,
                                   mint_kind, mint_nonce_hash, mint_authenticator_data, mint_client_data_json, mint_signature)
  VALUES (pg_temp.th(p_label), p_uid, p_cred, p_aal, now() - interval '1 hour', now(), now() + interval '7 hours', 'sign_in',
          decode(md5('n67:' || p_label) || md5('n67b:' || p_label), 'hex'), decode(repeat('04', 40), 'hex'),
          convert_to('{}', 'UTF8'), decode(repeat('05', 70), 'hex'))
  RETURNING id
$f$;
CREATE FUNCTION pg_temp.list_n(p_uid uuid) RETURNS int LANGUAGE plpgsql AS $f$
DECLARE n int;
BEGIN
  EXECUTE 'SET LOCAL ROLE edge_partner';
  SELECT count(*)::int INTO n FROM private.partner_credential_list_for_partner(p_uid);
  EXECUTE 'RESET ROLE';
  RETURN n;
END
$f$;
GRANT EXECUTE ON FUNCTION pg_temp.th(text), pg_temp.mk_cred(text, uuid), pg_temp.mk_session(text, uuid, uuid, int),
  pg_temp.list_n(uuid) TO PUBLIC;

-- ----------------------------------------------------------------------------
-- 1. Structure
-- ----------------------------------------------------------------------------
SELECT ok(
  (SELECT prosrc LIKE '%partner_reach_covers%' FROM pg_proc p
   JOIN pg_namespace n ON n.oid = p.pronamespace
   WHERE n.nspname = 'private' AND p.proname = 'partner_credential_list_for_partner'
     AND pg_get_function_identity_arguments(p.oid) = 'p_user_id uuid'),
  'structure: list definer body calls partner_reach_covers'
);
SELECT ok(
  (SELECT count(*)::int = 0 FROM pg_proc p
   JOIN pg_namespace n ON n.oid = p.pronamespace
   WHERE n.nspname = 'private' AND p.proname = 'partner_credential_list_for_partner'
     AND pg_get_function_identity_arguments(p.oid) = ''),
  'structure: zero-arg overload is gone'
);
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT ok(
  (SELECT note LIKE '%reach%' AND identity_args = 'p_user_id uuid'
   FROM private.function_inventory
   WHERE function_name = 'partner_credential_list_for_partner'),
  'inventory: identity_args p_user_id uuid and note mentions reach'
);
SELECT tests.clear_actor();
SELECT is(
  (SELECT count(*)::int FROM pg_proc p
   WHERE p.oid = 'private.partner_credential_list_for_partner(uuid)'::regprocedure
     AND pg_get_function_result(p.oid) ~* 'public_key|credential_id|sign_count'),
  0,
  'structure: list never returns key, credential id bytes, or counter'
);

-- ----------------------------------------------------------------------------
-- 2. Behaviour: manager@X lists staff@X; staff cannot list up; Y empty
-- ----------------------------------------------------------------------------
SELECT pg_temp.th('sx') AS th_sx \gset
SELECT pg_temp.th('mx') AS th_mx \gset
SELECT pg_temp.mk_cred('sx', '00000000-0000-0000-0000-1000000000a1') AS c_sx \gset
SELECT pg_temp.mk_cred('sx2', '00000000-0000-0000-0000-1000000000a1') AS c_sx2 \gset
SELECT pg_temp.mk_cred('mx', '00000000-0000-0000-0000-2000000000b1') AS c_mx \gset
SELECT pg_temp.mk_cred('sy', '00000000-0000-0000-0000-1000000000a3') AS c_sy \gset
SELECT pg_temp.mk_session('sx', '00000000-0000-0000-0000-1000000000a1', :'c_sx') AS s_sx \gset
SELECT pg_temp.mk_session('mx', '00000000-0000-0000-0000-2000000000b1', :'c_mx') AS s_mx \gset

SAVEPOINT reach_ok;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_mx');
RESET ROLE;
SELECT is(pg_temp.list_n(NULL), 1, 'manager lists own with NULL (default)');
SELECT is(pg_temp.list_n('00000000-0000-0000-0000-2000000000b1'::uuid), 1,
  'manager lists own when p_user_id is self');
SELECT is(pg_temp.list_n('00000000-0000-0000-0000-1000000000a1'::uuid), 2,
  'manager@X lists staff@X credentials (reach covers)');
SELECT is(pg_temp.list_n('00000000-0000-0000-0000-1000000000a3'::uuid), 0,
  'manager@X lists staff@Y as empty (outside reach)');
SELECT is(pg_temp.list_n('00000000-0000-0000-0000-999999999999'::uuid), 0,
  'unknown target is empty (no oracle)');
ROLLBACK TO SAVEPOINT reach_ok;

SAVEPOINT staff_up;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SELECT is(pg_temp.list_n(NULL), 2, 'staff still lists own');
SELECT is(pg_temp.list_n('00000000-0000-0000-0000-2000000000b1'::uuid), 0,
  'staff cannot list manager (reach does not cover up)');
ROLLBACK TO SAVEPOINT staff_up;

SELECT * FROM finish();
ROLLBACK;
