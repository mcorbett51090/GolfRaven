-- 68_partner_member_list.sql
-- 0090_partner_member_list.sql (P5 §80): class A0 org member roster
-- for manager / operator (active rows in facility scope).

\set QUIET 1
BEGIN;
SELECT plan(9);

GRANT edge_partner, private_definer TO CURRENT_USER WITH SET TRUE;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.partner_credential, app.partner_session TO CURRENT_USER;
ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_insert_guard_trg;
ALTER TABLE app.partner_credential DISABLE TRIGGER partner_credential_insert_guard_trg;
CREATE POLICY zz68_cred ON app.partner_credential FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz68_sess ON app.partner_session FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

CREATE FUNCTION pg_temp.th(p_label text) RETURNS text LANGUAGE sql IMMUTABLE AS $f$
  SELECT md5('s68:' || p_label) || md5('s68b:' || p_label)
$f$;
CREATE FUNCTION pg_temp.mk_cred(p_label text, p_uid uuid) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_credential (user_id, credential_id, public_key, alg)
  VALUES (p_uid, decode(md5('c68:' || p_label) || md5('c68b:' || p_label), 'hex'),
          decode(md5('k68:' || p_label) || md5('k68b:' || p_label), 'hex'), -7)
  RETURNING id
$f$;
CREATE FUNCTION pg_temp.mk_session(p_label text, p_uid uuid, p_cred uuid, p_aal int DEFAULT 1) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_session (token_hash, user_id, credential_id, aal, created_at, last_seen_at, expires_at,
                                   mint_kind, mint_nonce_hash, mint_authenticator_data, mint_client_data_json, mint_signature)
  VALUES (pg_temp.th(p_label), p_uid, p_cred, p_aal, now() - interval '1 hour', now(), now() + interval '7 hours', 'sign_in',
          decode(md5('n68:' || p_label) || md5('n68b:' || p_label), 'hex'), decode(repeat('04', 40), 'hex'),
          convert_to('{}', 'UTF8'), decode(repeat('05', 70), 'hex'))
  RETURNING id
$f$;
CREATE FUNCTION pg_temp.list_ids(p_org uuid) RETURNS uuid[] LANGUAGE plpgsql AS $f$
DECLARE ids uuid[];
BEGIN
  EXECUTE 'SET LOCAL ROLE edge_partner';
  SELECT coalesce(array_agg(o_user_id ORDER BY o_user_id), ARRAY[]::uuid[])
  INTO ids
  FROM private.partner_member_list_for_partner(p_org);
  EXECUTE 'RESET ROLE';
  RETURN ids;
END
$f$;
CREATE FUNCTION pg_temp.call(p_sql text) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r text;
BEGIN
  EXECUTE 'SET LOCAL ROLE edge_partner';
  EXECUTE p_sql INTO r;
  EXECUTE 'RESET ROLE';
  RETURN r;
END
$f$;
GRANT EXECUTE ON FUNCTION pg_temp.th(text), pg_temp.mk_cred(text, uuid), pg_temp.mk_session(text, uuid, uuid, int),
  pg_temp.list_ids(uuid), pg_temp.call(text) TO PUBLIC;

-- ----------------------------------------------------------------------------
-- 1. Structure
-- ----------------------------------------------------------------------------
SELECT ok(
  (SELECT prosrc LIKE '%has_facility_scope%' AND prosrc LIKE '%partner_authorize%'
   FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
   WHERE n.nspname = 'private' AND p.proname = 'partner_member_list_for_partner'),
  'structure: body authorizes and scopes via has_facility_scope'
);
SELECT is(
  (SELECT count(*)::int FROM pg_proc p
   WHERE p.oid = 'private.partner_member_list_for_partner(uuid)'::regprocedure
     AND pg_get_function_result(p.oid) ~* 'email|token'),
  0,
  'structure: list never returns email or token columns'
);
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT ok(
  (SELECT expected_edge_partner AND note LIKE '%A0%'
   FROM private.function_inventory
   WHERE function_name = 'partner_member_list_for_partner'),
  'inventory: edge_partner A0 row'
);
SELECT tests.clear_actor();

-- ----------------------------------------------------------------------------
-- 2. Behaviour (helpers: org X …0001, staff a1, manager b1, staff@Y a3, revoked a2/b2)
-- ----------------------------------------------------------------------------
SELECT pg_temp.th('sx') AS th_sx \gset
SELECT pg_temp.th('mx') AS th_mx \gset
SELECT pg_temp.th('op') AS th_op \gset
SELECT pg_temp.mk_cred('sx', '00000000-0000-0000-0000-1000000000a1') AS c_sx \gset
SELECT pg_temp.mk_cred('mx', '00000000-0000-0000-0000-2000000000b1') AS c_mx \gset
SELECT pg_temp.mk_cred('op', '00000000-0000-0000-0000-3000000000c1') AS c_op \gset
SELECT pg_temp.mk_session('sx', '00000000-0000-0000-0000-1000000000a1', :'c_sx') AS s_sx \gset
SELECT pg_temp.mk_session('mx', '00000000-0000-0000-0000-2000000000b1', :'c_mx') AS s_mx \gset
SELECT pg_temp.mk_session('op', '00000000-0000-0000-0000-3000000000c1', :'c_op', 2) AS s_op \gset

SAVEPOINT mgr;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_mx');
RESET ROLE;
SELECT ok(
  pg_temp.list_ids('10000000-0000-0000-0000-000000000001'::uuid)
    @> ARRAY['00000000-0000-0000-0000-1000000000a1'::uuid, '00000000-0000-0000-0000-2000000000b1'::uuid]
  AND NOT (pg_temp.list_ids('10000000-0000-0000-0000-000000000001'::uuid)
    && ARRAY['00000000-0000-0000-0000-1000000000a2'::uuid, '00000000-0000-0000-0000-2000000000b2'::uuid]),
  'manager@X lists active staff+self at org X; excludes revoked'
);
SELECT is(
  pg_temp.list_ids('10000000-0000-0000-0000-000000000002'::uuid),
  ARRAY[]::uuid[],
  'manager@X lists org Y as empty (outside facility scope)'
);
SELECT ok(
  pg_temp.list_ids(NULL)
    @> ARRAY['00000000-0000-0000-0000-1000000000a1'::uuid]
  AND NOT (pg_temp.list_ids(NULL) && ARRAY['00000000-0000-0000-0000-1000000000a3'::uuid]),
  'manager@X with NULL orgId sees X only (not Y)'
);
ROLLBACK TO SAVEPOINT mgr;

SAVEPOINT staff;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SELECT throws_ok(
  $$SELECT pg_temp.call($q$SELECT o_user_id::text FROM private.partner_member_list_for_partner('10000000-0000-0000-0000-000000000001'::uuid) LIMIT 1$q$)$$,
  '42501',
  'partner_authorize: no scope',
  'staff cannot list members (A0 manager/operator only)'
);
ROLLBACK TO SAVEPOINT staff;

SAVEPOINT opr;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_op');
RESET ROLE;
SELECT ok(
  pg_temp.list_ids('10000000-0000-0000-0000-000000000001'::uuid)
    @> ARRAY['00000000-0000-0000-0000-1000000000a1'::uuid],
  'operator@T (trail covers fac_x) lists active org X members'
);
ROLLBACK TO SAVEPOINT opr;

SELECT is(
  (SELECT count(*)::int FROM pg_proc p
   WHERE p.pronamespace = 'private'::regnamespace
     AND p.proname = 'partner_member_list_for_partner'
     AND has_function_privilege('edge_partner', p.oid, 'EXECUTE')
     AND NOT has_function_privilege('anon', p.oid, 'EXECUTE')
     AND NOT has_function_privilege('service_role', p.oid, 'EXECUTE')),
  1,
  'ACL: edge_partner only'
);

SELECT * FROM finish();
ROLLBACK;
