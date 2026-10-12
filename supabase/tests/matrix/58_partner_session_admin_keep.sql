-- 58_partner_session_admin_keep.sql
-- 0080_partner_session_admin_keep.sql (P5 §66 / design §4.1): Admin
-- concurrent keep = 2; staff / manager / operator stay 3. Policy returns
-- concurrent; mint evicts with v_pol.concurrent. Restricted harness:
-- auth.users inserts go through service_role.

\set QUIET 1
BEGIN;
SELECT plan(13);

GRANT edge_partner, edge_partner_minter, private_definer, partner_session_issuer TO CURRENT_USER WITH SET TRUE;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.partner_credential, app.partner_session, app.partner_auth_challenge, app.partner_rp_config, app.admin_user TO CURRENT_USER;
CREATE POLICY zz58_cred ON app.partner_credential FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz58_sess ON app.partner_session FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz58_chal ON app.partner_auth_challenge FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz58_rp ON app.partner_rp_config FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz58_adm ON app.admin_user FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz58_audit ON app.audit_log FOR SELECT TO CURRENT_USER USING (true);

INSERT INTO app.partner_rp_config (rp_id, origin)
VALUES ('partners.example.test', 'https://partners.example.test')
ON CONFLICT DO NOTHING;

SET LOCAL ROLE private_definer;
\i supabase/tests/partner-sign-helpers.sql
RESET ROLE;

CREATE TEMP TABLE creds (label text PRIMARY KEY, uid uuid, d numeric, qx numeric, qy numeric, cred_id bytea, cred_row uuid);
CREATE TEMP TABLE asr (label text PRIMARY KEY, token text, cred_id bytea, nonce bytea, exp bigint, mac bytea, ad bytea, cd bytea, sig bytea);
CREATE TEMP TABLE mres (label text, o_status text, o_session_id uuid, o_aal smallint, o_expires_at timestamptz);
GRANT ALL ON creds, asr, mres TO PUBLIC;

CREATE FUNCTION pg_temp.newcred(p_label text, p_uid uuid DEFAULT NULL, p_stored bigint DEFAULT 0) RETURNS uuid LANGUAGE plpgsql AS $f$
DECLARE
  d numeric; pub numeric[]; cid bytea; cose bytea; rid uuid;
BEGIN
  IF p_uid IS NULL THEN
    p_uid := gen_random_uuid();
    EXECUTE 'SET LOCAL ROLE service_role';
    INSERT INTO auth.users (id, email) VALUES (p_uid, 'mint58-' || p_label || '@example.test');
    EXECUTE 'RESET ROLE';
  END IF;
  EXECUTE 'SET LOCAL ROLE private_definer';
  d := private.partner_sig_os2ip(public.gen_random_bytes(32)) % (private.partner_sig_p256_n() - 1) + 1;
  pub := pg_temp.ps_pub(d);
  cose := pg_temp.ps_cose_es256(pub[1], pub[2]);
  EXECUTE 'RESET ROLE';
  cid := public.gen_random_bytes(32);
  INSERT INTO app.partner_credential (user_id, credential_id, public_key, alg, sign_count) VALUES (p_uid, cid, cose, -7, p_stored) RETURNING id INTO rid;
  INSERT INTO creds VALUES (p_label, p_uid, d, pub[1], pub[2], cid, rid);
  RETURN rid;
END
$f$;

CREATE FUNCTION pg_temp.go(p_label text, p_cred text, p_counter bigint, p_opts jsonb DEFAULT '{}'::jsonb) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE
  c record; a record;
BEGIN
  SELECT * INTO c FROM creds WHERE label = p_cred;
  EXECUTE 'SET LOCAL ROLE private_definer';
  SELECT * INTO a FROM pg_temp.ps_assertion(c.d, 'partners.example.test', 'https://partners.example.test', p_counter, p_opts);
  EXECUTE 'RESET ROLE';
  INSERT INTO asr VALUES (p_label, encode(sha256(convert_to('token:' || p_label, 'UTF8')), 'hex'), coalesce(decode(p_opts ->> 'cred_id_hex', 'hex'), c.cred_id), a.o_nonce, a.o_exp, a.o_mac, a.o_ad, a.o_cd, a.o_sig);
  EXECUTE 'SET LOCAL ROLE edge_partner_minter';
  INSERT INTO mres SELECT p_label, m.* FROM private.partner_session_mint(
    encode(sha256(convert_to('token:' || p_label, 'UTF8')), 'hex'),
    coalesce(decode(p_opts ->> 'cred_id_hex', 'hex'), c.cred_id), a.o_nonce, a.o_exp, a.o_mac, a.o_ad, a.o_cd, a.o_sig) m;
  EXECUTE 'RESET ROLE';
  RETURN (SELECT o_status FROM mres WHERE label = p_label ORDER BY ctid DESC LIMIT 1);
END
$f$;

CREATE FUNCTION pg_temp.plant(p_label text, p_cred text, p_age interval) RETURNS uuid LANGUAGE plpgsql AS $f$
DECLARE
  v_id uuid := gen_random_uuid();
  c record;
BEGIN
  SELECT * INTO c FROM creds WHERE label = p_cred;
  SET CONSTRAINTS ALL IMMEDIATE;
  ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_insert_guard_trg;
  INSERT INTO app.partner_session (
    id, token_hash, user_id, credential_id, aal, created_at, last_seen_at, expires_at,
    mint_kind, mint_nonce_hash, mint_authenticator_data, mint_client_data_json, mint_signature
  ) VALUES (
    v_id,
    encode(sha256(convert_to('plant58:' || p_label, 'UTF8')), 'hex'),
    c.uid, c.cred_row, 1,
    now() - p_age, now() - p_age, now() + interval '8 hours',
    'sign_in',
    sha256(convert_to('plant58n:' || p_label, 'UTF8')),
    decode(repeat('04', 40), 'hex'),
    convert_to('{}', 'UTF8'),
    decode(repeat('05', 70), 'hex')
  );
  ALTER TABLE app.partner_session ENABLE TRIGGER partner_session_insert_guard_trg;
  RETURN v_id;
END
$f$;

-- ----------------------------------------------------------------------------
-- 1. Structure: policy returns concurrent; mint / register_first COMMENT
-- ----------------------------------------------------------------------------
SELECT is(
  (SELECT p.proargnames FROM pg_proc p
   WHERE p.oid = 'private.partner_session_policy(uuid)'::regprocedure),
  ARRAY['p_uid', 'required_aal', 'idle', 'absolute', 'concurrent'],
  'structure: partner_session_policy OUT columns include concurrent'
);

SET LOCAL ROLE private_definer;
SELECT is(
  (SELECT concurrent FROM private.partner_session_policy('00000000-0000-0000-0000-000000000001')),
  3,
  'policy: a non-admin person keeps 3'
);
RESET ROLE;

SELECT pg_temp.newcred('adm') IS NOT NULL AS adm_cred \gset
INSERT INTO app.admin_user (user_id) SELECT uid FROM creds WHERE label = 'adm';

SET LOCAL ROLE private_definer;
SELECT is(
  (SELECT concurrent FROM private.partner_session_policy((SELECT uid FROM creds WHERE label = 'adm'))),
  2,
  'policy: an admin keeps 2'
);
RESET ROLE;

SELECT is(
  (SELECT obj_description('private.partner_session_mint(text, bytea, bytea, bigint, bytea, bytea, bytea, bytea)'::regprocedure) LIKE '%concurrent%'),
  true,
  'COMMENT on mint mentions concurrent keep'
);

SELECT is(
  (SELECT obj_description('private.partner_credential_register_first(text, uuid, smallint, uuid, bytea, bigint, bytea, bytea, bytea, bytea, bytea, text[])'::regprocedure) LIKE '%concurrent%'),
  true,
  'COMMENT on register_first mentions concurrent keep'
);

SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is(
  (SELECT note LIKE '%concurrent%' FROM private.function_inventory
   WHERE schema_name = 'private' AND function_name = 'partner_session_policy'),
  true,
  'function_inventory note for policy mentions concurrent'
);
SELECT tests.clear_actor();

-- ----------------------------------------------------------------------------
-- 2. Admin: three older live + mint → two live; oldest revoked
-- ----------------------------------------------------------------------------
SELECT pg_temp.plant('a1', 'adm', interval '50 minutes') AS sid_a1 \gset
SELECT pg_temp.plant('a2', 'adm', interval '40 minutes') AS sid_a2 \gset
SELECT pg_temp.plant('a3', 'adm', interval '30 minutes') AS sid_a3 \gset

SELECT is((SELECT count(*)::int FROM app.partner_session s JOIN creds c ON c.uid = s.user_id WHERE c.label = 'adm' AND s.revoked_at IS NULL), 3,
  'setup: three live admin sessions before mint');

SELECT is(pg_temp.go('adm1', 'adm', 1), 'ok', '4.1: admin sign-in mint with three older live sessions');

SELECT is(
  (SELECT count(*)::int FROM app.partner_session s JOIN creds c ON c.uid = s.user_id WHERE c.label = 'adm' AND s.revoked_at IS NULL),
  2,
  '4.1: at most TWO live sessions remain for an admin'
);

SELECT is(
  (SELECT revoked_at IS NOT NULL AND revoke_reason = 'session_limit' FROM app.partner_session WHERE id = :'sid_a1'::uuid),
  true,
  '4.1: the OLDEST admin session was revoked with session_limit'
);

SELECT is(
  (SELECT count(*)::int FROM app.partner_session s JOIN creds c ON c.uid = s.user_id WHERE c.label = 'adm'),
  4,
  '4.1: all four admin session rows remain (eviction never DELETE)'
);

-- ----------------------------------------------------------------------------
-- 3. Staff regression: four live + mint → three (unchanged from §64)
-- ----------------------------------------------------------------------------
SELECT pg_temp.newcred('stf') IS NOT NULL AS stf_cred \gset
SELECT pg_temp.plant('s1', 'stf', interval '5 hours');
SELECT pg_temp.plant('s2', 'stf', interval '4 hours');
SELECT pg_temp.plant('s3', 'stf', interval '3 hours');
SELECT pg_temp.plant('s4', 'stf', interval '2 hours');

SELECT is(pg_temp.go('stf1', 'stf', 1), 'ok', 'staff mint with four older live sessions');
SELECT is(
  (SELECT count(*)::int FROM app.partner_session s JOIN creds c ON c.uid = s.user_id WHERE c.label = 'stf' AND s.revoked_at IS NULL),
  3,
  'staff still keeps THREE live sessions'
);

SELECT * FROM finish();
ROLLBACK;
