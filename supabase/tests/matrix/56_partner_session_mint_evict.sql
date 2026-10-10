-- 56_partner_session_mint_evict.sql
-- 0078_partner_session_mint_evict.sql (P5 §64 / design §4.1): sign-in mint
-- keeps at most three live sessions of a person by REVOKING the oldest
-- beyond that (same helper / keep=3 as register_first). Rows stay
-- (60/h count is from partner_session). Restricted harness: auth.users
-- inserts go through service_role.

\set QUIET 1
BEGIN;
SELECT plan(12);

GRANT edge_partner, edge_partner_minter, private_definer, partner_session_issuer TO CURRENT_USER WITH SET TRUE;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.partner_credential, app.partner_session, app.partner_auth_challenge, app.partner_rp_config TO CURRENT_USER;
CREATE POLICY zz56_cred ON app.partner_credential FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz56_sess ON app.partner_session FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz56_chal ON app.partner_auth_challenge FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz56_rp ON app.partner_rp_config FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz56_audit ON app.audit_log FOR SELECT TO CURRENT_USER USING (true);

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
    INSERT INTO auth.users (id, email) VALUES (p_uid, 'mint56-' || p_label || '@example.test');
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

-- plant one live session with a given age (disable insert guard for back-dated created_at)
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
    encode(sha256(convert_to('plant56:' || p_label, 'UTF8')), 'hex'),
    c.uid, c.cred_row, 1,
    now() - p_age, now() - p_age, now() + interval '8 hours',
    'sign_in',
    sha256(convert_to('plant56n:' || p_label, 'UTF8')),
    decode(repeat('04', 40), 'hex'),
    convert_to('{}', 'UTF8'),
    decode(repeat('05', 70), 'hex')
  );
  ALTER TABLE app.partner_session ENABLE TRIGGER partner_session_insert_guard_trg;
  RETURN v_id;
END
$f$;

-- ----------------------------------------------------------------------------
-- 1. Structure: mint still issuer-owned; COMMENT / inventory mention eviction
-- ----------------------------------------------------------------------------
SELECT is(
  (SELECT p.prosecdef AND p.proconfig = ARRAY['search_path=""'] AND p.proowner = 'partner_session_issuer'::regrole
   FROM pg_proc p WHERE p.oid = 'private.partner_session_mint(text, bytea, bytea, bigint, bytea, bytea, bytea, bytea)'::regprocedure),
  true,
  'structure: partner_session_mint remains SECURITY DEFINER / issuer-owned / search_path='''''
);

SELECT is(
  (SELECT obj_description('private.partner_session_mint(text, bytea, bytea, bigint, bytea, bytea, bytea, bytea)'::regprocedure) LIKE '%evict%'),
  true,
  'COMMENT mentions eviction'
);

-- FORCE RLS on function_inventory: SELECT is service_role-only (0014); same pattern as matrix 54
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is(
  (SELECT note LIKE '%evict%' FROM private.function_inventory
   WHERE schema_name = 'private' AND function_name = 'partner_session_mint'),
  true,
  'function_inventory note mentions eviction'
);
SELECT tests.clear_actor();

-- ----------------------------------------------------------------------------
-- 2. 4.1: four older live sessions + a successful mint → three live; two oldest revoked
-- ----------------------------------------------------------------------------
SELECT pg_temp.newcred('ev') IS NOT NULL AS ev_cred \gset
SELECT pg_temp.plant('old1', 'ev', interval '5 hours') AS sid_old1 \gset
SELECT pg_temp.plant('old2', 'ev', interval '4 hours') AS sid_old2 \gset
SELECT pg_temp.plant('old3', 'ev', interval '3 hours') AS sid_old3 \gset
SELECT pg_temp.plant('old4', 'ev', interval '2 hours') AS sid_old4 \gset

SELECT is((SELECT count(*)::int FROM app.partner_session s JOIN creds c ON c.uid = s.user_id WHERE c.label = 'ev' AND s.revoked_at IS NULL), 4,
  'setup: four live sessions before mint');

SELECT is(pg_temp.go('ev1', 'ev', 1), 'ok', '4.1: sign-in mint with four older live sessions of the person');

SELECT is(
  (SELECT count(*)::int FROM app.partner_session s JOIN creds c ON c.uid = s.user_id WHERE c.label = 'ev' AND s.revoked_at IS NULL),
  3,
  '4.1: at most THREE live sessions remain'
);

SELECT is(
  (SELECT array_agg(s.id = :'sid_old1'::uuid OR s.id = :'sid_old2'::uuid ORDER BY s.created_at)
   FROM app.partner_session s JOIN creds c ON c.uid = s.user_id
   WHERE c.label = 'ev' AND s.revoked_at IS NOT NULL),
  ARRAY[true, true],
  '4.1: the two OLDEST were revoked (REVOKED, not deleted: the row stays)'
);

SELECT is(
  (SELECT count(*)::int FROM app.partner_session s JOIN creds c ON c.uid = s.user_id
   WHERE c.label = 'ev' AND s.revoke_reason = 'session_limit'),
  2,
  '... with reason session_limit'
);

SELECT is(
  (SELECT revoked_at IS NULL FROM app.partner_session WHERE id = (SELECT o_session_id FROM mres WHERE label = 'ev1' ORDER BY ctid DESC LIMIT 1)),
  true,
  '... and the NEW session is among the live ones'
);

SELECT is(
  (SELECT count(*)::int FROM app.partner_session s JOIN creds c ON c.uid = s.user_id WHERE c.label = 'ev'),
  5,
  '4.1: all five session rows remain (eviction never DELETE)'
);

-- ----------------------------------------------------------------------------
-- 3. Under the cap: two live + mint → no session_limit revokes
-- ----------------------------------------------------------------------------
SELECT pg_temp.newcred('ok2') IS NOT NULL AS ok2_cred \gset
SELECT pg_temp.plant('a', 'ok2', interval '1 hour');
SELECT pg_temp.plant('b', 'ok2', interval '30 minutes');
SELECT is(pg_temp.go('ok2m', 'ok2', 1), 'ok', 'under cap: mint with two live sessions succeeds');
SELECT is(
  (SELECT count(*)::int FROM app.partner_session s JOIN creds c ON c.uid = s.user_id
   WHERE c.label = 'ok2' AND s.revoke_reason = 'session_limit'),
  0,
  'under cap: no session_limit revokes'
);

SELECT * FROM finish();
ROLLBACK;
