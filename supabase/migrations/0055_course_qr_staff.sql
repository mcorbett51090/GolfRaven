-- 0055_course_qr_staff.sql
--
-- P5.1a, slice S2b: THE STAFF LANE OF THE COURSE QR. docs/security/partner-auth-design.md is the specification: "As built: S2a" (the formats, `private.course_pin_derive`, the token and printed-QR rows,
-- the epoch trigger), 6.3 (the class table: "Marker sold" mint is A1, "Rotate PIN" is A2, `qr-print` is A3, today's PIN is A0), 4.2 (idle is extended only by user-initiated calls; the course-QR refresh is
-- keep-alive exempt: PA-26), 8 (rate limits) and 12.1 (AT(19), PA-26); docs/security/p3-money-path-requirements.md "What S3 and S2b must do". Migrations 0001-0054 are untouched.
--
-- WHAT THIS ADDS (the database half; the Edge half is supabase/functions/course-qr and qr-print)
--   1. `_for_partner` definers, each beginning with private.partner_authorize (check 14), edge_partner only:
--        course_pin_show_for_partner(facility)           A0   today's PIN: private.course_pin_derive for the facility-local date and the epoch live NOW (the very arguments the player lane judges a scan made now
--                                                              under), nothing re-implemented. staff or manager at THE facility; a staff member of another facility is refused 42501 by the seam.
--        course_pin_rotate_for_partner(facility)         A2   UPDATE app.facility_programme SET pin_epoch = pin_epoch + 1 and nothing else: the 0046 trigger writes app.course_pin_epoch_log (this file never does).
--        course_qr_mint_for_partner(facility, nonce_hash) A1  "Marker sold": consumes the single-use PIN grant, INSERTs the app.course_qr_token row (nonce_hash, facility_id, issued_by_staff, kid, issued_at truncated to the
--                                                              SECOND so it IS the token's `iat`, expires_at = issued_at + 120 s) and returns what the Edge needs to SIGN (the kid and the signing key from Vault). The key is
--                                                              released only here, only after the A1 prerequisite, the facility scope and the programme check, and only with the row the signature is for.
--        course_qr_refresh_for_partner(facility, nonce_hash) A0_KEEPALIVE  the 30 s heartbeat of the sale screen, BOUND to a nonce this staff member's own A1 mint created. It READS that row (live | used | expired | unknown)
--                                                              and creates nothing: no token, no authority, and (PA-26) it never advances last_seen_at, so it cannot keep an idle session alive.
--        course_qr_print_key_for_partner(facility)       A3   qr-print step 1: the printed-QR kid and signing key from Vault (and the facility slug), for an operator or admin at an aal 2 session.
--        course_qr_print_write_for_partner(facility, qr_kid, sig, public_key)  A3  qr-print step 2: ensures the PUBLIC key row in app.course_qr_key (inserted when absent; an existing row must be EQUAL), then
--                                                              writes app.facility_qr (a reprint replaces its qr_kid and clears revoked_at). It cannot verify the signature (no Ed25519 in the database): the Edge self-verifies under the public key.
--        course_qr_print_read_for_partner(facility)      A0   the registered printed QR of a facility (operator or admin).
--   2. private.course_qr_signing_key_read(purpose): the ONLY reader of the Vault secrets `course_qr_signing_key_rotating_token` and `course_qr_signing_key_printed_qr`, each `<kid>:<32-byte Ed25519 seed, base64url>`.
--      EXECUTE for nobody but its owner (so only the wrappers above reach it, after their authorization). The PRIVATE key is never in a table, a log line or a migration; the PUBLIC half is in app.course_qr_key.
--   3. Grants and policies private_definer needs under a PARTNER binding. Every policy is keyed on the transaction's BINDING (private.partner_binding_kind() / partner_binding_user()), never on a settable GUC (the HARD
--      RULE), and registered in private.definer_policy_allowlist and supabase/tests/fixtures/definer_policy_exprs.txt. The 0046 policies (`actor_uid() IS NOT NULL`) never apply under a partner binding: actor_uid() is NULL.
--
-- WHAT THIS DOES NOT BUILD: the hand-over token (plan 9.4: S5), the 25-credits-a-day cap alert (S3's hook in marker-scan), pepper rotation tooling, the PWA screens (S7b), and the provisioning of the Vault secrets (an operator
-- step: tools/db/provision-course-qr-key.mjs prints the SQL; see the design doc's "As built: S2b").
--
-- Every `*_for_partner` body below contains NO dollar sign, no double quote, no backslash, no E-string and no comment marker (check 14 (a0): the first-statement reader cannot lex them).

-- ============================================================================
-- 1. Grants and policies (private_definer, under a partner binding). Table owners run these; the functions follow in section 2.
-- ============================================================================
-- 1a. the public key rows: read under a partner binding; INSERT only of a printed_qr key, only by a partner binding (the definer is the real gate: A3, operator at the facility)
GRANT INSERT (purpose, kid, public_key_b64url) ON app.course_qr_key TO private_definer;
CREATE POLICY pd_course_qr_staff_key_read ON app.course_qr_key FOR SELECT TO private_definer
  USING ((SELECT private.partner_binding_kind()) = 'partner');
CREATE POLICY pd_course_qr_staff_key_insert ON app.course_qr_key FOR INSERT TO private_definer
  WITH CHECK ((SELECT private.partner_binding_kind()) = 'partner' AND purpose = 'printed_qr' AND revoked_at IS NULL);

-- 1b. the facility facts the wrappers read: the timezone and slug of the catalog facility, the programme that decides whether a QR variant is live. Public catalog data: the binding kind is the whole predicate.
GRANT SELECT (slug) ON app.catalog_facility TO private_definer;
CREATE POLICY pd_course_qr_staff_facility_read ON app.catalog_facility FOR SELECT TO private_definer
  USING ((SELECT private.partner_binding_kind()) = 'partner');
CREATE POLICY pd_course_qr_staff_trail_programme_read ON app.trail_programme FOR SELECT TO private_definer
  USING ((SELECT private.partner_binding_kind()) = 'partner');

-- 1c. "Rotate PIN": pin_epoch only (the 0046 column grant), on the rows of a facility the bound person holds staff, manager or operator scope at
CREATE POLICY pd_course_qr_staff_programme_epoch ON app.facility_programme FOR UPDATE TO private_definer
  USING ((SELECT private.partner_binding_kind()) = 'partner'
         AND private.has_facility_scope((SELECT private.partner_binding_user()), facility_id, ARRAY['staff', 'manager', 'operator']::app.partner_role[]))
  WITH CHECK ((SELECT private.partner_binding_kind()) = 'partner'
         AND private.has_facility_scope((SELECT private.partner_binding_user()), facility_id, ARRAY['staff', 'manager', 'operator']::app.partner_role[]));

-- 1d. the rotating-token rows: INSERT of a fresh, unused row issued BY THE BOUND PERSON for a facility they are staff or manager at, expiring exactly 120 s after issue; SELECT of the person's OWN rows only (the refresh)
GRANT INSERT (nonce_hash, facility_id, issued_by_staff, kid, issued_at, expires_at) ON app.course_qr_token TO private_definer;
CREATE POLICY pd_course_qr_staff_token_insert ON app.course_qr_token FOR INSERT TO private_definer
  WITH CHECK ((SELECT private.partner_binding_kind()) = 'partner' AND issued_by_staff = (SELECT private.partner_binding_user())
              AND used_by_user IS NULL AND used_at IS NULL AND expires_at = issued_at + interval '120 seconds'
              AND private.has_facility_scope((SELECT private.partner_binding_user()), facility_id, ARRAY['staff', 'manager']::app.partner_role[]));
CREATE POLICY pd_course_qr_staff_token_read ON app.course_qr_token FOR SELECT TO private_definer
  USING ((SELECT private.partner_binding_kind()) = 'partner' AND issued_by_staff = (SELECT private.partner_binding_user()));

-- 1e. the printed-QR registration: an operator (or an admin) at the facility reads, registers and replaces it. A reprint clears revoked_at; it never writes a row for a facility the bound person has no scope at.
GRANT INSERT (facility_id, qr_kid, sig, printed_at, revoked_at), UPDATE (qr_kid, sig, printed_at, revoked_at) ON app.facility_qr TO private_definer;
CREATE POLICY pd_course_qr_staff_facility_qr_read ON app.facility_qr FOR SELECT TO private_definer
  USING ((SELECT private.partner_binding_kind()) = 'partner' AND private.has_facility_scope((SELECT private.partner_binding_user()), facility_id, ARRAY['operator']::app.partner_role[]));
CREATE POLICY pd_course_qr_staff_facility_qr_insert ON app.facility_qr FOR INSERT TO private_definer
  WITH CHECK ((SELECT private.partner_binding_kind()) = 'partner' AND revoked_at IS NULL
              AND private.has_facility_scope((SELECT private.partner_binding_user()), facility_id, ARRAY['operator']::app.partner_role[]));
CREATE POLICY pd_course_qr_staff_facility_qr_update ON app.facility_qr FOR UPDATE TO private_definer
  USING ((SELECT private.partner_binding_kind()) = 'partner' AND private.has_facility_scope((SELECT private.partner_binding_user()), facility_id, ARRAY['operator']::app.partner_role[]))
  WITH CHECK ((SELECT private.partner_binding_kind()) = 'partner' AND revoked_at IS NULL
              AND private.has_facility_scope((SELECT private.partner_binding_user()), facility_id, ARRAY['operator']::app.partner_role[]));

-- ============================================================================
-- 2. The functions (ownership bracket as 0045 / 0047 / 0052)
-- ============================================================================
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

-- 2a. THE signing-key reader. The Vault secret of a purpose is `<kid>:<seed>`: the kid (the public key's address in app.course_qr_key) and the 32-byte Ed25519 seed as 43 base64url characters. Returns the kid, the seed, the
-- PUBLIC key registered for that kid (NULL when none is) and whether it is revoked. A missing or malformed secret is 55000 (a deploy fault: the Edge answers a bare 503); no message names the secret. EXECUTE for nobody
-- but the owner: the wrappers below call it after partner_authorize, and it reads no binding itself.
CREATE FUNCTION private.course_qr_signing_key_read(p_purpose text)
RETURNS TABLE (o_kid text, o_seed text, o_public_key text, o_revoked boolean)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_raw text;
  v_kid text;
  v_seed text;
  v_pub text;
  v_rev timestamptz;
BEGIN
  IF p_purpose IS NULL OR p_purpose NOT IN ('rotating_token', 'printed_qr') THEN
    RAISE EXCEPTION 'course_qr_signing_key_read: a purpose (rotating_token | printed_qr) is required' USING ERRCODE = '22023';
  END IF;
  SELECT s.decrypted_secret INTO v_raw FROM vault.decrypted_secrets s WHERE s.name = 'course_qr_signing_key_' || p_purpose;
  IF v_raw IS NULL OR v_raw !~ '^[A-Za-z0-9_-]{1,64}:[A-Za-z0-9_-]{43}$' THEN
    RAISE EXCEPTION 'course_qr_signing_key_read: the course QR signing key is not provisioned in Vault' USING ERRCODE = '55000';
  END IF;
  v_kid := pg_catalog.split_part(v_raw, ':', 1);
  v_seed := pg_catalog.split_part(v_raw, ':', 2);
  SELECT k.public_key_b64url, k.revoked_at INTO v_pub, v_rev FROM app.course_qr_key k WHERE k.purpose = p_purpose AND k.kid = v_kid;
  RETURN QUERY SELECT v_kid, v_seed, v_pub, v_rev IS NOT NULL;
END;
$$;

-- 2b. Today's PIN (class A0). The date is the facility-local date of NOW and the epoch the one live NOW: exactly what course_pin_attempt_for_actor derives a PIN under for a scan made now with no qualifying fix
-- (v_date from p_at AT TIME ZONE tz, v_epoch from course_pin_epoch_at(facility, p_at)), through the same private.course_pin_derive, so the staff screen and the app cannot differ. Statuses (returned, nothing is written):
-- ok | no_facility | no_programme (no accepted, active, any_purchase programme row that allows the printed QR: the player lane would answer no_programme too, and there is no PIN to show).
CREATE FUNCTION private.course_pin_show_for_partner(p_facility_id text)
RETURNS TABLE (o_status text, o_pin text, o_local_date date, o_valid_until timestamptz, o_pin_epoch integer)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_tz text;
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_date date;
  v_epoch integer;
BEGIN
  v_uid := private.partner_authorize(p_facility_id, NULL, ARRAY['staff', 'manager']::app.partner_role[], 'A0');
  IF p_facility_id IS NULL OR pg_catalog.btrim(p_facility_id) = '' THEN
    RAISE EXCEPTION 'course_pin_show_for_partner: a facility is required' USING ERRCODE = '22023';
  END IF;
  SELECT f.tz INTO v_tz FROM app.catalog_facility f WHERE f.id = p_facility_id;
  IF v_tz IS NULL THEN
    RETURN QUERY SELECT 'no_facility'::text, NULL::text, NULL::date, NULL::timestamptz, NULL::integer;
    RETURN;
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM app.facility_programme fp JOIN app.trail_programme tp ON tp.trail_id = fp.trail_id
    WHERE fp.facility_id = p_facility_id AND fp.participation = 'accepted' AND tp.status IN ('pilot', 'live') AND tp.marker_source = 'any_purchase'
      AND fp.qr_mode IN ('static_pin', 'both')
  ) THEN
    RETURN QUERY SELECT 'no_programme'::text, NULL::text, NULL::date, NULL::timestamptz, NULL::integer;
    RETURN;
  END IF;
  v_date := (v_now AT TIME ZONE v_tz)::date;
  v_epoch := private.course_pin_epoch_at(p_facility_id, v_now);
  RETURN QUERY SELECT 'ok'::text, private.course_pin_derive(p_facility_id, v_date, v_epoch), v_date, ((v_date + 1)::timestamp AT TIME ZONE v_tz), v_epoch;
END;
$$;

-- 2c. "Rotate PIN" (class A2: a PIN verified in the last 30 s AND a passkey assertion in the last 5 minutes). It raises facility_programme.pin_epoch and writes NOTHING else: the 0046 trigger logs the new epoch in
-- app.course_pin_epoch_log (so a back-dated queued scan is still judged under the epoch that was live at its instant). Every programme row of the facility moves together. Statuses: ok | no_programme.
CREATE FUNCTION private.course_pin_rotate_for_partner(p_facility_id text)
RETURNS TABLE (o_status text, o_pin_epoch integer)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_n integer;
  v_epoch integer;
BEGIN
  v_uid := private.partner_authorize(p_facility_id, NULL, ARRAY['staff', 'manager', 'operator']::app.partner_role[], 'A2');
  IF p_facility_id IS NULL OR pg_catalog.btrim(p_facility_id) = '' THEN
    RAISE EXCEPTION 'course_pin_rotate_for_partner: a facility is required' USING ERRCODE = '22023';
  END IF;
  UPDATE app.facility_programme fp SET pin_epoch = fp.pin_epoch + 1 WHERE fp.facility_id = p_facility_id;
  GET DIAGNOSTICS v_n = ROW_COUNT;
  IF v_n = 0 THEN
    RETURN QUERY SELECT 'no_programme'::text, NULL::integer;
    RETURN;
  END IF;
  SELECT pg_catalog.max(fp.pin_epoch) INTO v_epoch FROM app.facility_programme fp WHERE fp.facility_id = p_facility_id;
  PERFORM private.partner_audit_write('partner.course_pin.rotate', 'app.facility_programme', p_facility_id, pg_catalog.jsonb_build_object('pin_epoch', v_epoch));
  RETURN QUERY SELECT 'ok'::text, v_epoch;
END;
$$;

-- 2d. "Marker sold" (class A1: it CONSUMES the single-use PIN grant in this transaction; a refused or failed call rolls the consumption back with everything else). The nonce hash is the Edge's: hex(SHA-256 of the 16 raw
-- nonce bytes), 64 lower-case hex characters. issued_at is TRUNCATED TO THE SECOND, so the row's issued_at IS the token's `iat` claim (the player lane judges the 120 s rule against the row, not the claim). The kid and
-- the signing key come from Vault; the PUBLIC key for that kid must be registered and not revoked (55000 otherwise: a token no player could verify is never minted). `no_programme` is a returned status (the handler
-- rolls the transaction back, so the PIN grant is not spent on a facility that cannot sell a marker): the facility has no accepted, active, any_purchase programme row that allows the rotating token.
CREATE FUNCTION private.course_qr_mint_for_partner(p_facility_id text, p_nonce_hash text)
RETURNS TABLE (o_status text, o_kid text, o_signing_key text, o_public_key text, o_issued_at bigint, o_expires_at bigint)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_k record;
  v_issued timestamptz;
BEGIN
  v_uid := private.partner_authorize(p_facility_id, NULL, ARRAY['staff', 'manager']::app.partner_role[], 'A1');
  IF p_facility_id IS NULL OR pg_catalog.btrim(p_facility_id) = '' THEN
    RAISE EXCEPTION 'course_qr_mint_for_partner: a facility is required' USING ERRCODE = '22023';
  END IF;
  IF p_nonce_hash IS NULL OR pg_catalog.length(p_nonce_hash) <> 64 OR p_nonce_hash ~ '[^0-9a-f]' THEN
    RAISE EXCEPTION 'course_qr_mint_for_partner: the nonce hash is 64 lower-case hex characters' USING ERRCODE = '22023';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM app.facility_programme fp JOIN app.trail_programme tp ON tp.trail_id = fp.trail_id
    WHERE fp.facility_id = p_facility_id AND fp.participation = 'accepted' AND tp.status IN ('pilot', 'live') AND tp.marker_source = 'any_purchase'
      AND fp.qr_mode IN ('rotating', 'both')
  ) THEN
    RETURN QUERY SELECT 'no_programme'::text, NULL::text, NULL::text, NULL::text, NULL::bigint, NULL::bigint;
    RETURN;
  END IF;
  SELECT k.o_kid, k.o_seed, k.o_public_key, k.o_revoked INTO v_k FROM private.course_qr_signing_key_read('rotating_token') k;
  IF v_k.o_public_key IS NULL OR v_k.o_revoked THEN
    RAISE EXCEPTION 'course_qr_mint_for_partner: no usable rotating-token key is registered' USING ERRCODE = '55000';
  END IF;
  v_issued := pg_catalog.date_trunc('second', pg_catalog.clock_timestamp());
  INSERT INTO app.course_qr_token (nonce_hash, facility_id, issued_by_staff, kid, issued_at, expires_at)
  VALUES (p_nonce_hash, p_facility_id, v_uid, v_k.o_kid, v_issued, v_issued + interval '120 seconds');
  RETURN QUERY SELECT 'ok'::text, v_k.o_kid, v_k.o_seed, v_k.o_public_key,
    pg_catalog.floor(pg_catalog.date_part('epoch', v_issued))::bigint, pg_catalog.floor(pg_catalog.date_part('epoch', v_issued + interval '120 seconds'))::bigint;
END;
$$;

-- 2e. The sale screen's heartbeat (class A0_KEEPALIVE: the idle bump of partner_authorize is skipped for it, PA-26). BOUND to a nonce hash that THIS person's own A1 mint created at THIS facility: anything else is
-- `unknown` (one answer for a nonce that does not exist, is another person's or another facility's: no oracle). It reads the row and returns live | used | expired with the whole seconds left of the 120 s;
-- it writes NOTHING and creates NO token, so it can create no authority. A session that is idle past its limit is refused by the seam (it cannot keep itself alive by calling this).
CREATE FUNCTION private.course_qr_refresh_for_partner(p_facility_id text, p_nonce_hash text)
RETURNS TABLE (o_state text, o_seconds_left integer)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_t record;
  v_left integer;
BEGIN
  v_uid := private.partner_authorize(p_facility_id, NULL, ARRAY['staff', 'manager']::app.partner_role[], 'A0_KEEPALIVE');
  IF p_facility_id IS NULL OR pg_catalog.btrim(p_facility_id) = '' THEN
    RAISE EXCEPTION 'course_qr_refresh_for_partner: a facility is required' USING ERRCODE = '22023';
  END IF;
  IF p_nonce_hash IS NULL OR pg_catalog.length(p_nonce_hash) <> 64 OR p_nonce_hash ~ '[^0-9a-f]' THEN
    RAISE EXCEPTION 'course_qr_refresh_for_partner: the nonce hash is 64 lower-case hex characters' USING ERRCODE = '22023';
  END IF;
  SELECT t.issued_at, t.used_at INTO v_t FROM app.course_qr_token t
  WHERE t.nonce_hash = p_nonce_hash AND t.facility_id = p_facility_id AND t.issued_by_staff = v_uid;
  IF NOT FOUND THEN
    RETURN QUERY SELECT 'unknown'::text, 0;
    RETURN;
  END IF;
  IF v_t.used_at IS NOT NULL THEN
    RETURN QUERY SELECT 'used'::text, 0;
    RETURN;
  END IF;
  v_left := pg_catalog.ceil(120 - pg_catalog.date_part('epoch', pg_catalog.clock_timestamp() - v_t.issued_at))::integer;
  IF v_left <= 0 THEN
    RETURN QUERY SELECT 'expired'::text, 0;
    RETURN;
  END IF;
  RETURN QUERY SELECT 'live'::text, LEAST(v_left, 120);
END;
$$;

-- 2f. qr-print, step 1 (class A3: aal 2 and a TOTP in the last 5 minutes; operator at the facility, or an admin). The printed-QR kid and signing key from Vault and the facility slug (for the link). Statuses:
-- ok | no_facility | key_revoked (the Vault key's public row is revoked: provision a new key). The key is released to this authorized A3 call only. The public key is NULL when no row is registered yet (step 2 ensures it).
CREATE FUNCTION private.course_qr_print_key_for_partner(p_facility_id text)
RETURNS TABLE (o_status text, o_kid text, o_signing_key text, o_public_key text, o_slug text)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_slug text;
  v_k record;
BEGIN
  v_uid := private.partner_authorize(p_facility_id, NULL, ARRAY['operator']::app.partner_role[], 'A3');
  IF p_facility_id IS NULL OR pg_catalog.btrim(p_facility_id) = '' THEN
    RAISE EXCEPTION 'course_qr_print_key_for_partner: a facility is required' USING ERRCODE = '22023';
  END IF;
  SELECT f.slug INTO v_slug FROM app.catalog_facility f WHERE f.id = p_facility_id;
  IF NOT FOUND THEN
    RETURN QUERY SELECT 'no_facility'::text, NULL::text, NULL::text, NULL::text, NULL::text;
    RETURN;
  END IF;
  SELECT k.o_kid, k.o_seed, k.o_public_key, k.o_revoked INTO v_k FROM private.course_qr_signing_key_read('printed_qr') k;
  IF v_k.o_revoked THEN
    RETURN QUERY SELECT 'key_revoked'::text, NULL::text, NULL::text, NULL::text, NULL::text;
    RETURN;
  END IF;
  RETURN QUERY SELECT 'ok'::text, v_k.o_kid, v_k.o_seed, v_k.o_public_key, v_slug;
END;
$$;

-- 2g. qr-print, step 2 (class A3): record what the Edge signed. The kid must be the Vault key's (kid_mismatch otherwise: a kid with no key behind it is never registered); the PUBLIC key row is inserted when absent and,
-- when present, must be EQUAL (key_mismatch) and not revoked (key_revoked); then app.facility_qr is written: a first registration inserts, a different kid or signature replaces (printed_at = now, revoked_at cleared:
-- "a reprint replaces its qr_kid, so an old kid is revoked"), the same kid and signature is a no-op (Ed25519 is deterministic: a re-print of an unchanged key changes nothing). The database CANNOT verify the signature
-- (no Ed25519 here); the Edge verified it under the registered public key before calling. Statuses: ok | no_facility | kid_mismatch | key_mismatch | key_revoked. o_changed is true when a row was written.
CREATE FUNCTION private.course_qr_print_write_for_partner(p_facility_id text, p_qr_kid text, p_sig text, p_public_key text)
RETURNS TABLE (o_status text, o_changed boolean)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_k record;
  v_q record;
  v_pub text;
  v_rev boolean;
BEGIN
  v_uid := private.partner_authorize(p_facility_id, NULL, ARRAY['operator']::app.partner_role[], 'A3');
  IF p_facility_id IS NULL OR pg_catalog.btrim(p_facility_id) = '' THEN
    RAISE EXCEPTION 'course_qr_print_write_for_partner: a facility is required' USING ERRCODE = '22023';
  END IF;
  IF p_qr_kid IS NULL OR pg_catalog.length(p_qr_kid) NOT BETWEEN 1 AND 64 OR p_qr_kid ~ '[^A-Za-z0-9_-]'
     OR p_sig IS NULL OR pg_catalog.length(p_sig) <> 86 OR p_sig ~ '[^A-Za-z0-9_-]'
     OR p_public_key IS NULL OR pg_catalog.length(p_public_key) <> 43 OR p_public_key ~ '[^A-Za-z0-9_-]' THEN
    RAISE EXCEPTION 'course_qr_print_write_for_partner: a kid (1 to 64), a signature (86) and a public key (43), all base64url, are required' USING ERRCODE = '22023';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM app.catalog_facility f WHERE f.id = p_facility_id) THEN
    RETURN QUERY SELECT 'no_facility'::text, false;
    RETURN;
  END IF;
  SELECT k.o_kid, k.o_seed, k.o_public_key, k.o_revoked INTO v_k FROM private.course_qr_signing_key_read('printed_qr') k;
  IF v_k.o_kid IS DISTINCT FROM p_qr_kid THEN
    RETURN QUERY SELECT 'kid_mismatch'::text, false;
    RETURN;
  END IF;
  IF v_k.o_revoked THEN
    RETURN QUERY SELECT 'key_revoked'::text, false;
    RETURN;
  END IF;
  v_pub := v_k.o_public_key;
  v_rev := v_k.o_revoked;
  IF v_pub IS NULL THEN
    INSERT INTO app.course_qr_key (purpose, kid, public_key_b64url) VALUES ('printed_qr', p_qr_kid, p_public_key) ON CONFLICT (purpose, kid) DO NOTHING;
    SELECT k.public_key_b64url, k.revoked_at IS NOT NULL INTO v_pub, v_rev FROM app.course_qr_key k WHERE k.purpose = 'printed_qr' AND k.kid = p_qr_kid;
  END IF;
  IF v_pub IS DISTINCT FROM p_public_key THEN
    RETURN QUERY SELECT 'key_mismatch'::text, false;
    RETURN;
  END IF;
  IF v_rev THEN
    RETURN QUERY SELECT 'key_revoked'::text, false;
    RETURN;
  END IF;
  SELECT q.qr_kid, q.sig, q.revoked_at INTO v_q FROM app.facility_qr q WHERE q.facility_id = p_facility_id;
  IF NOT FOUND THEN
    INSERT INTO app.facility_qr (facility_id, qr_kid, sig, printed_at) VALUES (p_facility_id, p_qr_kid, p_sig, pg_catalog.now());
  ELSIF v_q.qr_kid = p_qr_kid AND v_q.sig = p_sig AND v_q.revoked_at IS NULL THEN
    RETURN QUERY SELECT 'ok'::text, false;
    RETURN;
  ELSE
    UPDATE app.facility_qr q SET qr_kid = p_qr_kid, sig = p_sig, printed_at = pg_catalog.now(), revoked_at = NULL WHERE q.facility_id = p_facility_id;
  END IF;
  PERFORM private.partner_audit_write('partner.course_qr.print', 'app.facility_qr', p_facility_id, pg_catalog.jsonb_build_object('qr_kid', p_qr_kid));
  RETURN QUERY SELECT 'ok'::text, true;
END;
$$;

-- 2h. The registered printed QR of a facility (class A0; operator or admin). ok | no_facility | not_printed.
CREATE FUNCTION private.course_qr_print_read_for_partner(p_facility_id text)
RETURNS TABLE (o_status text, o_qr_kid text, o_sig text, o_printed_at timestamptz, o_revoked_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_q record;
BEGIN
  v_uid := private.partner_authorize(p_facility_id, NULL, ARRAY['operator']::app.partner_role[], 'A0');
  IF p_facility_id IS NULL OR pg_catalog.btrim(p_facility_id) = '' THEN
    RAISE EXCEPTION 'course_qr_print_read_for_partner: a facility is required' USING ERRCODE = '22023';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM app.catalog_facility f WHERE f.id = p_facility_id) THEN
    RETURN QUERY SELECT 'no_facility'::text, NULL::text, NULL::text, NULL::timestamptz, NULL::timestamptz;
    RETURN;
  END IF;
  SELECT q.qr_kid, q.sig, q.printed_at, q.revoked_at INTO v_q FROM app.facility_qr q WHERE q.facility_id = p_facility_id;
  IF NOT FOUND THEN
    RETURN QUERY SELECT 'not_printed'::text, NULL::text, NULL::text, NULL::timestamptz, NULL::timestamptz;
    RETURN;
  END IF;
  RETURN QUERY SELECT 'ok'::text, v_q.qr_kid, v_q.sig, v_q.printed_at, v_q.revoked_at;
END;
$$;

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

-- ============================================================================
-- 3. EXECUTE grants (PUBLIC revoked first: a function created by a role other than the migrating role defaults to PUBLIC EXECUTE). The seven lane functions: edge_partner and nobody else (check 14 (d), (e)).
-- The key reader: nobody but its owner.
-- ============================================================================
SET ROLE private_definer;
REVOKE EXECUTE ON FUNCTION
  private.course_qr_signing_key_read(text),
  private.course_pin_show_for_partner(text),
  private.course_pin_rotate_for_partner(text),
  private.course_qr_mint_for_partner(text, text),
  private.course_qr_refresh_for_partner(text, text),
  private.course_qr_print_key_for_partner(text),
  private.course_qr_print_write_for_partner(text, text, text, text),
  private.course_qr_print_read_for_partner(text)
FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.course_pin_show_for_partner(text) TO edge_partner;
GRANT EXECUTE ON FUNCTION private.course_pin_rotate_for_partner(text) TO edge_partner;
GRANT EXECUTE ON FUNCTION private.course_qr_mint_for_partner(text, text) TO edge_partner;
GRANT EXECUTE ON FUNCTION private.course_qr_refresh_for_partner(text, text) TO edge_partner;
GRANT EXECUTE ON FUNCTION private.course_qr_print_key_for_partner(text) TO edge_partner;
GRANT EXECUTE ON FUNCTION private.course_qr_print_write_for_partner(text, text, text, text) TO edge_partner;
GRANT EXECUTE ON FUNCTION private.course_qr_print_read_for_partner(text) TO edge_partner;
COMMENT ON FUNCTION private.course_qr_signing_key_read(text) IS
  '0055 (S2b). The ONLY reader of the Vault secrets course_qr_signing_key_rotating_token and course_qr_signing_key_printed_qr (<kid>:<32-byte Ed25519 seed, base64url>), and of the public key row registered for that kid. EXECUTE for nobody but its owner: only the A1 mint and the A3 qr-print definers reach it, after partner_authorize. A missing or malformed secret is 55000.';
COMMENT ON FUNCTION private.course_qr_mint_for_partner(text, text) IS
  '0055 (S2b). Class A1: consumes the single-use PIN grant, INSERTs the app.course_qr_token row (issued_at truncated to the second = the token''s iat, expires_at = issued_at + 120 s) and returns the kid, the signing key and the public key the Edge signs and self-verifies with. no_programme is a returned status the handler rolls back.';
COMMENT ON FUNCTION private.course_qr_refresh_for_partner(text, text) IS
  '0055 (S2b, PA-26). Class A0_KEEPALIVE: reads the state of a token THIS person''s own A1 mint created (live | used | expired | unknown); creates nothing and never advances last_seen_at.';
RESET ROLE;

-- ============================================================================
-- 4. Registries
-- ============================================================================
-- 4a. private.function_inventory: the eight functions. expected_edge_partner is true for the seven lane functions, and for nothing else.
INSERT INTO private.function_inventory
  (schema_name, function_name, identity_args, expected_anon, expected_authenticated, expected_service_role, expected_edge_actor, expected_edge_system, expected_edge_partner, expected_edge_partner_minter, note)
VALUES
  ('private', 'course_qr_signing_key_read', 'p_purpose text', false, false, false, false, false, false, false, '0055 (S2b): the ONLY reader of the Vault secrets course_qr_signing_key_<purpose> (<kid>:<seed>) and of the registered public key row; EXECUTE for nobody but its owner (the A1 mint and the A3 qr-print definers call it after partner_authorize); 55000 when the secret is missing or malformed'),
  ('private', 'course_pin_show_for_partner', 'p_facility_id text', false, false, false, false, false, true, false, '0055 (S2b): edge_partner only; today''s PIN, class A0 (staff or manager at THE facility): private.course_pin_derive for the facility-local date and the epoch live now, the same arguments the player lane judges a scan made now under; ok | no_facility | no_programme'),
  ('private', 'course_pin_rotate_for_partner', 'p_facility_id text', false, false, false, false, false, true, false, '0055 (S2b): edge_partner only; Rotate PIN, class A2: UPDATE facility_programme SET pin_epoch = pin_epoch + 1 and nothing else (the 0046 trigger writes the epoch log); audit_log row; ok | no_programme'),
  ('private', 'course_qr_mint_for_partner', 'p_facility_id text, p_nonce_hash text', false, false, false, false, false, true, false, '0055 (S2b): edge_partner only; Marker sold, class A1 (consumes the single-use PIN grant): INSERTs the app.course_qr_token row (issued_at = the token iat, expires_at = +120 s) and returns the kid, the Vault signing key and the public key for the Edge to sign and self-verify; ok | no_programme; 55000 without a registered rotating-token key'),
  ('private', 'course_qr_refresh_for_partner', 'p_facility_id text, p_nonce_hash text', false, false, false, false, false, true, false, '0055 (S2b, PA-26): edge_partner only; the sale screen heartbeat, class A0_KEEPALIVE: reads the state of a token this person''s own mint created (live | used | expired | unknown); writes nothing, creates no authority, never advances last_seen_at'),
  ('private', 'course_qr_print_key_for_partner', 'p_facility_id text', false, false, false, false, false, true, false, '0055 (S2b): edge_partner only; qr-print step 1, class A3 (operator at the facility, or admin): the printed-QR kid and Vault signing key and the facility slug; ok | no_facility | key_revoked'),
  ('private', 'course_qr_print_write_for_partner', 'p_facility_id text, p_qr_kid text, p_sig text, p_public_key text', false, false, false, false, false, true, false, '0055 (S2b): edge_partner only; qr-print step 2, class A3: ensures the public key row in app.course_qr_key (an existing row must be equal) and writes app.facility_qr (a reprint replaces the kid); ok | no_facility | kid_mismatch | key_mismatch | key_revoked; audit_log row'),
  ('private', 'course_qr_print_read_for_partner', 'p_facility_id text', false, false, false, false, false, true, false, '0055 (S2b): edge_partner only; the registered printed QR of a facility, class A0 (operator or admin): ok | no_facility | not_printed');

-- 4b. private.definer_policy_allowlist: the ten policies, their expressions derived from the live policies (checks 5 / 6 compare the two; supabase/tests/fixtures/definer_policy_exprs.txt is the checked-in third copy)
GRANT INSERT, UPDATE ON private.definer_policy_allowlist TO CURRENT_USER;
CREATE POLICY current_user_seed_definer_policy_allowlist_0055 ON private.definer_policy_allowlist
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
INSERT INTO private.definer_policy_allowlist (schema_name, table_name, policy_name, command, scoped, note, role_name) VALUES
  ('app', 'course_qr_key', 'pd_course_qr_staff_key_read', 'SELECT', true, 'S2b: the PUBLIC key rows (and whether a kid is revoked) the A1 mint and the A3 qr-print definers read; keyed on the partner binding kind, never a GUC', 'private_definer'),
  ('app', 'course_qr_key', 'pd_course_qr_staff_key_insert', 'INSERT', true, 'S2b: qr-print registers the PUBLIC key of the printed-QR signing key, only purpose printed_qr, only unrevoked, only under a partner binding (the definer is A3 and the key must equal the Vault kid''s)', 'private_definer'),
  ('app', 'catalog_facility', 'pd_course_qr_staff_facility_read', 'SELECT', true, 'S2b: the facility timezone (today''s PIN date) and slug (the print link): public catalog data, readable under a partner binding', 'private_definer'),
  ('app', 'trail_programme', 'pd_course_qr_staff_trail_programme_read', 'SELECT', true, 'S2b: whether a trail runs an active any_purchase programme (SELECT(trail_id, status, marker_source) only), for the PIN display and the mint', 'private_definer'),
  ('app', 'facility_programme', 'pd_course_qr_staff_programme_epoch', 'UPDATE', true, 'S2b Rotate PIN: UPDATE(pin_epoch) only (the 0046 column grant), on the rows of a facility the bound person is staff, manager or operator at (has_facility_scope, keyed on the binding)', 'private_definer'),
  ('app', 'course_qr_token', 'pd_course_qr_staff_token_insert', 'INSERT', true, 'S2b Marker sold: a fresh unused token row issued BY THE BOUND PERSON for a facility they are staff or manager at, expiring exactly 120 s after issue', 'private_definer'),
  ('app', 'course_qr_token', 'pd_course_qr_staff_token_read', 'SELECT', true, 'S2b refresh: the bound person''s OWN token rows only', 'private_definer'),
  ('app', 'facility_qr', 'pd_course_qr_staff_facility_qr_read', 'SELECT', true, 'S2b qr-print read: the printed QR of a facility the bound person is an operator at (or admin)', 'private_definer'),
  ('app', 'facility_qr', 'pd_course_qr_staff_facility_qr_insert', 'INSERT', true, 'S2b qr-print: the first registration of a facility''s printed QR, unrevoked, for an operator (or admin) at the facility', 'private_definer'),
  ('app', 'facility_qr', 'pd_course_qr_staff_facility_qr_update', 'UPDATE', true, 'S2b qr-print: a reprint replaces qr_kid / sig / printed_at and clears revoked_at, for an operator (or admin) at the facility', 'private_definer');
UPDATE private.definer_policy_allowlist al
SET using_expr = pg_get_expr(pol.polqual, pol.polrelid),
    with_check_expr = pg_get_expr(pol.polwithcheck, pol.polrelid)
FROM pg_policy pol
JOIN pg_class cl ON cl.oid = pol.polrelid
JOIN pg_namespace n ON n.oid = cl.relnamespace
WHERE n.nspname = al.schema_name AND cl.relname = al.table_name AND pol.polname = al.policy_name
  AND pol.polname IN ('pd_course_qr_staff_key_read', 'pd_course_qr_staff_key_insert', 'pd_course_qr_staff_facility_read', 'pd_course_qr_staff_trail_programme_read', 'pd_course_qr_staff_programme_epoch',
                      'pd_course_qr_staff_token_insert', 'pd_course_qr_staff_token_read', 'pd_course_qr_staff_facility_qr_read', 'pd_course_qr_staff_facility_qr_insert', 'pd_course_qr_staff_facility_qr_update');
DO $assert_0055_allowlist$
BEGIN
  IF (SELECT count(*) FROM private.definer_policy_allowlist WHERE policy_name LIKE 'pd\_course\_qr\_staff\_%' AND (using_expr IS NOT NULL OR with_check_expr IS NOT NULL)) <> 10 THEN
    RAISE EXCEPTION '0055: an allowlist row names no live policy (its expressions were not derived)';
  END IF;
END
$assert_0055_allowlist$;
DROP POLICY current_user_seed_definer_policy_allowlist_0055 ON private.definer_policy_allowlist;
REVOKE INSERT, UPDATE ON private.definer_policy_allowlist FROM CURRENT_USER;

-- ============================================================================
-- 5. Prove it (a refused or misapplied GRANT only warns, so the migration fails HERE rather than on the first request)
-- ============================================================================
DO $assert_0055_grants$
DECLARE
  v_role text;
  v_fn regprocedure;
  v_lane regprocedure[] := ARRAY[
    'private.course_pin_show_for_partner(text)'::regprocedure,
    'private.course_pin_rotate_for_partner(text)'::regprocedure,
    'private.course_qr_mint_for_partner(text, text)'::regprocedure,
    'private.course_qr_refresh_for_partner(text, text)'::regprocedure,
    'private.course_qr_print_key_for_partner(text)'::regprocedure,
    'private.course_qr_print_write_for_partner(text, text, text, text)'::regprocedure,
    'private.course_qr_print_read_for_partner(text)'::regprocedure];
  v_key regprocedure := 'private.course_qr_signing_key_read(text)'::regprocedure;
BEGIN
  IF EXISTS (SELECT 1 FROM unnest(v_lane || v_key) f(oid) JOIN pg_proc p ON p.oid = f.oid WHERE NOT p.prosecdef OR p.proconfig IS DISTINCT FROM ARRAY['search_path=""'] OR p.proowner <> 'private_definer'::regrole) THEN
    RAISE EXCEPTION '0055: a new function is not SECURITY DEFINER with search_path='''' owned by private_definer';
  END IF;
  -- check 14 (a0): no dollar sign, double quote or backslash in a *_for_partner body (the first-statement reader cannot lex them)
  IF EXISTS (SELECT 1 FROM unnest(v_lane) f(oid) JOIN pg_proc p ON p.oid = f.oid WHERE strpos(p.prosrc, chr(36)) > 0 OR strpos(p.prosrc, chr(34)) > 0 OR strpos(p.prosrc, chr(92)) > 0) THEN
    RAISE EXCEPTION '0055: a *_for_partner body contains a dollar sign, a double quote or a backslash';
  END IF;
  FOREACH v_fn IN ARRAY v_lane LOOP
    FOREACH v_role IN ARRAY ARRAY['edge_system', 'edge_actor', 'edge_partner_minter', 'edge_gateway', 'service_role', 'anon', 'authenticated'] LOOP
      IF has_function_privilege(v_role, v_fn, 'EXECUTE') THEN
        RAISE EXCEPTION '0055: % can execute %; only edge_partner may', v_role, v_fn;
      END IF;
    END LOOP;
    IF NOT has_function_privilege('edge_partner', v_fn, 'EXECUTE') THEN
      RAISE EXCEPTION '0055: edge_partner cannot execute %', v_fn;
    END IF;
  END LOOP;
  FOREACH v_role IN ARRAY ARRAY['edge_system', 'edge_actor', 'edge_partner', 'edge_partner_minter', 'edge_gateway', 'service_role', 'anon', 'authenticated', 'partner_pin_verifier', 'partner_session_issuer', 'partner_session_toucher'] LOOP
    IF has_function_privilege(v_role, v_key, 'EXECUTE') THEN
      RAISE EXCEPTION '0055: % can execute the Vault signing-key reader', v_role;
    END IF;
  END LOOP;
  -- the private key is in no table: the key rows hold the PUBLIC key only, and no edge role holds anything on the three tables
  FOREACH v_role IN ARRAY ARRAY['edge_partner', 'edge_partner_minter', 'edge_actor', 'edge_system', 'edge_gateway', 'anon', 'authenticated'] LOOP
    IF has_any_column_privilege(v_role, 'app.course_qr_key', 'SELECT,INSERT,UPDATE,REFERENCES') OR has_any_column_privilege(v_role, 'app.course_qr_token', 'SELECT,INSERT,UPDATE,REFERENCES')
       OR has_any_column_privilege(v_role, 'app.facility_qr', 'SELECT,INSERT,UPDATE,REFERENCES') OR has_table_privilege(v_role, 'app.course_qr_token', 'DELETE') THEN
      RAISE EXCEPTION '0055: % holds a privilege on app.course_qr_key / course_qr_token / facility_qr', v_role;
    END IF;
  END LOOP;
  -- private_definer: INSERT on the token only the issue columns (never used_by_user / used_at); UPDATE on facility_qr only the four reprint columns; INSERT on the key only (purpose, kid, public key)
  IF has_column_privilege('private_definer', 'app.course_qr_token', 'used_by_user', 'INSERT') OR has_column_privilege('private_definer', 'app.course_qr_token', 'used_at', 'INSERT')
     OR NOT has_column_privilege('private_definer', 'app.course_qr_token', 'issued_by_staff', 'INSERT') OR NOT has_column_privilege('private_definer', 'app.course_qr_token', 'nonce_hash', 'INSERT')
     OR has_column_privilege('private_definer', 'app.course_qr_token', 'issued_by_staff', 'UPDATE') OR has_column_privilege('private_definer', 'app.course_qr_token', 'kid', 'UPDATE')
     OR has_column_privilege('private_definer', 'app.facility_qr', 'facility_id', 'UPDATE') OR NOT has_column_privilege('private_definer', 'app.facility_qr', 'qr_kid', 'UPDATE')
     OR has_column_privilege('private_definer', 'app.course_qr_key', 'revoked_at', 'INSERT') OR has_column_privilege('private_definer', 'app.course_qr_key', 'public_key_b64url', 'UPDATE')
     OR NOT has_column_privilege('private_definer', 'app.course_qr_key', 'public_key_b64url', 'INSERT') OR NOT has_column_privilege('private_definer', 'app.catalog_facility', 'slug', 'SELECT') THEN
    RAISE EXCEPTION '0055: a column privilege of private_definer on the course QR tables is not where it must be';
  END IF;
  -- the ten policies exist, TO private_definer alone, and none reads a settable GUC
  IF (SELECT count(*) FROM pg_policy pol WHERE pol.polname LIKE 'pd\_course\_qr\_staff\_%' AND pol.polroles = ARRAY['private_definer'::regrole::oid]
        AND coalesce(pg_get_expr(pol.polqual, pol.polrelid), '') !~* 'current_setting|pg_settings' AND coalesce(pg_get_expr(pol.polwithcheck, pol.polrelid), '') !~* 'current_setting|pg_settings'
        AND coalesce(pg_get_expr(pol.polqual, pol.polrelid), pg_get_expr(pol.polwithcheck, pol.polrelid)) LIKE '%partner_binding_kind%') <> 10 THEN
    RAISE EXCEPTION '0055: the ten pd_course_qr_staff_* policies are not all TO private_definer, GUC-free and keyed on the partner binding';
  END IF;
  -- partner_authorize is still executable by nobody, and the three tables keep FORCE ROW LEVEL SECURITY
  FOREACH v_role IN ARRAY ARRAY['edge_partner', 'edge_actor', 'edge_system', 'edge_partner_minter', 'edge_gateway', 'service_role', 'anon', 'authenticated'] LOOP
    IF has_function_privilege(v_role, 'private.partner_authorize(text, text, app.partner_role[], text)'::regprocedure, 'EXECUTE') THEN
      RAISE EXCEPTION '0055: % can execute partner_authorize', v_role;
    END IF;
  END LOOP;
  IF (SELECT count(*) FROM pg_class c WHERE c.oid IN ('app.course_qr_key'::regclass, 'app.course_qr_token'::regclass, 'app.facility_qr'::regclass) AND c.relrowsecurity AND c.relforcerowsecurity) <> 3 THEN
    RAISE EXCEPTION '0055: a course QR table lost FORCE ROW LEVEL SECURITY';
  END IF;
END
$assert_0055_grants$;
