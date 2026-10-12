-- 0108_partner_totp_hard_lock.sql
--
-- P5 §116: a CEILING on consecutive partner (staff) TOTP failures. Until now partner_totp_attempt reset its failure count to 0 at every lock, so a person holding a valid aal 1 session
-- (a coworker at a shared iPad whose passkey session is open) could guess step-up codes for ever: 5 guesses per 15 minutes is 20 an hour and 480 a day, with no consecutive-failure
-- ceiling and no Edge-side limit on step-up/totp. Each guess is checked against three codes (the +/-1 step window), about 3 chances in 10^6, so roughly 0.14% a day and 40% a year
-- against one targeted person; a success gives aal 2 and mfa_until (class A3), which also stands in for the PIN of a PIN-less operator or admin. The PIN already had the ceiling
-- (20 failures in a day lock it, 0052); the TOTP did not.
--
-- WHAT THIS CHANGES
--   1. app.partner_totp gains consecutive_failed (a count that only a SUCCESS or an admin reset clears; it survives the 15-minute locks, which only clear failed_count) and
--      hard_locked_at (set by the 20th consecutive failure; a CHECK ties the two). No grant changes: partner_totp_verifier already holds table-level SELECT / INSERT / UPDATE on the
--      table and is its only writer; nobody else gains anything on the new columns.
--   2. partner_totp_attempt (CREATE OR REPLACE, same owner / ACL / search_path / volatility): a hard-locked row is refused FIRST, before any code is compared; the 5th, 10th and
--      15th consecutive failures lock for 15 minutes exactly as before; the 20th sets the hard lock (and the same 15-minute lock) and returns the internal status hard_lock_set.
--      A success clears consecutive_failed. The ±1 window, the replay rule, the HMAC compare, the compare-and-set on last_step and the FOR UPDATE row lock are untouched.
--   3. partner_totp_reset_apply (the admin reset, reused as it is: no new reset route) and partner_totp_enrol_apply (re-enrol of an unconfirmed row) clear both new columns;
--      partner_totp_confirm_apply clears them on a successful confirm. Confirm FAILURES are not counted toward the hard lock: a confirm code is checked against a seed that only
--      the enrolling session was shown, so guessing it gains nothing, and a typo during enrolment must not need an admin.
--   4. partner_totp_verify_for_partner (CREATE OR REPLACE): the attempt that SETS the hard lock writes ONE audit row (partner.totp.hard_locked) and raises ONE operator alarm
--      (partner_auth_alarm kind totp_hard_locked); it and every later attempt answer hard_locked. A refused attempt on a hard-locked row writes no audit row and no alarm.
--   5. app.partner_auth_alarm: kind totp_hard_locked (kind CHECK, row CHECK, partner-bound INSERT + SELECT policies for private_definer, the allow-list rows).
--
-- THE SELF-CHECK (the 0051 shape). Each CREATE OR REPLACE below is bracketed by the catalogue: the live source of every redefined function is captured first and the intended edits
-- (listed once, as old-fragment / new-fragment pairs, each of which must occur EXACTLY ONCE in the live source) are applied to it to give the expected new source; after the
-- redefinition the migration asserts that the live source IS that expected source and that owner, ACL, search_path, SECURITY DEFINER, volatility, return shape and comment are
-- byte-for-byte what they were. If a function drifted from 0053 / 0104 (another migration redefined it first) the migration aborts instead of silently reverting that change; if the
-- body written here differs from the listed edits, or an attribute moved, it aborts. The two alarm CHECKs get the same treatment, because they are dropped and recreated with a
-- full list of kinds and a concurrent migration that adds a kind must not be undone.
--
-- DELIBERATELY NOT HERE: a new reset route (the §86 / §95 admin reset is the only way out); session revocation on the hard lock (an aal 1 operator session can reach nothing but
-- step-up, which is exactly what is refused); counting confirm failures; an Edge-side rate limit on step-up/totp; Q7 email. Nothing from 0001-0107 is edited.

-- ============================================================================
-- 1. app.partner_totp: the consecutive-failure counter and the hard lock
-- ============================================================================
ALTER TABLE app.partner_totp
  ADD COLUMN consecutive_failed integer NOT NULL DEFAULT 0,
  ADD COLUMN hard_locked_at timestamptz,
  ADD CONSTRAINT partner_totp_consecutive_failed_check CHECK (consecutive_failed BETWEEN 0 AND 20),
  ADD CONSTRAINT partner_totp_hard_lock_iff_twenty CHECK ((hard_locked_at IS NOT NULL) = (consecutive_failed = 20));

COMMENT ON COLUMN app.partner_totp.consecutive_failed IS
  '0108 (§116). Wrong step-up codes in a row. Only a successful verify or confirm, an admin TOTP reset or a re-enrol clears it: the 15-minute lock (failed_count) does not, which is the point. The 20th sets hard_locked_at. CHECK 0..20.';
COMMENT ON COLUMN app.partner_totp.hard_locked_at IS
  '0108 (§116). Set by the 20th consecutive failure and cleared by nothing but an admin TOTP reset (partner_totp_reset_apply) or a re-enrol. While set, partner_totp_attempt refuses every code before comparing it; time does not clear it. NOT NULL exactly when consecutive_failed = 20.';
COMMENT ON TABLE app.partner_totp IS
  '0053/0108 (design 5.1, 6.4, §116). One row per person: seed_version (the seed is DERIVED from Vault partner_totp_key, never stored), enrolment / confirm state, HOTP replay (last_step), the 15-minute lockout (failed_count, locked_until) and the hard cap (consecutive_failed, hard_locked_at: 20 in a row, cleared only by an admin reset). FORCE RLS; no client, edge or service_role privilege. Written only by definers owned by partner_totp_verifier; delete_my_data''s window pair is the only other path.';

-- ============================================================================
-- 2. app.partner_auth_alarm: kind totp_hard_locked (the 0104 / 0107 shape), with the CHECKs proved against what is live
-- ============================================================================
CREATE TEMP TABLE r108_con (
  conname text PRIMARY KEY,
  old_def text NOT NULL,
  exp_def text
);
CREATE FUNCTION pg_temp.r108_edit(p_src text, p_old text, p_new text) RETURNS text LANGUAGE plpgsql AS $f$
BEGIN
  IF p_src IS NULL OR p_old IS NULL OR p_new IS NULL OR p_old = '' OR p_old = p_new
     OR (length(p_src) - length(replace(p_src, p_old, ''))) <> length(p_old) THEN
    RAISE EXCEPTION '0108: the live definition does not contain the expected fragment exactly once (it drifted from 0053 / 0104 / 0107): %', left(p_old, 70);
  END IF;
  RETURN replace(p_src, p_old, p_new);
END
$f$;
INSERT INTO r108_con (conname, old_def)
SELECT c.conname, pg_get_constraintdef(c.oid)
FROM pg_constraint c
WHERE c.conrelid = 'app.partner_auth_alarm'::regclass AND c.conname IN ('partner_auth_alarm_kind_check', 'partner_auth_alarm_bucket_shape_check');
UPDATE r108_con SET exp_def = pg_temp.r108_edit(old_def, $ok$'totp_enrol'::text])))$ok$, $nk$'totp_enrol'::text, 'totp_hard_locked'::text])))$nk$)
WHERE conname = 'partner_auth_alarm_kind_check';
UPDATE r108_con SET exp_def = pg_temp.r108_edit(old_def, $os$'totp_enrol'::text])) AND (credential_id IS NULL)$os$, $ns$'totp_enrol'::text, 'totp_hard_locked'::text])) AND (credential_id IS NULL)$ns$)
WHERE conname = 'partner_auth_alarm_bucket_shape_check';
DO $r108_con_pre$
BEGIN
  IF (SELECT count(*) FROM r108_con WHERE exp_def IS NOT NULL) <> 2 THEN
    RAISE EXCEPTION '0108: expected to capture both partner_auth_alarm CHECKs';
  END IF;
END
$r108_con_pre$;

ALTER TABLE app.partner_auth_alarm
  DROP CONSTRAINT partner_auth_alarm_kind_check;

ALTER TABLE app.partner_auth_alarm
  ADD CONSTRAINT partner_auth_alarm_kind_check CHECK (kind IN (
    'signature_invalid',
    'counter_regression',
    'rate_options_ip',
    'rate_options_global',
    'rate_verify_ip',
    'rate_member',
    'credential_add',
    'totp_reset',
    'pin_locked',
    'pin_reset',
    'member_recover',
    'org_revoke_all',
    'member_revoke',
    'credential_revoke',
    'invite_revoke',
    'enrolment_issue',
    'invite_create',
    'invite_accept',
    'enrolment_accept',
    'totp_locked',
    'credential_register',
    'pin_set',
    'totp_enrol',
    'totp_hard_locked'
  ));

ALTER TABLE app.partner_auth_alarm
  DROP CONSTRAINT partner_auth_alarm_bucket_shape_check;

ALTER TABLE app.partner_auth_alarm
  ADD CONSTRAINT partner_auth_alarm_bucket_shape_check CHECK (
    (
      kind IN ('signature_invalid', 'counter_regression', 'credential_add', 'credential_revoke', 'credential_register')
      AND credential_id IS NOT NULL
      AND bucket_key = credential_id::text
    )
    OR (
      kind IN ('rate_options_ip', 'rate_options_global', 'rate_verify_ip')
      AND credential_id IS NULL
      AND length(bucket_key) BETWEEN 1 AND 128
    )
    OR (
      kind IN ('rate_member', 'totp_reset', 'pin_locked', 'pin_reset', 'member_recover', 'org_revoke_all', 'member_revoke', 'invite_revoke', 'enrolment_issue', 'invite_create', 'invite_accept', 'enrolment_accept', 'totp_locked', 'pin_set', 'totp_enrol', 'totp_hard_locked')
      AND credential_id IS NULL
      AND bucket_key ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    )
  );

DO $r108_con_post$
DECLARE
  r record;
  v_def text;
BEGIN
  FOR r IN SELECT * FROM r108_con LOOP
    SELECT pg_get_constraintdef(c.oid) INTO v_def
    FROM pg_constraint c WHERE c.conrelid = 'app.partner_auth_alarm'::regclass AND c.conname = r.conname;
    IF v_def IS DISTINCT FROM r.exp_def THEN
      RAISE EXCEPTION '0108: % is not the previous definition plus totp_hard_locked (a kind was added or removed meanwhile?)', r.conname;
    END IF;
  END LOOP;
END
$r108_con_post$;
DROP TABLE r108_con;

COMMENT ON COLUMN app.partner_auth_alarm.bucket_key IS
  '0081/0083/0091/0092/0093/0094/0095/0096/0097/0098/0099/0100/0101/0102/0103/0104/0105/0106/0107/0108. Arbiter key with (kind, minute_bucket): mint/credential_add/credential_revoke/credential_register = credential_id::text; IP/global rate = 64-hex IP hash or global; rate_member / totp_reset / pin_locked / pin_reset / member_recover / member_revoke / enrolment_issue / totp_locked / pin_set / totp_enrol / totp_hard_locked = subject uid; org_revoke_all = org id; invite_revoke / invite_create / invite_accept = invite id; enrolment_accept = enrolment token id. Never a raw IP.';

COMMENT ON TABLE app.partner_auth_alarm IS
  '0048/0074/0075/0081/0083/0091/0092/0093/0094/0095/0096/0097/0098/0099/0100/0101/0102/0103/0104/0105/0106/0107/0108. Mint refusals, alert-only rate buckets, member any-call soft-cap (rate_member), credential-add (credential_add), TOTP-reset (totp_reset), PIN-lock (pin_locked), PIN-reset (pin_reset), member-recover (member_recover), org revoke-all (org_revoke_all), member-revoke (member_revoke), credential-revoke (credential_revoke), invite-revoke (invite_revoke), admin enrolment-issue (enrolment_issue), invite-create (invite_create), invite-accept (invite_accept), enrolment-accept (enrolment_accept), TOTP-lock (totp_locked), first-credential register (credential_register), PIN-set (pin_set), TOTP-enrol (totp_enrol), and the TOTP hard lock after 20 consecutive failures (totp_hard_locked: an admin reset is needed). UNIQUE (kind, bucket_key, minute_bucket). Operator-facing via partner_auth_alarm_list_for_partner. Retention: purge_partner_auth_alarms (90 days).';

CREATE POLICY pd_partner_totp_hard_locked_alarm_insert ON app.partner_auth_alarm FOR INSERT TO private_definer
  WITH CHECK (
    (SELECT private.partner_binding_kind()) = 'partner'
    AND kind = 'totp_hard_locked'
    AND credential_id IS NULL
    AND bucket_key ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
  );

CREATE POLICY pd_partner_totp_hard_locked_alarm_select ON app.partner_auth_alarm FOR SELECT TO private_definer
  USING (
    (SELECT private.partner_binding_kind()) = 'partner'
    AND kind = 'totp_hard_locked'
    AND credential_id IS NULL
    AND bucket_key ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
  );

-- ============================================================================
-- 3. The self-check, first half: what the five functions are NOW, and what they must be after the intended edits (and nothing else)
-- ============================================================================
CREATE TEMP TABLE r108_fn (
  fn text PRIMARY KEY,
  fn_oid oid NOT NULL,
  attr text NOT NULL,
  cmt text,
  old_src text NOT NULL,
  exp_src text
);
INSERT INTO r108_fn (fn, fn_oid, attr, cmt, old_src)
SELECT p.proname, p.oid,
       md5(ROW(pg_get_userbyid(p.proowner), p.proacl, p.proconfig, p.prosecdef, p.prolang, p.prorettype, p.proretset, pg_get_function_result(p.oid), pg_get_function_arguments(p.oid),
               p.provolatile, p.proparallel, p.proisstrict, p.proleakproof, p.pronargdefaults, p.prokind, p.procost, p.prorows, p.proargmodes, p.proargnames)::text),
       obj_description(p.oid, 'pg_proc'), p.prosrc
FROM pg_proc p
WHERE p.oid = ANY (ARRAY[
  'private.partner_totp_attempt(uuid, text)'::regprocedure,
  'private.partner_totp_enrol_apply()'::regprocedure,
  'private.partner_totp_confirm_apply(text)'::regprocedure,
  'private.partner_totp_reset_apply(uuid)'::regprocedure,
  'private.partner_totp_verify_for_partner(text)'::regprocedure]);

-- The intended edits: each old fragment must occur exactly once in the live source (pg_temp.r108_edit raises otherwise, BEFORE anything is redefined).
UPDATE r108_fn SET exp_src = pg_temp.r108_edit(pg_temp.r108_edit(pg_temp.r108_edit(pg_temp.r108_edit(pg_temp.r108_edit(pg_temp.r108_edit(old_src,
    $oa1$  v_fc integer;
BEGIN
$oa1$,
    $na1$  v_fc integer;
  v_cc integer;
BEGIN
$na1$),
    $oa2$  SELECT t.seed_version, t.confirmed_at, t.last_step, t.failed_count, t.locked_until, t.revoked_at INTO v_t
  FROM app.partner_totp t WHERE t.user_id = p_uid FOR UPDATE;
$oa2$,
    $na2$  SELECT t.seed_version, t.confirmed_at, t.last_step, t.failed_count, t.locked_until, t.revoked_at, t.consecutive_failed, t.hard_locked_at INTO v_t
  FROM app.partner_totp t WHERE t.user_id = p_uid FOR UPDATE;
$na2$),
    $oa3$  IF v_t.locked_until IS NOT NULL AND v_t.locked_until > v_now THEN
    RETURN QUERY SELECT 'locked'::text, pg_catalog.ceil($oa3$,
    $na3$  IF v_t.hard_locked_at IS NOT NULL THEN
    -- 0108: the HARD lock (20 consecutive failures). Refused before anything is compared, whatever the code and however long ago it was set: time never clears it, only an admin's TOTP
    -- reset does (partner_totp_reset_apply). Nothing is counted or changed here, and the caller writes no audit row and raises no alarm for it: the attempt that SET the lock
    -- (hard_lock_set, below) is the one event that is recorded.
    RETURN QUERY SELECT 'hard_locked'::text, 0;
    RETURN;
  END IF;
  IF v_t.locked_until IS NOT NULL AND v_t.locked_until > v_now THEN
    RETURN QUERY SELECT 'locked'::text, pg_catalog.ceil($na3$),
    $oa4$      SET last_step = v_cand, failed_count = 0, locked_until = NULL
      WHERE t.user_id = p_uid AND (t.last_step IS NULL OR t.last_step < v_cand);$oa4$,
    $na4$      SET last_step = v_cand, failed_count = 0, locked_until = NULL, consecutive_failed = 0
      WHERE t.user_id = p_uid AND (t.last_step IS NULL OR t.last_step < v_cand);$na4$),
    $oa5$  v_fc := v_t.failed_count + 1;
  IF v_fc >= 5 THEN
    UPDATE app.partner_totp t
    SET failed_count = 0, locked_until = v_now + interval '15 minutes'
    WHERE t.user_id = p_uid;
$oa5$,
    $na5$  v_fc := v_t.failed_count + 1;
  v_cc := v_t.consecutive_failed + 1;
  IF v_cc >= 20 THEN
    -- 0108: the 20th CONSECUTIVE failure (only a success clears the count; the 15-minute locks do not) HARD locks the row. It is also the 5th failure of its group, so the 15-minute lock
    -- still applies exactly as before; hard_locked_at is what keeps the row locked once that lapses. 'hard_lock_set' is the status of THIS attempt only: the wrapper audits and alerts on
    -- it once and answers the Edge 'hard_locked'. Every later attempt answers 'hard_locked' at the top, before anything is compared.
    UPDATE app.partner_totp t
    SET failed_count = 0, locked_until = v_now + interval '15 minutes', consecutive_failed = 20, hard_locked_at = v_now
    WHERE t.user_id = p_uid;
    RETURN QUERY SELECT 'hard_lock_set'::text, 0;
    RETURN;
  END IF;
  IF v_fc >= 5 THEN
    UPDATE app.partner_totp t
    SET failed_count = 0, locked_until = v_now + interval '15 minutes', consecutive_failed = v_cc
    WHERE t.user_id = p_uid;
$na5$),
    $oa6$  UPDATE app.partner_totp t SET failed_count = v_fc WHERE t.user_id = p_uid;
  RETURN QUERY SELECT 'wrong'::text, 0;
END$oa6$,
    $na6$  UPDATE app.partner_totp t SET failed_count = v_fc, consecutive_failed = v_cc WHERE t.user_id = p_uid;
  RETURN QUERY SELECT 'wrong'::text, 0;
END$na6$)
WHERE fn = 'partner_totp_attempt';
UPDATE r108_fn SET exp_src = pg_temp.r108_edit(old_src,
    $oe1$        last_step = NULL, failed_count = 0, locked_until = NULL, revoked_at = NULL
    WHERE t.user_id = v_uid;$oe1$,
    $ne1$        last_step = NULL, failed_count = 0, locked_until = NULL, revoked_at = NULL,
        consecutive_failed = 0, hard_locked_at = NULL
    WHERE t.user_id = v_uid;$ne1$)
WHERE fn = 'partner_totp_enrol_apply';
UPDATE r108_fn SET exp_src = pg_temp.r108_edit(old_src,
    $oc1$      SET confirmed_at = v_now, last_step = v_cand, failed_count = 0, locked_until = NULL
      WHERE t.user_id = v_uid AND (t.last_step IS NULL OR t.last_step < v_cand);$oc1$,
    $nc1$      SET confirmed_at = v_now, last_step = v_cand, failed_count = 0, locked_until = NULL, consecutive_failed = 0, hard_locked_at = NULL
      WHERE t.user_id = v_uid AND (t.last_step IS NULL OR t.last_step < v_cand);$nc1$)
WHERE fn = 'partner_totp_confirm_apply';
UPDATE r108_fn SET exp_src = pg_temp.r108_edit(old_src,
    $or1$      failed_count = 0,
      locked_until = NULL
  WHERE t.user_id = p_target AND t.revoked_at IS NULL;$or1$,
    $nr1$      failed_count = 0,
      locked_until = NULL,
      consecutive_failed = 0,
      hard_locked_at = NULL
  WHERE t.user_id = p_target AND t.revoked_at IS NULL;$nr1$)
WHERE fn = 'partner_totp_reset_apply';
UPDATE r108_fn SET exp_src = pg_temp.r108_edit(pg_temp.r108_edit(old_src,
    $ov1$  IF v_r.o_status IN ('wrong', 'locked') THEN
$ov1$,
    $nv1$  IF v_r.o_status = 'hard_lock_set' THEN
    -- 0108: the 20th consecutive failure, the ONE attempt that set the hard lock: one audit row and one alarm, here and nowhere else. A later attempt on the hard-locked row comes back
    -- as hard_locked and writes nothing (no audit row, no alarm), so a loop of guesses can neither grow audit_log nor alert again.
    PERFORM private.partner_audit_write('partner.totp.hard_locked', 'app.partner_totp', v_uid::text, pg_catalog.jsonb_build_object('stage', 'verify'));
    v_detail := pg_catalog.jsonb_build_object('subject', v_uid::text, 'stage', 'verify');
    INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket, detail)
    VALUES (
      'totp_hard_locked',
      NULL,
      v_uid::text,
      pg_catalog.floor(pg_catalog.date_part('epoch', pg_catalog.clock_timestamp()) / 60)::bigint,
      v_detail
    )
    ON CONFLICT (kind, bucket_key, minute_bucket) DO NOTHING;
  END IF;
  IF v_r.o_status IN ('wrong', 'locked') THEN
$nv1$),
    $ov2$  RETURN QUERY SELECT v_r.o_status, v_r.o_retry_after, v_r.o_mfa_until;$ov2$,
    $nv2$  RETURN QUERY SELECT CASE WHEN v_r.o_status = 'hard_lock_set' THEN 'hard_locked' ELSE v_r.o_status END, v_r.o_retry_after, v_r.o_mfa_until;$nv2$)
WHERE fn = 'partner_totp_verify_for_partner';
DO $r108_fn_pre$
BEGIN
  IF (SELECT count(*) FROM r108_fn WHERE exp_src IS NOT NULL AND exp_src <> old_src) <> 5 THEN
    RAISE EXCEPTION '0108: expected to capture five functions and derive an edited source for each';
  END IF;
END
$r108_fn_pre$;

-- ============================================================================
-- 4. The verifier-owned writers (the 0087 owner bracket: the migrating role holds SET on the owner for the length of this section only)
-- ============================================================================
GRANT partner_totp_verifier TO CURRENT_USER WITH INHERIT FALSE, SET TRUE;
GRANT CREATE ON SCHEMA private TO partner_totp_verifier;
SET ROLE partner_totp_verifier;

-- 4a. ONE ATTEMPT against a person's confirmed TOTP. Statuses (never a RAISE): unset | hard_locked | hard_lock_set | locked | unconfirmed | ok | wrong. Internal: EXECUTE for nobody.
CREATE OR REPLACE FUNCTION private.partner_totp_attempt(p_uid uuid, p_code text)
RETURNS TABLE (o_status text, o_retry_after integer)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_t record;
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_seed bytea;
  v_step bigint;
  v_cand bigint;
  v_i integer;
  v_expected text;
  v_code text;
  v_match boolean;
  v_fc integer;
  v_cc integer;
BEGIN
  IF p_uid IS NULL OR p_code IS NULL OR p_code !~ '^[0-9]{6}$' THEN
    RAISE EXCEPTION 'partner_totp_attempt: a user and a 6-digit code are required' USING ERRCODE = '22023';
  END IF;
  v_code := p_code;
  SELECT t.seed_version, t.confirmed_at, t.last_step, t.failed_count, t.locked_until, t.revoked_at, t.consecutive_failed, t.hard_locked_at INTO v_t
  FROM app.partner_totp t WHERE t.user_id = p_uid FOR UPDATE;
  IF NOT FOUND OR v_t.revoked_at IS NOT NULL THEN
    RETURN QUERY SELECT 'unset'::text, 0;
    RETURN;
  END IF;
  IF v_t.hard_locked_at IS NOT NULL THEN
    -- 0108: the HARD lock (20 consecutive failures). Refused before anything is compared, whatever the code and however long ago it was set: time never clears it, only an admin's TOTP
    -- reset does (partner_totp_reset_apply). Nothing is counted or changed here, and the caller writes no audit row and raises no alarm for it: the attempt that SET the lock
    -- (hard_lock_set, below) is the one event that is recorded.
    RETURN QUERY SELECT 'hard_locked'::text, 0;
    RETURN;
  END IF;
  IF v_t.locked_until IS NOT NULL AND v_t.locked_until > v_now THEN
    RETURN QUERY SELECT 'locked'::text, pg_catalog.ceil(pg_catalog.date_part('epoch', v_t.locked_until - v_now))::integer;
    RETURN;
  END IF;
  IF v_t.confirmed_at IS NULL THEN
    RETURN QUERY SELECT 'unconfirmed'::text, 0;
    RETURN;
  END IF;
  IF v_t.seed_version < 1 THEN
    RETURN QUERY SELECT 'unset'::text, 0;
    RETURN;
  END IF;
  v_seed := private.partner_totp_seed_derive(p_uid, v_t.seed_version);
  v_step := pg_catalog.floor(pg_catalog.date_part('epoch', v_now) / 30.0)::bigint;
  FOR v_i IN 0..2 LOOP
    v_cand := v_step + (v_i - 1);
    IF v_cand < 0 THEN
      CONTINUE;
    END IF;
    IF v_t.last_step IS NOT NULL AND v_cand <= v_t.last_step THEN
      CONTINUE;
    END IF;
    v_expected := private.hotp(v_seed, v_cand, 6, 'sha1');
    -- compare via HMAC under the seed so equality does not short-circuit on a secret-derived value's bytes
    v_match := public.hmac(pg_catalog.convert_to(v_code, 'UTF8'), v_seed, 'sha256')
             = public.hmac(pg_catalog.convert_to(v_expected, 'UTF8'), v_seed, 'sha256');
    IF v_match THEN
      UPDATE app.partner_totp t
      SET last_step = v_cand, failed_count = 0, locked_until = NULL, consecutive_failed = 0
      WHERE t.user_id = p_uid AND (t.last_step IS NULL OR t.last_step < v_cand);
      IF NOT FOUND THEN
        -- lost the compare-and-set (concurrent accept of the same or a later step): treat as wrong without counting
        RETURN QUERY SELECT 'wrong'::text, 0;
        RETURN;
      END IF;
      RETURN QUERY SELECT 'ok'::text, 0;
      RETURN;
    END IF;
  END LOOP;
  -- wrong: count toward lockout (5 consecutive -> 15 min lock; failed_count reset on lock so the unlock window starts clean)
  v_fc := v_t.failed_count + 1;
  v_cc := v_t.consecutive_failed + 1;
  IF v_cc >= 20 THEN
    -- 0108: the 20th CONSECUTIVE failure (only a success clears the count; the 15-minute locks do not) HARD locks the row. It is also the 5th failure of its group, so the 15-minute lock
    -- still applies exactly as before; hard_locked_at is what keeps the row locked once that lapses. 'hard_lock_set' is the status of THIS attempt only: the wrapper audits and alerts on
    -- it once and answers the Edge 'hard_locked'. Every later attempt answers 'hard_locked' at the top, before anything is compared.
    UPDATE app.partner_totp t
    SET failed_count = 0, locked_until = v_now + interval '15 minutes', consecutive_failed = 20, hard_locked_at = v_now
    WHERE t.user_id = p_uid;
    RETURN QUERY SELECT 'hard_lock_set'::text, 0;
    RETURN;
  END IF;
  IF v_fc >= 5 THEN
    UPDATE app.partner_totp t
    SET failed_count = 0, locked_until = v_now + interval '15 minutes', consecutive_failed = v_cc
    WHERE t.user_id = p_uid;
    RETURN QUERY SELECT 'locked'::text, 900;
    RETURN;
  END IF;
  UPDATE app.partner_totp t SET failed_count = v_fc, consecutive_failed = v_cc WHERE t.user_id = p_uid;
  RETURN QUERY SELECT 'wrong'::text, 0;
END
$$;

-- 4b. ENROL: an unconfirmed re-enrol starts from a clean slate, the hard lock included.
CREATE OR REPLACE FUNCTION private.partner_totp_enrol_apply()
RETURNS TABLE (o_status text, o_seed bytea, o_seed_version integer, o_issuer text, o_period integer, o_digits integer, o_algo text)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid := private.partner_binding_user();
  v_sid uuid := private.partner_binding_session();
  v_s record;
  v_t record;
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_ver integer;
  v_seed bytea;
  v_n integer;
BEGIN
  IF v_uid IS NULL OR v_sid IS NULL THEN
    RAISE EXCEPTION 'partner_totp_enrol_apply: no partner session is bound in this transaction' USING ERRCODE = '42501';
  END IF;
  SELECT s.enrolment_until, s.otp_proof_until INTO v_s FROM app.partner_session s WHERE s.id = v_sid;
  IF NOT FOUND OR NOT ((v_s.enrolment_until IS NOT NULL AND v_s.enrolment_until > v_now)
                       OR (v_s.otp_proof_until IS NOT NULL AND v_s.otp_proof_until > v_now)) THEN
    RAISE EXCEPTION 'partner_totp_enrol_apply: TOTP is enrolled only inside an enrolment window or after an email proof' USING ERRCODE = '42501';
  END IF;
  SELECT t.confirmed_at, t.seed_version INTO v_t FROM app.partner_totp t WHERE t.user_id = v_uid FOR UPDATE;
  IF FOUND AND v_t.confirmed_at IS NOT NULL THEN
    RETURN QUERY SELECT 'already_confirmed'::text, NULL::bytea, NULL::integer, NULL::text, NULL::integer, NULL::integer, NULL::text;
    RETURN;
  END IF;
  IF NOT FOUND THEN
    INSERT INTO app.partner_totp (user_id, seed_version, enrolled_at, enrol_session_id, confirmed_at, last_step, failed_count, locked_until, revoked_at, created_at)
    VALUES (v_uid, 1, v_now, v_sid, NULL, NULL, 0, NULL, NULL, v_now);
    GET DIAGNOSTICS v_n = ROW_COUNT;
    IF v_n <> 1 THEN
      RAISE EXCEPTION 'partner_totp_enrol_apply: enrol insert failed' USING ERRCODE = '42501';
    END IF;
    v_ver := 1;
  ELSE
    v_ver := v_t.seed_version + 1;
    UPDATE app.partner_totp t
    SET seed_version = v_ver, enrolled_at = v_now, enrol_session_id = v_sid, confirmed_at = NULL,
        last_step = NULL, failed_count = 0, locked_until = NULL, revoked_at = NULL,
        consecutive_failed = 0, hard_locked_at = NULL
    WHERE t.user_id = v_uid;
  END IF;
  v_seed := private.partner_totp_seed_derive(v_uid, v_ver);
  RETURN QUERY SELECT 'ok'::text, v_seed, v_ver, 'GolfRaven'::text, 30, 6, 'SHA1'::text;
END
$$;

-- 4c. CONFIRM: a successful confirm clears the counter and the hard lock (a confirm FAILURE is not counted toward it).
CREATE OR REPLACE FUNCTION private.partner_totp_confirm_apply(p_code text)
RETURNS TABLE (o_status text, o_retry_after integer)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid := private.partner_binding_user();
  v_sid uuid := private.partner_binding_session();
  v_t record;
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_seed bytea;
  v_step bigint;
  v_cand bigint;
  v_i integer;
  v_expected text;
  v_match boolean;
  v_fc integer;
BEGIN
  IF v_uid IS NULL OR v_sid IS NULL THEN
    RAISE EXCEPTION 'partner_totp_confirm_apply: no partner session is bound in this transaction' USING ERRCODE = '42501';
  END IF;
  IF p_code IS NULL OR p_code !~ '^[0-9]{6}$' THEN
    RAISE EXCEPTION 'partner_totp_confirm_apply: a 6-digit code is required' USING ERRCODE = '22023';
  END IF;
  SELECT t.seed_version, t.confirmed_at, t.enrol_session_id, t.last_step, t.failed_count, t.locked_until, t.revoked_at INTO v_t
  FROM app.partner_totp t WHERE t.user_id = v_uid FOR UPDATE;
  IF NOT FOUND OR v_t.revoked_at IS NOT NULL OR v_t.seed_version < 1 THEN
    RETURN QUERY SELECT 'unset'::text, 0;
    RETURN;
  END IF;
  IF v_t.confirmed_at IS NOT NULL THEN
    RETURN QUERY SELECT 'already_confirmed'::text, 0;
    RETURN;
  END IF;
  IF v_t.enrol_session_id IS DISTINCT FROM v_sid THEN
    RETURN QUERY SELECT 'wrong_session'::text, 0;
    RETURN;
  END IF;
  IF v_t.locked_until IS NOT NULL AND v_t.locked_until > v_now THEN
    RETURN QUERY SELECT 'locked'::text, pg_catalog.ceil(pg_catalog.date_part('epoch', v_t.locked_until - v_now))::integer;
    RETURN;
  END IF;
  v_seed := private.partner_totp_seed_derive(v_uid, v_t.seed_version);
  v_step := pg_catalog.floor(pg_catalog.date_part('epoch', v_now) / 30.0)::bigint;
  FOR v_i IN 0..2 LOOP
    v_cand := v_step + (v_i - 1);
    IF v_cand < 0 THEN CONTINUE; END IF;
    IF v_t.last_step IS NOT NULL AND v_cand <= v_t.last_step THEN CONTINUE; END IF;
    v_expected := private.hotp(v_seed, v_cand, 6, 'sha1');
    v_match := public.hmac(pg_catalog.convert_to(p_code, 'UTF8'), v_seed, 'sha256')
             = public.hmac(pg_catalog.convert_to(v_expected, 'UTF8'), v_seed, 'sha256');
    IF v_match THEN
      UPDATE app.partner_totp t
      SET confirmed_at = v_now, last_step = v_cand, failed_count = 0, locked_until = NULL, consecutive_failed = 0, hard_locked_at = NULL
      WHERE t.user_id = v_uid AND (t.last_step IS NULL OR t.last_step < v_cand);
      IF NOT FOUND THEN
        RETURN QUERY SELECT 'wrong'::text, 0;
        RETURN;
      END IF;
      RETURN QUERY SELECT 'ok'::text, 0;
      RETURN;
    END IF;
  END LOOP;
  v_fc := v_t.failed_count + 1;
  IF v_fc >= 5 THEN
    UPDATE app.partner_totp t SET failed_count = 0, locked_until = v_now + interval '15 minutes' WHERE t.user_id = v_uid;
    RETURN QUERY SELECT 'locked'::text, 900;
    RETURN;
  END IF;
  UPDATE app.partner_totp t SET failed_count = v_fc WHERE t.user_id = v_uid;
  RETURN QUERY SELECT 'wrong'::text, 0;
END
$$;

-- 4d. Admin reset (the only way out of a hard lock): clears the counter and the hard lock with the rest of the row's state.
CREATE OR REPLACE FUNCTION private.partner_totp_reset_apply(p_target uuid)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_caller uuid := private.partner_binding_user();
  v_n integer;
BEGIN
  IF v_caller IS NULL OR p_target IS NULL OR p_target = v_caller THEN
    RAISE EXCEPTION 'partner_totp_reset_apply: a different target user is required' USING ERRCODE = '22023';
  END IF;
  IF NOT private.is_admin(v_caller) THEN
    RAISE EXCEPTION 'partner_totp_reset_apply: only an admin may reset another person''s TOTP' USING ERRCODE = '42501';
  END IF;
  UPDATE app.partner_totp t
  SET seed_version = t.seed_version + 1,
      confirmed_at = NULL,
      enrolled_at = NULL,
      enrol_session_id = NULL,
      last_step = NULL,
      failed_count = 0,
      locked_until = NULL,
      consecutive_failed = 0,
      hard_locked_at = NULL
  WHERE t.user_id = p_target AND t.revoked_at IS NULL;
  GET DIAGNOSTICS v_n = ROW_COUNT;
  IF v_n = 0 THEN
    -- no row yet: insert a bumped unconfirmed placeholder so a later enrol starts at version 1 from a clean slate, OR simply report unset
    RETURN 'unset';
  END IF;
  RETURN 'ok';
END
$$;

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM partner_totp_verifier;
REVOKE partner_totp_verifier FROM CURRENT_USER;

-- ============================================================================
-- 5. The step-up wrapper (private_definer): the attempt that sets the hard lock audits and alerts once; the Edge sees hard_locked
-- ============================================================================
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

CREATE OR REPLACE FUNCTION private.partner_totp_verify_for_partner(p_code text)
RETURNS TABLE (o_status text, o_retry_after integer, o_mfa_until timestamptz)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_r record;
  v_detail jsonb;
BEGIN
  v_uid := private.partner_authorize(NULL, NULL, ARRAY['operator']::app.partner_role[], 'A0_MFA');
  SELECT a.o_status, a.o_retry_after, a.o_mfa_until INTO v_r FROM private.partner_totp_verify_apply(p_code) a;
  IF v_r.o_status = 'hard_lock_set' THEN
    -- 0108: the 20th consecutive failure, the ONE attempt that set the hard lock: one audit row and one alarm, here and nowhere else. A later attempt on the hard-locked row comes back
    -- as hard_locked and writes nothing (no audit row, no alarm), so a loop of guesses can neither grow audit_log nor alert again.
    PERFORM private.partner_audit_write('partner.totp.hard_locked', 'app.partner_totp', v_uid::text, pg_catalog.jsonb_build_object('stage', 'verify'));
    v_detail := pg_catalog.jsonb_build_object('subject', v_uid::text, 'stage', 'verify');
    INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket, detail)
    VALUES (
      'totp_hard_locked',
      NULL,
      v_uid::text,
      pg_catalog.floor(pg_catalog.date_part('epoch', pg_catalog.clock_timestamp()) / 60)::bigint,
      v_detail
    )
    ON CONFLICT (kind, bucket_key, minute_bucket) DO NOTHING;
  END IF;
  IF v_r.o_status IN ('wrong', 'locked') THEN
    PERFORM private.partner_audit_write(
      CASE WHEN v_r.o_status = 'locked' THEN 'partner.totp.locked' ELSE 'partner.totp.wrong' END,
      'app.partner_totp', v_uid::text, pg_catalog.jsonb_build_object('stage', 'verify'));
  END IF;
  IF v_r.o_status = 'locked' AND v_r.o_retry_after = 900 THEN
    v_detail := pg_catalog.jsonb_build_object('subject', v_uid::text, 'stage', 'verify');
    INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket, detail)
    VALUES (
      'totp_locked',
      NULL,
      v_uid::text,
      pg_catalog.floor(pg_catalog.date_part('epoch', pg_catalog.clock_timestamp()) / 60)::bigint,
      v_detail
    )
    ON CONFLICT (kind, bucket_key, minute_bucket) DO NOTHING;
  END IF;
  RETURN QUERY SELECT CASE WHEN v_r.o_status = 'hard_lock_set' THEN 'hard_locked' ELSE v_r.o_status END, v_r.o_retry_after, v_r.o_mfa_until;
END
$$;

COMMENT ON FUNCTION private.partner_totp_verify_for_partner(text) IS
  '0053/0104/0108 (§110, §116). edge_partner only; POST step-up/totp: class A0_MFA; sets aal 2 and mfa_until on ok; audit wrong/locked; raises partner_auth_alarm kind totp_locked when newly locked (retry_after = 900; one per subject uid per minute). The attempt that sets the HARD lock (the 20th consecutive failure) writes ONE partner.totp.hard_locked audit row and ONE totp_hard_locked alarm; it and every later attempt answer hard_locked (the later ones write nothing).';

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

-- ============================================================================
-- 6. The self-check, second half
-- ============================================================================
DO $r108_fn_post$
DECLARE
  r record;
  v_attr text;
  v_src text;
  v_cmt text;
  v_n int := 0;
BEGIN
  FOR r IN SELECT * FROM r108_fn ORDER BY fn LOOP
    SELECT md5(ROW(pg_get_userbyid(p.proowner), p.proacl, p.proconfig, p.prosecdef, p.prolang, p.prorettype, p.proretset, pg_get_function_result(p.oid), pg_get_function_arguments(p.oid),
                   p.provolatile, p.proparallel, p.proisstrict, p.proleakproof, p.pronargdefaults, p.prokind, p.procost, p.prorows, p.proargmodes, p.proargnames)::text),
           p.prosrc, obj_description(p.oid, 'pg_proc')
      INTO v_attr, v_src, v_cmt
    FROM pg_proc p WHERE p.oid = r.fn_oid;
    IF v_attr IS DISTINCT FROM r.attr THEN
      RAISE EXCEPTION '0108: % changed an attribute (owner, ACL, search_path, SECURITY DEFINER, volatility, return shape, ...) when it was redefined', r.fn;
    END IF;
    IF v_src IS DISTINCT FROM r.exp_src OR v_src = r.old_src THEN
      RAISE EXCEPTION '0108: % differs from its previous definition by more than the intended hard-lock edits', r.fn;
    END IF;
    IF r.fn <> 'partner_totp_verify_for_partner' AND v_cmt IS DISTINCT FROM r.cmt THEN
      RAISE EXCEPTION '0108: % lost or changed its comment', r.fn;
    END IF;
    v_n := v_n + 1;
  END LOOP;
  IF v_n <> 5 THEN
    RAISE EXCEPTION '0108: expected to check five redefined functions';
  END IF;
  IF obj_description('private.partner_totp_verify_for_partner(text)'::regprocedure, 'pg_proc') NOT LIKE '%0108%' THEN
    RAISE EXCEPTION '0108: the step-up wrapper comment was not updated';
  END IF;
END
$r108_fn_post$;
DROP TABLE r108_fn;
DROP FUNCTION pg_temp.r108_edit(text, text, text);

-- ============================================================================
-- 7. Inventories
-- ============================================================================
GRANT INSERT, UPDATE ON private.function_inventory TO CURRENT_USER;
CREATE POLICY current_user_edit_function_inventory_0108 ON private.function_inventory
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

UPDATE private.function_inventory
SET note = '0053/0108 (§116): owned by partner_totp_verifier; ONE attempt against a confirmed TOTP: hard lock (20 consecutive failures, admin reset only), 15-minute lock, window +/-1, replay, counters; every outcome a status; EXECUTE for nobody'
WHERE schema_name = 'private' AND function_name = 'partner_totp_attempt' AND identity_args = 'p_uid uuid, p_code text';

UPDATE private.function_inventory
SET note = '0053/0108 (§116): owned by partner_totp_verifier; bumps seed_version, gated by enrolment/otp proof; returns seed once; a re-enrol clears the counter and the hard lock; EXECUTE for private_definer only'
WHERE schema_name = 'private' AND function_name = 'partner_totp_enrol_apply' AND identity_args = '';

UPDATE private.function_inventory
SET note = '0053/0108 (§116): owned by partner_totp_verifier; confirm in the enrolling session; a successful confirm clears the counter and the hard lock; EXECUTE for private_definer only'
WHERE schema_name = 'private' AND function_name = 'partner_totp_confirm_apply' AND identity_args = 'p_code text';

UPDATE private.function_inventory
SET note = '0053/0108 (§116): owned by partner_totp_verifier; admin reset of another person''s TOTP (bump version, clear confirmed, the counter and the hard lock); EXECUTE for private_definer only'
WHERE schema_name = 'private' AND function_name = 'partner_totp_reset_apply' AND identity_args = 'p_target uuid';

UPDATE private.function_inventory
SET note = '0053/0104/0108 (§110, §116): edge_partner only; POST step-up/totp: class A0_MFA; raises totp_locked alarm on newly locked; the 20th consecutive failure hard-locks (one audit row, one totp_hard_locked alarm)'
WHERE schema_name = 'private' AND function_name = 'partner_totp_verify_for_partner' AND identity_args = 'p_code text';

DROP POLICY current_user_edit_function_inventory_0108 ON private.function_inventory;
REVOKE INSERT, UPDATE ON private.function_inventory FROM CURRENT_USER;

GRANT INSERT, UPDATE ON private.definer_policy_allowlist TO CURRENT_USER;
CREATE POLICY current_user_seed_definer_policy_allowlist_0108 ON private.definer_policy_allowlist
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
INSERT INTO private.definer_policy_allowlist (schema_name, table_name, policy_name, command, scoped, note, role_name) VALUES
  ('app', 'partner_auth_alarm', 'pd_partner_totp_hard_locked_alarm_insert', 'INSERT', true,
   '0108 (§116): partner-bound private_definer inserts totp_hard_locked for subject uid', 'private_definer'),
  ('app', 'partner_auth_alarm', 'pd_partner_totp_hard_locked_alarm_select', 'SELECT', true,
   '0108 (§116): partner-bound private_definer reads totp_hard_locked rows for ON CONFLICT', 'private_definer');
UPDATE private.definer_policy_allowlist al
SET using_expr = pg_get_expr(pol.polqual, pol.polrelid),
    with_check_expr = pg_get_expr(pol.polwithcheck, pol.polrelid)
FROM pg_policy pol
JOIN pg_class c ON c.oid = pol.polrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE al.schema_name = n.nspname AND al.table_name = c.relname AND al.policy_name = pol.polname
  AND pol.polname IN ('pd_partner_totp_hard_locked_alarm_insert', 'pd_partner_totp_hard_locked_alarm_select');
DO $assert_0108_allowlist$
BEGIN
  IF (SELECT count(*) FROM private.definer_policy_allowlist
      WHERE policy_name IN ('pd_partner_totp_hard_locked_alarm_insert', 'pd_partner_totp_hard_locked_alarm_select')
        AND (using_expr IS NOT NULL OR with_check_expr IS NOT NULL)) <> 2 THEN
    RAISE EXCEPTION '0108: an allowlist row names no live policy (its expressions were not derived)';
  END IF;
END
$assert_0108_allowlist$;
DROP POLICY current_user_seed_definer_policy_allowlist_0108 ON private.definer_policy_allowlist;
REVOKE INSERT, UPDATE ON private.definer_policy_allowlist FROM CURRENT_USER;

-- ============================================================================
-- 8. DO asserts
-- ============================================================================
DO $assert_0108$
DECLARE
  v_n int;
  v_def text;
BEGIN
  SELECT count(*)::int INTO v_n
  FROM pg_policy pol
  WHERE pol.polname IN ('pd_partner_totp_hard_locked_alarm_insert', 'pd_partner_totp_hard_locked_alarm_select');
  IF v_n <> 2 THEN
    RAISE EXCEPTION '0108: expected partner-bound totp_hard_locked INSERT + SELECT policies';
  END IF;
  SELECT pg_get_constraintdef(oid) INTO v_def
  FROM pg_constraint
  WHERE conname = 'partner_auth_alarm_kind_check'
    AND conrelid = 'app.partner_auth_alarm'::regclass;
  IF v_def IS NULL OR v_def NOT LIKE '%totp_hard_locked%' THEN
    RAISE EXCEPTION '0108: partner_auth_alarm kind CHECK must include totp_hard_locked';
  END IF;
  SELECT count(*)::int INTO v_n
  FROM pg_attribute a
  WHERE a.attrelid = 'app.partner_totp'::regclass AND a.attname IN ('consecutive_failed', 'hard_locked_at') AND NOT a.attisdropped;
  IF v_n <> 2 THEN
    RAISE EXCEPTION '0108: app.partner_totp must carry consecutive_failed and hard_locked_at';
  END IF;
  -- no grant moved: the verifier is still the table's only writer, and no other role can see the new columns
  IF EXISTS (SELECT 1 FROM unnest(ARRAY['anon', 'authenticated', 'service_role', 'edge_gateway', 'edge_actor', 'edge_system', 'edge_partner', 'edge_partner_minter', 'private_definer']) r(n)
             WHERE has_column_privilege(r.n, 'app.partner_totp', 'consecutive_failed', 'SELECT,INSERT,UPDATE,REFERENCES')
                OR has_column_privilege(r.n, 'app.partner_totp', 'hard_locked_at', 'SELECT,INSERT,UPDATE,REFERENCES')) THEN
    RAISE EXCEPTION '0108: a role other than partner_totp_verifier can reach the hard-lock columns';
  END IF;
END
$assert_0108$;
