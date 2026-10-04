-- 0046_course_qr_marker_scan.sql
--
-- P5.1a S2a: the PLAYER lane of the course QR (build plan §4.6(q), §7.6 "Offline marker purchase (G2-03)", §9.2 "Proving a marker purchase (O5)"; P5 acceptance
-- tests AT(3), AT(4), AT(13) and AT(19); docs/security/partner-auth-design.md section 12, row S2a). This migration adds what the DATABASE owns of the `marker-scan`
-- function and of the player's co-signal intake. The Edge half is supabase/functions/marker-scan and supabase/functions/_shared/course-qr/. The STAFF lane
-- (minting a rotating token on "Marker sold", showing today's PIN and rotating it, `qr-print`, the Ed25519 signing keys, the writers of `course_qr_token` and
-- `facility_qr`) is S2b and builds nothing here. Migrations 0001-0045 are untouched.
--
-- WHAT A SCAN IS, IN ONE PARAGRAPH
--   A player scans the shop's QR with the app. Two variants (plan §9.2): Q1, a ROTATING token a staff member's "Marker sold" tap minted (a row of app.course_qr_token
--   holds the hash of its 128-bit nonce, single use) or Q2, the PRINTED facility QR (registered in app.facility_qr) plus today's 4-digit PIN. The scan carries the app's
--   co-signal (a challenge-bound foreground fix, plan §4.5). The database decides, in ONE transaction: the QR is genuine for this facility and not used (Q1) / the PIN
--   is today's (Q2); the 120 s rule against the FIX's time (Q1) or the same facility-local date (Q2); and writes app.purchase_evidence (method course_qr) plus app.marker_credit:
--     attested co-signal    -> purchase `valid`,        credit `credited`
--     unattestable          -> purchase `held_review`,  credit `held_review`   (plan §4.5 row 3: never a silent refusal)
--     no qualifying fix     -> purchase `pending`,      credit `pending`       (AT(3): never credited without a co-signal)
--   A `pending` row carries the WINDOW in which a later qualifying fix may complete it (`cosignal.awaiting`, below); the player's co-signal intake
--   (private.marker_cosignal_attach_for_actor) joins a fix to such a row. That join is generic over the row's method: it is the seam the S3 offline-code staff scan plugs into.
--
-- THE KEYS (the decision the task asked to be documented)
--   * PRINTED QR and ROTATING TOKEN signatures are Ed25519, VERIFIED ON THE PLAYER PATH ONLY. The PUBLIC halves live in app.course_qr_key (this migration), `kid`-addressed
--     and revocable (`revoked_at`), read through private.course_qr_public_key_for_actor; the Edge code verifies the signature with WebCrypto. WHY A TABLE, not Vault and not config:
--     a public key is not a secret; a table needs no redeploy to rotate or to revoke a compromised kid (config would), and it is the same shape as app.catalog_signing_key (0019). The
--     PRIVATE halves are S2b's: the plan keeps them in Vault (§4.8) and the staff lane's `course-qr` / `qr-print` sign with them. NOTHING in the player lane can sign.
--   * The DAILY PIN is derived inside Postgres from a Vault secret, `course_pin_pepper` (>= 32 bytes), in the style of 0045's offline seed:
--         pin = LPAD( (first 4 bytes of HMAC-SHA256(pepper, label || 0x00 || facility_id || 0x00 || local_date || 0x00 || pin_epoch)) as an unsigned big-endian integer MOD 10000, 4, '0' )
--         label = 'golfraven/course-pin/v1' (UTF-8); facility_id = UTF-8; local_date = 'YYYY-MM-DD' (ASCII); pin_epoch = 4 bytes, big-endian (int4send).
--     The 0x00 separators make the encoding unambiguous (a facility id cannot contain NUL); the encoding is pinned by an OUT-OF-DB test vector (24_course_qr_marker_scan.sql and
--     supabase/tests/unit/course-qr-pin-vector.test.ts compute it with an independent implementation). The pepper is read ONLY inside private.course_pin_derive, EXECUTE for NOBODY;
--     the player lane never returns a PIN, only ok / wrong / locked. S2b adds the staff-lane wrapper that SHOWS today's PIN to an authenticated staff member.
--
-- WHAT THIS ADDS
--   1. app.course_qr_key            public keys (see above). FORCE RLS, no client / edge grant, definer-only.
--   2. app.course_pin_alarm         one row each time the facility-wide failure alarm rotated a PIN (operator-facing; S2b / the portal read it). No user id: not a personal table.
--   3. app.facility_programme.pin_epoch  gets a monotonic trigger (a lower epoch would revive a rotated-out PIN) and ONE column grant, UPDATE(pin_epoch), for private_definer.
--   4. app.course_qr_token          write-once consumption (trigger) and the two policies / one column grant the consume needs. The staff lane's INSERT is S2b's.
--   5. app.purchase_evidence        a UNIQUE partial index (user, trail, ref_id) for course_qr rows (a replayed printed-QR scan is a duplicate), and the definer grants / policies.
--   6. private.course_pin_derive, course_pin_attempt_for_actor, marker_scan_for_actor, marker_cosignal_attach_for_actor, course_qr_public_key_for_actor.
--   7. The registries (function inventory, definer policy allow-list) and proofs.
--
-- RULES FOLLOWED (docs/security/p3-money-path-requirements.md, "HARD RULE"): every private_definer policy added here is keyed on the actor BINDING (private.actor_uid()), never on a
-- settable GUC; every `_for_actor` definer filters by the bound uid in its own SQL, on every statement that touches a caller-visible row, and names the explicit check at the statement.
-- The wide visibility the token / QR / programme READ policies give (any row, to any bound actor's definer) is NOT an ownership boundary: the definer's own predicates are
-- (the facility, the nonce hash, the kid), and no definer here returns another account's value (the token's used_by_user is never returned, only the fact that it was used).
--
-- DEPLOY: apply this migration, THEN create the Vault secret (`select vault.create_secret('<random, >= 32 bytes>', 'course_pin_pepper')`), THEN register the Ed25519 public
-- keys (S2b's key ceremony; until a key exists every QR is `invalid_qr`: fail closed), THEN deploy the Edge code. Until the pepper exists the PIN functions raise 55000
-- and the endpoint answers 503 `course_pin_unavailable`; nothing else is affected. ROTATING the pepper changes every facility's PIN at once (an incident response; plan §4.8's
-- `pepper_kid` per local day is NOT built here: see docs/security/partner-auth-design.md "As built: S2a", departures).
-- [unverified] on a real Supabase project: that Vault accepts the name `course_pin_pepper` and that pgcrypto's `hmac` is reachable as public.hmac (0029 and 0045 already rely on that).

-- ============================================================================
-- 1. app.course_qr_key (the PUBLIC keys that verify a rotating token or a printed QR)
-- ============================================================================
CREATE TABLE app.course_qr_key (
  purpose text NOT NULL CHECK (purpose IN ('rotating_token', 'printed_qr')),
  kid text NOT NULL CHECK (kid ~ '^[A-Za-z0-9_-]{1,64}$'),
  -- The raw 32-byte Ed25519 public key, unpadded base64url: exactly 43 characters.
  public_key_b64url text NOT NULL CHECK (public_key_b64url ~ '^[A-Za-z0-9_-]{43}$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  -- A revoked kid verifies nothing, at once (the printed-QR key is revoked only on suspected compromise: every printed QR is then reprinted, plan §4.8).
  revoked_at timestamptz,
  PRIMARY KEY (purpose, kid)
);
COMMENT ON TABLE app.course_qr_key IS
  '0046. PUBLIC Ed25519 keys that verify the rotating course-QR token (purpose rotating_token) and the printed facility QR (printed_qr), kid-addressed and revocable. The private halves are NOT here: S2b signs with a Vault key. No client role and no edge role has any privilege on it; the player lane reads it through private.course_qr_public_key_for_actor.';
ALTER TABLE app.course_qr_key ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.course_qr_key FORCE ROW LEVEL SECURITY;
REVOKE ALL ON app.course_qr_key FROM PUBLIC, anon, authenticated;
GRANT SELECT ON app.course_qr_key TO service_role;
GRANT SELECT ON app.course_qr_key TO private_definer;
CREATE POLICY pd_marker_scan_key_read ON app.course_qr_key FOR SELECT TO private_definer USING (private.actor_uid() IS NOT NULL);

-- ============================================================================
-- 2. app.course_pin_alarm (the operator alert of plan §9.2 / §4.7.8: 30 wrong PINs at one facility in one local day)
-- ============================================================================
CREATE TABLE app.course_pin_alarm (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  facility_id text NOT NULL REFERENCES app.catalog_facility (id),
  local_date date NOT NULL,
  pin_epoch_before integer NOT NULL,
  pin_epoch_after integer NOT NULL CHECK (pin_epoch_after > pin_epoch_before),
  failures integer NOT NULL CHECK (failures > 0),
  raised_at timestamptz NOT NULL DEFAULT now(),
  -- One alarm per (facility, day, epoch): the 30th failure of an epoch rotates it once, however the requests interleave.
  UNIQUE (facility_id, local_date, pin_epoch_before)
);
COMMENT ON TABLE app.course_pin_alarm IS
  '0046. One row each time the facility-wide wrong-PIN alarm (30 failures at one facility on one facility-local date, plan §9.2) rotated that facility''s PIN (pin_epoch + 1). Operator-facing: the portal (S2b / P5.1b) reads it. Holds no user id and no PIN, so it is not a personal table. Written only by private.course_pin_attempt_for_actor. Retention (a purge step) is a follow-up.';
ALTER TABLE app.course_pin_alarm ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.course_pin_alarm FORCE ROW LEVEL SECURITY;
REVOKE ALL ON app.course_pin_alarm FROM PUBLIC, anon, authenticated;
GRANT SELECT ON app.course_pin_alarm TO service_role;
-- SELECT is needed too: INSERT ... ON CONFLICT (cols) DO NOTHING reads the arbiter's columns. The alarm rows hold no personal data.
GRANT INSERT, SELECT ON app.course_pin_alarm TO private_definer;
CREATE POLICY pd_marker_scan_alarm_select ON app.course_pin_alarm FOR SELECT TO private_definer USING (private.actor_uid() IS NOT NULL);
CREATE POLICY pd_marker_scan_alarm_insert ON app.course_pin_alarm FOR INSERT TO private_definer WITH CHECK (private.actor_uid() IS NOT NULL);

-- ============================================================================
-- 3. app.facility_programme.pin_epoch: monotonic, and the one narrow write the failure alarm needs
-- ============================================================================
CREATE FUNCTION app.facility_programme_pin_epoch_monotonic() RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
  -- A lower epoch would make a rotated-out PIN valid again: the very alarm this column serves, undone.
  IF NEW.pin_epoch < OLD.pin_epoch THEN
    RAISE EXCEPTION 'facility_programme: pin_epoch is monotonic (% -> % refused, trail=%, facility=%)', OLD.pin_epoch, NEW.pin_epoch, OLD.trail_id, OLD.facility_id
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER facility_programme_pin_epoch_monotonic_trg
BEFORE UPDATE OF pin_epoch ON app.facility_programme
FOR EACH ROW EXECUTE FUNCTION app.facility_programme_pin_epoch_monotonic();

-- ROW filter: a bound actor must exist (the definer is the real scope: it rotates ONE facility's rows, and only from the failure alarm). COLUMN filter: pin_epoch only.
GRANT UPDATE (pin_epoch) ON app.facility_programme TO private_definer;
CREATE POLICY pd_marker_scan_facility_programme_epoch ON app.facility_programme
  FOR UPDATE TO private_definer USING (private.actor_uid() IS NOT NULL) WITH CHECK (private.actor_uid() IS NOT NULL);

-- Reads the scan needs and no definer had: the facility's tz, and which trails run an any_purchase programme. Column grants: nothing else is readable.
GRANT SELECT (id, tz) ON app.catalog_facility TO private_definer;
CREATE POLICY pd_marker_scan_facility_read ON app.catalog_facility FOR SELECT TO private_definer USING (private.actor_uid() IS NOT NULL);
GRANT SELECT (trail_id, status, marker_source) ON app.trail_programme TO private_definer;
CREATE POLICY pd_marker_scan_trail_programme_read ON app.trail_programme FOR SELECT TO private_definer USING (private.actor_uid() IS NOT NULL);
GRANT SELECT ON app.facility_qr TO private_definer;
CREATE POLICY pd_marker_scan_facility_qr_read ON app.facility_qr FOR SELECT TO private_definer USING (private.actor_uid() IS NOT NULL);

-- ============================================================================
-- 4. app.course_qr_token: consumption is write-once, and the definer may mark a token used BY THE BOUND ACTOR only
-- ============================================================================
CREATE FUNCTION app.course_qr_token_single_use() RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
  -- "The first valid scan consumes it, and a second gets 409" (plan §9.2): once a token is used, nobody changes who used it or when. (The key and the facts of issue
  -- are S2b's to write at INSERT; nothing here lets a later UPDATE touch them: the only UPDATE grant is on the two used_* columns.)
  IF OLD.used_at IS NOT NULL AND (NEW.used_at IS DISTINCT FROM OLD.used_at OR NEW.used_by_user IS DISTINCT FROM OLD.used_by_user) THEN
    RAISE EXCEPTION 'course_qr_token: a used token cannot be changed (nonce_hash=%)', OLD.nonce_hash USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER course_qr_token_single_use_trg
BEFORE UPDATE ON app.course_qr_token
FOR EACH ROW EXECUTE FUNCTION app.course_qr_token_single_use();

GRANT UPDATE (used_by_user, used_at) ON app.course_qr_token TO private_definer;
-- SELECT: the scan has to tell "unknown" (422) from "already used" (409), including a token another account used, so the row must be visible to a bound actor's definer whoever
-- used it. The definer returns the FACT of use, never the account.
CREATE POLICY pd_marker_scan_token_select ON app.course_qr_token FOR SELECT TO private_definer USING (private.actor_uid() IS NOT NULL);
-- UPDATE: the only thing a bound actor's definer may write is its OWN use of the token.
CREATE POLICY pd_marker_scan_token_update ON app.course_qr_token FOR UPDATE TO private_definer
  USING (private.actor_uid() IS NOT NULL) WITH CHECK (used_by_user = private.actor_uid() AND used_at IS NOT NULL);

-- ============================================================================
-- 5. app.purchase_evidence / app.marker_credit: the rows a scan writes, ONLY the bound actor's own
-- ============================================================================
-- A course_qr scan is unique per (user, trail, ref_id): a rotating token's ref is its nonce hash (single use anyway), a printed-QR scan's ref is 'pin:<facility>:<date>:<epoch>',
-- so the same player scanning the same shop twice on one local day under one epoch is a duplicate (409), not a second purchase.
CREATE UNIQUE INDEX purchase_evidence_course_qr_ref_uniq ON app.purchase_evidence (user_id, trail_id, ref_id) WHERE method = 'course_qr' AND ref_id IS NOT NULL;

GRANT INSERT (user_id, facility_id, trail_id, method, qr_variant, ref_id, offline, cosignal, local_date, status) ON app.purchase_evidence TO private_definer;
GRANT UPDATE (status, cosignal) ON app.purchase_evidence TO private_definer;
CREATE POLICY pd_marker_scan_purchase_select ON app.purchase_evidence FOR SELECT TO private_definer USING (user_id = private.actor_uid());
CREATE POLICY pd_marker_scan_purchase_insert ON app.purchase_evidence FOR INSERT TO private_definer WITH CHECK (user_id = private.actor_uid());
CREATE POLICY pd_marker_scan_purchase_update ON app.purchase_evidence FOR UPDATE TO private_definer USING (user_id = private.actor_uid()) WITH CHECK (user_id = private.actor_uid());

GRANT INSERT (user_id, trail_id, facility_id, purchase_evidence_id, status) ON app.marker_credit TO private_definer;
GRANT UPDATE (status) ON app.marker_credit TO private_definer;
CREATE POLICY pd_marker_scan_credit_select ON app.marker_credit FOR SELECT TO private_definer USING (user_id = private.actor_uid());
CREATE POLICY pd_marker_scan_credit_insert ON app.marker_credit FOR INSERT TO private_definer WITH CHECK (user_id = private.actor_uid());
CREATE POLICY pd_marker_scan_credit_update ON app.marker_credit FOR UPDATE TO private_definer USING (user_id = private.actor_uid()) WITH CHECK (user_id = private.actor_uid());

-- ============================================================================
-- 6. The definer functions (ownership bracket: 0020 / 0022 / 0030 / 0045)
-- ============================================================================
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

-- 6a. THE derivation. The only place the pepper is read. No role is granted EXECUTE: it derives for ANY (facility, date, epoch) it is handed, so it must never be reachable
-- from a session (the staff lane's wrapper, S2b, checks the caller's scope first). The failure message names no key material.
CREATE FUNCTION private.course_pin_derive(p_facility_id text, p_local_date date, p_pin_epoch integer)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_key text;
  v_mac bytea;
  v_n bigint;
BEGIN
  IF p_facility_id IS NULL OR pg_catalog.btrim(p_facility_id) = '' OR p_local_date IS NULL OR p_pin_epoch IS NULL OR p_pin_epoch < 0 THEN
    RAISE EXCEPTION 'course_pin_derive: a facility, a date and an epoch of at least 0 are required' USING ERRCODE = '22023';
  END IF;
  SELECT s.decrypted_secret INTO v_key FROM vault.decrypted_secrets s WHERE s.name = 'course_pin_pepper';
  IF v_key IS NULL OR pg_catalog.octet_length(pg_catalog.convert_to(v_key, 'UTF8')) < 32 THEN
    RAISE EXCEPTION 'course_pin_derive: the course PIN pepper is not provisioned in Vault' USING ERRCODE = '55000';
  END IF;
  v_mac := public.hmac(
    pg_catalog.convert_to('golfraven/course-pin/v1', 'UTF8')
      || pg_catalog.decode('00', 'hex')
      || pg_catalog.convert_to(p_facility_id, 'UTF8')
      || pg_catalog.decode('00', 'hex')
      || pg_catalog.convert_to(pg_catalog.to_char(p_local_date, 'YYYY-MM-DD'), 'UTF8')
      || pg_catalog.decode('00', 'hex')
      || pg_catalog.int4send(p_pin_epoch),
    pg_catalog.convert_to(v_key, 'UTF8'),
    'sha256');
  v_n := (pg_catalog.get_byte(v_mac, 0)::bigint * 16777216) + (pg_catalog.get_byte(v_mac, 1)::bigint * 65536) + (pg_catalog.get_byte(v_mac, 2)::bigint * 256) + pg_catalog.get_byte(v_mac, 3)::bigint;
  RETURN pg_catalog.lpad((v_n % 10000)::text, 4, '0');
END;
$$;

-- 6b. The public key of a kid, for the Edge's signature check. ZERO ROWS for an unknown kid; a revoked kid is returned flagged (the caller refuses it: same answer to the player
-- as an unknown one). The bound actor is required only so the read cannot be made outside a request; the key is public, so no per-actor filter exists to make.
CREATE FUNCTION private.course_qr_public_key_for_actor(p_kid text, p_purpose text)
RETURNS TABLE (o_public_key_b64url text, o_revoked boolean)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_kind text;
BEGIN
  SELECT b.actor_uid, b.kind INTO v_uid, v_kind
  FROM private.actor_binding b
  WHERE b.backend_pid = pg_backend_pid() AND b.xact = pg_current_xact_id_if_assigned();
  IF v_uid IS NULL THEN
    RAISE EXCEPTION 'course_qr_public_key_for_actor: no actor is bound in this transaction' USING ERRCODE = '42501';
  END IF;
  IF v_kind <> 'user' THEN
    RAISE EXCEPTION 'course_qr_public_key_for_actor: a system delegate may not read a course QR key' USING ERRCODE = '42501';
  END IF;
  IF p_kid IS NULL OR p_purpose IS NULL OR p_purpose NOT IN ('rotating_token', 'printed_qr') THEN
    RAISE EXCEPTION 'course_qr_public_key_for_actor: a kid and a purpose (rotating_token | printed_qr) are required' USING ERRCODE = '22023';
  END IF;
  RETURN QUERY
    SELECT k.public_key_b64url, (k.revoked_at IS NOT NULL)
    FROM app.course_qr_key k
    WHERE k.purpose = p_purpose AND k.kid = p_kid;
END;
$$;

-- 6c. The wrong-PIN counters (Q2). Runs BEFORE the scan, in the same request transaction, and RETURNS instead of raising: a refusal has to COMMIT so the failure counts
-- ("count the attempt first", money doc step 2, the lesson of 0020: a raise rolls the increment back).
--   * per USER per facility per facility-local date OF THE ATTEMPT (not of the fix: see below): the 6th attempt is refused ('locked', a 429 until the next local day), whether or not its PIN is right (a correct 6th
--     guess after five wrong ones is exactly what the cap exists to stop). A correct PIN consumes nothing: only failures are counted.
--   * per FACILITY per local date per epoch: the 30th wrong PIN rotates the facility's PIN (pin_epoch + 1 on every programme row of the facility) and writes
--     app.course_pin_alarm for the operator. A user already locked out adds nothing to the facility's count (their attempts are refused before the PIN is looked at).
-- The counts are SUMS over private.rate_limit_bucket rows of the key (private.hit_rate_limit, the existing limiter, increments; its windows are UTC days, and a facility-local date
-- can straddle two of them, so the sum over the key, which names the local date, is the exact per-local-date count). Each key is serialised by a transaction advisory lock, so
-- the read-then-increment cannot be raced: 50 parallel guesses give exactly five 'wrong' and the rest 'locked'.
-- Results: ok | wrong | locked | no_facility | no_programme (no accepted, active, any_purchase programme row that allows the printed QR: nothing is counted).
CREATE FUNCTION private.course_pin_attempt_for_actor(p_facility_id text, p_pin text, p_at timestamptz)
RETURNS TABLE (o_result text, o_retry_after_seconds integer)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_kind text;
  v_tz text;
  v_date date;
  v_today date;
  v_epoch integer;
  v_now timestamptz := pg_catalog.now();
  v_user_key text;
  v_fac_key text;
  v_user_fails bigint;
  v_fac_fails bigint;
BEGIN
  SELECT b.actor_uid, b.kind INTO v_uid, v_kind
  FROM private.actor_binding b
  WHERE b.backend_pid = pg_backend_pid() AND b.xact = pg_current_xact_id_if_assigned();
  IF v_uid IS NULL THEN
    RAISE EXCEPTION 'course_pin_attempt_for_actor: no actor is bound in this transaction' USING ERRCODE = '42501';
  END IF;
  IF v_kind <> 'user' THEN
    RAISE EXCEPTION 'course_pin_attempt_for_actor: a system delegate may not attempt a course PIN' USING ERRCODE = '42501';
  END IF;
  IF p_facility_id IS NULL OR pg_catalog.btrim(p_facility_id) = '' OR p_pin IS NULL OR p_pin !~ '^[0-9]{4}$' OR p_at IS NULL
     OR p_at < v_now - interval '7 days' OR p_at > v_now + interval '5 minutes' THEN
    RAISE EXCEPTION 'course_pin_attempt_for_actor: a facility, a 4-digit PIN and a time within 7 days are required' USING ERRCODE = '22023';
  END IF;

  SELECT f.tz INTO v_tz FROM app.catalog_facility f WHERE f.id = p_facility_id;
  IF v_tz IS NULL THEN
    o_result := 'no_facility';
    RETURN NEXT;
    RETURN;
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM app.facility_programme fp JOIN app.trail_programme tp ON tp.trail_id = fp.trail_id
    WHERE fp.facility_id = p_facility_id AND fp.participation = 'accepted' AND tp.status IN ('pilot', 'live') AND tp.marker_source = 'any_purchase'
      AND fp.qr_mode IN ('static_pin', 'both')
  ) THEN
    o_result := 'no_programme';
    RETURN NEXT;
    RETURN;
  END IF;
  SELECT pg_catalog.max(fp.pin_epoch) INTO v_epoch FROM app.facility_programme fp WHERE fp.facility_id = p_facility_id;

  -- The PIN is the one for the date of the FIX (an offline purchase is uploaded days later), but the counters run on the facility-local date the ATTEMPT is made: otherwise a client
  -- could claim any of the last seven fix dates and have a fresh five tries for each. The 429 is "until the next local day" for the attempt, whatever fix date it names.
  v_date := (p_at AT TIME ZONE v_tz)::date;
  v_today := (v_now AT TIME ZONE v_tz)::date;
  v_user_key := 'marker-scan:pin-fail:u:' || v_uid::text || ':' || p_facility_id || ':' || pg_catalog.to_char(v_today, 'YYYY-MM-DD');
  PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(v_user_key, 0));
  SELECT coalesce(pg_catalog.sum(r.count), 0) INTO v_user_fails FROM private.rate_limit_bucket r WHERE r.bucket_key = v_user_key;
  IF v_user_fails >= 5 THEN
    o_result := 'locked';
    -- until the facility-local midnight that ends today
    o_retry_after_seconds := greatest(1, pg_catalog.ceil(pg_catalog.date_part('epoch', ((v_today + 1)::timestamp AT TIME ZONE v_tz) - v_now))::integer);
    RETURN NEXT;
    RETURN;
  END IF;

  IF private.course_pin_derive(p_facility_id, v_date, v_epoch) = p_pin THEN
    o_result := 'ok';
    RETURN NEXT;
    RETURN;
  END IF;

  -- A wrong PIN: count it for the user, then for the facility.
  PERFORM private.hit_rate_limit(v_user_key, interval '1 day', 1000000);
  v_fac_key := 'marker-scan:pin-fail:f:' || p_facility_id || ':' || pg_catalog.to_char(v_today, 'YYYY-MM-DD') || ':' || v_epoch::text;
  PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(v_fac_key, 0));
  PERFORM private.hit_rate_limit(v_fac_key, interval '1 day', 1000000);
  SELECT coalesce(pg_catalog.sum(r.count), 0) INTO v_fac_fails FROM private.rate_limit_bucket r WHERE r.bucket_key = v_fac_key;
  IF v_fac_fails = 30 THEN
    -- the 30th wrong PIN of this epoch: rotate (every programme row of the facility, so the PIN stays one value) and alert the operator
    UPDATE app.facility_programme fp SET pin_epoch = v_epoch + 1 WHERE fp.facility_id = p_facility_id AND fp.pin_epoch <= v_epoch;
    INSERT INTO app.course_pin_alarm (facility_id, local_date, pin_epoch_before, pin_epoch_after, failures)
    VALUES (p_facility_id, v_today, v_epoch, v_epoch + 1, v_fac_fails::integer)
    ON CONFLICT (facility_id, local_date, pin_epoch_before) DO NOTHING;
  END IF;
  o_result := 'wrong';
  RETURN NEXT;
END;
$$;

-- 6d. THE scan. One transaction; the bound kind = 'user' actor is the buyer (no user argument: a wrong uid cannot even be expressed). The Edge has already verified the QR's
-- Ed25519 signature, graded the fix (the checkin token, the geometry) and written the fix's foreground_checkin evidence row; it hands the database the facts the database
-- cannot check itself (the verified QR's nonce hash / kid, the claimed time, the co-signal's grade and ids). EVERYTHING the database CAN check it checks again:
-- the token row, its facility, single use, the 120 s rule against p_at, the facility_qr registration, the PIN (re-derived: the counters ran earlier, this is the gate),
-- the programme and the QR mode of each trail.
--
-- ⛔ NO RAISE for a refusal: every refusal is a RETURNED status and a row-less answer, written BEFORE any write; the Edge maps it to an HTTP error and throws, which rolls the
-- whole request transaction back (the checkin token it consumed, the evidence row it wrote). Only the PIN counters and the forged-signature fraud signal have to survive a refusal, and
-- they run earlier (course_pin_attempt_for_actor; the Edge's fraud signal).
--   o_result:  accepted | no_facility | no_programme | variant_disabled | qr_unknown | qr_wrong_facility | qr_used | qr_expired | qr_revoked | pin_wrong | duplicate
--   One row per eligible trail when accepted (a facility can sit on more than one trail's programme): the purchase and its credit.
-- p_at is the CLAIMED fix time (the 120 s rule is judged against the fix, plan §4.6(q)), or now() when the scan carries no fix.
-- A qualifying co-signal is p_cosignal_grade 'attested' | 'unattestable' (with its fix id and its evidence row's id); NULL means none: the row is `pending`, and `cosignal.awaiting`
-- records the window a later fix must fall in (Q1: within 120 s of issue; Q2: the same facility-local date) and the 7-day deadline (plan §4.6(q)).
CREATE FUNCTION private.marker_scan_for_actor(
  p_facility_id text,
  p_variant text,
  p_nonce_hash text,
  p_qr_kid text,
  p_pin text,
  p_at timestamptz,
  p_cosignal_grade text,
  p_cosignal_fix_id text,
  p_cosignal_evidence_id uuid
)
RETURNS TABLE (o_result text, o_purchase_id uuid, o_trail_id text, o_purchase_status text, o_credit_id uuid, o_credit_status text, o_local_date date)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_kind text;
  v_now timestamptz := pg_catalog.now();
  v_tz text;
  v_local date;
  v_trails text[];
  v_trail text;
  v_ref text;
  v_issued timestamptz;
  v_win_from timestamptz;
  v_win_to timestamptz;
  v_epoch integer;
  v_qr_kid text;
  v_qr_revoked timestamptz;
  v_tok_facility text;
  v_tok_used timestamptz;
  v_pstatus text;
  v_cstatus text;
  v_cosignal jsonb;
  v_purchase uuid;
  v_credit uuid;
  v_existing_credit uuid;
BEGIN
  SELECT b.actor_uid, b.kind INTO v_uid, v_kind
  FROM private.actor_binding b
  WHERE b.backend_pid = pg_backend_pid() AND b.xact = pg_current_xact_id_if_assigned();
  IF v_uid IS NULL THEN
    RAISE EXCEPTION 'marker_scan_for_actor: no actor is bound in this transaction' USING ERRCODE = '42501';
  END IF;
  IF v_kind <> 'user' THEN
    RAISE EXCEPTION 'marker_scan_for_actor: a system delegate may not record a marker purchase' USING ERRCODE = '42501';
  END IF;
  IF p_facility_id IS NULL OR pg_catalog.btrim(p_facility_id) = '' OR p_variant IS NULL OR p_variant NOT IN ('rotating', 'static_pin') OR p_at IS NULL
     OR (p_variant = 'rotating' AND (p_nonce_hash IS NULL OR p_nonce_hash !~ '^[0-9a-f]{64}$'))
     OR (p_variant = 'static_pin' AND (p_qr_kid IS NULL OR pg_catalog.btrim(p_qr_kid) = '' OR p_pin IS NULL OR p_pin !~ '^[0-9]{4}$'))
     OR (p_cosignal_grade IS NOT NULL AND (p_cosignal_grade NOT IN ('attested', 'unattestable') OR p_cosignal_fix_id IS NULL OR p_cosignal_evidence_id IS NULL))
     OR p_at < v_now - interval '7 days' OR p_at > v_now + interval '5 minutes' THEN
    RAISE EXCEPTION 'marker_scan_for_actor: invalid arguments (a facility, rotating+nonce hash or static_pin+kid+PIN, a time within 7 days, a complete co-signal or none)' USING ERRCODE = '22023';
  END IF;

  SELECT f.tz INTO v_tz FROM app.catalog_facility f WHERE f.id = p_facility_id;
  IF v_tz IS NULL THEN
    o_result := 'no_facility';
    RETURN NEXT;
    RETURN;
  END IF;
  v_local := (p_at AT TIME ZONE v_tz)::date;

  -- The programme: every ACCEPTED facility row on an ACTIVE any_purchase trail (course-QR is the any_purchase path; code cards are programme_marker's, plan §9.3).
  SELECT pg_catalog.array_agg(fp.trail_id ORDER BY fp.trail_id) INTO v_trails
  FROM app.facility_programme fp JOIN app.trail_programme tp ON tp.trail_id = fp.trail_id
  WHERE fp.facility_id = p_facility_id AND fp.participation = 'accepted' AND tp.status IN ('pilot', 'live') AND tp.marker_source = 'any_purchase';
  IF v_trails IS NULL THEN
    o_result := 'no_programme';
    RETURN NEXT;
    RETURN;
  END IF;
  -- The facility's QR mode (per programme row): a trail whose facility row says `rotating` does not take a printed-QR scan, and the reverse.
  SELECT pg_catalog.array_agg(fp.trail_id ORDER BY fp.trail_id) INTO v_trails
  FROM app.facility_programme fp
  WHERE fp.facility_id = p_facility_id AND fp.trail_id = ANY (v_trails) AND fp.qr_mode::text IN (p_variant, 'both');
  IF v_trails IS NULL THEN
    o_result := 'variant_disabled';
    RETURN NEXT;
    RETURN;
  END IF;

  IF p_variant = 'rotating' THEN
    SELECT t.facility_id, t.issued_at, t.used_at INTO v_tok_facility, v_issued, v_tok_used FROM app.course_qr_token t WHERE t.nonce_hash = p_nonce_hash;
    IF v_tok_facility IS NULL THEN
      o_result := 'qr_unknown';
      RETURN NEXT;
      RETURN;
    END IF;
    IF v_tok_facility <> p_facility_id THEN
      o_result := 'qr_wrong_facility';
      RETURN NEXT;
      RETURN;
    END IF;
    IF v_tok_used IS NOT NULL THEN
      o_result := 'qr_used';
      RETURN NEXT;
      RETURN;
    END IF;
    -- the 120 s rule, judged against the FIX's time (p_at), not the upload time: "a token more than 120 s from the fix time gives 422 qr_expired" (AT(19))
    IF pg_catalog.abs(pg_catalog.date_part('epoch', p_at - v_issued)) > 120 THEN
      o_result := 'qr_expired';
      RETURN NEXT;
      RETURN;
    END IF;
    v_ref := p_nonce_hash;
    v_win_from := v_issued - interval '120 seconds';
    v_win_to := v_issued + interval '120 seconds';
  ELSE
    -- Q2: the printed QR is registered (facility_qr is one row per facility: a reprint replaces its qr_kid, so an old kid is `revoked`), and today's PIN is the one for the
    -- fix's facility-local date under the facility's current epoch. EXPLICIT checks: this definer's own SQL, not a policy, is the boundary.
    SELECT q.qr_kid, q.revoked_at INTO v_qr_kid, v_qr_revoked FROM app.facility_qr q WHERE q.facility_id = p_facility_id;
    IF v_qr_kid IS NULL THEN
      o_result := 'qr_unknown';
      RETURN NEXT;
      RETURN;
    END IF;
    IF v_qr_revoked IS NOT NULL OR v_qr_kid <> p_qr_kid THEN
      o_result := 'qr_revoked';
      RETURN NEXT;
      RETURN;
    END IF;
    SELECT pg_catalog.max(fp.pin_epoch) INTO v_epoch FROM app.facility_programme fp WHERE fp.facility_id = p_facility_id;
    IF private.course_pin_derive(p_facility_id, v_local, v_epoch) <> p_pin THEN
      o_result := 'pin_wrong';
      RETURN NEXT;
      RETURN;
    END IF;
    v_ref := 'pin:' || p_facility_id || ':' || pg_catalog.to_char(v_local, 'YYYY-MM-DD') || ':' || v_epoch::text;
    v_win_from := (v_local::timestamp) AT TIME ZONE v_tz;
    v_win_to := ((v_local + 1)::timestamp AT TIME ZONE v_tz) - interval '1 millisecond';
    -- a repeat of the same scan by the same player (same shop, same local date, same epoch) is a duplicate
    IF EXISTS (SELECT 1 FROM app.purchase_evidence p WHERE p.user_id = v_uid AND p.trail_id = ANY (v_trails) AND p.method = 'course_qr' AND p.ref_id = v_ref) THEN
      o_result := 'duplicate';
      RETURN NEXT;
      RETURN;
    END IF;
  END IF;

  IF p_cosignal_grade = 'attested' THEN
    v_pstatus := 'valid';
    v_cstatus := 'credited';
    v_cosignal := pg_catalog.jsonb_build_object('fixId', p_cosignal_fix_id, 'grade', p_cosignal_grade, 'capturedAt', pg_catalog.to_char(p_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'), 'evidenceId', p_cosignal_evidence_id);
  ELSIF p_cosignal_grade = 'unattestable' THEN
    v_pstatus := 'held_review';
    v_cstatus := 'held_review';
    v_cosignal := pg_catalog.jsonb_build_object('fixId', p_cosignal_fix_id, 'grade', p_cosignal_grade, 'capturedAt', pg_catalog.to_char(p_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'), 'evidenceId', p_cosignal_evidence_id);
  ELSE
    v_pstatus := 'pending';
    v_cstatus := 'pending';
    v_cosignal := pg_catalog.jsonb_build_object('awaiting', pg_catalog.jsonb_build_object(
      'from', pg_catalog.to_char(v_win_from AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
      'to', pg_catalog.to_char(v_win_to AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
      'until', pg_catalog.to_char((v_now + interval '7 days') AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')));
  END IF;

  -- ACCEPTED. Consume the token (Q1): the UPDATE is conditional on `used_at IS NULL`, so of two concurrent scans exactly one gets a row; the loser sees the 409.
  IF p_variant = 'rotating' THEN
    UPDATE app.course_qr_token t SET used_by_user = v_uid, used_at = v_now WHERE t.nonce_hash = p_nonce_hash AND t.used_at IS NULL;
    IF NOT FOUND THEN
      o_result := 'qr_used';
      RETURN NEXT;
      RETURN;
    END IF;
  END IF;

  FOREACH v_trail IN ARRAY v_trails LOOP
    -- one writer per (user, trail, facility): the credited-credit uniqueness below is decided under this lock
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('marker-credit:' || v_uid::text || ':' || v_trail || ':' || p_facility_id, 0));
    INSERT INTO app.purchase_evidence (user_id, facility_id, trail_id, method, qr_variant, ref_id, offline, cosignal, local_date, status)
    VALUES (v_uid, p_facility_id, v_trail, 'course_qr', p_variant::app.qr_variant, v_ref, false, v_cosignal, v_local, v_pstatus::app.purchase_status)
    RETURNING id INTO v_purchase;

    v_credit := NULL;
    v_existing_credit := NULL;
    IF v_cstatus = 'credited' THEN
      SELECT c.id INTO v_existing_credit FROM app.marker_credit c WHERE c.user_id = v_uid AND c.trail_id = v_trail AND c.facility_id = p_facility_id AND c.status = 'credited';
    END IF;
    IF v_existing_credit IS NOT NULL THEN
      -- This player already holds the credit for this shop on this trail: the purchase is recorded (valid), a second credit would add nothing (and the partial unique index forbids it).
      v_credit := v_existing_credit;
    ELSE
      INSERT INTO app.marker_credit (user_id, trail_id, facility_id, purchase_evidence_id, status)
      VALUES (v_uid, v_trail, p_facility_id, v_purchase, v_cstatus::app.credit_status)
      RETURNING id INTO v_credit;
    END IF;

    o_result := 'accepted';
    o_purchase_id := v_purchase;
    o_trail_id := v_trail;
    o_purchase_status := v_pstatus;
    o_credit_id := v_credit;
    o_credit_status := CASE WHEN v_existing_credit IS NOT NULL THEN 'credited' ELSE v_cstatus END;
    o_local_date := v_local;
    RETURN NEXT;
  END LOOP;
END;
$$;

-- 6e. The player's CO-SIGNAL INTAKE: a qualifying fix (the Edge has graded it and written its foreground_checkin row) is tied to the bound player's own `pending` purchase at that
-- facility, if one is awaiting a co-signal whose window contains the fix's time and whose 7-day deadline has not passed (AT(13): "becomes valid / credited on the player's
-- reconnect"). THIS IS THE SEAM S3 PLUGS INTO: the join reads only the row (user, facility, status = 'pending', cosignal.awaiting = { from, to, until }), never its method, so an offline-code
-- `staff_scan` row the staff lane inserts with that window (+-10 min of the code's step) is joined by the same call. One fix completes ONE scan: every programme row of that scan
-- (rows sharing one ref_id) moves together; the earliest awaiting scan wins. A credit that cannot be `credited` because the player already holds one for that shop is voided.
-- o_result: attached | no_pending_purchase (and no row for any other account's purchase is ever visible: every statement filters by the bound uid).
CREATE FUNCTION private.marker_cosignal_attach_for_actor(
  p_facility_id text,
  p_at timestamptz,
  p_cosignal_grade text,
  p_cosignal_fix_id text,
  p_cosignal_evidence_id uuid
)
RETURNS TABLE (o_result text, o_purchase_id uuid, o_trail_id text, o_purchase_status text, o_credit_id uuid, o_credit_status text)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_kind text;
  v_now timestamptz := pg_catalog.now();
  v_ref text;
  v_method app.purchase_method;
  v_row record;
  v_pstatus text;
  v_cstatus text;
  v_cosignal jsonb;
  v_credit uuid;
  v_credit_status text;
  v_existing_credit uuid;
  v_any boolean := false;
BEGIN
  SELECT b.actor_uid, b.kind INTO v_uid, v_kind
  FROM private.actor_binding b
  WHERE b.backend_pid = pg_backend_pid() AND b.xact = pg_current_xact_id_if_assigned();
  IF v_uid IS NULL THEN
    RAISE EXCEPTION 'marker_cosignal_attach_for_actor: no actor is bound in this transaction' USING ERRCODE = '42501';
  END IF;
  IF v_kind <> 'user' THEN
    RAISE EXCEPTION 'marker_cosignal_attach_for_actor: a system delegate may not attach a co-signal' USING ERRCODE = '42501';
  END IF;
  IF p_facility_id IS NULL OR pg_catalog.btrim(p_facility_id) = '' OR p_at IS NULL OR p_cosignal_grade IS NULL OR p_cosignal_grade NOT IN ('attested', 'unattestable')
     OR p_cosignal_fix_id IS NULL OR p_cosignal_evidence_id IS NULL OR p_at < v_now - interval '7 days' OR p_at > v_now + interval '5 minutes' THEN
    RAISE EXCEPTION 'marker_cosignal_attach_for_actor: invalid arguments (a facility, a qualifying co-signal and a time within 7 days)' USING ERRCODE = '22023';
  END IF;

  -- The earliest awaiting scan of THIS player at THIS facility whose window holds the fix. Explicit filters on the bound uid (the HARD RULE), and the row lock.
  SELECT p.ref_id, p.method INTO v_ref, v_method
  FROM app.purchase_evidence p
  WHERE p.user_id = v_uid AND p.facility_id = p_facility_id AND p.status = 'pending'
    AND p.cosignal ? 'awaiting'
    AND (p.cosignal -> 'awaiting' ->> 'from')::timestamptz <= p_at
    AND p_at <= (p.cosignal -> 'awaiting' ->> 'to')::timestamptz
    AND v_now <= (p.cosignal -> 'awaiting' ->> 'until')::timestamptz
  ORDER BY p.created_at, p.id
  LIMIT 1;
  IF NOT FOUND THEN
    o_result := 'no_pending_purchase';
    RETURN NEXT;
    RETURN;
  END IF;

  IF p_cosignal_grade = 'attested' THEN
    v_pstatus := 'valid';
    v_cstatus := 'credited';
  ELSE
    v_pstatus := 'held_review';
    v_cstatus := 'held_review';
  END IF;
  v_cosignal := pg_catalog.jsonb_build_object('fixId', p_cosignal_fix_id, 'grade', p_cosignal_grade, 'capturedAt', pg_catalog.to_char(p_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'), 'evidenceId', p_cosignal_evidence_id);

  FOR v_row IN
    SELECT p.id, p.trail_id
    FROM app.purchase_evidence p
    WHERE p.user_id = v_uid AND p.facility_id = p_facility_id AND p.status = 'pending' AND p.method = v_method AND p.ref_id IS NOT DISTINCT FROM v_ref
      AND p.cosignal ? 'awaiting'
    ORDER BY p.trail_id, p.id
    FOR UPDATE
  LOOP
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('marker-credit:' || v_uid::text || ':' || v_row.trail_id || ':' || p_facility_id, 0));
    UPDATE app.purchase_evidence p SET status = v_pstatus::app.purchase_status, cosignal = v_cosignal WHERE p.id = v_row.id AND p.user_id = v_uid;

    -- The credit of this purchase: a pending one linked to it (the scan wrote it, or the staff lane did), else the player's existing credited credit for this shop (the scan found
    -- the player already credited), else a NEW credit (the staff lane inserted the purchase row alone). Every statement filters by the bound uid.
    v_credit := NULL;
    v_credit_status := v_cstatus;
    v_existing_credit := NULL;
    IF v_cstatus = 'credited' THEN
      SELECT c.id INTO v_existing_credit FROM app.marker_credit c WHERE c.user_id = v_uid AND c.trail_id = v_row.trail_id AND c.facility_id = p_facility_id AND c.status = 'credited';
    END IF;
    SELECT c.id INTO v_credit FROM app.marker_credit c WHERE c.purchase_evidence_id = v_row.id AND c.user_id = v_uid AND c.status = 'pending';
    IF v_credit IS NOT NULL THEN
      IF v_existing_credit IS NOT NULL THEN
        -- the player became credited for this shop through another scan while this one waited: this pending credit is redundant
        UPDATE app.marker_credit c SET status = 'void' WHERE c.id = v_credit AND c.user_id = v_uid;
        v_credit := v_existing_credit;
        v_credit_status := 'credited';
      ELSE
        UPDATE app.marker_credit c SET status = v_cstatus::app.credit_status WHERE c.id = v_credit AND c.user_id = v_uid;
      END IF;
    ELSIF v_existing_credit IS NOT NULL THEN
      v_credit := v_existing_credit;
      v_credit_status := 'credited';
    ELSIF NOT EXISTS (SELECT 1 FROM app.marker_credit c WHERE c.purchase_evidence_id = v_row.id AND c.user_id = v_uid) THEN
      INSERT INTO app.marker_credit (user_id, trail_id, facility_id, purchase_evidence_id, status)
      VALUES (v_uid, v_row.trail_id, p_facility_id, v_row.id, v_cstatus::app.credit_status)
      RETURNING id INTO v_credit;
    END IF;

    v_any := true;
    o_result := 'attached';
    o_purchase_id := v_row.id;
    o_trail_id := v_row.trail_id;
    o_purchase_status := v_pstatus;
    o_credit_id := v_credit;
    o_credit_status := v_credit_status;
    RETURN NEXT;
  END LOOP;
  IF NOT v_any THEN
    o_result := 'no_pending_purchase';
    o_purchase_id := NULL;
    o_trail_id := NULL;
    o_purchase_status := NULL;
    o_credit_id := NULL;
    o_credit_status := NULL;
    RETURN NEXT;
  END IF;
END;
$$;

-- 6f. EXECUTE grants. PUBLIC first (private_definer-created functions default to PUBLIC), then exactly the roles below. The derivation core: nobody.
REVOKE EXECUTE ON FUNCTION private.course_pin_derive(text, date, integer) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.course_qr_public_key_for_actor(text, text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.course_pin_attempt_for_actor(text, text, timestamptz) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.marker_scan_for_actor(text, text, text, text, text, timestamptz, text, text, uuid) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.marker_cosignal_attach_for_actor(text, timestamptz, text, text, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.course_qr_public_key_for_actor(text, text) TO edge_actor;
GRANT EXECUTE ON FUNCTION private.course_pin_attempt_for_actor(text, text, timestamptz) TO edge_actor;
GRANT EXECUTE ON FUNCTION private.marker_scan_for_actor(text, text, text, text, text, timestamptz, text, text, uuid) TO edge_actor;
GRANT EXECUTE ON FUNCTION private.marker_cosignal_attach_for_actor(text, timestamptz, text, text, uuid) TO edge_actor;

COMMENT ON FUNCTION private.course_pin_derive(text, date, integer) IS
  '0046. The ONLY reader of Vault secret course_pin_pepper: pin = LPAD((first 4 bytes of HMAC-SHA256(pepper, ''golfraven/course-pin/v1'' || 0x00 || facility_id || 0x00 || YYYY-MM-DD || 0x00 || int4send(pin_epoch)) as an unsigned big-endian integer) MOD 10000, 4, ''0''). No role has EXECUTE; the staff lane (S2b) wraps it behind a scope check. The pepper is never returned.';
COMMENT ON FUNCTION private.course_qr_public_key_for_actor(text, text) IS
  '0046. edge_actor only. The PUBLIC Ed25519 key of a kid for rotating_token | printed_qr (zero rows when unknown, a revoked flag when revoked). Public data; the bound actor is required so it cannot be read outside a request.';
COMMENT ON FUNCTION private.course_pin_attempt_for_actor(text, text, timestamptz) IS
  '0046. edge_actor only. Q2 PIN gate with the failure counters: ok | wrong | locked (the 6th attempt of a user at a facility on a facility-local date, whatever its PIN) | no_facility | no_programme. The 30th wrong PIN at a facility on a date rotates its PIN (pin_epoch + 1) and writes app.course_pin_alarm. Returns, never raises, so a refusal commits.';
COMMENT ON FUNCTION private.marker_scan_for_actor(text, text, text, text, text, timestamptz, text, text, uuid) IS
  '0046. edge_actor only. The course-QR scan of the BOUND actor: validates the token / printed QR + PIN, the 120 s rule against the fix time, single use; writes purchase_evidence (course_qr) + marker_credit per eligible trail: valid/credited (attested co-signal), held_review (unattestable), pending (none; cosignal.awaiting holds the window). Refusals are returned statuses, written before any write.';
COMMENT ON FUNCTION private.marker_cosignal_attach_for_actor(text, timestamptz, text, text, uuid) IS
  '0046. edge_actor only. The player''s co-signal intake: ties a qualifying fix to the bound actor''s own pending purchase at that facility whose cosignal.awaiting window holds the fix (and whose 7-day deadline has not passed). Method-agnostic: the S3 offline-code staff_scan row plugs in by carrying that window.';

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

-- ============================================================================
-- 7. Registries
-- ============================================================================
-- 7a. private.definer_policy_allowlist (FORCE RLS, no policy for the migrating role: the temporary, self-dropped CURRENT_USER policy 0035 / 0039 / 0045 use).
GRANT INSERT, UPDATE ON private.definer_policy_allowlist TO CURRENT_USER;
CREATE POLICY current_user_seed_definer_policy_allowlist_0046 ON private.definer_policy_allowlist
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
INSERT INTO private.definer_policy_allowlist (schema_name, table_name, policy_name, command, scoped, note) VALUES
  ('app', 'course_qr_key', 'pd_marker_scan_key_read', 'SELECT', true, 'course_qr_public_key_for_actor: the PUBLIC verification keys; requires a bound actor, the definer filters by (purpose, kid)'),
  ('app', 'course_pin_alarm', 'pd_marker_scan_alarm_select', 'SELECT', true, 'course_pin_attempt_for_actor: INSERT ... ON CONFLICT DO NOTHING reads the arbiter columns of the alarm table (facility, date, epoch); no personal data; requires a bound actor'),
  ('app', 'course_pin_alarm', 'pd_marker_scan_alarm_insert', 'INSERT', true, 'course_pin_attempt_for_actor: the one alarm row of the 30th wrong PIN of an epoch; requires a bound actor; no user id is stored'),
  ('app', 'facility_programme', 'pd_marker_scan_facility_programme_epoch', 'UPDATE', true, 'course_pin_attempt_for_actor: pin_epoch + 1 on the facility''s own programme rows (UPDATE(pin_epoch) column grant only; monotonic trigger); requires a bound actor, the definer names the facility'),
  ('app', 'catalog_facility', 'pd_marker_scan_facility_read', 'SELECT', true, 'the scan reads the facility''s tz (SELECT(id, tz) column grant only); public catalog data; requires a bound actor'),
  ('app', 'trail_programme', 'pd_marker_scan_trail_programme_read', 'SELECT', true, 'the scan reads which trails run an active any_purchase programme (SELECT(trail_id, status, marker_source) only); requires a bound actor'),
  ('app', 'facility_qr', 'pd_marker_scan_facility_qr_read', 'SELECT', true, 'marker_scan_for_actor: is the printed QR registered for the facility and not revoked (qr_kid); requires a bound actor, the definer names the facility'),
  ('app', 'course_qr_token', 'pd_marker_scan_token_select', 'SELECT', true, 'marker_scan_for_actor: the token row by nonce hash, to tell unknown / wrong facility / used from consumable; visible whoever used it (a 409 must be told from a 422), the definer returns only the FACT of use'),
  ('app', 'course_qr_token', 'pd_marker_scan_token_update', 'UPDATE', true, 'marker_scan_for_actor: marks a token used BY THE BOUND ACTOR (WITH CHECK used_by_user = private.actor_uid()); UPDATE(used_by_user, used_at) only; write-once trigger'),
  ('app', 'purchase_evidence', 'pd_marker_scan_purchase_select', 'SELECT', true, 'the scan and the co-signal intake read the BOUND actor''s own purchase rows only (user_id = private.actor_uid())'),
  ('app', 'purchase_evidence', 'pd_marker_scan_purchase_insert', 'INSERT', true, 'marker_scan_for_actor writes the BOUND actor''s own course_qr purchase row (column-listed INSERT grant)'),
  ('app', 'purchase_evidence', 'pd_marker_scan_purchase_update', 'UPDATE', true, 'marker_cosignal_attach_for_actor completes the BOUND actor''s own pending purchase (UPDATE(status, cosignal) only)'),
  ('app', 'marker_credit', 'pd_marker_scan_credit_select', 'SELECT', true, 'the scan and the co-signal intake read the BOUND actor''s own credits only (user_id = private.actor_uid())'),
  ('app', 'marker_credit', 'pd_marker_scan_credit_insert', 'INSERT', true, 'marker_scan_for_actor writes the BOUND actor''s own credit (column-listed INSERT grant)'),
  ('app', 'marker_credit', 'pd_marker_scan_credit_update', 'UPDATE', true, 'marker_cosignal_attach_for_actor completes / voids the BOUND actor''s own pending credit (UPDATE(status) only)');
UPDATE private.definer_policy_allowlist al
SET using_expr = pg_get_expr(pol.polqual, pol.polrelid),
    with_check_expr = pg_get_expr(pol.polwithcheck, pol.polrelid)
FROM pg_policy pol
JOIN pg_class cl ON cl.oid = pol.polrelid
JOIN pg_namespace n ON n.oid = cl.relnamespace
WHERE n.nspname = al.schema_name AND cl.relname = al.table_name AND pol.polname = al.policy_name
  AND al.policy_name LIKE 'pd\_marker\_scan\_%';
DROP POLICY current_user_seed_definer_policy_allowlist_0046 ON private.definer_policy_allowlist;
REVOKE INSERT, UPDATE ON private.definer_policy_allowlist FROM CURRENT_USER;

-- 7b. private.function_inventory (the 0017 INSERT policy is still in place)
INSERT INTO private.function_inventory
  (schema_name, function_name, identity_args, expected_anon, expected_authenticated, expected_service_role, expected_edge_actor, expected_edge_system, note)
VALUES
  ('app', 'facility_programme_pin_epoch_monotonic', '', false, false, false, false, false,
   '0046: trigger function (app.facility_programme_pin_epoch_monotonic_trg, BEFORE UPDATE OF pin_epoch) -- the PIN epoch never decreases (a lower one would revive a rotated-out PIN); never EXECUTEd directly by any role'),
  ('app', 'course_qr_token_single_use', '', false, false, false, false, false,
   '0046: trigger function (app.course_qr_token_single_use_trg, BEFORE UPDATE) -- a used token''s used_at / used_by_user never change (single use, plan §9.2); never EXECUTEd directly by any role'),
  ('private', 'course_pin_derive', 'p_facility_id text, p_local_date date, p_pin_epoch integer', false, false, false, false, false,
   '0046: the ONLY reader of Vault secret course_pin_pepper; derives the daily PIN for ANY (facility, date, epoch) it is handed, so NO role has EXECUTE: reachable only through the SECURITY DEFINER wrappers (the player-lane attempt and scan, and the staff-lane wrapper S2b adds)'),
  ('private', 'course_qr_public_key_for_actor', 'p_kid text, p_purpose text', false, false, false, true, false,
   '0046: edge_actor only; the PUBLIC Ed25519 key of a kid (rotating_token | printed_qr); public data, a bound actor is required'),
  ('private', 'course_pin_attempt_for_actor', 'p_facility_id text, p_pin text, p_at timestamp with time zone', false, false, false, true, false,
   '0046: edge_actor only; the Q2 PIN gate of the BOUND actor with the per-user (5) and per-facility (30 -> rotate + alarm) failure counters; returns ok | wrong | locked | no_facility | no_programme, never a PIN'),
  ('private', 'marker_scan_for_actor', 'p_facility_id text, p_variant text, p_nonce_hash text, p_qr_kid text, p_pin text, p_at timestamp with time zone, p_cosignal_grade text, p_cosignal_fix_id text, p_cosignal_evidence_id uuid', false, false, false, true, false,
   '0046: edge_actor only; the course-QR scan of the BOUND actor: token / printed QR + PIN, the 120 s rule against the fix time, single use; purchase_evidence + marker_credit (valid/credited | held_review | pending); refusals are returned statuses'),
  ('private', 'marker_cosignal_attach_for_actor', 'p_facility_id text, p_at timestamp with time zone, p_cosignal_grade text, p_cosignal_fix_id text, p_cosignal_evidence_id uuid', false, false, false, true, false,
   '0046: edge_actor only; the player co-signal intake: ties a qualifying fix to the BOUND actor''s own pending purchase whose cosignal.awaiting window holds it (the seam the S3 offline-code scan plugs into)');

-- ============================================================================
-- 8. Proofs (the migration stops if any of them fails)
-- ============================================================================
DO $assert_0046$
DECLARE
  v_fn text;
BEGIN
  IF has_table_privilege('edge_actor', 'app.course_qr_key', 'SELECT') OR has_table_privilege('edge_actor', 'app.course_pin_alarm', 'SELECT')
     OR has_any_column_privilege('edge_actor', 'app.course_qr_key', 'SELECT,INSERT,UPDATE,REFERENCES') OR has_any_column_privilege('edge_actor', 'app.course_pin_alarm', 'SELECT,INSERT,UPDATE,REFERENCES')
     OR has_table_privilege('edge_system', 'app.course_qr_key', 'SELECT') OR has_table_privilege('edge_system', 'app.course_pin_alarm', 'SELECT')
     OR has_table_privilege('authenticated', 'app.course_qr_key', 'SELECT') OR has_table_privilege('authenticated', 'app.course_pin_alarm', 'SELECT')
     OR has_table_privilege('anon', 'app.course_qr_key', 'SELECT') OR has_table_privilege('anon', 'app.course_pin_alarm', 'SELECT') THEN
    RAISE EXCEPTION '0046: no edge or client role may hold any privilege on app.course_qr_key or app.course_pin_alarm (every path is a definer)';
  END IF;
  IF NOT (SELECT relforcerowsecurity AND relrowsecurity FROM pg_class WHERE oid = 'app.course_qr_key'::regclass)
     OR NOT (SELECT relforcerowsecurity AND relrowsecurity FROM pg_class WHERE oid = 'app.course_pin_alarm'::regclass) THEN
    RAISE EXCEPTION '0046: the new tables must have ENABLE and FORCE ROW LEVEL SECURITY';
  END IF;
  FOREACH v_fn IN ARRAY ARRAY['app.purchase_evidence', 'app.marker_credit', 'app.course_qr_token', 'app.facility_qr', 'app.facility_programme', 'app.trail_programme', 'app.catalog_facility'] LOOP
    IF NOT (SELECT relforcerowsecurity FROM pg_class WHERE oid = v_fn::regclass) THEN
      RAISE EXCEPTION '0046: % must keep FORCE ROW LEVEL SECURITY', v_fn;
    END IF;
  END LOOP;
  IF has_function_privilege('edge_actor', 'private.course_pin_derive(text, date, integer)', 'EXECUTE')
     OR has_function_privilege('edge_system', 'private.course_pin_derive(text, date, integer)', 'EXECUTE')
     OR has_function_privilege('service_role', 'private.course_pin_derive(text, date, integer)', 'EXECUTE')
     OR has_function_privilege('authenticated', 'private.course_pin_derive(text, date, integer)', 'EXECUTE')
     OR has_function_privilege('anon', 'private.course_pin_derive(text, date, integer)', 'EXECUTE') THEN
    RAISE EXCEPTION '0046: no role may EXECUTE private.course_pin_derive (the one reader of the PIN pepper)';
  END IF;
  IF NOT has_function_privilege('edge_actor', 'private.course_pin_attempt_for_actor(text, text, timestamptz)', 'EXECUTE')
     OR NOT has_function_privilege('edge_actor', 'private.marker_scan_for_actor(text, text, text, text, text, timestamptz, text, text, uuid)', 'EXECUTE')
     OR NOT has_function_privilege('edge_actor', 'private.marker_cosignal_attach_for_actor(text, timestamptz, text, text, uuid)', 'EXECUTE')
     OR NOT has_function_privilege('edge_actor', 'private.course_qr_public_key_for_actor(text, text)', 'EXECUTE') THEN
    RAISE EXCEPTION '0046: edge_actor must EXECUTE the four player-lane wrappers';
  END IF;
  IF has_function_privilege('edge_system', 'private.marker_scan_for_actor(text, text, text, text, text, timestamptz, text, text, uuid)', 'EXECUTE')
     OR has_function_privilege('anon', 'private.marker_scan_for_actor(text, text, text, text, text, timestamptz, text, text, uuid)', 'EXECUTE')
     OR has_function_privilege('authenticated', 'private.marker_scan_for_actor(text, text, text, text, text, timestamptz, text, text, uuid)', 'EXECUTE')
     OR has_function_privilege('service_role', 'private.marker_scan_for_actor(text, text, text, text, text, timestamptz, text, text, uuid)', 'EXECUTE') THEN
    RAISE EXCEPTION '0046: only edge_actor may EXECUTE private.marker_scan_for_actor';
  END IF;
  IF has_column_privilege('edge_actor', 'app.facility_programme', 'pin_epoch', 'UPDATE') OR has_table_privilege('edge_actor', 'app.purchase_evidence', 'INSERT')
     OR has_table_privilege('edge_actor', 'app.marker_credit', 'INSERT') OR has_any_column_privilege('edge_actor', 'app.course_qr_token', 'UPDATE') THEN
    RAISE EXCEPTION '0046: edge_actor must hold no write privilege on the tables a scan writes (every write is a definer)';
  END IF;
END
$assert_0046$;
