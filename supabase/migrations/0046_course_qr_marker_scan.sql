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
--   6. private.course_pin_derive, course_pin_attempt_for_actor, marker_scan_for_actor, marker_cosignal_attach_for_actor, course_qr_public_key_for_actor, and the helpers
--      course_pin_from_key, course_pin_matches, course_pin_epoch_at, course_pin_epoch_log_write, marker_cosignal_check (no EXECUTE for any role).
--   7. The registries (function inventory, definer policy allow-list) and proofs.
--   8. app.course_pin_epoch_log (+ its trigger on facility_programme.pin_epoch): WHEN each PIN epoch took effect, so the PIN of a fix is judged under the epoch live at the FIX'S
--      instant. A rotation (the failure alarm, S2b's "Rotate PIN") must not turn the honest, queued, printed-QR scans of the last 7 days into wrong guesses.
--   9. private.course_pin_proof: "the PIN gate passed in this transaction, for this instant". The scan REFUSES a printed-QR scan without it (so it is never an uncounted PIN oracle) and CONSUMES it;
--      a deferred constraint trigger deletes the backend's rows at COMMIT, so the table is empty at rest. app.course_pin_pepper_epoch: when the current pepper took effect (the operator writes it).
--  10. The co-signal is tied to its evidence row by the DATABASE (marker_cosignal_check), for the scan and for the intake: a grade, a fix id and an evidence id are claims until the
--      bound actor's own row has been read back (source, fix id, facility, status, grade, local date, captured time, the derived fix that QUALIFIES, used by no other scan).
--  11. The scan instant is the fix's ONLY when a co-signal backs it; without one the database refuses a time more than 5 minutes from now.

-- THE PIN'S INSTANT, in one place (M1): the PIN for (facility, local date of p_at, the epoch live at p_at, the pepper in effect at p_at). A rotation changes the PIN of scans made AFTER it only.
--   * epoch: app.course_pin_epoch_log, written by a trigger on any rise of facility_programme.pin_epoch. Two rotations on one day give three epochs for that date; each scan is judged under
--     the epoch live when its fix was captured. A PIN of a rotated-out epoch tried for a LATER instant is a wrong guess and counts (a free oracle would let it be brute-forced).
--   * pepper: Vault secret `course_pin_pepper` (current) and, optionally, `course_pin_pepper_previous`, with the effective time of the current one in app.course_pin_pepper_epoch (written by the operator's
--     rotation procedure, see private.course_pin_matches). An instant before the latest effective_from is judged under the previous pepper. A COMPROMISE rotation keeps no previous pepper: back-dated PINs
--     from before it then no longer verify (the honest consequence, documented rather than hidden).
--   * RESIDUAL (documented, not closed): the instant is the CLIENT-reported capture time of a fix that qualifies as a co-signal, bounded by the check-in challenge's window (a prefetched challenge lives 24 h).
--     So for up to about 24 h after a rotation, a holder of a prefetched challenge issued BEFORE it can back-date a fix to before the rotation and have the OLD epoch's PIN (and, while `course_pin_pepper_previous`
--     exists, the previous pepper's) verify. An instant AFTER the rotation is judged under the new epoch: an old PIN tried for it is a counted wrong guess.
--
-- RULES FOLLOWED (docs/security/p3-money-path-requirements.md, "HARD RULE"): every private_definer policy added here is keyed on the actor BINDING (private.actor_uid()), never on a
-- settable GUC; every `_for_actor` definer filters by the bound uid in its own SQL, on every statement that touches a caller-visible row, and names the explicit check at the statement.
-- The wide visibility the token / QR / programme READ policies give (any row, to any bound actor's definer) is NOT an ownership boundary: the definer's own predicates are
-- (the facility, the nonce hash, the kid), and no definer here returns another account's value (the token's used_by_user is never returned, only the fact that it was used).
--
-- DEPLOY: apply this migration, THEN create the Vault secret (`select vault.create_secret('<random, >= 32 bytes>', 'course_pin_pepper')`), THEN register the Ed25519 public
-- keys (S2b's key ceremony; until a key exists every QR is `invalid_qr`: fail closed), THEN deploy the Edge code. Until the pepper exists the PIN functions raise 55000
-- and the endpoint answers 503 `course_pin_unavailable`; nothing else is affected. ROTATING the pepper changes every facility's PIN at once (an incident response; see the previous-pepper rule above; plan §4.8's
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

-- 3b. app.course_pin_epoch_log: WHEN each epoch took effect. The PIN of a past fix date is derived under the epoch that was LIVE when the fix was taken, not under the
-- facility's current one: a scan queued offline (plan §7.6 G2-03) and uploaded after a rotation must still verify, and a rotation (an attack response) must not make honest
-- back-dated PINs count as wrong guesses. Written ONLY by the trigger below (any rotation, by whichever definer, is logged); read by private.course_pin_epoch_at.
CREATE TABLE app.course_pin_epoch_log (
  facility_id text NOT NULL REFERENCES app.catalog_facility (id),
  pin_epoch integer NOT NULL CHECK (pin_epoch > 0),
  previous_epoch integer NOT NULL CHECK (previous_epoch >= 0 AND previous_epoch < pin_epoch),
  effective_from timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (facility_id, pin_epoch)
);
COMMENT ON TABLE app.course_pin_epoch_log IS
  '0046. One row per PIN rotation of a facility: the new epoch, the one it replaced and the instant it took effect. Holds no user id and no PIN. Written only by the trigger on app.facility_programme.pin_epoch (private.course_pin_epoch_log_write); read by private.course_pin_epoch_at. A facility with no row has never rotated since its programme rows were created. Retention (a purge step) is a follow-up.';
ALTER TABLE app.course_pin_epoch_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.course_pin_epoch_log FORCE ROW LEVEL SECURITY;
REVOKE ALL ON app.course_pin_epoch_log FROM PUBLIC, anon, authenticated;
GRANT SELECT ON app.course_pin_epoch_log TO service_role;
GRANT INSERT, SELECT ON app.course_pin_epoch_log TO private_definer;
-- SELECT: unconditional for private_definer too, because INSERT ... ON CONFLICT also evaluates the SELECT policy and an operator's rotation has no bound actor. The table holds no personal data.
CREATE POLICY pd_marker_scan_epoch_log_select ON app.course_pin_epoch_log FOR SELECT TO private_definer USING (true);
-- INSERT: the logging trigger runs as SECURITY DEFINER whoever rotates (a bound actor, or an operator with no actor bound), so the policy cannot require a binding. The only writer is
-- that trigger function; no other definer inserts here (a pgTAP cell pins that no function names the table but the trigger function and the reader).
CREATE POLICY pd_marker_scan_epoch_log_insert ON app.course_pin_epoch_log FOR INSERT TO private_definer WITH CHECK (true);

-- 3c. private.course_pin_proof: "the PIN gate passed in THIS transaction, for THIS instant". private.course_pin_attempt_for_actor writes a row when a PIN is right; private.marker_scan_for_actor
-- REFUSES a printed-QR scan without one for the same actor, facility, local date AND INSTANT (so the scan can never be called as an uncounted PIN oracle, and the gate and the scan never judge
-- two different instants), and CONSUMES it (deletes it) when it accepts the scan. UNLOGGED does not mean transaction-scoped, so the lifetime is ENFORCED, not assumed: a DEFERRED constraint
-- trigger (6g) deletes every row of this backend at COMMIT, so no committed path leaves a row: not a scan, not a gate that passed with no scan after it, not another actor's. The table is
-- empty at rest (a pgTAP cell and a Deno test commit real transactions and read it back), so it holds nothing to purge on `DELETE /v1/me`.
CREATE UNLOGGED TABLE private.course_pin_proof (
  backend_pid int NOT NULL,
  xact xid8 NOT NULL,
  actor_uid uuid NOT NULL,
  facility_id text NOT NULL,
  local_date date NOT NULL,
  -- the instant the gate judged the PIN at; the scan must present the SAME p_at
  pin_at timestamptz NOT NULL,
  PRIMARY KEY (backend_pid, xact, actor_uid, facility_id, local_date)
);
COMMENT ON TABLE private.course_pin_proof IS
  '0046. A right PIN passed the failure counters for (actor, facility, local date, instant) in the transaction whose id it stores. Written by course_pin_attempt_for_actor, required and consumed by marker_scan_for_actor for a printed-QR scan; a deferred constraint trigger deletes every row of the backend at COMMIT, so the table is empty at rest (rows of a rolled-back transaction vanish with it). Holds an actor id only inside one transaction.';
ALTER TABLE private.course_pin_proof ENABLE ROW LEVEL SECURITY;
ALTER TABLE private.course_pin_proof FORCE ROW LEVEL SECURITY;
REVOKE ALL ON private.course_pin_proof FROM PUBLIC, anon, authenticated;
GRANT SELECT, INSERT, DELETE ON private.course_pin_proof TO private_definer;
-- Keyed on THIS BACKEND and the bound ACTOR (never a settable GUC). DELETE is keyed on the backend only: the proof's own expiry deletes the backend's rows at COMMIT and a row is only ever
-- written by the bound actor of the transaction that ends there.
CREATE POLICY pd_marker_scan_proof_select ON private.course_pin_proof FOR SELECT TO private_definer USING (backend_pid = pg_backend_pid() AND actor_uid = private.actor_uid());
CREATE POLICY pd_marker_scan_proof_insert ON private.course_pin_proof FOR INSERT TO private_definer WITH CHECK (backend_pid = pg_backend_pid() AND actor_uid = private.actor_uid());
CREATE POLICY pd_marker_scan_proof_delete ON private.course_pin_proof FOR DELETE TO private_definer USING (backend_pid = pg_backend_pid());

-- 3d. app.course_pin_pepper_epoch: WHEN each pepper took effect, written by the operator's rotation procedure (never inferred from Vault's created_at / updated_at, which move on any
-- vault.update_secret, metadata edits included). An instant before the latest row's effective_from is judged under the previous pepper (course_pin_matches). No personal data.
CREATE TABLE app.course_pin_pepper_epoch (
  effective_from timestamptz PRIMARY KEY,
  recorded_at timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE app.course_pin_pepper_epoch IS
  '0046. One row per pepper rotation that keeps the old pepper as Vault secret course_pin_pepper_previous: the instant the NEW pepper took effect. Written by the operator (service_role) in the same transaction as the Vault update; read by private.course_pin_matches. A COMPROMISE rotation writes no row and keeps no previous pepper. Holds no user id and no secret.';
ALTER TABLE app.course_pin_pepper_epoch ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.course_pin_pepper_epoch FORCE ROW LEVEL SECURITY;
REVOKE ALL ON app.course_pin_pepper_epoch FROM PUBLIC, anon, authenticated;
GRANT SELECT, INSERT ON app.course_pin_pepper_epoch TO service_role;
GRANT SELECT ON app.course_pin_pepper_epoch TO private_definer;
CREATE POLICY pd_marker_scan_pepper_epoch_select ON app.course_pin_pepper_epoch FOR SELECT TO private_definer USING (true);

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
-- A course_qr scan is unique per (user, trail, ref_id): a rotating token's ref is its nonce hash (single use anyway), a printed-QR scan's ref is 'pin:<facility>:<date>' (no epoch: a rotation must not allow a second same-day purchase),
-- so the same player scanning the same shop twice on one local day is a duplicate (409), not a second purchase.
CREATE UNIQUE INDEX purchase_evidence_course_qr_ref_uniq ON app.purchase_evidence (user_id, trail_id, ref_id) WHERE method = 'course_qr' AND ref_id IS NOT NULL;

-- A co-signal's evidence row is used by AT MOST ONE scan (per trail: one scan writes one row per eligible trail, all carrying the same evidence id). The race-proof backstop of the
-- definers' own "already used" check.
CREATE UNIQUE INDEX purchase_evidence_cosignal_evidence_uniq ON app.purchase_evidence (trail_id, (cosignal ->> 'evidenceId')) WHERE cosignal ? 'evidenceId';

GRANT INSERT (user_id, facility_id, trail_id, method, qr_variant, ref_id, offline, cosignal, local_date, status) ON app.purchase_evidence TO private_definer;
GRANT UPDATE (status, cosignal) ON app.purchase_evidence TO private_definer;
CREATE POLICY pd_marker_scan_purchase_select ON app.purchase_evidence FOR SELECT TO private_definer USING (user_id = private.actor_uid());
CREATE POLICY pd_marker_scan_purchase_insert ON app.purchase_evidence FOR INSERT TO private_definer WITH CHECK (user_id = private.actor_uid());
CREATE POLICY pd_marker_scan_purchase_update ON app.purchase_evidence FOR UPDATE TO private_definer USING (user_id = private.actor_uid()) WITH CHECK (user_id = private.actor_uid());

-- The co-signal's evidence row, read back by the DATABASE (the Edge wrote it; the database re-checks it, plan: "everything the database CAN check it checks again"): the bound actor's own
-- rows only. app.evidence already grants private_definer SELECT (0016) behind GUC-keyed windows; this is the binding-keyed one a `_for_actor` definer needs.
CREATE POLICY pd_marker_scan_evidence_select ON app.evidence FOR SELECT TO private_definer USING (user_id = private.actor_uid());

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

-- 6a. THE derivation. The pure core takes its key as an argument and reads nothing; the ONLY readers of the Vault pepper are private.course_pin_derive (the CURRENT pepper) and
-- private.course_pin_matches (the current one, and the previous one for fix times before the current one took effect). No role is granted EXECUTE on any of them: they derive for ANY
-- (facility, date, epoch) they are handed, so they must never be reachable from a session (the staff lane's wrapper, S2b, checks the caller's scope first). The failure message names
-- no key material.
CREATE FUNCTION private.course_pin_from_key(p_key text, p_facility_id text, p_local_date date, p_pin_epoch integer)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_mac bytea;
  v_n bigint;
BEGIN
  IF p_key IS NULL OR p_facility_id IS NULL OR pg_catalog.btrim(p_facility_id) = '' OR p_local_date IS NULL OR p_pin_epoch IS NULL OR p_pin_epoch < 0 THEN
    RAISE EXCEPTION 'course_pin_from_key: a key, a facility, a date and an epoch of at least 0 are required' USING ERRCODE = '22023';
  END IF;
  v_mac := public.hmac(
    pg_catalog.convert_to('golfraven/course-pin/v1', 'UTF8')
      || pg_catalog.decode('00', 'hex')
      || pg_catalog.convert_to(p_facility_id, 'UTF8')
      || pg_catalog.decode('00', 'hex')
      || pg_catalog.convert_to(pg_catalog.to_char(p_local_date, 'YYYY-MM-DD'), 'UTF8')
      || pg_catalog.decode('00', 'hex')
      || pg_catalog.int4send(p_pin_epoch),
    pg_catalog.convert_to(p_key, 'UTF8'),
    'sha256');
  v_n := (pg_catalog.get_byte(v_mac, 0)::bigint * 16777216) + (pg_catalog.get_byte(v_mac, 1)::bigint * 65536) + (pg_catalog.get_byte(v_mac, 2)::bigint * 256) + pg_catalog.get_byte(v_mac, 3)::bigint;
  RETURN pg_catalog.lpad((v_n % 10000)::text, 4, '0');
END;
$$;

CREATE FUNCTION private.course_pin_derive(p_facility_id text, p_local_date date, p_pin_epoch integer)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_key text;
BEGIN
  IF p_facility_id IS NULL OR pg_catalog.btrim(p_facility_id) = '' OR p_local_date IS NULL OR p_pin_epoch IS NULL OR p_pin_epoch < 0 THEN
    RAISE EXCEPTION 'course_pin_derive: a facility, a date and an epoch of at least 0 are required' USING ERRCODE = '22023';
  END IF;
  SELECT s.decrypted_secret INTO v_key FROM vault.decrypted_secrets s WHERE s.name = 'course_pin_pepper';
  IF v_key IS NULL OR pg_catalog.octet_length(pg_catalog.convert_to(v_key, 'UTF8')) < 32 THEN
    RAISE EXCEPTION 'course_pin_derive: the course PIN pepper is not provisioned in Vault' USING ERRCODE = '55000';
  END IF;
  RETURN private.course_pin_from_key(v_key, p_facility_id, p_local_date, p_pin_epoch);
END;
$$;

-- Does p_pin equal the PIN that was DISPLAYED for (facility, local date, epoch) at the instant p_at? A pepper rotation (an incident response) would otherwise make every queued back-dated
-- scan of the last 7 days a wrong guess. THE OPERATOR'S PROCEDURE for a rotation that is NOT a compromise, in ONE transaction: (1) create the Vault secret `course_pin_pepper_previous` holding the
-- OLD pepper (>= 32 bytes); (2) vault.update_secret the current one; (3) INSERT INTO app.course_pin_pepper_epoch (effective_from) VALUES (now()). An instant before the latest effective_from is then
-- judged under the previous pepper. Delete `course_pin_pepper_previous` after 7 days (the longest a scan can be queued): while it exists, a leaked OLD pepper keeps verifying for instants before
-- effective_from. For a COMPROMISE rotation do NOT keep the old pepper anywhere: replace the current one and write nothing else; every back-dated PIN from before it is then a wrong guess (the honest
-- offline players re-scan). The effective time is the table's, never Vault's created_at / updated_at (which move on any vault.update_secret, metadata edits included). One previous pepper is
-- kept: two rotations inside 7 days leave the older queued scans judged under the wrong pepper. The current pepper's absence is the 55000.
CREATE FUNCTION private.course_pin_matches(p_facility_id text, p_local_date date, p_pin_epoch integer, p_pin text, p_at timestamptz)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_since timestamptz;
  v_prev text;
BEGIN
  IF p_pin IS NULL OR p_pin !~ '^[0-9]{4}$' OR p_at IS NULL THEN
    RETURN false;
  END IF;
  SELECT pg_catalog.max(e.effective_from) INTO v_since FROM app.course_pin_pepper_epoch e;
  IF v_since IS NOT NULL AND p_at < v_since THEN
    SELECT s.decrypted_secret INTO v_prev FROM vault.decrypted_secrets s WHERE s.name = 'course_pin_pepper_previous';
    IF v_prev IS NOT NULL AND pg_catalog.octet_length(pg_catalog.convert_to(v_prev, 'UTF8')) >= 32 THEN
      RETURN private.course_pin_from_key(v_prev, p_facility_id, p_local_date, p_pin_epoch) = p_pin;
    END IF;
  END IF;
  RETURN private.course_pin_derive(p_facility_id, p_local_date, p_pin_epoch) = p_pin;
END;
$$;

-- The epoch in effect at the facility at the instant p_at: the newest rotation at or before it; before the first logged rotation, the epoch that rotation replaced; with no rotation ever
-- logged, the current epoch (the highest over the facility's programme rows: they are rotated together, and `max` is what a partial rotation must not lower).
CREATE FUNCTION private.course_pin_epoch_at(p_facility_id text, p_at timestamptz)
RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_epoch integer;
BEGIN
  SELECT l.pin_epoch INTO v_epoch FROM app.course_pin_epoch_log l WHERE l.facility_id = p_facility_id AND l.effective_from <= p_at ORDER BY l.effective_from DESC, l.pin_epoch DESC LIMIT 1;
  IF v_epoch IS NOT NULL THEN
    RETURN v_epoch;
  END IF;
  SELECT l.previous_epoch INTO v_epoch FROM app.course_pin_epoch_log l WHERE l.facility_id = p_facility_id ORDER BY l.effective_from ASC, l.pin_epoch ASC LIMIT 1;
  IF v_epoch IS NOT NULL THEN
    RETURN v_epoch;
  END IF;
  SELECT pg_catalog.max(fp.pin_epoch) INTO v_epoch FROM app.facility_programme fp WHERE fp.facility_id = p_facility_id;
  RETURN COALESCE(v_epoch, 0);
END;
$$;

-- The rotation log's only writer. SECURITY DEFINER because the rotation can come from a bound actor (the failure alarm, S2b's "Rotate PIN") or from an operator with none; it logs each
-- (facility, new epoch) once however many programme rows the rotation updates.
CREATE FUNCTION private.course_pin_epoch_log_write() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  INSERT INTO app.course_pin_epoch_log (facility_id, pin_epoch, previous_epoch, effective_from)
  VALUES (NEW.facility_id, NEW.pin_epoch, OLD.pin_epoch, pg_catalog.now())
  ON CONFLICT (facility_id, pin_epoch) DO NOTHING;
  RETURN NEW;
END;
$$;

-- The proof's lifetime. A DEFERRED constraint trigger on private.course_pin_proof runs this at COMMIT: every row of THIS backend goes (whoever's, whichever transaction's), so no committed
-- transaction leaves a proof behind: not a scan (which also consumes its own), not a PIN gate that passed with no scan after it. SECURITY DEFINER because the table has no other writer.
CREATE FUNCTION private.course_pin_proof_expire() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  DELETE FROM private.course_pin_proof pf WHERE pf.backend_pid = pg_catalog.pg_backend_pid();
  RETURN NULL;
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
--   * THE PIN IS JUDGED AT THE FIX'S INSTANT: the PIN for the facility-local date of p_at under the epoch that was live at p_at (private.course_pin_epoch_at), so a scan queued offline
--     and uploaded after a rotation verifies and is NOT counted as a failure (a PIN that was displayed when the fix was taken is not a wrong guess). The Edge passes p_at = the fix's time only
--     when the fix qualified as a co-signal, else now (the scan definer refuses a far-from-now p_at without a co-signal). A PIN of a rotated-out epoch, tried at a time after the rotation, IS
--     a wrong guess and counts: making it free would be an uncounted oracle for brute-forcing a rotated-out PIN.
--   * A RIGHT PIN WRITES A PROOF (private.course_pin_proof) for this transaction and this instant: marker_scan_for_actor refuses a printed-QR scan without one, so no caller can reach the PIN check
--     in the scan without passing the lockout and the counters here (the scan is never an uncounted oracle), and CONSUMES it on use. The proof is deleted at COMMIT whatever happens next (6g).
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
  v_cur integer;
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
  -- v_cur: the facility's CURRENT epoch (the failure counters and a rotation are relative to it); v_epoch: the epoch that was live at the fix's instant (the PIN is judged under it).
  SELECT pg_catalog.max(fp.pin_epoch) INTO v_cur FROM app.facility_programme fp WHERE fp.facility_id = p_facility_id;
  v_epoch := private.course_pin_epoch_at(p_facility_id, p_at);

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

  IF private.course_pin_matches(p_facility_id, v_date, v_epoch, p_pin, p_at) THEN
    -- the proof the scan requires: this transaction, this actor, this facility, this local date, THIS INSTANT. The deferred trigger of 6g deletes every row of this backend at COMMIT, so no
    -- committed transaction leaves one, and a rolled-back one vanishes with its transaction. A second gate for the same facility and date in this transaction REPLACES the first: the proof
    -- is for the LAST instant judged.
    DELETE FROM private.course_pin_proof pf
    WHERE pf.backend_pid = pg_catalog.pg_backend_pid() AND pf.xact = pg_catalog.pg_current_xact_id() AND pf.actor_uid = v_uid AND pf.facility_id = p_facility_id AND pf.local_date = v_date;
    INSERT INTO private.course_pin_proof (backend_pid, xact, actor_uid, facility_id, local_date, pin_at)
    VALUES (pg_catalog.pg_backend_pid(), pg_catalog.pg_current_xact_id(), v_uid, p_facility_id, v_date, p_at);
    o_result := 'ok';
    RETURN NEXT;
    RETURN;
  END IF;

  -- A wrong PIN: count it for the user, then for the facility.
  PERFORM private.hit_rate_limit(v_user_key, interval '1 day', 1000000);
  v_fac_key := 'marker-scan:pin-fail:f:' || p_facility_id || ':' || pg_catalog.to_char(v_today, 'YYYY-MM-DD') || ':' || v_cur::text;
  PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(v_fac_key, 0));
  PERFORM private.hit_rate_limit(v_fac_key, interval '1 day', 1000000);
  SELECT coalesce(pg_catalog.sum(r.count), 0) INTO v_fac_fails FROM private.rate_limit_bucket r WHERE r.bucket_key = v_fac_key;
  IF v_fac_fails = 30 THEN
    -- the 30th wrong PIN of this epoch: rotate (every programme row of the facility, so the PIN stays one value) and alert the operator
    UPDATE app.facility_programme fp SET pin_epoch = v_cur + 1 WHERE fp.facility_id = p_facility_id AND fp.pin_epoch <= v_cur;
    INSERT INTO app.course_pin_alarm (facility_id, local_date, pin_epoch_before, pin_epoch_after, failures)
    VALUES (p_facility_id, v_today, v_cur, v_cur + 1, v_fac_fails::integer)
    ON CONFLICT (facility_id, local_date, pin_epoch_before) DO NOTHING;
  END IF;
  o_result := 'wrong';
  RETURN NEXT;
END;
$$;

-- 6c2. The DATABASE ties a co-signal to its evidence row. The Edge hands over a grade, a fix id and an evidence id; none of them is believed until this function has read the row back:
-- the BOUND actor's own (p_uid is the binding's, passed by the two definers, never a caller argument) accepted, facility-level foreground_checkin row for `fix:<fix id>` at THIS facility, whose
-- stored grade is the one claimed (and not `failed`), whose local date is the scan's, whose captured time (the derived fix in its summary) is p_at, and which no other scan has used.
-- 'ok' | 'cosignal_invalid' | 'cosignal_used'. No EXECUTE for any role: reachable only from the two definers.
CREATE FUNCTION private.marker_cosignal_check(p_uid uuid, p_facility_id text, p_local_date date, p_at timestamptz, p_grade text, p_fix_id text, p_evidence_id uuid)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_row record;
  v_captured text;
  v_fix jsonb;
BEGIN
  IF p_uid IS NULL OR p_uid IS DISTINCT FROM private.actor_uid() THEN
    RAISE EXCEPTION 'marker_cosignal_check: the checked actor is not the bound actor' USING ERRCODE = '42501';
  END IF;
  SELECT e.source::text AS source, e.source_ref, e.facility_id, e.course_id, e.status::text AS status, e.attestation_grade::text AS grade, e.local_date, e.summary
  INTO v_row
  FROM app.evidence e
  WHERE e.id = p_evidence_id AND e.user_id = p_uid;
  IF NOT FOUND THEN
    RETURN 'cosignal_invalid';
  END IF;
  IF v_row.source <> 'foreground_checkin' OR v_row.source_ref <> 'fix:' || p_fix_id OR v_row.facility_id IS DISTINCT FROM p_facility_id OR v_row.course_id IS NOT NULL
     OR v_row.status <> 'accepted' OR v_row.grade <> p_grade OR v_row.local_date <> p_local_date THEN
    RETURN 'cosignal_invalid';
  END IF;
  v_captured := v_row.summary #>> '{fix,capturedAt}';
  IF (CASE WHEN v_captured ~ '^[0-9]{10,16}$' THEN pg_catalog.abs(v_captured::numeric - pg_catalog.date_part('epoch', p_at) * 1000) <= 1000 ELSE false END) IS NOT TRUE THEN
    RETURN 'cosignal_invalid';
  END IF;
  -- QUALIFICATION, not only identity: the row's own derived fix must be what the co-signal rule requires (packages/rules isQualityCoSignalFix, and the Edge's coSignalGrade): from the app, not
  -- simulated, foreground, against a live or prefetched challenge, accuracy 0..50 m, a polygon geometry of a play-verified facility, inside the buffer, with a token whose grade is the claimed one.
  -- An evidence-endpoint-shaped row (a facility-level foreground_checkin with no geometry match: radius, unverified, outside the buffer) describes a real fix but is NO co-signal.
  v_fix := v_row.summary -> 'fix';
  IF v_fix ->> 'fixId' IS DISTINCT FROM p_fix_id
     OR v_fix ->> 'facilityId' IS DISTINCT FROM p_facility_id
     OR v_fix -> 'fromApp' IS DISTINCT FROM 'true'::jsonb
     OR v_fix -> 'simulated' IS DISTINCT FROM 'false'::jsonb
     OR v_fix -> 'foreground' IS DISTINCT FROM 'true'::jsonb
     OR v_fix ->> 'challenge' IS NULL OR v_fix ->> 'challenge' NOT IN ('live', 'prefetched')
     OR (CASE WHEN pg_catalog.jsonb_typeof(v_fix -> 'accuracyMeters') = 'number' THEN (v_fix ->> 'accuracyMeters')::numeric BETWEEN 0 AND 50 ELSE false END) IS NOT TRUE
     OR v_fix ->> 'geometryKind' IS DISTINCT FROM 'polygon'
     OR v_fix ->> 'verificationTier' IS DISTINCT FROM 'play-verified'
     OR v_fix -> 'insideBuffer' IS DISTINCT FROM 'true'::jsonb
     OR v_fix #> '{token,present}' IS DISTINCT FROM 'true'::jsonb
     OR v_fix #>> '{token,grade}' IS DISTINCT FROM p_grade THEN
    RETURN 'cosignal_invalid';
  END IF;
  IF EXISTS (SELECT 1 FROM app.purchase_evidence p WHERE p.user_id = p_uid AND p.cosignal ->> 'evidenceId' = p_evidence_id::text) THEN
    RETURN 'cosignal_used';
  END IF;
  RETURN 'ok';
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
-- p_at is the fix's time (the 120 s rule is judged against the fix, plan §4.6(q)) when the scan carries a co-signal, else now(): WITHOUT a co-signal the database refuses a p_at more than
-- 5 minutes from now (an unqualified, client-chosen time may not drive the 120 s rule, the PIN's date or `local_date`: a photographed token cannot be burned days later as `pending`).
-- A co-signal is tied to its EVIDENCE ROW (private.marker_cosignal_check): the bound actor's own accepted facility-level foreground_checkin row for `fix:<fix id>` at this facility, whose
-- grade is the one claimed, whose local date is the scan's and whose captured time is p_at, used by no other scan. A printed-QR scan also needs the PIN gate's proof in this
-- transaction (private.course_pin_proof, written by course_pin_attempt_for_actor): the scan never checks a PIN the counters did not see.
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
  v_tok_kid text;
  v_check text;
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
     OR (p_variant = 'rotating' AND (p_nonce_hash IS NULL OR p_nonce_hash !~ '^[0-9a-f]{64}$' OR p_qr_kid IS NULL OR pg_catalog.btrim(p_qr_kid) = ''))
     OR (p_variant = 'static_pin' AND (p_qr_kid IS NULL OR pg_catalog.btrim(p_qr_kid) = '' OR p_pin IS NULL OR p_pin !~ '^[0-9]{4}$'))
     OR (p_cosignal_grade IS NOT NULL AND (p_cosignal_grade NOT IN ('attested', 'unattestable') OR p_cosignal_fix_id IS NULL OR p_cosignal_evidence_id IS NULL))
     OR p_at < v_now - interval '7 days' OR p_at > v_now + interval '5 minutes'
     OR (p_cosignal_grade IS NULL AND pg_catalog.abs(pg_catalog.date_part('epoch', p_at - v_now)) > 300) THEN
    RAISE EXCEPTION 'marker_scan_for_actor: invalid arguments (a facility, rotating+nonce hash+kid or static_pin+kid+PIN, a time within 7 days, a complete co-signal or none, and a time within 5 minutes of now without a co-signal)' USING ERRCODE = '22023';
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
    SELECT t.facility_id, t.issued_at, t.used_at, t.kid INTO v_tok_facility, v_issued, v_tok_used, v_tok_kid FROM app.course_qr_token t WHERE t.nonce_hash = p_nonce_hash;
    -- the token row names the kid it was minted under: a token presented under another kid is not that token (the Edge verified the signature under p_qr_kid)
    IF v_tok_facility IS NULL OR v_tok_kid <> p_qr_kid THEN
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
    -- THE PIN GATE MUST HAVE PASSED IN THIS TRANSACTION, FOR THIS INSTANT (its lockout and failure counters): without its proof this definer is not a PIN oracle, it refuses before looking at the PIN. A
    -- p_at other than the one the gate judged is refused the same way (the gate and the scan never judge two instants: a wrong PIN here would otherwise go uncounted). A caller who holds the proof
    -- already holds the right PIN, so a refusal that is RETURNED from here on (pin_wrong, duplicate, ...) reveals nothing. The proof is CONSUMED where the scan is accepted (below); the deferred
    -- trigger of 6g deletes whatever is left at COMMIT.
    IF NOT EXISTS (SELECT 1 FROM private.course_pin_proof pf
                   WHERE pf.backend_pid = pg_catalog.pg_backend_pid() AND pf.xact = pg_catalog.pg_current_xact_id() AND pf.actor_uid = v_uid AND pf.facility_id = p_facility_id AND pf.local_date = v_local AND pf.pin_at = p_at) THEN
      RAISE EXCEPTION 'marker_scan_for_actor: a printed-QR scan needs course_pin_attempt_for_actor to have accepted the PIN in this transaction' USING ERRCODE = '42501';
    END IF;
    -- the PIN displayed at the fix's instant: the facility-local date of p_at under the epoch that was live then (a rotation after the fix does not invalidate a queued scan)
    v_epoch := private.course_pin_epoch_at(p_facility_id, p_at);
    IF NOT private.course_pin_matches(p_facility_id, v_local, v_epoch, p_pin, p_at) THEN
      o_result := 'pin_wrong';
      RETURN NEXT;
      RETURN;
    END IF;
    -- one purchase per player per shop per facility-local day: the epoch is NOT part of the key (a rotation must not allow a second same-day purchase)
    v_ref := 'pin:' || p_facility_id || ':' || pg_catalog.to_char(v_local, 'YYYY-MM-DD');
    v_win_from := (v_local::timestamp) AT TIME ZONE v_tz;
    v_win_to := ((v_local + 1)::timestamp AT TIME ZONE v_tz) - interval '1 millisecond';
    -- a repeat of the same scan by the same player (same shop, same local date) is a duplicate
    IF EXISTS (SELECT 1 FROM app.purchase_evidence p WHERE p.user_id = v_uid AND p.trail_id = ANY (v_trails) AND p.method = 'course_qr' AND p.ref_id = v_ref) THEN
      o_result := 'duplicate';
      RETURN NEXT;
      RETURN;
    END IF;
  END IF;

  IF p_cosignal_grade IS NOT NULL THEN
    v_check := private.marker_cosignal_check(v_uid, p_facility_id, v_local, p_at, p_cosignal_grade, p_cosignal_fix_id, p_cosignal_evidence_id);
    IF v_check <> 'ok' THEN
      o_result := v_check;
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

  -- ACCEPTED: the printed-QR scan consumes its PIN-gate proof (one gate, one purchase). A bound actor's own row only: the actor and the key are named here.
  IF p_variant = 'static_pin' THEN
    DELETE FROM private.course_pin_proof pf
    WHERE pf.backend_pid = pg_catalog.pg_backend_pid() AND pf.xact = pg_catalog.pg_current_xact_id() AND pf.actor_uid = v_uid AND pf.facility_id = p_facility_id AND pf.local_date = v_local;
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
-- o_result: attached | no_pending_purchase | cosignal_invalid | cosignal_used (and no row for any other account's purchase is ever visible: every statement filters by the bound uid).
-- The co-signal itself is verified first (private.marker_cosignal_check): a fix id and an evidence id the bound actor does not own, or that do not describe this fix here, complete nothing.
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
  v_tz text;
  v_check text;
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

  -- The co-signal must be real: the bound actor's own evidence row for this fix, at this facility, with this grade and this captured time, used by no scan (private.marker_cosignal_check).
  SELECT f.tz INTO v_tz FROM app.catalog_facility f WHERE f.id = p_facility_id;
  IF v_tz IS NULL THEN
    o_result := 'no_pending_purchase';
    RETURN NEXT;
    RETURN;
  END IF;
  v_check := private.marker_cosignal_check(v_uid, p_facility_id, (p_at AT TIME ZONE v_tz)::date, p_at, p_cosignal_grade, p_cosignal_fix_id, p_cosignal_evidence_id);
  IF v_check <> 'ok' THEN
    o_result := v_check;
    RETURN NEXT;
    RETURN;
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
REVOKE EXECUTE ON FUNCTION private.course_pin_from_key(text, text, date, integer) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.course_pin_matches(text, date, integer, text, timestamptz) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.course_pin_epoch_at(text, timestamptz) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.course_pin_epoch_log_write() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.course_pin_proof_expire() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.marker_cosignal_check(uuid, text, date, timestamptz, text, text, uuid) FROM PUBLIC;
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
  '0046. Reads Vault secret course_pin_pepper (with private.course_pin_matches, the only readers): pin = LPAD((first 4 bytes of HMAC-SHA256(pepper, ''golfraven/course-pin/v1'' || 0x00 || facility_id || 0x00 || YYYY-MM-DD || 0x00 || int4send(pin_epoch)) as an unsigned big-endian integer) MOD 10000, 4, ''0''). No role has EXECUTE; the staff lane (S2b) wraps it behind a scope check and shows the CURRENT pepper''s PIN. The pepper is never returned.';
COMMENT ON FUNCTION private.course_pin_matches(text, date, integer, text, timestamptz) IS
  '0046. Is this PIN the one displayed for (facility, local date, epoch) at the instant p_at? Uses the previous pepper (Vault secret course_pin_pepper_previous) for instants before app.course_pin_pepper_epoch says the current pepper took effect. No role has EXECUTE.';
COMMENT ON FUNCTION private.course_pin_epoch_at(text, timestamptz) IS
  '0046. The PIN epoch in effect at a facility at an instant (app.course_pin_epoch_log; with no rotation logged, the current epoch). No role has EXECUTE.';
COMMENT ON FUNCTION private.marker_cosignal_check(uuid, text, date, timestamptz, text, text, uuid) IS
  '0046. Reads a co-signal''s evidence row back for the two definers: the bound actor''s own accepted facility-level foreground_checkin row for fix:<fix id> at this facility, with the claimed grade, the scan''s local date and captured time, used by no other scan. No role has EXECUTE.';
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

-- 6g. The two trigger functions' triggers: the rotation log's (the table's only writer; see 3b; AFTER UPDATE OF pin_epoch, only when the epoch RISES) and the proof's deferred expiry (3c).
-- CREATE TRIGGER needs EXECUTE on the trigger function for the role running the migration (a trigger function is not checked again when it fires). Each function's ACL is owner-only, so
-- the owner lends EXECUTE to the migrating role for the one statement and takes it back: the end state is unchanged (exactly {private_definer=X/private_definer}; a pgTAP cell pins it).
SET ROLE private_definer;
DO $lend$ BEGIN
  EXECUTE pg_catalog.format('GRANT EXECUTE ON FUNCTION private.course_pin_epoch_log_write() TO %I', session_user);
  EXECUTE pg_catalog.format('GRANT EXECUTE ON FUNCTION private.course_pin_proof_expire() TO %I', session_user);
END $lend$;
RESET ROLE;
CREATE TRIGGER facility_programme_pin_epoch_log_trg
AFTER UPDATE OF pin_epoch ON app.facility_programme
FOR EACH ROW WHEN (NEW.pin_epoch > OLD.pin_epoch)
EXECUTE FUNCTION private.course_pin_epoch_log_write();
CREATE CONSTRAINT TRIGGER course_pin_proof_expire_trg
AFTER INSERT ON private.course_pin_proof
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION private.course_pin_proof_expire();
SET ROLE private_definer;
DO $lend$ BEGIN
  EXECUTE pg_catalog.format('REVOKE EXECUTE ON FUNCTION private.course_pin_epoch_log_write() FROM %I', session_user);
  EXECUTE pg_catalog.format('REVOKE EXECUTE ON FUNCTION private.course_pin_proof_expire() FROM %I', session_user);
END $lend$;
RESET ROLE;

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
  ('app', 'course_pin_epoch_log', 'pd_marker_scan_epoch_log_select', 'SELECT', true, 'private.course_pin_epoch_at and the logging trigger (INSERT ... ON CONFLICT also evaluates this policy): the epoch history of a facility; USING (true) because an operator rotation has no bound actor; no personal data'),
  ('app', 'course_pin_pepper_epoch', 'pd_marker_scan_pepper_epoch_select', 'SELECT', true, 'private.course_pin_matches: WHEN the current pepper took effect (the operator''s rotation procedure writes it); no personal data and no secret, so USING (true)'),
  ('app', 'course_pin_epoch_log', 'pd_marker_scan_epoch_log_insert', 'INSERT', true, 'private.course_pin_epoch_log_write (the trigger on facility_programme.pin_epoch, SECURITY DEFINER, whoever rotates): the ONLY writer; WITH CHECK (true) because an operator rotation has no bound actor; no personal data'),
  ('private', 'course_pin_proof', 'pd_marker_scan_proof_select', 'SELECT', true, 'marker_scan_for_actor and the proof''s own expiry read THIS backend''s row of the BOUND actor only'),
  ('private', 'course_pin_proof', 'pd_marker_scan_proof_insert', 'INSERT', true, 'course_pin_attempt_for_actor: writes the proof for THIS backend and the BOUND actor only'),
  ('private', 'course_pin_proof', 'pd_marker_scan_proof_delete', 'DELETE', true, 'marker_scan_for_actor consumes its proof; course_pin_attempt_for_actor and the deferred expiry trigger clear THIS backend''s rows (the backend, never a GUC, is the key)'),
  ('app', 'evidence', 'pd_marker_scan_evidence_select', 'SELECT', true, 'private.marker_cosignal_check: reads back the BOUND actor''s own co-signal evidence row (user_id = private.actor_uid()); the definer also filters user_id explicitly'),
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
  ('private', 'course_pin_from_key', 'p_key text, p_facility_id text, p_local_date date, p_pin_epoch integer', false, false, false, false, false,
   '0046: the pure PIN derivation over a key it is handed (reads no secret); no role has EXECUTE'),
  ('private', 'course_pin_matches', 'p_facility_id text, p_local_date date, p_pin_epoch integer, p_pin text, p_at timestamp with time zone', false, false, false, false, false,
   '0046: is this PIN the one displayed at the instant p_at (current pepper, or the previous one for instants before app.course_pin_pepper_epoch says the current one took effect); reads the Vault peppers; no role has EXECUTE'),
  ('private', 'course_pin_epoch_at', 'p_facility_id text, p_at timestamp with time zone', false, false, false, false, false,
   '0046: the PIN epoch in effect at a facility at an instant (app.course_pin_epoch_log); no role has EXECUTE'),
  ('private', 'course_pin_epoch_log_write', '', false, false, false, false, false,
   '0046: trigger function (app.facility_programme_pin_epoch_log_trg) -- logs each PIN rotation once; the log''s only writer; never EXECUTEd directly by any role'),
  ('private', 'course_pin_proof_expire', '', false, false, false, false, false,
   '0046: trigger function (private.course_pin_proof_expire_trg, a DEFERRED constraint trigger) -- deletes the backend''s proof rows at COMMIT, so the PIN proof never outlives its transaction; never EXECUTEd directly by any role'),
  ('private', 'marker_cosignal_check', 'p_uid uuid, p_facility_id text, p_local_date date, p_at timestamp with time zone, p_grade text, p_fix_id text, p_evidence_id uuid', false, false, false, false, false,
   '0046: reads a co-signal''s evidence row back for the scan and the intake (own row, source, facility, grade, local date, captured time, the derived fix that qualifies, unused); no role has EXECUTE'),
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
  FOREACH v_fn IN ARRAY ARRAY['app.course_pin_epoch_log', 'app.course_pin_pepper_epoch', 'private.course_pin_proof', 'app.purchase_evidence', 'app.marker_credit', 'app.course_qr_token', 'app.facility_qr', 'app.facility_programme', 'app.trail_programme', 'app.catalog_facility'] LOOP
    IF NOT (SELECT relforcerowsecurity FROM pg_class WHERE oid = v_fn::regclass) THEN
      RAISE EXCEPTION '0046: % must keep FORCE ROW LEVEL SECURITY', v_fn;
    END IF;
  END LOOP;
  IF has_any_column_privilege('edge_actor', 'app.course_pin_pepper_epoch', 'SELECT,INSERT,UPDATE,REFERENCES') OR has_table_privilege('edge_system', 'app.course_pin_pepper_epoch', 'SELECT')
     OR has_table_privilege('authenticated', 'app.course_pin_pepper_epoch', 'SELECT') OR has_table_privilege('anon', 'app.course_pin_pepper_epoch', 'SELECT') THEN
    RAISE EXCEPTION '0046: no edge or client role may hold any privilege on app.course_pin_pepper_epoch';
  END IF;
  IF has_table_privilege('edge_actor', 'app.course_pin_epoch_log', 'SELECT') OR has_any_column_privilege('edge_actor', 'app.course_pin_epoch_log', 'SELECT,INSERT,UPDATE,REFERENCES')
     OR has_any_column_privilege('edge_actor', 'private.course_pin_proof', 'SELECT,INSERT,UPDATE,REFERENCES') OR has_table_privilege('edge_system', 'private.course_pin_proof', 'SELECT')
     OR has_table_privilege('authenticated', 'app.course_pin_epoch_log', 'SELECT') OR has_table_privilege('anon', 'app.course_pin_epoch_log', 'SELECT') THEN
    RAISE EXCEPTION '0046: no edge or client role may hold any privilege on app.course_pin_epoch_log or private.course_pin_proof';
  END IF;
  FOREACH v_fn IN ARRAY ARRAY['private.course_pin_from_key(text, text, date, integer)', 'private.course_pin_matches(text, date, integer, text, timestamptz)', 'private.course_pin_epoch_at(text, timestamptz)',
                              'private.course_pin_epoch_log_write()', 'private.course_pin_proof_expire()', 'private.marker_cosignal_check(uuid, text, date, timestamptz, text, text, uuid)'] LOOP
    IF has_function_privilege('edge_actor', v_fn, 'EXECUTE') OR has_function_privilege('edge_system', v_fn, 'EXECUTE') OR has_function_privilege('service_role', v_fn, 'EXECUTE')
       OR has_function_privilege('authenticated', v_fn, 'EXECUTE') OR has_function_privilege('anon', v_fn, 'EXECUTE') THEN
      RAISE EXCEPTION '0046: no role may EXECUTE %', v_fn;
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
