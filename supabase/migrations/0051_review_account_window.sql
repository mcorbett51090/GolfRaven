-- 0051_review_account_window.sql
--
-- The App Store review account (Apple guideline 2.1; build plan "FM-16.1": "One `app-review` account ... It has no partner scope, can receive no offer or special
-- marker, audits every sign-in, and is disabled outside submission windows"; AT 14: "The review account can sign in and cannot receive a reward"). The repository had
-- the table (app.app_review_demo_account, 0007), the 403 on reward activation and the partner-route refusal. It did NOT have the last two behaviours of the sentence
-- above. This migration builds them. Migrations 0001-0049 are untouched.
--
-- WHAT THIS ADDS
--   1. app.app_review_window: the admin-controlled SUBMISSION WINDOWS. One row is one half-open interval [starts_at, ends_at). The review account is ENABLED while
--      the clock is inside at least one window and DISABLED everywhere else (no row at all = disabled: the default is closed). Written only by service_role (the same
--      posture as app.admin_user and app.app_review_demo_account: FORCE RLS, no client policy, service_role DML grant). It is global, not per account: there is one
--      review account, and a per-account window would be a second place a stale row could keep the account open.
--   2. private.review_window_open_at(timestamptz): the one predicate. Pure over the table; the boundary is closed at the start and OPEN at the end (starts_at <= t < ends_at).
--   3. private.review_account_gate(uid, session_id): the AUDIT + the REFUSAL STATUS. Returns 'not_review' | 'allowed' | 'disabled' and, for a review account only, writes ONE
--      app.audit_log row per (account, GoTrue session, outcome). It RETURNS a status and never raises, so the audit row COMMITS WITH the refusal (the lesson of 0020: a
--      RAISE rolls back the very row that records the refusal). edge_system EXECUTE only: it is called by privileged.ts#getActorFromRequest, the one choke point every
--      authenticated Edge Function already passes through.
--   4. private.bind_actor_internal (redefined from 0047, ONE added check): a kind = 'user' binding of a review account OUTSIDE a window is refused (42501). This is the
--      BACKSTOP in the database: an Edge path that forgot the gate above still cannot open an actor-bound transaction for a disabled review account.
--   4b. THE REVIEW ACCOUNT RECEIVES NOTHING: the four edge_actor-executable definers that create a purchase / credit or hand a reward to its holder (marker_scan_for_actor,
--      marker_cosignal_attach_for_actor, activate_offer_code_for_actor, activate_entitlement_for_actor) are redefined as their current definitions plus ONE block that refuses the review
--      account (a returned status 'review_account' for the two marker functions, 42501 for the two activations); the migration asserts in the catalogue that nothing else changed.
--   4c. ONE review account: a unique index on a constant over app.app_review_demo_account.
--   5. A partial UNIQUE index on app.audit_log that makes "one row per session" a database fact (the gate catches its unique_violation; no ON CONFLICT arbiter is read).
--   6. Registries: function_inventory, definer_policy_allowlist (+ the checked-in fixture twin).
--
-- WHAT "SIGN-IN" MEANS HERE
--   GoTrue (Supabase Auth) owns the sign-in itself (email OTP -> a session). The database never sees that call. What it can see, on every Edge request, is the GoTrue SESSION
--   id carried in the access token (`session_id` claim). "Audits every sign-in" is therefore implemented as: the FIRST authenticated request made under each GoTrue session id
--   writes one audit row (action review_account.session_allowed or review_account.session_refused), keyed on that session id; every later request under the same session writes
--   nothing. A token with no readable session id is audited on every request (never deduped: the failure direction is "more rows", never "a sign-in that left no record").
--   The audit row holds: the account's uid (the actor column, redacted to NULL by delete_my_data like every audit row), the session id (a random uuid, not personal data), and the
--   outcome. No email, no IP, no user agent, no token.
--
-- WHAT "DISABLED" MEANS HERE, AND WHERE IT IS ENFORCED (docs/security/review-account-design.md has the full argument)
--   (a) Database, exact to the instant: the gate refuses (403 review_account_disabled at the Edge) and the binder backstop raises. Needs no hosted feature.
--   (b) GoTrue, so a token can no longer be OBTAINED: auth.users.banned_until, set and cleared by tools/review-account/review-account.sh (provision / open / close / sync).
--       That script needs the Auth admin API and a scheduler to run `sync`: both are deploy steps, marked [unverified] in the docs. This migration deliberately does NOT write
--       auth.users from SQL: it would need a new grant on a table owned by the Auth service, and the repository's rule is that no migration broadens a grant.
--   Not covered by either: a still-valid access token read DIRECTLY through PostgREST (api.* views, as `authenticated`, keyed on auth.uid()). Those views hold only the
--   account's own rows (an empty profile), and the token dies at jwt_expiry. Stated in the design doc; not claimed away.
--
-- THE HARD RULES this file keeps: FORCE RLS on the new table; no grant to anon / authenticated / any edge role on it; no settable-GUC-keyed policy anywhere (the one new
-- private_definer policy is `USING (true)` on a table that holds no personal data, the pd_read_demo_account shape); no existing grant or policy is widened.
--
-- OWNERSHIP BRACKET as 0030 / 0047: GRANT CREATE ON SCHEMA private TO private_definer; SET ROLE private_definer; CREATE ...; RESET ROLE; REVOKE CREATE.
-- `migration_owner` is never named.

-- ============================================================================
-- 1. app.app_review_window
-- ============================================================================
CREATE TABLE app.app_review_window (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  starts_at timestamptz NOT NULL,
  ends_at timestamptz NOT NULL,
  -- free text for the owner ("build 1.0.3 submission"): never a name, an address or a credential
  note text CHECK (note IS NULL OR length(note) <= 200),
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT app_review_window_order_check CHECK (ends_at > starts_at),
  -- a window opened by mistake cannot stay open for months: the longest one is 60 days (a review can take days, not weeks)
  CONSTRAINT app_review_window_length_check CHECK (ends_at - starts_at <= interval '60 days')
);
CREATE INDEX app_review_window_range_idx ON app.app_review_window (starts_at, ends_at);
COMMENT ON TABLE app.app_review_window IS
  '0051. Submission windows of the App Store review account: the account is enabled only while the clock is inside one (starts_at <= t < ends_at), disabled otherwise (no row = disabled). service_role writes; no client or edge role holds any privilege; private.review_window_open_at reads it. Holds no personal data.';
ALTER TABLE app.app_review_window ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.app_review_window FORCE ROW LEVEL SECURITY;
-- No client policy (default deny), exactly as app.admin_user / app.app_review_demo_account (0007): service_role bypasses RLS; the SECURITY DEFINER helper reads it.
GRANT SELECT, INSERT, UPDATE, DELETE ON app.app_review_window TO service_role;

-- The helper's owner reads the table. A policy for private_definer (FORCE RLS applies to the owner role of a definer too): USING (true) on a table with no personal data.
GRANT SELECT ON app.app_review_window TO private_definer;
CREATE POLICY pd_read_review_window ON app.app_review_window FOR SELECT TO private_definer USING (true);

-- ============================================================================
-- 1b. ONE review account, as a database fact
-- ============================================================================
-- "One `app-review` account" (plan line 1871). A second row would be a second account that a window enables; the unique index on a constant makes a second INSERT a 23505.
-- (The owner tool refuses to provision a second one with its own message first; this is the floor beneath it.)
CREATE UNIQUE INDEX app_review_demo_account_single ON app.app_review_demo_account ((true));
COMMENT ON INDEX app.app_review_demo_account_single IS
  '0051. At most one app-review account may exist (plan line 1871: "One app-review account"). To replace it, DELETE the old row first.';

-- ============================================================================
-- 2. One audit row per (account, session, outcome), as a database fact
-- ============================================================================
-- Partial: only the two review-account actions are constrained, so no other audit action can ever collide. NULL subject_id (a token with no readable session id) never
-- conflicts (NULLs are distinct in a unique index), which is the "audit every request when the session is unknown" direction. delete_my_data redacts actor_user_id to NULL;
-- NULL actors do not conflict either.
CREATE UNIQUE INDEX audit_log_review_session_once
  ON app.audit_log (actor_user_id, action, subject_id)
  WHERE action IN ('review_account.session_allowed', 'review_account.session_refused');

-- ============================================================================
-- 3. The functions (ownership bracket)
-- ============================================================================
-- 3d-pre. what the four definitions are NOW (attributes as a digest, source as text), so the section after the bracket can prove nothing but the inserted check changed
DO $r51_capture$
BEGIN
  PERFORM set_config('r51.before.marker_scan_for_actor', (SELECT md5(concat_ws('|', pg_get_userbyid(p.proowner), p.proacl::text, p.proconfig::text, p.prosecdef, p.prolang, p.prorettype, pg_get_function_arguments(p.oid), p.provolatile, p.proparallel, p.proisstrict, p.proleakproof, p.pronargdefaults)) FROM pg_proc p WHERE p.oid = 'private.marker_scan_for_actor(text, text, text, text, text, timestamptz, text, text, uuid)'::regprocedure), false);
  PERFORM set_config('r51.src.marker_scan_for_actor', (SELECT p.prosrc FROM pg_proc p WHERE p.oid = 'private.marker_scan_for_actor(text, text, text, text, text, timestamptz, text, text, uuid)'::regprocedure), false);
  PERFORM set_config('r51.before.marker_cosignal_attach_for_actor', (SELECT md5(concat_ws('|', pg_get_userbyid(p.proowner), p.proacl::text, p.proconfig::text, p.prosecdef, p.prolang, p.prorettype, pg_get_function_arguments(p.oid), p.provolatile, p.proparallel, p.proisstrict, p.proleakproof, p.pronargdefaults)) FROM pg_proc p WHERE p.oid = 'private.marker_cosignal_attach_for_actor(text, timestamptz, text, text, uuid)'::regprocedure), false);
  PERFORM set_config('r51.src.marker_cosignal_attach_for_actor', (SELECT p.prosrc FROM pg_proc p WHERE p.oid = 'private.marker_cosignal_attach_for_actor(text, timestamptz, text, text, uuid)'::regprocedure), false);
  PERFORM set_config('r51.before.activate_offer_code_for_actor', (SELECT md5(concat_ws('|', pg_get_userbyid(p.proowner), p.proacl::text, p.proconfig::text, p.prosecdef, p.prolang, p.prorettype, pg_get_function_arguments(p.oid), p.provolatile, p.proparallel, p.proisstrict, p.proleakproof, p.pronargdefaults)) FROM pg_proc p WHERE p.oid = 'private.activate_offer_code_for_actor(uuid, uuid, text, text, jsonb)'::regprocedure), false);
  PERFORM set_config('r51.src.activate_offer_code_for_actor', (SELECT p.prosrc FROM pg_proc p WHERE p.oid = 'private.activate_offer_code_for_actor(uuid, uuid, text, text, jsonb)'::regprocedure), false);
  PERFORM set_config('r51.before.activate_entitlement_for_actor', (SELECT md5(concat_ws('|', pg_get_userbyid(p.proowner), p.proacl::text, p.proconfig::text, p.prosecdef, p.prolang, p.prorettype, pg_get_function_arguments(p.oid), p.provolatile, p.proparallel, p.proisstrict, p.proleakproof, p.pronargdefaults)) FROM pg_proc p WHERE p.oid = 'private.activate_entitlement_for_actor(uuid, uuid, text, text, jsonb)'::regprocedure), false);
  PERFORM set_config('r51.src.activate_entitlement_for_actor', (SELECT p.prosrc FROM pg_proc p WHERE p.oid = 'private.activate_entitlement_for_actor(uuid, uuid, text, text, jsonb)'::regprocedure), false);
END
$r51_capture$;

GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

-- 3a. THE predicate. Closed at the start, open at the end.
CREATE FUNCTION private.review_window_open_at(p_at timestamptz)
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT EXISTS (SELECT 1 FROM app.app_review_window w WHERE w.starts_at <= p_at AND p_at < w.ends_at);
$$;

-- 3b. The gate: audit + status. NEVER raises over the outcome (the audit row must commit with a refusal); it raises only on a malformed argument (22023), which writes nothing.
-- p_session_id is TEXT, not uuid: the Edge reads it out of a JWT, and anything that is not a canonical uuid must degrade to "unknown session" instead of failing the request.
CREATE FUNCTION private.review_account_gate(p_uid uuid, p_session_id text)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_open boolean;
  v_action text;
  v_sid text;
BEGIN
  IF p_uid IS NULL THEN
    RAISE EXCEPTION 'review_account_gate: the uid must not be NULL' USING ERRCODE = '22023';
  END IF;
  IF NOT private.is_demo_account(p_uid) THEN
    RETURN 'not_review';
  END IF;
  -- clock_timestamp(), not now(): a long-lived transaction must not carry a stale "open" past the window's end
  v_open := private.review_window_open_at(clock_timestamp());
  v_action := CASE WHEN v_open THEN 'review_account.session_allowed' ELSE 'review_account.session_refused' END;
  v_sid := CASE WHEN p_session_id ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN lower(p_session_id) ELSE NULL END;
  BEGIN
    INSERT INTO app.audit_log (actor_user_id, action, subject_table, subject_id, detail)
    VALUES (p_uid, v_action, 'auth_session', v_sid, pg_catalog.jsonb_build_object('outcome', CASE WHEN v_open THEN 'allowed' ELSE 'refused' END));
  EXCEPTION WHEN unique_violation THEN
    -- the session was already recorded with this outcome: nothing to add (dedupe per session)
    NULL;
  END;
  RETURN CASE WHEN v_open THEN 'allowed' ELSE 'disabled' END;
END;
$$;

-- 3c. The binder, redefined from 0047 with exactly ONE added check (marked): a review account cannot be bound as a user outside a window. Same owner, ACL and signature.
CREATE OR REPLACE FUNCTION private.bind_actor_internal(p_uid uuid, p_kind text)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_xact xid8;
BEGIN
  IF p_uid IS NULL THEN
    RAISE EXCEPTION 'bind_actor: the actor uid must not be NULL' USING ERRCODE = '22023';
  END IF;
  IF p_kind IS NULL OR p_kind NOT IN ('user', 'system_delegate') THEN
    RAISE EXCEPTION 'bind_actor: unknown binding kind' USING ERRCODE = '22023';
  END IF;
  -- Assigns the transaction id (an INSERT would anyway).
  v_xact := pg_current_xact_id();
  -- One bind per transaction, ever: this is what stops a delegate-bound or user-bound transaction
  -- from being re-pointed at another user half way through.
  IF EXISTS (SELECT 1 FROM private.actor_binding WHERE backend_pid = pg_backend_pid() AND xact = v_xact) THEN
    RAISE EXCEPTION 'bind_actor: this transaction already has a bound actor' USING ERRCODE = '42501';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM auth.users WHERE id = p_uid) THEN
    RAISE EXCEPTION 'bind_actor: no such user' USING ERRCODE = 'P0002';
  END IF;
  -- 0051 (the ONE added check): the app-review account is DISABLED outside a submission window. A system delegate is not a sign-in (it acts on one queued row of the owner,
  -- on the system's own schedule), so only the user kind is refused.
  IF p_kind = 'user' AND private.is_demo_account(p_uid) AND NOT private.review_window_open_at(clock_timestamp()) THEN
    RAISE EXCEPTION 'bind_actor: the review account is disabled outside a submission window' USING ERRCODE = '42501';
  END IF;
  INSERT INTO private.actor_binding (backend_pid, xact, actor_uid, kind, session_id, bound_at)
  VALUES (pg_backend_pid(), v_xact, p_uid, p_kind, NULL, clock_timestamp())
  ON CONFLICT (backend_pid) DO UPDATE
    SET xact = EXCLUDED.xact, actor_uid = EXCLUDED.actor_uid, kind = EXCLUDED.kind, session_id = NULL, bound_at = EXCLUDED.bound_at;
END;
$$;

REVOKE EXECUTE ON FUNCTION private.review_window_open_at(timestamptz) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.review_account_gate(uuid, text) FROM PUBLIC;
-- service_role: an operator (and the tools/review-account script) can ask "is the window open" through the same predicate the database enforces.
GRANT EXECUTE ON FUNCTION private.review_window_open_at(timestamptz) TO service_role;
GRANT EXECUTE ON FUNCTION private.review_account_gate(uuid, text) TO edge_system;

COMMENT ON FUNCTION private.review_window_open_at(timestamptz) IS
  '0051. Is the instant inside an app.app_review_window row? starts_at <= t < ends_at; no row, no window.';
COMMENT ON FUNCTION private.review_account_gate(uuid, text) IS
  '0051. edge_system only. For a review account: writes one audit_log row per (account, GoTrue session, outcome) and returns allowed | disabled; for anyone else returns not_review and writes nothing. Returns a status, never raises on the outcome, so the audit row commits with the refusal (0020).';

-- 3c2. THE REVIEW ACCOUNT RECEIVES NOTHING (plan line 1871: "can receive no offer or special marker"; AT 14: "cannot receive a reward"). Every edge_actor-executable definer that CREATES a purchase / credit,
-- or hands a reward to its holder, refuses the review account. The bodies below are the CURRENT definitions (0046 for the two marker functions, 0032 for the two activations: no later
-- migration redefines them) with ONE block added after the delegate check; section 3d proves that in the catalogue. The marker functions return the status 'review_account' (their own refusal
-- style: every refusal is a returned status and nothing has been written yet); the activation functions RAISE 42501 (theirs; the Edge handler answers 403 before it gets here).
-- Reviewed and left as they are: reserve_offer_for_code / release_offer_budget (budget counters on an offer, reached only from a code that already exists), hold_play_rewards_for_actor and
-- lock_own_reward_for_actor (they restrict an existing reward, never grant one), the evidence, device and sign-in definers (no reward, offer, entitlement or credit is written). There is no minter
-- of offer codes or entitlements yet (P6); the requirement on those future minters is pinned in docs/security/review-account-design.md section 8 and by supabase/tests/unit/review-account-minters.test.ts.
CREATE OR REPLACE FUNCTION private.marker_scan_for_actor(
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
  -- 0051: the app-review account can record no marker purchase and earn no credit (plan line 1871: "can receive no offer or special marker"). A returned status, this function's own
  -- refusal style: nothing has been written yet, and the Edge answers 403.
  IF private.is_demo_account(v_uid) THEN
    o_result := 'review_account';
    RETURN NEXT;
    RETURN;
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

CREATE OR REPLACE FUNCTION private.marker_cosignal_attach_for_actor(
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
  -- 0051: the app-review account can record no marker purchase and earn no credit (plan line 1871: "can receive no offer or special marker"). A returned status, this function's own
  -- refusal style: nothing has been written yet, and the Edge answers 403.
  IF private.is_demo_account(v_uid) THEN
    o_result := 'review_account';
    RETURN NEXT;
    RETURN;
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

CREATE OR REPLACE FUNCTION private.activate_offer_code_for_actor(
  p_code_id uuid, p_device_id uuid, p_token_hash text, p_decision text, p_hold_detail jsonb DEFAULT NULL
) RETURNS app.offer_code_state
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
    RAISE EXCEPTION 'activate_offer_code_for_actor: no actor is bound in this transaction' USING ERRCODE = '42501';
  END IF;
  IF v_kind <> 'user' THEN
    RAISE EXCEPTION 'activate_offer_code_for_actor: a system delegate may not activate a reward' USING ERRCODE = '42501';
  END IF;
  -- 0051: the app-review account can receive no reward (AT 14; plan line 1871). The Edge handler already answers 403 before this is reached; this is the database's own refusal.
  IF private.is_demo_account(v_uid) THEN
    RAISE EXCEPTION 'activate_offer_code_for_actor: the review account may not activate a reward' USING ERRCODE = '42501';
  END IF;
  RETURN app.activate_offer_code(p_code_id, v_uid, p_device_id, p_token_hash, p_decision, p_hold_detail);
END;
$$;

CREATE OR REPLACE FUNCTION private.activate_entitlement_for_actor(
  p_entitlement_id uuid, p_device_id uuid, p_token_hash text, p_decision text, p_hold_detail jsonb DEFAULT NULL
) RETURNS app.entitlement_state
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
    RAISE EXCEPTION 'activate_entitlement_for_actor: no actor is bound in this transaction' USING ERRCODE = '42501';
  END IF;
  IF v_kind <> 'user' THEN
    RAISE EXCEPTION 'activate_entitlement_for_actor: a system delegate may not activate a reward' USING ERRCODE = '42501';
  END IF;
  -- 0051: the app-review account can receive no reward (AT 14; plan line 1871). The Edge handler already answers 403 before this is reached; this is the database's own refusal.
  IF private.is_demo_account(v_uid) THEN
    RAISE EXCEPTION 'activate_entitlement_for_actor: the review account may not activate a reward' USING ERRCODE = '42501';
  END IF;
  RETURN app.activate_entitlement(p_entitlement_id, v_uid, p_device_id, p_token_hash, p_decision, p_hold_detail);
END;
$$;


RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

-- 3d-post. ASSERT, inside the migration, that each CREATE OR REPLACE changed NOTHING but the inserted check: owner, ACL, search_path, SECURITY DEFINER, language, return type, arguments,
-- volatility, parallel safety, strictness are byte-for-byte the digest taken before; and the new source with the inserted block removed IS the old source, character for character.
DO $r51_assert$
DECLARE
  v_after text;
  v_src text;
  v_n int := 0;
BEGIN
  SELECT md5(concat_ws('|', pg_get_userbyid(p.proowner), p.proacl::text, p.proconfig::text, p.prosecdef, p.prolang, p.prorettype, pg_get_function_arguments(p.oid), p.provolatile, p.proparallel, p.proisstrict, p.proleakproof, p.pronargdefaults)), p.prosrc
    INTO v_after, v_src FROM pg_proc p WHERE p.oid = 'private.marker_scan_for_actor(text, text, text, text, text, timestamptz, text, text, uuid)'::regprocedure;
  IF v_after IS DISTINCT FROM current_setting('r51.before.marker_scan_for_actor') THEN
    RAISE EXCEPTION '0051: % changed an attribute (owner, ACL, search_path, ...) when it was redefined', 'marker_scan_for_actor';
  END IF;
  IF replace(v_src, $blk$  -- 0051: the app-review account can record no marker purchase and earn no credit (plan line 1871: "can receive no offer or special marker"). A returned status, this function's own
  -- refusal style: nothing has been written yet, and the Edge answers 403.
  IF private.is_demo_account(v_uid) THEN
    o_result := 'review_account';
    RETURN NEXT;
    RETURN;
  END IF;
$blk$, '') IS DISTINCT FROM current_setting('r51.src.marker_scan_for_actor') OR v_src = current_setting('r51.src.marker_scan_for_actor') THEN
    RAISE EXCEPTION '0051: % differs from its previous definition by more than the review-account refusal', 'marker_scan_for_actor';
  END IF;
  v_n := v_n + 1;
  SELECT md5(concat_ws('|', pg_get_userbyid(p.proowner), p.proacl::text, p.proconfig::text, p.prosecdef, p.prolang, p.prorettype, pg_get_function_arguments(p.oid), p.provolatile, p.proparallel, p.proisstrict, p.proleakproof, p.pronargdefaults)), p.prosrc
    INTO v_after, v_src FROM pg_proc p WHERE p.oid = 'private.marker_cosignal_attach_for_actor(text, timestamptz, text, text, uuid)'::regprocedure;
  IF v_after IS DISTINCT FROM current_setting('r51.before.marker_cosignal_attach_for_actor') THEN
    RAISE EXCEPTION '0051: % changed an attribute (owner, ACL, search_path, ...) when it was redefined', 'marker_cosignal_attach_for_actor';
  END IF;
  IF replace(v_src, $blk$  -- 0051: the app-review account can record no marker purchase and earn no credit (plan line 1871: "can receive no offer or special marker"). A returned status, this function's own
  -- refusal style: nothing has been written yet, and the Edge answers 403.
  IF private.is_demo_account(v_uid) THEN
    o_result := 'review_account';
    RETURN NEXT;
    RETURN;
  END IF;
$blk$, '') IS DISTINCT FROM current_setting('r51.src.marker_cosignal_attach_for_actor') OR v_src = current_setting('r51.src.marker_cosignal_attach_for_actor') THEN
    RAISE EXCEPTION '0051: % differs from its previous definition by more than the review-account refusal', 'marker_cosignal_attach_for_actor';
  END IF;
  v_n := v_n + 1;
  SELECT md5(concat_ws('|', pg_get_userbyid(p.proowner), p.proacl::text, p.proconfig::text, p.prosecdef, p.prolang, p.prorettype, pg_get_function_arguments(p.oid), p.provolatile, p.proparallel, p.proisstrict, p.proleakproof, p.pronargdefaults)), p.prosrc
    INTO v_after, v_src FROM pg_proc p WHERE p.oid = 'private.activate_offer_code_for_actor(uuid, uuid, text, text, jsonb)'::regprocedure;
  IF v_after IS DISTINCT FROM current_setting('r51.before.activate_offer_code_for_actor') THEN
    RAISE EXCEPTION '0051: % changed an attribute (owner, ACL, search_path, ...) when it was redefined', 'activate_offer_code_for_actor';
  END IF;
  IF replace(v_src, $blk$  -- 0051: the app-review account can receive no reward (AT 14; plan line 1871). The Edge handler already answers 403 before this is reached; this is the database's own refusal.
  IF private.is_demo_account(v_uid) THEN
    RAISE EXCEPTION 'activate_offer_code_for_actor: the review account may not activate a reward' USING ERRCODE = '42501';
  END IF;
$blk$, '') IS DISTINCT FROM current_setting('r51.src.activate_offer_code_for_actor') OR v_src = current_setting('r51.src.activate_offer_code_for_actor') THEN
    RAISE EXCEPTION '0051: % differs from its previous definition by more than the review-account refusal', 'activate_offer_code_for_actor';
  END IF;
  v_n := v_n + 1;
  SELECT md5(concat_ws('|', pg_get_userbyid(p.proowner), p.proacl::text, p.proconfig::text, p.prosecdef, p.prolang, p.prorettype, pg_get_function_arguments(p.oid), p.provolatile, p.proparallel, p.proisstrict, p.proleakproof, p.pronargdefaults)), p.prosrc
    INTO v_after, v_src FROM pg_proc p WHERE p.oid = 'private.activate_entitlement_for_actor(uuid, uuid, text, text, jsonb)'::regprocedure;
  IF v_after IS DISTINCT FROM current_setting('r51.before.activate_entitlement_for_actor') THEN
    RAISE EXCEPTION '0051: % changed an attribute (owner, ACL, search_path, ...) when it was redefined', 'activate_entitlement_for_actor';
  END IF;
  IF replace(v_src, $blk$  -- 0051: the app-review account can receive no reward (AT 14; plan line 1871). The Edge handler already answers 403 before this is reached; this is the database's own refusal.
  IF private.is_demo_account(v_uid) THEN
    RAISE EXCEPTION 'activate_entitlement_for_actor: the review account may not activate a reward' USING ERRCODE = '42501';
  END IF;
$blk$, '') IS DISTINCT FROM current_setting('r51.src.activate_entitlement_for_actor') OR v_src = current_setting('r51.src.activate_entitlement_for_actor') THEN
    RAISE EXCEPTION '0051: % differs from its previous definition by more than the review-account refusal', 'activate_entitlement_for_actor';
  END IF;
  v_n := v_n + 1;
  IF v_n <> 4 THEN RAISE EXCEPTION '0051: expected to check four redefined functions'; END IF;
END
$r51_assert$;


-- ============================================================================
-- 4. Registries
-- ============================================================================
-- 4a. private.function_inventory (0017 owner INSERT policy; the role columns are 0030 / 0047 / 0048's)
INSERT INTO private.function_inventory
  (schema_name, function_name, identity_args, expected_anon, expected_authenticated, expected_service_role, expected_edge_actor, expected_edge_system, expected_edge_partner, expected_edge_partner_minter, note)
VALUES
  ('private', 'review_window_open_at', 'p_at timestamp with time zone', false, false, true, false, false, false, false, '0051: is the instant inside a submission window of the app-review account (starts_at <= t < ends_at); service_role may ask, so an operator reads the predicate the database enforces'),
  ('private', 'review_account_gate', 'p_uid uuid, p_session_id text', false, false, false, false, true, false, false, '0051: edge_system only; for a review account writes ONE audit_log row per (account, session, outcome) and returns allowed | disabled, for anyone else not_review; a status, never a RAISE, so the audit row commits with the refusal');

-- 4b. private.definer_policy_allowlist: the one new private_definer policy (expressions derived from the live policy)
GRANT INSERT, UPDATE ON private.definer_policy_allowlist TO CURRENT_USER;
CREATE POLICY current_user_seed_definer_policy_allowlist_0051 ON private.definer_policy_allowlist
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
INSERT INTO private.definer_policy_allowlist (schema_name, table_name, policy_name, command, scoped, note, role_name) VALUES
  ('app', 'app_review_window', 'pd_read_review_window', 'SELECT', true, 'review_window_open_at: reads the submission windows (USING(true): the table holds no personal data and the function body is the scope; the pd_read_demo_account shape)', 'private_definer');
UPDATE private.definer_policy_allowlist al
SET using_expr = pg_get_expr(pol.polqual, pol.polrelid),
    with_check_expr = pg_get_expr(pol.polwithcheck, pol.polrelid)
FROM pg_policy pol
JOIN pg_class cl ON cl.oid = pol.polrelid
JOIN pg_namespace n ON n.oid = cl.relnamespace
WHERE n.nspname = al.schema_name AND cl.relname = al.table_name AND pol.polname = al.policy_name
  AND pol.polname = 'pd_read_review_window';
DO $assert_0051_allowlist$
BEGIN
  IF (SELECT count(*) FROM private.definer_policy_allowlist WHERE policy_name = 'pd_read_review_window' AND using_expr IS NOT NULL) <> 1 THEN
    RAISE EXCEPTION '0051: the allowlist row names no live policy (its expressions were not derived)';
  END IF;
END
$assert_0051_allowlist$;
DROP POLICY current_user_seed_definer_policy_allowlist_0051 ON private.definer_policy_allowlist;
REVOKE INSERT, UPDATE ON private.definer_policy_allowlist FROM CURRENT_USER;
