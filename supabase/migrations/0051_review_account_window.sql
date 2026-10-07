-- 0051_review_account_window.sql
--
-- The App Store review account (Apple guideline 2.1; build plan "FM-16.1": "One `app-review` account ... It has no partner scope, can receive no offer or special
-- marker, audits every sign-in, and is disabled outside submission windows"; AT 14: "The review account can sign in and cannot receive a reward"). The repository had
-- the table (app.app_review_demo_account, 0007), the 403 on reward activation and the partner-route refusal. It did NOT have the last two behaviours of the sentence
-- above. This migration builds them. Migrations 0001-0048 are untouched.
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

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

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
