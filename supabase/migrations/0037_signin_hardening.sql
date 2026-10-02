-- 0037_signin_hardening.sql
-- O12 sign-in providers: the non-blocking follow-ups of the 0035 security gate (PR #24). 0001-0036 are untouched.
--
-- L1  THE OTP COUNTER WAS CALLABLE BY ANY edge_actor CONNECTION, BOUND OR NOT.
--     0035 granted peek_ / reserve_ / release_signin_otp_attempt straight to edge_actor. They take no user and check no
--     binding, so a SQL-level edge_actor caller (no Edge code, no actor bound) could call `release` in a loop and reset any
--     address's brute-force counter to zero (release is a decrement), or `reserve` to burn another address's five attempts.
--     F7 closed the same shape for signin_find_account_by_email by giving it a `_for_actor` wrapper that requires a kind =
--     'user' binding (private.signin_bound_user) and revoking the core from edge_actor. This file does the same for the three
--     counter functions: peek_signin_otp_failures_for_actor / reserve_signin_otp_attempt_for_actor /
--     release_signin_otp_attempt_for_actor (edge_actor only), and EXECUTE on the three cores is revoked from edge_actor
--     (service_role keeps them: the legacy lane). An unbound edge_actor and a system delegate are both refused (42501).
--     HONEST LIMIT: a BOUND user actor can still call `release` for an address of its choosing (the counter is keyed by the
--     target address's hash, not by the caller), exactly as a bound actor can call signin_find_account_by_email_for_actor
--     for any address. The binding is the authorization the Edge entrypoint established (a verified session); this closes
--     "any connection", not "any signed-in caller going around the Edge code".
--
-- L2  `release` REFUNDED THE WRONG WINDOW.
--     release computed the CURRENT hour window itself, so a reservation taken at 10:59 and released at 11:00 (the proof's
--     transport failed, or it succeeded) decremented the NEW 11:00 bucket, handing a free attempt to a window that never
--     paid for it. reserve now RETURNS the window it took the attempt in, and release takes that window and decrements
--     exactly it. Both are therefore redefined: a changed return type / argument list cannot be CREATE OR REPLACEd, so the
--     0035 versions are dropped and recreated (same names, same private_definer ownership, same empty search_path), and
--     the function-inventory rows follow (the release row's identity args change; the reserve row's note does).
--       reserve_signin_otp_attempt(p_email_hash)      -> (o_attempts int, o_window_start timestamptz); o_attempts = -1 at the cap
--       release_signin_otp_attempt(p_email_hash, p_window_start timestamptz) -> int
--     p_window_start must be hour-aligned (the only values reserve ever returns): anything else is 22023. A window with no
--     bucket row (an old window already purged, or never reserved) is a no-op that returns 0.
--
-- N2/O10  (a link that waited on the per-account lock storing a grant between the delete's commit and deleteAuthUser):
--     NOT CLOSED HERE, on purpose. The gate's cheap closure was "signin_link_identity / signin_store_token refuse when the
--     app-side row delete_my_data removes is gone". That needs a row EVERY user is guaranteed to have. There is none:
--     app.profile (the obvious candidate) has no INSERT path anywhere in the repo (no migration, no Edge function, INSERT is
--     revoked from anon/authenticated in 0009) and no trigger on auth.users creates it, so an account that signs in by email
--     OTP and links Apple holds no app-side row at all; the same is true of every other FK-to-auth.users table in 0014's
--     pii_retention_policy (app.device, push_token, play, ... are created by use). A refusal keyed on such a row would
--     either block every user who has none or be a no-op, and inventing a row (a deletion tombstone) is a new table with its
--     own retention and export classification, which this follow-up was told not to do. The residual is recorded as O10 in
--     docs/security/p3-money-path-requirements.md with the corrected timing.
--
-- No table, column, grant on a table, policy or RLS setting is touched; FORCE RLS is not involved. The only grants this file
-- changes are EXECUTE: three revoked from edge_actor, three new wrappers granted to edge_actor, and the two recreated functions
-- granted to service_role only (NOT to edge_actor, NOT to edge_system). private.edge_policy_allowlist and
-- private.definer_policy_allowlist are unchanged.

-- ============================================================================
-- 1. The ownership bracket (0020 / 0022 / 0035): drop and recreate the two changed cores, add the three wrappers
-- ============================================================================
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

DROP FUNCTION private.reserve_signin_otp_attempt(text);
DROP FUNCTION private.release_signin_otp_attempt(text);

-- reserve: the attempt is taken BEFORE the proof is verified, in ONE statement that both checks the cap and increments (F3), and
-- the window the attempt was charged to comes back with it so the matching release can name it (L2). At the cap nothing is
-- incremented and o_attempts is -1 (o_window_start is still the current window; there is nothing to release).
CREATE FUNCTION private.reserve_signin_otp_attempt(p_email_hash text)
RETURNS TABLE (o_attempts int, o_window_start timestamptz)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_window_start timestamptz;
  v_count int;
BEGIN
  IF p_email_hash IS NULL OR p_email_hash !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'reserve_signin_otp_attempt: the email hash must be 64 lowercase hex characters' USING ERRCODE = '22023';
  END IF;
  v_window_start := to_timestamp(floor(extract(epoch FROM now()) / 3600) * 3600);
  INSERT INTO private.rate_limit_bucket AS b (bucket_key, window_start, count)
  VALUES ('signin-otp-fail:' || p_email_hash, v_window_start, 1)
  ON CONFLICT (bucket_key, window_start)
  DO UPDATE SET count = b.count + 1 WHERE b.count < 5
  RETURNING b.count INTO v_count;
  o_attempts := coalesce(v_count, -1);
  o_window_start := v_window_start;
  RETURN NEXT;
END;
$$;

-- release: undoes ONE reservation in the window it was taken in (a proof that SUCCEEDED, or that never reached a verdict because
-- the transport failed, is not a failure). Never below zero. Decrements ONLY the named window: after a rollover the caller's
-- window is an old bucket and the current one is untouched (L2).
CREATE FUNCTION private.release_signin_otp_attempt(p_email_hash text, p_window_start timestamptz)
RETURNS int
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_count int;
BEGIN
  IF p_email_hash IS NULL OR p_email_hash !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'release_signin_otp_attempt: the email hash must be 64 lowercase hex characters' USING ERRCODE = '22023';
  END IF;
  IF p_window_start IS NULL OR mod(extract(epoch FROM p_window_start), 3600) <> 0 THEN
    RAISE EXCEPTION 'release_signin_otp_attempt: the window must be the hour-aligned window start reserve returned' USING ERRCODE = '22023';
  END IF;
  UPDATE private.rate_limit_bucket b SET count = greatest(b.count - 1, 0)
  WHERE b.bucket_key = 'signin-otp-fail:' || p_email_hash AND b.window_start = p_window_start
  RETURNING b.count INTO v_count;
  RETURN coalesce(v_count, 0);
END;
$$;

-- The `_for_actor` wrappers (edge_actor): the same three operations, refused unless a kind = 'user' actor is bound in this
-- transaction (an unbound edge_actor, or a system delegate, gets 42501 and no answer): the F7 shape (private.signin_bound_user).
CREATE FUNCTION private.peek_signin_otp_failures_for_actor(p_email_hash text)
RETURNS int
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  PERFORM private.signin_bound_user('peek_signin_otp_failures_for_actor');
  RETURN private.peek_signin_otp_failures(p_email_hash);
END;
$$;

CREATE FUNCTION private.reserve_signin_otp_attempt_for_actor(p_email_hash text)
RETURNS TABLE (o_attempts int, o_window_start timestamptz)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  PERFORM private.signin_bound_user('reserve_signin_otp_attempt_for_actor');
  RETURN QUERY SELECT r.o_attempts, r.o_window_start FROM private.reserve_signin_otp_attempt(p_email_hash) r;
END;
$$;

CREATE FUNCTION private.release_signin_otp_attempt_for_actor(p_email_hash text, p_window_start timestamptz)
RETURNS int
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  PERFORM private.signin_bound_user('release_signin_otp_attempt_for_actor');
  RETURN private.release_signin_otp_attempt(p_email_hash, p_window_start);
END;
$$;

-- EXECUTE. PUBLIC first (private_definer-created functions default to PUBLIC), then exactly the roles below.
REVOKE EXECUTE ON FUNCTION private.reserve_signin_otp_attempt(text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.release_signin_otp_attempt(text, timestamptz) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.peek_signin_otp_failures_for_actor(text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.reserve_signin_otp_attempt_for_actor(text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.release_signin_otp_attempt_for_actor(text, timestamptz) FROM PUBLIC;

-- the cores: service_role only (the legacy lane). edge_actor loses the peek it was granted in 0035.
GRANT EXECUTE ON FUNCTION private.reserve_signin_otp_attempt(text) TO service_role;
GRANT EXECUTE ON FUNCTION private.release_signin_otp_attempt(text, timestamptz) TO service_role;
REVOKE EXECUTE ON FUNCTION private.peek_signin_otp_failures(text) FROM edge_actor;
-- the wrappers: edge_actor only.
GRANT EXECUTE ON FUNCTION private.peek_signin_otp_failures_for_actor(text) TO edge_actor;
GRANT EXECUTE ON FUNCTION private.reserve_signin_otp_attempt_for_actor(text) TO edge_actor;
GRANT EXECUTE ON FUNCTION private.release_signin_otp_attempt_for_actor(text, timestamptz) TO edge_actor;

COMMENT ON FUNCTION private.reserve_signin_otp_attempt(text) IS
  '0037. service_role core. Takes one OTP-proof attempt (atomic cap check + increment) and returns (attempts used incl. this one or -1 at the cap, the hour window it was charged to). Pass that window to release_signin_otp_attempt.';
COMMENT ON FUNCTION private.release_signin_otp_attempt(text, timestamptz) IS
  '0037. service_role core. Gives back one attempt in EXACTLY the named window (never the current one by itself: a release after a rollover must not refund the new window).';
COMMENT ON FUNCTION private.reserve_signin_otp_attempt_for_actor(text) IS
  '0037. edge_actor only. reserve_signin_otp_attempt, refused unless a kind = user actor is bound in this transaction (L1).';

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

-- ============================================================================
-- 2. Registry: private.function_inventory (the 0017 INSERT policy is still in place; the UPDATE / DELETE need the 0032 pattern)
-- ============================================================================
GRANT UPDATE, DELETE ON private.function_inventory TO CURRENT_USER;
CREATE POLICY current_user_edit_function_inventory_0037 ON private.function_inventory
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
-- the old release signature is gone
DELETE FROM private.function_inventory
WHERE schema_name = 'private' AND function_name = 'release_signin_otp_attempt' AND identity_args = 'p_email_hash text';
-- edge_actor can no longer call the cores
UPDATE private.function_inventory SET expected_edge_actor = false,
  note = '0035/0037: failed OTP proofs for one target email in the current hour (the bucket key is built in the database); service_role core, edge_actor reaches it through peek_signin_otp_failures_for_actor (L1)'
WHERE schema_name = 'private' AND function_name = 'peek_signin_otp_failures' AND identity_args = 'p_email_hash text';
UPDATE private.function_inventory SET expected_edge_actor = false,
  note = '0035/0037: take one OTP-proof attempt for a target email BEFORE verifying (atomic cap check + increment, o_attempts = -1 at the cap of 5 per hour); returns the window it was charged to (L2); service_role core, edge_actor reaches it through reserve_signin_otp_attempt_for_actor (L1)'
WHERE schema_name = 'private' AND function_name = 'reserve_signin_otp_attempt' AND identity_args = 'p_email_hash text';
INSERT INTO private.function_inventory
  (schema_name, function_name, identity_args, expected_anon, expected_authenticated, expected_service_role, expected_edge_actor, expected_edge_system, note)
VALUES
  ('private', 'release_signin_otp_attempt', 'p_email_hash text, p_window_start timestamp with time zone', false, false, true, false, false, '0037: give back one reserved OTP-proof attempt in exactly the window reserve returned (L2: not the current one); service_role core, edge_actor reaches it through release_signin_otp_attempt_for_actor (L1)'),
  ('private', 'peek_signin_otp_failures_for_actor', 'p_email_hash text', false, false, false, true, false, '0037: edge_actor only; peek_signin_otp_failures, refused unless a kind=user actor is bound (L1)'),
  ('private', 'reserve_signin_otp_attempt_for_actor', 'p_email_hash text', false, false, false, true, false, '0037: edge_actor only; reserve_signin_otp_attempt, refused unless a kind=user actor is bound (L1)'),
  ('private', 'release_signin_otp_attempt_for_actor', 'p_email_hash text, p_window_start timestamp with time zone', false, false, false, true, false, '0037: edge_actor only; release_signin_otp_attempt, refused unless a kind=user actor is bound (L1)');
DROP POLICY current_user_edit_function_inventory_0037 ON private.function_inventory;
REVOKE UPDATE, DELETE ON private.function_inventory FROM CURRENT_USER;
