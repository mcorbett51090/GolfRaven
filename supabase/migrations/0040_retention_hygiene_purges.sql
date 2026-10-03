-- 0040_retention_hygiene_purges.sql
-- Edge role PR4c: the two TTL hygiene purges join the independent retention schedule, and the two sign-in purges that were single DELETEs
-- become bounded. 0001-0039 are untouched.
--
-- WHY (owner decision 2026-10-02, edge-role-design.md section 14.4)
--   private.purge_consumed_nonce() (7 days past a challenge's expiry) and private.purge_rate_limit_buckets() (windows older than 2 days) were
--   `service_role`-only (0007 / 0017) and nothing ran them: the edge runtime has no service_role path (PR4b deleted it), so they could not be
--   scheduled from the Edge Function that already runs the other four retention classes. The owner approved granting EXECUTE on EXACTLY these
--   two functions to edge_system, and making them steps of `retention-purge`. Both are TTL hygiene on hashes and `<uid>:<key>` counters, not part
--   of the E5 retention promises, so they sit behind the four promised classes in the step order.
--
-- THE ONE NEW GRANT
--   GRANT EXECUTE ON FUNCTION private.purge_consumed_nonce()      TO edge_system;
--   GRANT EXECUTE ON FUNCTION private.purge_rate_limit_buckets()  TO edge_system;
--   Nothing else is granted to anyone. No table privilege, no column privilege, no policy, no role membership changes; FORCE RLS is untouched;
--   private.edge_policy_allowlist and private.definer_policy_allowlist are unchanged (both functions already ran under their own private_definer
--   policies: pd_purge_consumed_nonce_expired[_r] (the 7-day floor, repeated in the policy) and pd_rate_limit_purge[_r]). Proved below by a
--   has_function_privilege assertion for every role, and afterwards by the existing inventory gate (matrix 10 check 2 / verify-function-inventory):
--   any OTHER function edge_system could execute would disagree with private.function_inventory.
--
-- THE BOUNDS (read first, as the task required). Both functions were age-bounded (7 days past expiry / 2 days past window start) and NEITHER was
--   row-bounded: a single DELETE of the whole backlog. purge_rate_limit_buckets has never run (nothing scheduled it), so its first scheduled run
--   would delete every expired window since launch in one statement, and a backlog that exceeds the 10 s statement timeout would fail the same
--   way on every run and never shrink. So both are redefined, each with an explicit row bound (5000 per call), and the retention-purge step loops
--   the batch exactly as it does for the fix-coordinate and tombstone purges. The two sign-in purges (purge_signin_email_proofs,
--   purge_signin_revocation_queue) had the same property (LOW-3 of the PR4b gate) and get the same bound.
--
--   * Same identities (name and argument list), so CREATE OR REPLACE keeps owner (private_definer), search_path (''), every existing grant, the
--     comment and the private.function_inventory row. The ONE exception is purge_rate_limit_buckets(): it returned void, a batched step needs the
--     count, and CREATE OR REPLACE cannot change a return type, so it is DROPped and recreated with the SAME name and NO arguments, returning int.
--     Its existing grants (service_role EXECUTE, nothing for anyone else) are RE-made, not widened; the assertions at the end prove the set.
--   * The bound is a constant inside the function (v_limit, 5000), not a parameter: a caller cannot raise it, and the signatures (and so the
--     inventory identities and every existing caller) are unchanged. `RETENTION_BATCH_ROWS` in privileged.ts is the same 5000; the Deno suite
--     proves a full batch is exactly 5000 so the two cannot drift apart silently.
--   * No ORDER BY on the three tables with no index on their age column (consumed_nonce, rate_limit_bucket, signin_revocation_queue): an ordered
--     batch would sort the whole backlog on every call. A hygiene purge needs no order (it is idempotent and age-bounded); each call removes up to
--     5000 expired rows and the step repeats while a batch comes back full. The proof table has an index on expires_at and keeps the oldest-first order.
--   * The retention floors are unchanged AND still enforced twice: the WHERE clause of the inner SELECT and the private_definer RLS policies.
--
-- THE `<uid>:me-delete:user` BUCKET (PR4b gate, LOW). delete_my_data deliberately keeps each deleted account's `<uid>:me-delete:user` rate-limit
--   bucket (so a retry of the same deletion stays limited). The requirements document assumed a "nightly sweep" would remove it. This purge does
--   (any bucket whose window_start is more than 2 days old, whatever its key; the me-delete bucket's window is one day), once its window has passed
--   by a day. Proved in matrix 20 and in the Deno suite.
--
-- Same bracket as 0030/0033/0037: GRANT CREATE ON SCHEMA private TO private_definer; SET ROLE private_definer; ...; RESET ROLE; REVOKE CREATE.
-- `migration_owner` is never named.

-- ============================================================================
-- 1. The four bounded purges (as private_definer)
-- ============================================================================
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

-- 1a. TTL purge of the consumed-nonce tombstones: 7 days past each row's own source expiry (consumed_at for rows with no stored expiry).
CREATE OR REPLACE FUNCTION private.purge_consumed_nonce()
RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_limit constant int := 5000;
  v_deleted bigint;
BEGIN
  -- The floor stays in TWO places (here and in pd_purge_consumed_nonce_expired[_r], 0017): even if this predicate were wrong, private_definer can
  -- neither read nor delete a tombstone that is not 7 days past its expiry.
  DELETE FROM private.consumed_nonce n
  WHERE n.nonce_hash IN (
    SELECT s.nonce_hash FROM private.consumed_nonce s
    WHERE COALESCE(s.expires_at, s.consumed_at) < now() - interval '7 days'
    LIMIT v_limit
  );
  GET DIAGNOSTICS v_deleted = ROW_COUNT;
  RETURN v_deleted;
END;
$$;

-- 1b. TTL purge of rate-limit windows older than 2 days (every key: a bucket never outlives its window by more than a day). It returned void
-- (0007); a batched step needs the count, so it is dropped and recreated with the same name and no arguments, returning int.
DROP FUNCTION private.purge_rate_limit_buckets();
CREATE FUNCTION private.purge_rate_limit_buckets()
RETURNS int
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_limit constant int := 5000;
  v_deleted int;
BEGIN
  DELETE FROM private.rate_limit_bucket b
  WHERE (b.bucket_key, b.window_start) IN (
    SELECT s.bucket_key, s.window_start FROM private.rate_limit_bucket s
    WHERE s.window_start < now() - interval '2 days'
    LIMIT v_limit
  );
  GET DIAGNOSTICS v_deleted = ROW_COUNT;
  RETURN v_deleted;
END;
$$;
-- The same two statements 0007 made, no more: nobody but service_role held EXECUTE (anon / authenticated / PUBLIC: no).
REVOKE EXECUTE ON FUNCTION private.purge_rate_limit_buckets() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.purge_rate_limit_buckets() TO service_role;

-- 1c. Sign-in proofs an hour past their expiry (0039, was one DELETE). The expires_at index makes the ordered batch cheap.
CREATE OR REPLACE FUNCTION private.purge_signin_email_proofs()
RETURNS int
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_limit constant int := 5000;
  v_n int;
BEGIN
  DELETE FROM private.signin_email_proof p
  WHERE p.id IN (
    SELECT s.id FROM private.signin_email_proof s
    WHERE s.expires_at < now() - interval '1 hour'
    ORDER BY s.expires_at, s.id
    LIMIT v_limit
  );
  GET DIAGNOSTICS v_n = ROW_COUNT;
  RETURN v_n;
END;
$$;

-- 1d. Finished revocation rows older than p_older_than (1 .. 365 days) (0035, was one DELETE). A pending row is never purged.
CREATE OR REPLACE FUNCTION private.purge_signin_revocation_queue(p_older_than interval)
RETURNS int
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_limit constant int := 5000;
  v_n int;
BEGIN
  IF p_older_than IS NULL OR p_older_than < interval '1 day' OR p_older_than > interval '365 days' THEN
    RAISE EXCEPTION 'purge_signin_revocation_queue: the age must be between 1 and 365 days' USING ERRCODE = '22023';
  END IF;
  DELETE FROM private.signin_revocation_queue q
  WHERE q.id IN (
    SELECT s.id FROM private.signin_revocation_queue s
    WHERE s.status <> 'pending' AND s.completed_at < now() - p_older_than
    LIMIT v_limit
  );
  GET DIAGNOSTICS v_n = ROW_COUNT;
  RETURN v_n;
END;
$$;

-- 1e. The grants, inside the bracket (the owner makes them): the owner-approved EXECUTE for edge_system on exactly the two hygiene purges.
-- (The other two already grant service_role and edge_system; CREATE OR REPLACE kept those.) PUBLIC is revoked again for the two, belt and braces.
REVOKE EXECUTE ON FUNCTION private.purge_consumed_nonce() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.purge_consumed_nonce() TO edge_system;
GRANT EXECUTE ON FUNCTION private.purge_rate_limit_buckets() TO edge_system;

COMMENT ON FUNCTION private.purge_consumed_nonce() IS
  '0017/0040. service_role and edge_system (retention-purge). Deletes consumed_nonce tombstones more than 7 days past their own source expiry (consumed_at when there is none), at most 5000 per call, returns the count. The floor is repeated in the private_definer policies pd_purge_consumed_nonce_expired[_r].';
COMMENT ON FUNCTION private.purge_rate_limit_buckets() IS
  '0007/0040. service_role and edge_system (retention-purge). Deletes rate_limit_bucket rows whose window_start is more than 2 days old (any key, the kept <uid>:me-delete:user bucket included once its window has passed), at most 5000 per call, returns the count.';
COMMENT ON FUNCTION private.purge_signin_email_proofs() IS
  '0039/0040. System work (edge_system, service_role): deletes proofs an hour past their expiry, oldest first, at most 5000 per call, returns the count.';
COMMENT ON FUNCTION private.purge_signin_revocation_queue(interval) IS
  '0035/0040. System work (edge_system, service_role): deletes finished (revoked / expired) queue rows older than the given age (1..365 days), never a pending one, at most 5000 per call, returns the count.';

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

-- ============================================================================
-- 2. Prove the grants: a refused or misapplied GRANT only warns, so the migration fails HERE rather than on the first scheduled run
-- ============================================================================
DO $assert_0040_grants$
DECLARE
  v_fn text;
  v_role text;
  v_expected boolean;
BEGIN
  FOREACH v_fn IN ARRAY ARRAY['private.purge_consumed_nonce()', 'private.purge_rate_limit_buckets()'] LOOP
    FOREACH v_role IN ARRAY ARRAY['edge_system', 'service_role', 'edge_actor', 'anon', 'authenticated'] LOOP
      -- edge_system and service_role may execute; nobody else may
      v_expected := v_role IN ('edge_system', 'service_role');
      IF has_function_privilege(v_role, v_fn::regprocedure, 'EXECUTE') IS DISTINCT FROM v_expected THEN
        RAISE EXCEPTION '0040: % EXECUTE for % is % but must be %', v_fn, v_role, NOT v_expected, v_expected;
      END IF;
    END LOOP;
    IF NOT EXISTS (SELECT 1 FROM pg_proc p WHERE p.oid = v_fn::regprocedure AND p.prosecdef AND p.proowner = 'private_definer'::regrole AND p.proconfig = ARRAY['search_path=""']) THEN
      RAISE EXCEPTION '0040: % is not SECURITY DEFINER owned by private_definer with search_path=''''', v_fn;
    END IF;
  END LOOP;
  -- the two sign-in purges kept their grants through CREATE OR REPLACE
  FOREACH v_fn IN ARRAY ARRAY['private.purge_signin_email_proofs()', 'private.purge_signin_revocation_queue(interval)'] LOOP
    FOREACH v_role IN ARRAY ARRAY['edge_system', 'service_role'] LOOP
      IF NOT has_function_privilege(v_role, v_fn::regprocedure, 'EXECUTE') THEN
        RAISE EXCEPTION '0040: % lost EXECUTE for %', v_fn, v_role;
      END IF;
    END LOOP;
    FOREACH v_role IN ARRAY ARRAY['edge_actor', 'anon', 'authenticated'] LOOP
      IF has_function_privilege(v_role, v_fn::regprocedure, 'EXECUTE') THEN
        RAISE EXCEPTION '0040: % gained EXECUTE for %', v_fn, v_role;
      END IF;
    END LOOP;
  END LOOP;
END
$assert_0040_grants$;

-- ============================================================================
-- 3. Registry: private.function_inventory (the 0017 INSERT policy is not enough; UPDATE needs the 0037 pattern)
-- ============================================================================
GRANT UPDATE ON private.function_inventory TO CURRENT_USER;
CREATE POLICY current_user_edit_function_inventory_0040 ON private.function_inventory
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
UPDATE private.function_inventory SET expected_edge_system = true,
  note = '0017/0040: TTL purge of private.consumed_nonce (7 days past source expiry, 5000 per call); service_role and edge_system (retention-purge step; owner decision 2026-10-02). SECURITY DEFINER owned by private_definer'
WHERE schema_name = 'private' AND function_name = 'purge_consumed_nonce' AND identity_args = '';
UPDATE private.function_inventory SET expected_edge_system = true,
  note = '0007/0040: TTL purge of private.rate_limit_bucket (windows older than 2 days, 5000 per call, returns int since 0040); service_role and edge_system (retention-purge step; owner decision 2026-10-02)'
WHERE schema_name = 'private' AND function_name = 'purge_rate_limit_buckets' AND identity_args = '';
UPDATE private.function_inventory SET note = '0039/0040: delete proofs an hour past their expiry, at most 5000 per call; system work (service_role, edge_system)'
WHERE schema_name = 'private' AND function_name = 'purge_signin_email_proofs' AND identity_args = '';
UPDATE private.function_inventory SET note = '0035/0040: delete finished revocation rows older than 1..365 days, at most 5000 per call; system work'
WHERE schema_name = 'private' AND function_name = 'purge_signin_revocation_queue' AND identity_args = 'p_older_than interval';
-- Four rows must have been changed, no more and no fewer (an UPDATE that matches nothing is silent).
DO $assert_0040_inventory$
BEGIN
  IF (SELECT count(*) FROM private.function_inventory
      WHERE schema_name = 'private' AND note LIKE '%0040%'
        AND function_name IN ('purge_consumed_nonce', 'purge_rate_limit_buckets', 'purge_signin_email_proofs', 'purge_signin_revocation_queue')) <> 4 THEN
    RAISE EXCEPTION '0040: expected exactly four function_inventory rows updated';
  END IF;
  IF (SELECT count(*) FROM private.function_inventory WHERE expected_edge_system AND function_name IN ('purge_consumed_nonce', 'purge_rate_limit_buckets')) <> 2 THEN
    RAISE EXCEPTION '0040: the inventory must expect edge_system EXECUTE on exactly the two hygiene purges';
  END IF;
END
$assert_0040_inventory$;

DROP POLICY current_user_edit_function_inventory_0040 ON private.function_inventory;
REVOKE UPDATE ON private.function_inventory FROM CURRENT_USER;
