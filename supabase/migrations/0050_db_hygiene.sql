-- 0050_db_hygiene.sql
-- DB hygiene follow-up: the batched purge definers stop depending on the planner's statistics (S1.1b gate L-4), and the S2a gate's pepper-epoch NIT. 0001-0048 are untouched.
--
-- WHY (S1.1b gate L-4; docs/security/partner-auth-design.md 17.3 / 17.10, p3-money-path-requirements.md "Tracked follow-up")
--   The batched purges delete with `DELETE ... WHERE key IN (SELECT key ... LIMIT n)` under RLS. When pg_class carries stale statistics for the table (a vacuum that could not
--   truncate left it at "N pages, 0 tuples", so the planner estimates a bulk-loaded backlog as ONE row) the planner can choose a Nested Loop Semi Join that re-runs the LIMIT subquery
--   once per outer row: 5,003 fresh rows took 26.9 s instead of about 30 ms. A production table that has been loaded for a while has usually been analyzed by autovacuum, but the
--   dependence was real. Section 1 redefines every such definer so the batch is taken ONCE and the delete is keyed on it, whatever the table's estimate.
--
--   WHAT WAS MEASURED, and why the shape is not the `WITH b AS MATERIALIZED (...) DELETE ... USING b` the follow-up note proposed (stale statistics reproduced with VACUUM (TRUNCATE false), no ANALYZE,
--   5,003 rows, as private_definer under RLS): the old shape took 5.8 s on consumed_nonce and 119 s on signin_email_proof; the MATERIALIZED / USING shape took 4.2 s and 4.4 s. It stops the
--   LIMIT subquery being re-run, but the join is still planned from a one-row estimate: a Nested Loop with the CTE as its inner side, 25 million comparisons, the same quadratic cost with a
--   cheaper constant. So the materialised batch is made an ARRAY, an uncorrelated InitPlan evaluated exactly once, and the key is matched with `key = ANY (ARRAY(SELECT key ... LIMIT n))`: an index
--   probe per key (or a hashed filter), linear however the table is estimated (consumed_nonce 8.6 ms, signin_email_proof 66 ms in the same state).
--   Two tables have a COMPOSITE key, which `= ANY` cannot probe: private.rate_limit_bucket (bucket_key, window_start) and app.install_link_account (install_link_hash, account_pseudonym). A ctid array is
--   not used: private_definer holds only COLUMN-level SELECT on install_link_account (0033), and ctid needs the table-level privilege, which this migration will not grant. Those two read the
--   batch once and delete it row by row in a loop, by primary key (a parameterised DELETE is an index probe whatever the estimate).
--
--   The six definers of that shape (latest definition of each): purge_consumed_nonce (0040), purge_rate_limit_buckets (0040), purge_signin_email_proofs (0041),
--   purge_signin_revocation_queue (0040), purge_install_link_tombstones (0033) and purge_fix_coords (0032; an UPDATE, the same shape). CREATE OR REPLACE with the SAME identity,
--   return type, SECURITY DEFINER, search_path = '' and owner: every grant, the comment and the private.function_inventory row are kept as they are (asserted below). The row bound, the age
--   floors, the argument checks, the purge windows (set_config) and the returned counts are unchanged; no ORDER BY is added to a table that had none (those tables have no index on their age column).
--   Nothing is granted, no policy is touched by this section: each definer reads and writes through the same private_definer policies as before.
--
-- Same bracket as 0030/0033/0037/0040: GRANT CREATE ON SCHEMA private TO private_definer; SET ROLE private_definer; ...; RESET ROLE; REVOKE CREATE. `migration_owner` is never named.

-- ============================================================================
-- 1. The six batched purges, the batch taken once (as private_definer)
-- ============================================================================
-- Evidence of what was there before, so the assertion at the end of section 1 can prove nothing but the body changed.
CREATE TEMP TABLE hygiene_0050_before AS
SELECT p.oid::regprocedure::text AS ident, p.proowner::regrole::text AS owner, p.prosecdef, p.proconfig, p.prorettype::regtype::text AS rettype, p.proacl::text AS acl, obj_description(p.oid, 'pg_proc') AS comment
FROM pg_proc p
WHERE p.oid IN ('private.purge_consumed_nonce()'::regprocedure, 'private.purge_rate_limit_buckets()'::regprocedure, 'private.purge_signin_email_proofs()'::regprocedure,
                'private.purge_signin_revocation_queue(interval)'::regprocedure, 'private.purge_install_link_tombstones(integer)'::regprocedure, 'private.purge_fix_coords(integer, integer)'::regprocedure);

GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

-- 1a. Consumed-nonce tombstones, 7 days past each row's own source expiry (consumed_at for rows with no stored expiry). (0017 / 0040)
CREATE OR REPLACE FUNCTION private.purge_consumed_nonce()
RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_limit constant int := 5000;
  v_deleted bigint;
BEGIN
  -- The floor stays in TWO places (here and in pd_purge_consumed_nonce_expired[_r], 0017). The batch is taken once, as an array (an InitPlan), whatever the statistics say.
  DELETE FROM private.consumed_nonce n
  WHERE n.nonce_hash = ANY (ARRAY(
    SELECT s.nonce_hash FROM private.consumed_nonce s
    WHERE COALESCE(s.expires_at, s.consumed_at) < now() - interval '7 days'
    LIMIT v_limit
  ));
  GET DIAGNOSTICS v_deleted = ROW_COUNT;
  RETURN v_deleted;
END;
$$;

-- 1b. Rate-limit windows older than 2 days (every key). (0007 / 0040)
CREATE OR REPLACE FUNCTION private.purge_rate_limit_buckets()
RETURNS int
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_limit constant int := 5000;
  v_deleted int := 0;
  v_k int;
  v_row record;
BEGIN
  -- A composite key: the batch is read once and each row is deleted by its primary key (an index probe whatever the estimate).
  FOR v_row IN
    SELECT s.bucket_key, s.window_start FROM private.rate_limit_bucket s
    WHERE s.window_start < now() - interval '2 days'
    LIMIT v_limit
  LOOP
    DELETE FROM private.rate_limit_bucket r WHERE r.bucket_key = v_row.bucket_key AND r.window_start = v_row.window_start;
    GET DIAGNOSTICS v_k = ROW_COUNT;
    v_deleted := v_deleted + v_k;
  END LOOP;
  RETURN v_deleted;
END;
$$;

-- 1c. Sign-in proofs an hour past their expiry, oldest first; opens and closes the app.signin.proof_purge window. (0039 / 0040 / 0041)
CREATE OR REPLACE FUNCTION private.purge_signin_email_proofs()
RETURNS int
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_limit constant int := 5000;
  v_n int;
BEGIN
  PERFORM set_config('app.signin.proof_purge', 'on', true);
  DELETE FROM private.signin_email_proof p
  WHERE p.id = ANY (ARRAY(
    SELECT s.id FROM private.signin_email_proof s
    WHERE s.expires_at < now() - interval '1 hour'
    ORDER BY s.expires_at, s.id
    LIMIT v_limit
  ));
  GET DIAGNOSTICS v_n = ROW_COUNT;
  PERFORM set_config('app.signin.proof_purge', '', true);
  RETURN v_n;
END;
$$;

-- 1d. Finished revocation rows older than p_older_than (1 .. 365 days); a pending row is never purged. (0035 / 0040)
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
  WHERE q.id = ANY (ARRAY(
    SELECT s.id FROM private.signin_revocation_queue s
    WHERE s.status <> 'pending' AND s.completed_at < now() - p_older_than
    LIMIT v_limit
  ));
  GET DIAGNOSTICS v_n = ROW_COUNT;
  RETURN v_n;
END;
$$;

-- 1e. Install-link tombstones 24 months past first_seen_at, oldest first, at most p_max_rows (1..100000). (0033)
CREATE OR REPLACE FUNCTION private.purge_install_link_tombstones(p_max_rows integer)
RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  -- THE retention (owner decision 2026-10-02). The private_definer policies pd_purge_install_link_read / _delete (0033, section 4) repeat the same interval.
  v_retention constant interval := interval '24 months';
  v_n integer := 0;
  v_k integer;
  v_row record;
BEGIN
  IF p_max_rows IS NULL OR p_max_rows < 1 OR p_max_rows > 100000 THEN
    RAISE EXCEPTION 'purge_install_link_tombstones: p_max_rows must be between 1 and 100000' USING ERRCODE = '22023';
  END IF;
  -- A composite key (and only column-level SELECT, so no ctid): the batch is read once, oldest first, and each row is deleted by its primary key.
  FOR v_row IN
    SELECT o.install_link_hash, o.account_pseudonym
    FROM app.install_link_account o
    WHERE o.first_seen_at < now() - v_retention
    ORDER BY o.first_seen_at, o.install_link_hash, o.account_pseudonym
    LIMIT p_max_rows
  LOOP
    DELETE FROM app.install_link_account t WHERE t.install_link_hash = v_row.install_link_hash AND t.account_pseudonym = v_row.account_pseudonym;
    GET DIAGNOSTICS v_k = ROW_COUNT;
    v_n := v_n + v_k;
  END LOOP;
  RETURN v_n;
END;
$$;

-- 1f. Raw fix coordinates past retention (an UPDATE that removes the 'fixCoords' key; the same shape, the batch an array). (0030 / 0032)
CREATE OR REPLACE FUNCTION private.purge_fix_coords(p_retention_days int, p_limit int)
RETURNS int
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_n int;
BEGIN
  IF p_retention_days IS NULL OR p_retention_days < 7 OR p_retention_days > 30 THEN
    RAISE EXCEPTION 'purge_fix_coords: retention must be between 7 and 30 days' USING ERRCODE = '22023';
  END IF;
  IF p_limit IS NULL OR p_limit < 1 OR p_limit > 10000 THEN
    RAISE EXCEPTION 'purge_fix_coords: limit must be between 1 and 10000' USING ERRCODE = '22023';
  END IF;
  -- Open the read window (policy pd_fix_coords_read) for this transaction; closed again below.
  PERFORM set_config('app.edge.purge_fix_coords', 'on', true);
  UPDATE app.evidence e SET integrity = e.integrity - 'fixCoords'
  WHERE e.id = ANY (ARRAY(
    SELECT d.id FROM app.evidence d
    WHERE d.integrity ? 'fixCoords'
      AND (
        d.created_at < now() - make_interval(days => p_retention_days)
        OR d.course_id IS NULL
        OR NOT EXISTS (
          SELECT 1 FROM app.catalog_id_ledger l
          WHERE l.id = d.course_id
            AND (l.status = 'stub'
                 OR l.split_from IS NOT NULL
                 OR EXISTS (SELECT 1 FROM app.catalog_id_ledger s WHERE s.split_from = l.id)
                 OR EXISTS (SELECT 1 FROM app.catalog_rescore_backlog b WHERE b.course_id = l.id AND b.done_at IS NULL))
        )
      )
    ORDER BY d.created_at
    LIMIT p_limit
  ));
  GET DIAGNOSTICS v_n = ROW_COUNT;
  PERFORM set_config('app.edge.purge_fix_coords', '', true);
  RETURN v_n;
END;
$$;

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

-- Prove only the bodies changed: identity, owner, SECURITY DEFINER, search_path, return type, ACL (every grant) and comment are exactly what they were; and no body holds the per-row-rescanned `IN (SELECT ... LIMIT)` shape any more.
DO $assert_0050_purges$
DECLARE
  v_row record;
  v_now record;
BEGIN
  IF (SELECT count(*) FROM hygiene_0050_before) <> 6 THEN
    RAISE EXCEPTION '0050: expected six purge definers';
  END IF;
  FOR v_row IN SELECT * FROM hygiene_0050_before LOOP
    SELECT p.proowner::regrole::text AS owner, p.prosecdef, p.proconfig, p.prorettype::regtype::text AS rettype, p.proacl::text AS acl, obj_description(p.oid, 'pg_proc') AS comment, p.prosrc
      INTO v_now FROM pg_proc p WHERE p.oid = v_row.ident::regprocedure;
    IF v_now.owner IS DISTINCT FROM v_row.owner OR v_now.prosecdef IS DISTINCT FROM v_row.prosecdef OR v_now.proconfig IS DISTINCT FROM v_row.proconfig
       OR v_now.rettype IS DISTINCT FROM v_row.rettype OR v_now.acl IS DISTINCT FROM v_row.acl OR v_now.comment IS DISTINCT FROM v_row.comment THEN
      RAISE EXCEPTION '0050: % changed more than its body (owner / security / search_path / return type / grants / comment)', v_row.ident;
    END IF;
    IF v_now.prosrc ~ '\mIN \(\s*SELECT' OR v_now.prosrc !~ '(= ANY \(ARRAY\(|FOR v_row IN)' THEN
      RAISE EXCEPTION '0050: % does not take its batch once (an InitPlan array, or a loop over the batch)', v_row.ident;
    END IF;
  END LOOP;
END
$assert_0050_purges$;
DROP TABLE hygiene_0050_before;
