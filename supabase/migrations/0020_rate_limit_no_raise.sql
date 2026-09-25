-- 0020_rate_limit_no_raise.sql
-- P3c gate round 3, blocking MEDIUM 3: "Rate-limit hits roll back on 4xx
-- (privileged.ts:233-235, inside the single db.begin()). 80 x
-- catalog_forged 422s left the bucket at 0. Record rate-limit hits in
-- their own short transaction BEFORE withOwnership's transaction, so
-- every attempt counts."
--
-- Isolating the CALL into its own short transaction (privileged.ts#
-- rateLimit.hit, this round) is necessary but NOT sufficient on its own:
-- 0007's original `private.hit_rate_limit` does its increment (the
-- INSERT ... ON CONFLICT DO UPDATE) and its over-limit check (RAISE
-- EXCEPTION ... USING ERRCODE = 'P0429') in the SAME statement, with no
-- EXCEPTION handler inside the function body. A RAISE EXCEPTION that
-- escapes a plpgsql function with no enclosing BEGIN...EXCEPTION block
-- aborts the CURRENT transaction -- and because there is no savepoint
-- boundary anywhere in that one statement's own execution, "the current
-- transaction" here is the SAME one-statement transaction the increment
-- itself ran in. Wrapping the call in its own `db.begin()` does not
-- change that: a single-statement transaction that raises still loses
-- ALL of that statement's own effects, including the increment that
-- statement had already performed moments earlier in the SAME plpgsql
-- call. This is exactly how "80 rejected requests leave the bucket at 0"
-- happens: every one of those 80 calls incremented, then immediately
-- un-incremented itself by raising.
--
-- FIX: `hit_rate_limit` no longer raises at all. It always returns the
-- POST-increment count (same as before, when under the limit) -- the
-- caller (privileged.ts#rateLimit.hit) compares `count > max` itself and
-- reports `{ok: false}` without ever needing the SQL layer to signal
-- failure via an aborted transaction. The increment statement can no
-- longer fail on its own account, so it always commits, whether the
-- bucket ends up under or over its cap -- which is the actual "every
-- attempt counts" property the gate asked for. Same signature (`(text,
-- interval, int) returns int`), so `CREATE OR REPLACE FUNCTION` preserves
-- the function's OID -- and therefore its existing GRANT EXECUTE
-- (service_role, 0007) -- with nothing further to re-grant in this file.
-- 0007/0016 are already merged, so this is a NEW migration rather than an
-- edit to either.
--
-- ⛔ Ownership, unlike the grant, is NOT free here and needs its own
-- fix, found only by actually RUNNING this migration (H2, tools/db/
-- test-migrations-no-migration-owner.sh, AND HARNESS_MODE=restricted):
-- `CREATE OR REPLACE FUNCTION` requires OWNING the function you're
-- replacing (or being a superuser) -- 0016_private_definer.sql already
-- transferred `hit_rate_limit`'s ownership to `private_definer`, and the
-- role actually APPLYING migrations (`migration_owner` in
-- HARNESS_MODE=restricted; the H2 check's own non-superuser
-- approximation; a real hosted project's own non-superuser migrator) is
-- NOT `private_definer` and is NOT a superuser.
--
-- First attempt (found insufficient by the SAME H2 run): `SET ROLE
-- private_definer` (0016's own `GRANT private_definer TO CURRENT_USER
-- WITH INHERIT FALSE, SET TRUE;` gives the migrate_user exactly enough
-- membership to do this) gets ownership right, but `CREATE OR REPLACE
-- FUNCTION` ALSO independently requires CREATE privilege on the
-- function's own SCHEMA -- for both a brand-new function AND a replace
-- of an existing one, not merely for a new one, contrary to this file's
-- own first-draft assumption. 0016's own should-fix ("private_definer
-- keeps USAGE... REVOKE CREATE ON SCHEMA private FROM private_definer")
-- deliberately left `private_definer` with NO create privilege on its
-- own schema at all -- a real hardening boundary (a compromised
-- SECURITY DEFINER function can't redefine itself or any sibling), not
-- an oversight to route around by just handing it back permanently.
--
-- FIX: bracket the SAME `SET ROLE private_definer` block with a
-- TEMPORARY re-grant of that one schema privilege, done as the
-- migrate_user itself (the owner of schema `private`, from 0001's own
-- `CREATE SCHEMA private`, so it needs no privilege of its own to
-- GRANT/REVOKE on it) -- opened immediately before, closed immediately
-- after, restoring 0016's exact hardened end-state (USAGE only) once
-- this migration finishes. This is the smallest window that satisfies
-- BOTH checks (ownership via SET ROLE, schema CREATE via the bracketed
-- grant) without leaving `private_definer` durably more privileged than
-- 0016 intended.
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

CREATE OR REPLACE FUNCTION private.hit_rate_limit(p_bucket_key text, p_window interval, p_max int)
RETURNS int
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_window_start timestamptz;
  v_count int;
BEGIN
  v_window_start := to_timestamp(floor(extract(epoch FROM now()) / extract(epoch FROM p_window)) * extract(epoch FROM p_window));

  INSERT INTO private.rate_limit_bucket (bucket_key, window_start, count)
  VALUES (p_bucket_key, v_window_start, 1)
  ON CONFLICT (bucket_key, window_start)
  DO UPDATE SET count = private.rate_limit_bucket.count + 1
  RETURNING count INTO v_count;

  -- No RAISE. The caller (privileged.ts#rateLimit.hit) decides ok/not-ok
  -- from the returned count vs. its own p_max -- see this file's own
  -- header for why the raise-based version could never satisfy "every
  -- attempt counts".
  RETURN v_count;
END;
$$;

COMMENT ON FUNCTION private.hit_rate_limit(text, interval, int) IS
  'Fixed-window rate limiter. Always increments and always returns the post-increment count -- never raises on over-limit (P3c gate round 3, blocking MEDIUM 3: a raise-on-overlimit design cannot make "every attempt counts" true, since the raise unavoidably discards the SAME statement''s own increment). The caller compares the returned count to its own max.';

RESET ROLE;
-- Restore 0016's exact hardened end-state — private_definer keeps only
-- USAGE on schema private, never CREATE, once this migration finishes.
REVOKE CREATE ON SCHEMA private FROM private_definer;
