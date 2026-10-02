-- 0030_edge_role_core.sql
-- Accepted follow-up 6 (docs/security/p3-money-path-requirements.md, "Updated Accepted follow-ups"):
-- "Before the FIRST real deploy, move to a dedicated NOBYPASSRLS login role for the Edge Function
-- connection, with SET LOCAL-scoped, actor-parameterized policies or SECURITY DEFINER functions
-- replacing the current blanket service_role BYPASSRLS model."
--
-- THIS IS PR1 OF 4 (database only; nothing in TypeScript uses any of it yet — see
-- docs/security/edge-role-design.md for the full design, the sequencing and what PR2-PR4 do).
-- This file (N_a) creates the ROLES, the ACTOR-BINDING mechanism, the definer functions and the
-- registries. 0031 (N_b) creates every GRANT and every RLS POLICY for the new roles, and the one
-- trigger-function redefinition. Both leave `service_role`, `anon` and `authenticated` untouched:
-- service_role keeps its blanket access until PR5, so nothing that works today stops working.
--
-- ============================================================================
-- THE MODEL
-- ============================================================================
--   edge_gateway  the ONLY role of the three that can log in. Created NOLOGIN here; LOGIN and the
--                 password come ONLY from tools/db/provision-edge-login.sh (never a migration, so no
--                 credential is ever committed). NOSUPERUSER NOBYPASSRLS NOINHERIT, no grants of its
--                 own, a member of edge_actor and edge_system WITH INHERIT FALSE, SET TRUE.
--   edge_actor    per-user work. NOLOGIN NOINHERIT NOBYPASSRLS. Every policy that applies to it is
--                 keyed on private.actor_uid(), never on a GUC and never on auth.uid().
--   edge_system   catalog import only. NOLOGIN NOINHERIT NOBYPASSRLS. It has NO policy and NO grant
--                 on any table that holds personal data; it reaches another user's rows only through
--                 the narrow definer functions below, or by BINDING AS a row's owner through one of
--                 the two delegate binders (and then switching to edge_actor).
--
-- Why not `authenticated` + request.jwt.claims: the connecting role could forge the claims GUC. A
-- GUC is set by whoever holds the connection; so no identity decision is ever made from one here.
--
-- ACTOR BINDING (no GUC):
--   private.actor_binding is an UNLOGGED table keyed on the backend pid, FORCE RLS, with no edge
--   grant at all. private.bind_actor(uid) (edge_actor only) records (pid, top-level transaction id,
--   uid). private.actor_uid() returns the uid ONLY when the stored transaction id equals the current
--   transaction's, else NULL -- so a binding left behind by an earlier transaction on a pooled
--   connection, or undone by a rolled-back savepoint, fails CLOSED: every `user_id = actor_uid()`
--   comparison is NULL, every policy admits nothing. A second bind in the same transaction raises.
--   Honest limit (the authenticator trust model): a fully compromised Edge runtime can still bind any
--   uid. What this buys is that the identity is an in-database fact the CONNECTION cannot forge by
--   setting a session variable, that a forgotten bind fails closed, and that every cross-user path is
--   a named, reviewed function. (An optional follow-up, not built: verify the JWT in the database.)
--
-- ============================================================================
-- OWNERSHIP BRACKET
-- ============================================================================
-- Every new function is SECURITY DEFINER, owned by private_definer, search_path = '', in schema
-- `private`, and created INSIDE the 0020/0022 bracket (GRANT CREATE ON SCHEMA private TO
-- private_definer; SET ROLE private_definer; ...; RESET ROLE; REVOKE CREATE ...). Functions created
-- as private_definer get PUBLIC EXECUTE by default (the 0001 default-privilege revoke belongs to the
-- migration role, not to private_definer), so each one REVOKEs it explicitly while still owner.
-- `migration_owner` is never named: CURRENT_USER is used wherever the migrating role is meant.
--
-- DEPENDS ON the final (P3f round 3, merged) 0027: it reads app.install_link_account and grants on
-- app.record_install_link / private.account_pseudonyms, which exist only there.
--
-- This migration needs CREATEROLE (CREATE ROLE edge_*). HARNESS_MODE=restricted runs it as a
-- NOSUPERUSER CREATEROLE role, which is the proof that no superuser is required.

-- ============================================================================
-- 1. Roles + membership
-- ============================================================================
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'edge_gateway') THEN
    CREATE ROLE edge_gateway NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'edge_actor') THEN
    CREATE ROLE edge_actor NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'edge_system') THEN
    CREATE ROLE edge_system NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
  END IF;
END
$$;
-- Re-assert what a CREATEROLE (non-superuser) migrator is allowed to re-assert on a re-run, without
-- touching LOGIN on edge_gateway (the provisioning script owns that). SUPERUSER / BYPASSRLS /
-- REPLICATION cannot be altered by a non-superuser at all (not even to "NO..."); they are fixed at
-- CREATE ROLE above, and tools/db/verify-function-inventory.mjs check 9 (and matrix check 9) fail the
-- build if any of the three edge roles ever holds one.
ALTER ROLE edge_gateway NOINHERIT NOCREATEROLE NOCREATEDB;
ALTER ROLE edge_actor NOLOGIN NOINHERIT NOCREATEROLE NOCREATEDB;
ALTER ROLE edge_system NOLOGIN NOINHERIT NOCREATEROLE NOCREATEDB;

-- INHERIT FALSE: edge_gateway must not silently hold the privileges of edge_actor/edge_system, only
-- be ABLE to `SET LOCAL ROLE` into them (the same posture 0016 gives the migrating role towards
-- private_definer). The creating role holds ADMIN OPTION on all three (PG16+ CREATE ROLE), which is
-- what makes these GRANTs legal for a NOSUPERUSER CREATEROLE migrator.
GRANT edge_actor TO edge_gateway WITH INHERIT FALSE, SET TRUE;
GRANT edge_system TO edge_gateway WITH INHERIT FALSE, SET TRUE;

-- Schema USAGE only (name resolution). It grants no table privilege and no EXECUTE: every table
-- grant is explicit in 0031, and every function in `private` has had PUBLIC EXECUTE revoked
-- (0014 §4, 0001's default-privilege revoke), so USAGE on `private` reaches only the functions
-- granted below. edge_gateway itself gets NO usage on app/private: until it SETs ROLE it can name
-- nothing there.
GRANT USAGE ON SCHEMA app, private TO edge_actor, edge_system;

-- PostGIS (Repo#catalog.matchFix runs ST_DWithin as the actor). The extension lives in whichever
-- schema CREATE EXTENSION chose (`public` here, `extensions` on Supabase), so the grant is dynamic.
-- Function EXECUTE on the extension's functions is PUBLIC's by default.
DO $$
DECLARE
  v_schema text;
BEGIN
  SELECT n.nspname INTO v_schema FROM pg_extension e JOIN pg_namespace n ON n.oid = e.extnamespace WHERE e.extname = 'postgis';
  IF v_schema IS NOT NULL THEN
    EXECUTE format('GRANT USAGE ON SCHEMA %I TO edge_actor, edge_system', v_schema);
  END IF;
END
$$;

-- ============================================================================
-- 2. private.actor_binding
-- ============================================================================
-- UNLOGGED: contents are meaningless after a crash (no transaction survives one), and it keeps the
-- bind write out of the WAL. It holds at most one row per backend; a row outlives its transaction
-- but is dead (actor_uid() ignores it) the moment the transaction ends.
CREATE UNLOGGED TABLE private.actor_binding (
  backend_pid int PRIMARY KEY,
  xact xid8 NOT NULL,
  actor_uid uuid NOT NULL,
  kind text NOT NULL CHECK (kind IN ('user', 'system_delegate')),
  bound_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
COMMENT ON TABLE private.actor_binding IS
  'Edge-role actor binding (0030). One row per backend pid. A row binds an actor ONLY for the transaction whose top-level id it stores (private.actor_uid() compares it with pg_current_xact_id_if_assigned()). kind = user: bound by edge_actor via private.bind_actor. kind = system_delegate: bound by edge_system via a delegate binder, for the owner of one specific queued row. No role other than private_definer has any privilege on this table.';
ALTER TABLE private.actor_binding ENABLE ROW LEVEL SECURITY;
ALTER TABLE private.actor_binding FORCE ROW LEVEL SECURITY;
GRANT SELECT, INSERT, UPDATE ON private.actor_binding TO private_definer;
-- Each policy admits only the CURRENT backend's own row: no function running as private_definer can
-- read or write any other session's binding through this table.
CREATE POLICY pd_actor_binding_select ON private.actor_binding
  FOR SELECT TO private_definer USING (backend_pid = pg_backend_pid());
CREATE POLICY pd_actor_binding_insert ON private.actor_binding
  FOR INSERT TO private_definer WITH CHECK (backend_pid = pg_backend_pid());
CREATE POLICY pd_actor_binding_update ON private.actor_binding
  FOR UPDATE TO private_definer USING (backend_pid = pg_backend_pid()) WITH CHECK (backend_pid = pg_backend_pid());

-- ============================================================================
-- 3. private.function_inventory: the edge_* EXECUTE columns
-- ============================================================================
-- check 2 of tools/db/verify-function-inventory.mjs (and the matrix) compares each inventory row's
-- expected EXECUTE grants with the real ones for every role; the two edge roles are added.
ALTER TABLE private.function_inventory
  ADD COLUMN expected_edge_actor boolean NOT NULL DEFAULT false,
  ADD COLUMN expected_edge_system boolean NOT NULL DEFAULT false;

-- ============================================================================
-- 4. Supporting private_definer reach for the definers below
-- ============================================================================
-- Every one of these is a policy applying to private_definer, so each is registered in
-- private.definer_policy_allowlist (section 6) and the checked-in fixture
-- supabase/tests/fixtures/definer_policy_exprs.txt.

-- 4a. The delegate binders find the OWNER of one specific queued row. queued_catalog rows only.
CREATE POLICY pd_queued_catalog_read ON app.evidence
  FOR SELECT TO private_definer USING (status = 'queued_catalog'::app.evidence_status);

-- 4b. The fix-coordinate purge removes ONLY the 'fixCoords' key (retention minimisation, P3e), across all
-- users. UPDATE is narrow by construction: private_definer may update only rows that carry the key, only to
-- a state where they no longer do, and only the `integrity` column (column grant). But an UPDATE also checks
-- its NEW row against the SELECT policy (the 0016 "_r companion" finding, there for set_null columns), and the
-- new row -- without 'fixCoords' -- is exactly what a narrow read policy must NOT admit. So the read policy is
-- a WINDOW: it admits rows only while private.purge_fix_coords has set app.edge.purge_fix_coords = 'on' for the
-- current transaction (the 0017 guard-read pattern, nullif(current_setting(..., true), '') form). No other
-- function an edge role can reach reads app.evidence without its own row filter (export/delete filter by the
-- bound uid, the binders by one id or by status), so a forged window opens nothing; and nothing outside the
-- purge can UPDATE, because the UPDATE policy and the column grant do not depend on the window.
GRANT UPDATE (integrity) ON app.evidence TO private_definer;
CREATE POLICY pd_fix_coords_read ON app.evidence
  FOR SELECT TO private_definer USING (nullif(current_setting('app.edge.purge_fix_coords', true), '') = 'on');
CREATE POLICY pd_fix_coords_update ON app.evidence
  FOR UPDATE TO private_definer USING (integrity ? 'fixCoords') WITH CHECK (NOT (integrity ? 'fixCoords'));

-- 4c. Public catalog data the purge and the rescore delegate read (no personal data in either table).
GRANT SELECT ON app.catalog_id_ledger, app.catalog_rescore_backlog TO private_definer;
CREATE POLICY pd_read_catalog_id_ledger ON app.catalog_id_ledger FOR SELECT TO private_definer USING (true);
CREATE POLICY pd_read_catalog_rescore_backlog ON app.catalog_rescore_backlog FOR SELECT TO private_definer USING (true);

-- 4d. The rescore delegate / list function read plays ONLY at a course that has an open backlog row.
CREATE POLICY pd_rescore_play_read ON app.play
  FOR SELECT TO private_definer USING (
    EXISTS (SELECT 1 FROM app.catalog_rescore_backlog b WHERE b.course_id = play.course_id AND b.done_at IS NULL)
  );

-- 4e. device_link_signals_for_actor: the Android A20 substitute counts accounts ACROSS users (live device rows,
-- and, since P3f round 3, the pseudonymous install-link tombstone app.install_link_account), which edge_actor's
-- own-rows policies cannot do (so the P3f function under edge_actor would silently undercount and fail OPEN).
-- The definer sets three transaction-local GUCs to exactly the values it is about to match on, and clears them
-- right after -- the 0017 guard-read pattern, in the exact nullif(current_setting(.., true), '') form check 7
-- requires. Outside that window the policies admit nothing. (A caller who sets these GUCs himself gains nothing:
-- no function reachable from an edge role runs an unfiltered read of app.device or app.install_link_account as
-- private_definer.) The tombstone read is column-limited: no hmac key id, no timestamps but fraud_voided_at.
CREATE POLICY pd_device_link_read ON app.device
  FOR SELECT TO private_definer USING (
    id = nullif(current_setting('app.edge.link_device_id', true), '')::uuid
    OR install_link_hash = nullif(current_setting('app.edge.link_hash', true), '')
    OR attest_key_id = nullif(current_setting('app.edge.link_attest_key', true), '')
  );
GRANT SELECT (install_link_hash, account_pseudonym, fraud_voided_at) ON app.install_link_account TO private_definer;
CREATE POLICY pd_install_link_read ON app.install_link_account
  FOR SELECT TO private_definer USING (install_link_hash = nullif(current_setting('app.edge.link_hash', true), ''));

-- 4f. record_consumed_nonce (the nonce tombstone, redefined trigger in 0031): INSERT only, and only
-- the one source this path writes. No SELECT or DELETE policy: the unique violation is what rejects a reuse.
GRANT INSERT ON private.consumed_nonce TO private_definer;
CREATE POLICY pd_record_consumed_nonce ON private.consumed_nonce
  FOR INSERT TO private_definer WITH CHECK (source = 'checkin_challenge');

-- ============================================================================
-- 5. The definer functions
-- ============================================================================
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

-- 5a. The binding core. NOT granted to any edge role: only the three public binders below call it.
CREATE FUNCTION private.bind_actor_internal(p_uid uuid, p_kind text)
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
  INSERT INTO private.actor_binding (backend_pid, xact, actor_uid, kind, bound_at)
  VALUES (pg_backend_pid(), v_xact, p_uid, p_kind, clock_timestamp())
  ON CONFLICT (backend_pid) DO UPDATE
    SET xact = EXCLUDED.xact, actor_uid = EXCLUDED.actor_uid, kind = EXCLUDED.kind, bound_at = EXCLUDED.bound_at;
END;
$$;

-- 5b. THE identity every edge_actor policy is written against. NULL unless a bind happened in THIS
-- transaction (pg_current_xact_id_if_assigned() is NULL for a transaction that never wrote anything,
-- which compares as NULL: fail closed). PARALLEL UNSAFE: pg_backend_pid() is a different number in a
-- parallel worker, which would silently turn every policy into "no rows".
CREATE FUNCTION private.actor_uid()
RETURNS uuid
LANGUAGE sql STABLE PARALLEL UNSAFE SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT b.actor_uid
  FROM private.actor_binding b
  WHERE b.backend_pid = pg_backend_pid() AND b.xact = pg_current_xact_id_if_assigned()
$$;

CREATE FUNCTION private.bind_actor(p_uid uuid)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  PERFORM private.bind_actor_internal(p_uid, 'user');
END;
$$;

-- 5c. Delegate binders: edge_system ONLY, one specific row each.
-- queued_catalog drain: binds the owner of ONE evidence row that is still queued_catalog.
CREATE FUNCTION private.bind_delegate_for_queued_evidence(p_evidence_id uuid)
RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
BEGIN
  SELECT e.user_id INTO v_uid FROM app.evidence e WHERE e.id = p_evidence_id AND e.status = 'queued_catalog';
  IF NOT FOUND THEN
    RAISE EXCEPTION 'bind_delegate_for_queued_evidence: no queued_catalog evidence row with that id' USING ERRCODE = 'P0002';
  END IF;
  PERFORM private.bind_actor_internal(v_uid, 'system_delegate');
  RETURN v_uid;
END;
$$;

-- rescore: binds the owner of ONE play, only while the backlog row is open and the play is at that
-- backlog row's course.
CREATE FUNCTION private.bind_delegate_for_rescore(p_backlog_id bigint, p_play_id uuid)
RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_course text;
  v_uid uuid;
BEGIN
  SELECT b.course_id INTO v_course FROM app.catalog_rescore_backlog b WHERE b.id = p_backlog_id AND b.done_at IS NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'bind_delegate_for_rescore: no open rescore backlog row with that id' USING ERRCODE = 'P0002';
  END IF;
  SELECT p.user_id INTO v_uid FROM app.play p WHERE p.id = p_play_id AND p.course_id = v_course;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'bind_delegate_for_rescore: that play is not at the backlog row''s course' USING ERRCODE = 'P0002';
  END IF;
  PERFORM private.bind_actor_internal(v_uid, 'system_delegate');
  RETURN v_uid;
END;
$$;

-- 5d. Rate limits. The bucket key is built IN THE DATABASE (the Edge code cannot reach another
-- user's bucket, nor the global one): `<uid>:<key>` -- the exact format hitRateLimitForActor writes
-- today, so private.delete_my_data's purge (`LIKE '<uid>:%'`, keeping `<uid>:me-delete:user`)
-- keeps matching. A uuid contains no ':' so two users' prefixes can never collide.
-- Windows are bounded at one day: private.purge_rate_limit_buckets deletes windows older than two.
CREATE FUNCTION private.hit_actor_rate_limit(p_bucket_key text, p_window interval, p_max int)
RETURNS int
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid := private.actor_uid();
BEGIN
  IF v_uid IS NULL THEN
    RAISE EXCEPTION 'hit_actor_rate_limit: no actor is bound in this transaction' USING ERRCODE = '42501';
  END IF;
  IF p_bucket_key IS NULL OR p_bucket_key = '' OR length(p_bucket_key) > 128
     OR p_window IS NULL OR p_window < interval '1 second' OR p_window > interval '1 day'
     OR p_max IS NULL OR p_max < 1 OR p_max > 1000000 THEN
    RAISE EXCEPTION 'hit_actor_rate_limit: invalid bucket key, window or max' USING ERRCODE = '22023';
  END IF;
  RETURN private.hit_rate_limit(v_uid::text || ':' || p_bucket_key, p_window, p_max);
END;
$$;

-- System buckets (import-catalog and friends): `system:<key>`. No actor involved.
CREATE FUNCTION private.hit_system_rate_limit(p_bucket_key text, p_window interval, p_max int)
RETURNS int
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  IF p_bucket_key IS NULL OR p_bucket_key = '' OR length(p_bucket_key) > 128
     OR p_window IS NULL OR p_window < interval '1 second' OR p_window > interval '1 day'
     OR p_max IS NULL OR p_max < 1 OR p_max > 1000000 THEN
    RAISE EXCEPTION 'hit_system_rate_limit: invalid bucket key, window or max' USING ERRCODE = '22023';
  END IF;
  RETURN private.hit_rate_limit('system:' || p_bucket_key, p_window, p_max);
END;
$$;

-- 5e. Account deletion / export for THE BOUND ACTOR ONLY. No uid argument: the target is whoever this
-- transaction is bound to, and only a kind = 'user' binding (never a system delegate) may use them.
-- (app.release_account_reservations stays a separate edge_actor call BEFORE the delete: private_definer
-- holds no grant on app.offer and must not get one, see 0027.)
CREATE FUNCTION private.delete_my_data_for_actor()
RETURNS jsonb
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
    RAISE EXCEPTION 'delete_my_data_for_actor: no actor is bound in this transaction' USING ERRCODE = '42501';
  END IF;
  IF v_kind <> 'user' THEN
    RAISE EXCEPTION 'delete_my_data_for_actor: a system delegate may not delete an account' USING ERRCODE = '42501';
  END IF;
  RETURN private.delete_my_data(v_uid);
END;
$$;

CREATE FUNCTION private.export_my_data_for_actor()
RETURNS jsonb
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
    RAISE EXCEPTION 'export_my_data_for_actor: no actor is bound in this transaction' USING ERRCODE = '42501';
  END IF;
  IF v_kind <> 'user' THEN
    RAISE EXCEPTION 'export_my_data_for_actor: a system delegate may not export an account' USING ERRCODE = '42501';
  END IF;
  RETURN private.export_my_data(v_uid);
END;
$$;

-- 5f. The nonce tombstone. app.checkin_challenge_tombstone_nonce (a trigger function that runs as the
-- WRITING role) used to read and insert private.consumed_nonce directly; edge_actor has no access to
-- private.* tables, so 0031 redefines that one trigger function to call this. Same contract, same
-- error: a nonce hash that was ever recorded can never be recorded again (23514), row or no row.
CREATE FUNCTION private.record_consumed_nonce(p_nonce_hash text, p_expires_at timestamptz)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  INSERT INTO private.consumed_nonce (nonce_hash, source, expires_at)
  VALUES (p_nonce_hash, 'checkin_challenge', p_expires_at);
EXCEPTION WHEN unique_violation THEN
  RAISE EXCEPTION 'checkin_challenge: nonce_hash % was already consumed (tombstoned) and cannot be reused', p_nonce_hash
    USING ERRCODE = '23514';
END;
$$;

-- 5g. app.device_link_signals for the actor, across accounts (see policy 4e). Same result shape and
-- semantics as app.device_link_signals(device): accounts seen on the install (linked by an equal
-- install_link_hash or attest_key_id, plus the tombstone) and whether a fraud-voided account used it. The device must be
-- the actor's own, else the same P0002 the P3f functions raise for "not yours".
CREATE FUNCTION private.device_link_signals_for_actor(p_device_id uuid)
RETURNS TABLE (accounts_on_install int, voided_account_used_install boolean)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid := private.actor_uid();
  v_owner uuid;
  v_hash text;
  v_key text;
  v_n int;
  v_voided boolean;
BEGIN
  IF v_uid IS NULL THEN
    RAISE EXCEPTION 'device_link_signals_for_actor: no actor is bound in this transaction' USING ERRCODE = '42501';
  END IF;
  PERFORM set_config('app.edge.link_device_id', coalesce(p_device_id::text, ''), true);
  SELECT d.user_id, d.install_link_hash, d.attest_key_id INTO v_owner, v_hash, v_key FROM app.device d WHERE d.id = p_device_id;
  IF NOT FOUND OR v_owner IS DISTINCT FROM v_uid THEN
    PERFORM set_config('app.edge.link_device_id', '', true);
    RAISE EXCEPTION 'device_link_signals_for_actor: that device is not owned by this actor' USING ERRCODE = 'P0002';
  END IF;
  PERFORM set_config('app.edge.link_hash', coalesce(v_hash, ''), true);
  PERFORM set_config('app.edge.link_attest_key', coalesce(v_key, ''), true);
  -- Exactly app.device_link_signals (0027, round 3): accounts_on_install is the LARGER of the live-device count
  -- (user ids) and the tombstone count (pseudonyms; survives account deletion), and voided is the OR of both.
  SELECT greatest(
           (SELECT count(DISTINCT d.user_id) FROM app.device d
            WHERE d.id = p_device_id
               OR (v_hash IS NOT NULL AND d.install_link_hash = v_hash)
               OR (v_key IS NOT NULL AND d.attest_key_id = v_key)),
           (SELECT count(DISTINCT t.account_pseudonym) FROM app.install_link_account t
            WHERE v_hash IS NOT NULL AND t.install_link_hash = v_hash)
         )::int,
         coalesce((SELECT bool_or(d.fraud_voided_at IS NOT NULL) FROM app.device d
                   WHERE d.id = p_device_id
                      OR (v_hash IS NOT NULL AND d.install_link_hash = v_hash)
                      OR (v_key IS NOT NULL AND d.attest_key_id = v_key)), false)
         OR coalesce((SELECT bool_or(t.fraud_voided_at IS NOT NULL) FROM app.install_link_account t
                      WHERE v_hash IS NOT NULL AND t.install_link_hash = v_hash), false)
  INTO v_n, v_voided;
  PERFORM set_config('app.edge.link_device_id', '', true);
  PERFORM set_config('app.edge.link_hash', '', true);
  PERFORM set_config('app.edge.link_attest_key', '', true);
  accounts_on_install := v_n;
  voided_account_used_install := v_voided;
  RETURN NEXT;
END;
$$;

-- 5h. Cross-user list definers for edge_system (never the whole row where a column is not needed).
-- The queued rows' raw coordinates (queued_input) are deliberately NOT returned: the drain re-reads
-- the row AS ITS OWNER (delegate binding, then edge_actor) when it processes it.
CREATE FUNCTION private.list_queued_catalog(p_limit int)
RETURNS TABLE (id uuid, user_id uuid, claimed_facility_id text, claimed_course_id text, claimed_catalog_version text, created_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT e.id, e.user_id, e.claimed_facility_id, e.claimed_course_id, e.claimed_catalog_version, e.created_at
  FROM app.evidence e
  WHERE e.status = 'queued_catalog'
  ORDER BY e.created_at ASC
  LIMIT least(greatest(coalesce(p_limit, 1), 1), 500)
$$;

-- The stable keyset page of one course's plays (Repo#rescoreBacklog.nextPlays). created_at_text is
-- the cursor round-trip form the importer stores (microsecond-exact through text).
CREATE FUNCTION private.list_rescore_plays(p_course_id text, p_after_created_at timestamptz, p_after_id uuid, p_limit int)
RETURNS TABLE (play_id uuid, user_id uuid, facility_id text, course_id text, play_date date, created_at timestamptz, created_at_text text)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT p.id, p.user_id, p.facility_id, p.course_id, p.play_date, p.created_at, p.created_at::text
  FROM app.play p
  WHERE p.course_id = p_course_id
    AND (p_after_id IS NULL OR (p.created_at, p.id) > (p_after_created_at, p_after_id))
  ORDER BY p.created_at, p.id
  LIMIT least(greatest(coalesce(p_limit, 1), 1), 500)
$$;

-- The fix-coordinate retention purge (Repo#rescoreBacklog.purgeFixCoords) across all users. Same
-- statement as the Edge code ran as service_role, with the retention bound pinned: it can only
-- remove the 'fixCoords' key, only from rows that still carry it (policy 4b enforces both), and a
-- caller cannot ask for a retention longer than the 30 days P3e documents.
CREATE FUNCTION private.purge_fix_coords(p_retention_days int, p_limit int)
RETURNS int
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_n int;
BEGIN
  IF p_retention_days IS NULL OR p_retention_days < 1 OR p_retention_days > 30 THEN
    RAISE EXCEPTION 'purge_fix_coords: retention must be between 1 and 30 days' USING ERRCODE = '22023';
  END IF;
  IF p_limit IS NULL OR p_limit < 1 OR p_limit > 10000 THEN
    RAISE EXCEPTION 'purge_fix_coords: limit must be between 1 and 10000' USING ERRCODE = '22023';
  END IF;
  -- Open the read window (policy pd_fix_coords_read) for this transaction; closed again below.
  PERFORM set_config('app.edge.purge_fix_coords', 'on', true);
  UPDATE app.evidence e SET integrity = e.integrity - 'fixCoords'
  WHERE e.id IN (
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
  );
  GET DIAGNOSTICS v_n = ROW_COUNT;
  PERFORM set_config('app.edge.purge_fix_coords', '', true);
  RETURN v_n;
END;
$$;

-- 5i. EXECUTE grants (PUBLIC revoked first: private_definer-created functions default to PUBLIC) and
-- the inventory comments. The three internal-only/binder-core and trigger-adjacent functions get none.
REVOKE EXECUTE ON FUNCTION private.bind_actor_internal(uuid, text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.actor_uid() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.bind_actor(uuid) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.bind_delegate_for_queued_evidence(uuid) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.bind_delegate_for_rescore(bigint, uuid) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.hit_actor_rate_limit(text, interval, int) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.hit_system_rate_limit(text, interval, int) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.delete_my_data_for_actor() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.export_my_data_for_actor() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.record_consumed_nonce(text, timestamptz) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.device_link_signals_for_actor(uuid) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.list_queued_catalog(int) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.list_rescore_plays(text, timestamptz, uuid, int) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.purge_fix_coords(int, int) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION private.actor_uid() TO edge_actor;
GRANT EXECUTE ON FUNCTION private.bind_actor(uuid) TO edge_actor;
GRANT EXECUTE ON FUNCTION private.bind_delegate_for_queued_evidence(uuid) TO edge_system;
GRANT EXECUTE ON FUNCTION private.bind_delegate_for_rescore(bigint, uuid) TO edge_system;
GRANT EXECUTE ON FUNCTION private.hit_actor_rate_limit(text, interval, int) TO edge_actor;
GRANT EXECUTE ON FUNCTION private.hit_system_rate_limit(text, interval, int) TO edge_system;
GRANT EXECUTE ON FUNCTION private.delete_my_data_for_actor() TO edge_actor;
GRANT EXECUTE ON FUNCTION private.export_my_data_for_actor() TO edge_actor;
-- service_role keeps inserting checkin_challenge rows until PR5 and the trigger now runs this as the writing role.
GRANT EXECUTE ON FUNCTION private.record_consumed_nonce(text, timestamptz) TO edge_actor, service_role;
GRANT EXECUTE ON FUNCTION private.device_link_signals_for_actor(uuid) TO edge_actor;
GRANT EXECUTE ON FUNCTION private.list_queued_catalog(int) TO edge_system;
GRANT EXECUTE ON FUNCTION private.list_rescore_plays(text, timestamptz, uuid, int) TO edge_system;
GRANT EXECUTE ON FUNCTION private.purge_fix_coords(int, int) TO edge_system;

COMMENT ON FUNCTION private.actor_uid() IS
  'The actor every edge_actor policy is keyed on (0030): the uid bound in THIS transaction, else NULL (fail closed).';
COMMENT ON FUNCTION private.bind_actor(uuid) IS
  'edge_actor only. Binds the uid for the current transaction; a second bind in the same transaction raises (42501).';
COMMENT ON FUNCTION private.record_consumed_nonce(text, timestamptz) IS
  'Records a checkin challenge nonce in the append-only tombstone ledger; a nonce recorded once can never be recorded again (23514). Called by the redefined app.checkin_challenge_tombstone_nonce trigger function as the writing role.';

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

-- ============================================================================
-- 6. Registries: definer_policy_allowlist rows + function_inventory rows
-- ============================================================================
-- definer_policy_allowlist is FORCE RLS with no policy for the migrating role: the same temporary,
-- self-revoked CURRENT_USER policy 0017/0019/0022 use.
GRANT INSERT, UPDATE ON private.definer_policy_allowlist TO CURRENT_USER;
CREATE POLICY current_user_seed_definer_policy_allowlist_0030 ON private.definer_policy_allowlist
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
INSERT INTO private.definer_policy_allowlist (schema_name, table_name, policy_name, command, scoped, note) VALUES
  ('private', 'actor_binding', 'pd_actor_binding_select', 'SELECT', true, 'actor_uid() and the binders read THIS backend''s own binding row only'),
  ('private', 'actor_binding', 'pd_actor_binding_insert', 'INSERT', true, 'bind_actor_internal writes THIS backend''s own binding row only'),
  ('private', 'actor_binding', 'pd_actor_binding_update', 'UPDATE', true, 'bind_actor_internal re-binds THIS backend''s own row on a later transaction (ON CONFLICT DO UPDATE)'),
  ('app', 'evidence', 'pd_queued_catalog_read', 'SELECT', true, 'bind_delegate_for_queued_evidence / list_queued_catalog: rows still in status queued_catalog only'),
  ('app', 'evidence', 'pd_fix_coords_read', 'SELECT', true, 'purge_fix_coords: a GUC-scoped WINDOW (app.edge.purge_fix_coords = on, opened and closed by the function body): the UPDATE checks its NEW row against the SELECT policy, and the new row no longer carries fixCoords, so a row-narrow read policy cannot work (0016 "_r companion" finding)'),
  ('app', 'evidence', 'pd_fix_coords_update', 'UPDATE', true, 'purge_fix_coords: may only turn a row that carries integrity.fixCoords into one that does not (column grant: integrity only)'),
  ('app', 'catalog_id_ledger', 'pd_read_catalog_id_ledger', 'SELECT', true, 'public catalog data, no personal data; purge_fix_coords reads the ledger (USING(true): the function body is the scope)'),
  ('app', 'catalog_rescore_backlog', 'pd_read_catalog_rescore_backlog', 'SELECT', true, 'server-only work queue, no personal data; the rescore delegate and purge_fix_coords read it'),
  ('app', 'play', 'pd_rescore_play_read', 'SELECT', true, 'bind_delegate_for_rescore / list_rescore_plays: plays at a course with an OPEN backlog row only'),
  ('app', 'device', 'pd_device_link_read', 'SELECT', true, 'device_link_signals_for_actor: GUC-scoped (app.edge.link_*) to exactly the device and its linked rows, cleared right after -- the 0017 guard-read pattern'),
  ('app', 'install_link_account', 'pd_install_link_read', 'SELECT', true, 'device_link_signals_for_actor: the install-link tombstone rows of ONE install (GUC app.edge.link_hash, cleared right after); column grant excludes the hmac key id and the timestamp'),
  ('private', 'consumed_nonce', 'pd_record_consumed_nonce', 'INSERT', true, 'record_consumed_nonce: INSERT only, source = checkin_challenge only; the unique violation is what rejects a reuse');
UPDATE private.definer_policy_allowlist al
SET using_expr = pg_get_expr(pol.polqual, pol.polrelid),
    with_check_expr = pg_get_expr(pol.polwithcheck, pol.polrelid)
FROM pg_policy pol
JOIN pg_class cl ON cl.oid = pol.polrelid
JOIN pg_namespace n ON n.oid = cl.relnamespace
WHERE n.nspname = al.schema_name AND cl.relname = al.table_name AND pol.polname = al.policy_name
  AND al.policy_name IN (
    'pd_actor_binding_select', 'pd_actor_binding_insert', 'pd_actor_binding_update',
    'pd_queued_catalog_read', 'pd_fix_coords_read', 'pd_fix_coords_update',
    'pd_read_catalog_id_ledger', 'pd_read_catalog_rescore_backlog',
    'pd_rescore_play_read', 'pd_device_link_read', 'pd_install_link_read', 'pd_record_consumed_nonce');
DROP POLICY current_user_seed_definer_policy_allowlist_0030 ON private.definer_policy_allowlist;
REVOKE INSERT, UPDATE ON private.definer_policy_allowlist FROM CURRENT_USER;

-- function_inventory has the 0017 owner INSERT policy; the columns above are new, so the inserts name them.
INSERT INTO private.function_inventory
  (schema_name, function_name, identity_args, expected_anon, expected_authenticated, expected_service_role, expected_edge_actor, expected_edge_system, note)
VALUES
  ('private', 'bind_actor_internal', 'p_uid uuid, p_kind text', false, false, false, false, false, '0030: the binding core; reachable only through the three public binders (no role is granted EXECUTE)'),
  ('private', 'actor_uid', '', false, false, false, true, false, '0030: the identity every edge_actor policy is keyed on; the uid bound in THIS transaction, else NULL (fail closed)'),
  ('private', 'bind_actor', 'p_uid uuid', false, false, false, true, false, '0030: edge_actor only; one bind per transaction'),
  ('private', 'bind_delegate_for_queued_evidence', 'p_evidence_id uuid', false, false, false, false, true, '0030: edge_system only; binds the owner of ONE queued_catalog evidence row as a system delegate'),
  ('private', 'bind_delegate_for_rescore', 'p_backlog_id bigint, p_play_id uuid', false, false, false, false, true, '0030: edge_system only; binds the owner of ONE play at an open rescore backlog row''s course'),
  ('private', 'hit_actor_rate_limit', 'p_bucket_key text, p_window interval, p_max integer', false, false, false, true, false, '0030: edge_actor rate limit; the <uid>: prefix is added in the database'),
  ('private', 'hit_system_rate_limit', 'p_bucket_key text, p_window interval, p_max integer', false, false, false, false, true, '0030: edge_system rate limit; the system: prefix is added in the database'),
  ('private', 'delete_my_data_for_actor', '', false, false, false, true, false, '0030: delete_my_data for the bound kind=user actor; no uid argument'),
  ('private', 'export_my_data_for_actor', '', false, false, false, true, false, '0030: export_my_data for the bound kind=user actor; no uid argument'),
  ('private', 'record_consumed_nonce', 'p_nonce_hash text, p_expires_at timestamp with time zone', false, false, true, true, false, '0030: the nonce tombstone insert, called by the redefined checkin_challenge trigger function as the writing role (edge_actor; service_role until PR5)'),
  ('private', 'device_link_signals_for_actor', 'p_device_id uuid', false, false, false, true, false, '0030: app.device_link_signals across accounts for the actor''s own device (the P3f function under edge_actor would undercount)'),
  ('private', 'list_queued_catalog', 'p_limit integer', false, false, false, false, true, '0030: edge_system list of queued_catalog evidence rows (no raw coordinates)'),
  ('private', 'list_rescore_plays', 'p_course_id text, p_after_created_at timestamp with time zone, p_after_id uuid, p_limit integer', false, false, false, false, true, '0030: edge_system keyset page of the plays at one course with an open rescore backlog row'),
  ('private', 'purge_fix_coords', 'p_retention_days integer, p_limit integer', false, false, false, false, true, '0030: edge_system fix-coordinate retention purge (retention pinned to <= 30 days)');
