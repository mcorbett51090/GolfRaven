-- 0021_export_my_data.sql
-- build plan §4.7.1a inventory ("me-export") — task instruction: "Return
-- all of the caller's personal data as JSON: the same row set
-- delete_my_data treats as personal, discovered from the same
-- pii_retention_policy registry or catalog where possible, so the two
-- can't drift."
--
-- `private.export_my_data(p_user_id uuid) RETURNS jsonb` is the READ-ONLY
-- twin of `private.delete_my_data` (0015_delete_my_data.sql): it drives
-- itself off the EXACT SAME `private.pii_retention_policy` registry
-- (0014_hardening.sql), walked the SAME way — every FK-to-`auth.users`
-- column in `app`, classified `delete_row` / `set_null` / `special` — so
-- a table added to the registry later is picked up by BOTH functions
-- automatically, and there is only ONE place ("is this column personal
-- data") to get right, not two that could drift apart. Unlike
-- `delete_my_data`, this function never writes anything; every table it
-- touches is read with a plain `SELECT`, not `DELETE`/`UPDATE`.
--
-- ⛔ WHY THIS IS SECURITY DEFINER, OWNED BY `private_definer`, NOT A
-- PLAIN service_role QUERY IN privileged.ts: `delete_my_data` already
-- established the pattern this function follows (S1 close-out, gate
-- round 3, 0016_private_definer.sql: "close S1 with a design that keeps
-- FORCE on every table and gives less privilege, not more"). Even though
-- the OUTER connection (`privileged.ts#withOwnership`) already runs as
-- `service_role`, which BYPASSES RLS entirely, calling INTO a `SECURITY
-- DEFINER` function owned by the NOBYPASSRLS `private_definer` role
-- means the actual row-reading SQL inside this function's body is still
-- subject to real RLS policies, scoped by session-local GUCs to exactly
-- the target user's own rows — defense in depth against a bug in this
-- function's own SQL (a missing WHERE clause, a copy-paste error) ever
-- reading another account's data, not merely trusting this file's own
-- correctness. This is NOT a new, broader policy: it reuses the EXACT
-- SAME SELECT policies 0016 already created as the mandatory read-
-- visibility companions to `delete_my_data`'s own DELETE/UPDATE policies
-- (every `..._r`-suffixed policy in 0016) — see the "GUC reuse" note
-- below for why no NEW RLS policy is added by this migration at all.
--
-- ⛔ GUC REUSE (deliberate, not an oversight): this function sets
-- `app.delete_my_data.target_user_id`/`target_email` — the SAME GUC
-- names `delete_my_data` (0015) sets and 0016's policies already read.
-- A differently-named GUC (e.g. `app.export_my_data.target_user_id`)
-- would require an entirely new set of ~25 SELECT policies, one per
-- table, duplicating 0016's own `..._r` policies for no behavioural
-- difference — the hard rule against broadening a policy to make code
-- work cuts the other way too: it is also a reason not to multiply
-- narrow policies that say the exact same thing under a second name.
-- Reusing the existing GUC means this migration adds ZERO new RLS
-- policies to `private.definer_policy_allowlist` — every table this
-- function reads already has a `..._r` SELECT policy scoped to that
-- GUC, created and allow-listed by 0016.
--
-- ⛔ SCOPE BOUNDARY: `app.attestation_shift_log` is deliberately NOT
-- exported. It has no FK to `auth.users` at all (§4.4 line 842: "no user
-- id") — it is a write-time PROJECTION matched by a computed HMAC
-- pseudonym, handled by `delete_my_data` via a SEPARATE mechanism (the
-- `private.pseudonym_key_registry` loop, 0015/0018) entirely outside the
-- `pii_retention_policy` registry this function walks. It therefore has
-- no row in `pii_retention_policy` at all (confirmed against 0014's own
-- INSERT list before writing this file) and is out of scope for "the
-- same row set... discovered from the pii_retention_policy registry" —
-- this is the "where possible" the task instruction itself allows for,
-- not a gap silently left open. Revisit only if a future round needs the
-- player's own shift-log entries in an export; the read-visibility
-- policy for it already exists (`pd_shift_log_update_r`) if it does.

CREATE OR REPLACE FUNCTION private.export_my_data(p_user_id uuid)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_email text;
  v_result jsonb := '{}'::jsonb;
  v_pol record;
  v_where text;
  v_table_json jsonb;
BEGIN
  IF p_user_id IS NULL THEN
    RAISE EXCEPTION 'export_my_data: user_id is required';
  END IF;

  -- Same ordering rationale as delete_my_data (0015): set the GUC(s)
  -- BEFORE the first read that depends on a policy checking them.
  PERFORM set_config('app.delete_my_data.target_user_id', p_user_id::text, true);
  SELECT email INTO v_email FROM auth.users WHERE id = p_user_id;
  PERFORM set_config('app.delete_my_data.target_email', COALESCE(v_email, ''), true);

  -- ==========================================================================
  -- Generic pass: every table classified delete_row/set_null in
  -- private.pii_retention_policy, grouped by table (a table can carry
  -- MORE THAN ONE classified column — e.g. checkin_challenge has both
  -- user_id and staff_user_id — in which case a row counts if ANY
  -- classified column matches, mirroring "this row is personal to this
  -- account through any of its classified columns"). `special` rows are
  -- excluded here and handled by name below, exactly mirroring
  -- delete_my_data's own CONTINUE branch.
  -- ==========================================================================
  FOR v_pol IN
    SELECT cl.relname AS table_name, array_agg(DISTINCT a.attname) AS column_names
    FROM pg_constraint con
    JOIN pg_class cl ON cl.oid = con.conrelid
    JOIN pg_namespace n ON n.oid = cl.relnamespace
    JOIN pg_attribute a ON a.attrelid = con.conrelid AND a.attnum = ANY (con.conkey)
    JOIN private.pii_retention_policy pol
      ON pol.schema_name = 'app' AND pol.table_name = cl.relname AND pol.column_name = a.attname
    WHERE con.contype = 'f'
      AND n.nspname = 'app'
      AND con.confrelid = 'auth.users'::regclass
      AND pol.action IN ('delete_row', 'set_null')
    GROUP BY cl.relname
  LOOP
    v_where := array_to_string(ARRAY(SELECT format('%I = $1', c) FROM unnest(v_pol.column_names) AS c), ' OR ');
    EXECUTE format('SELECT coalesce(jsonb_agg(to_jsonb(t)), ''[]''::jsonb) FROM app.%I t WHERE %s', v_pol.table_name, v_where)
      INTO v_table_json USING p_user_id;
    v_result := v_result || jsonb_build_object(v_pol.table_name, v_table_json);
  END LOOP;

  -- ==========================================================================
  -- Special cases — same six rows delete_my_data (0015) treats specially,
  -- read-only here, each using the EXACT SAME read-visibility policy
  -- 0016 already created as that row's DELETE/UPDATE companion.
  -- ==========================================================================
  SELECT coalesce(jsonb_agg(to_jsonb(t)), '[]'::jsonb) INTO v_table_json
    FROM app.attestation t WHERE player_user_id = p_user_id; -- pd_attestation_player_update_r
  v_result := v_result || jsonb_build_object('attestation', v_table_json);

  SELECT coalesce(jsonb_agg(to_jsonb(t)), '[]'::jsonb) INTO v_table_json
    FROM app.entitlement t WHERE user_id = p_user_id; -- pd_entitlement_update_r
  v_result := v_result || jsonb_build_object('entitlement', v_table_json);

  SELECT coalesce(jsonb_agg(to_jsonb(t)), '[]'::jsonb) INTO v_table_json
    FROM app.fraud_signal t WHERE user_id = p_user_id; -- pd_fraud_signal_update_r
  v_result := v_result || jsonb_build_object('fraud_signal', v_table_json);

  SELECT coalesce(jsonb_agg(to_jsonb(t)), '[]'::jsonb) INTO v_table_json
    FROM app.audit_log t WHERE actor_user_id = p_user_id; -- pd_audit_log_update_r
  v_result := v_result || jsonb_build_object('audit_log', v_table_json);

  SELECT coalesce(jsonb_agg(to_jsonb(t)), '[]'::jsonb) INTO v_table_json
    FROM app.partner_invite t
    WHERE invited_by = p_user_id OR (v_email IS NOT NULL AND invitee_email = v_email); -- pd_partner_invite_delete_r
  v_result := v_result || jsonb_build_object('partner_invite', v_table_json);

  SELECT coalesce(jsonb_agg(to_jsonb(t)), '[]'::jsonb) INTO v_table_json
    FROM app.receipt_fingerprint t WHERE user_id = p_user_id; -- pd_receipt_fingerprint_update_r
  v_result := v_result || jsonb_build_object('receipt_fingerprint', v_table_json);

  RETURN v_result;
END;
$$;

-- Not on the api.* RPC allowlist (§4.7 item 5) — this is called only from
-- the me-export Edge Function as service_role, never directly by a
-- client. No GRANT to anon/authenticated — same posture as
-- private.delete_my_data (0015).
--
-- ⛔ ORDERING (found by actually running this migration this round, H2
-- approximation mode): these REVOKE/GRANT statements must run BEFORE the
-- OWNER TO transfer below, not after — mirrors 0015/0016's OWN ordering
-- exactly (0015 REVOKEs/GRANTs while it still owns the function it just
-- created; ownership moves to private_definer only later, in 0016). Once
-- ownership transfers to private_definer, the migration-running role no
-- longer OWNS this function, and REVOKE/GRANT on an object you don't own
-- (and aren't a superuser for) fails with "permission denied for
-- function export_my_data" — reproduced this round under H2's
-- NOSUPERUSER approximation role before this ordering fix.
REVOKE EXECUTE ON FUNCTION private.export_my_data(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.export_my_data(uuid) TO service_role;

-- ⛔ Same GRANT/REVOKE bracketing 0016_private_definer.sql itself needed
-- around its own OWNER TO transfers (its §2 comment: "ALTER FUNCTION...
-- OWNER TO private_definer fails with 'permission denied for schema
-- private' without [CREATE]... Postgres checks the NEW owner has CREATE
-- privilege in the object's schema for an ownership transfer"). 0016
-- deliberately REVOKED that CREATE grant from private_definer again once
-- its OWN transfers were done ("nothing in its actual job... ever
-- needs it") — so a LATER migration transferring a NEW function's
-- ownership to private_definer (this one) needs the same temporary
-- grant, bracketed the same way, rather than assuming 0016's own grant
-- is still standing (it isn't).
GRANT CREATE ON SCHEMA private TO private_definer;
ALTER FUNCTION private.export_my_data(uuid) OWNER TO private_definer;
REVOKE CREATE ON SCHEMA private FROM private_definer;

-- Derived function inventory (§4.7.1a, A2-09) — 0014_hardening.sql's
-- private.function_inventory table; verify-function-inventory.mjs /
-- 10_function_inventory.sql fail CI if this row is missing.
INSERT INTO private.function_inventory
  (schema_name, function_name, identity_args, expected_anon, expected_authenticated, expected_service_role, note)
VALUES
  ('private', 'export_my_data', 'p_user_id uuid', false, false, true, 'me-export Edge Function only (0021) — read-only twin of private.delete_my_data (0015)');
