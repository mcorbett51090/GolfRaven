-- 0014_delete_my_data.sql
-- build plan §10 P3 AT(6) (docs/golf-trails/02-build-plan.md:2759):
-- "DELETE /v1/me removes all personal rows (asserted by query), revokes
-- connectors and deletes push tokens; an unredeemed special-marker
-- entitlement or stock voucher is voided at once, and no address exists to
-- retain (O9/O10)."
--
-- ⛔ REWRITE (B3, gate round 2): the original version was a hand-written
-- list of DELETE/UPDATE statements in a fixed order, discovered broken by
-- its own ordering (a FK violation the first time it was actually run) and
-- by construction silent about any personal table added later. This
-- version is DRIVEN by `private.pii_retention_policy` (0015): it iterates
-- every FK-to-`auth.users` column `pg_constraint` reports for schema
-- `app`, looks each one up in the policy table, and either deletes the row
-- or nulls the column per the declared action — a column found in
-- `pg_constraint` but missing from the policy table makes the function
-- RAISE rather than silently skip it (fail-closed: a new personal table's
-- FK must be classified before this function can run at all, catching
-- exactly the "a table added later" gap the gate asked for). Every
-- `action = 'special'` row is excluded from the generic loop and handled
-- by the bespoke blocks below it, each cross-referenced to its policy row.
--
-- 0015's DEFERRABLE INITIALLY DEFERRED pass makes every app-internal FK
-- check happen at COMMIT, not at each statement — so the loop below runs
-- in `pg_constraint`'s own (arbitrary) order without needing to hand-order
-- deletes the way the original version had to.

CREATE OR REPLACE FUNCTION private.delete_my_data(p_user_id uuid)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_handle text;
  v_email text;
  v_result jsonb := '{}'::jsonb;
  v_pol record;
  v_row_count int;
  v_pseudonym text;
BEGIN
  IF p_user_id IS NULL THEN
    RAISE EXCEPTION 'delete_my_data: user_id is required';
  END IF;

  -- S1 close-out (gate round 3): this function is owned by `private_definer`
  -- (0016_private_definer.sql), a NOLOGIN NOSUPERUSER NOBYPASSRLS role that
  -- is NOT the table owner — every table below stays ENABLE + FORCE ROW
  -- LEVEL SECURITY, and private_definer reaches rows only through the
  -- explicit, narrow policies 0016 defines, each scoped to this session-
  -- local GUC. Set it FIRST, before the very first table read below, since
  -- even `app.profile`'s own SELECT now goes through a policy keyed on it.
  PERFORM set_config('app.delete_my_data.target_user_id', p_user_id::text, true);

  SELECT handle INTO v_handle FROM app.profile WHERE user_id = p_user_id;
  SELECT email INTO v_email FROM auth.users WHERE id = p_user_id;
  -- Fully qualified: this function runs with search_path = '' (below),
  -- and pgcrypto is installed into `public` (confirmed this session via
  -- `pg_extension.extnamespace`), so an unqualified hmac()/digest() would
  -- 42883 ("function ... does not exist") here even though the extension
  -- is present.
  --
  -- ⛔ FIX (M1, post-P3a re-gate): the pseudonym key is NEVER read from a
  -- GUC any more (0015/0016's prior `current_setting('app.pseudonym_key')`
  -- design had four confirmed problems: readable by anon/authenticated,
  -- overridable by any caller's own `SET LOCAL`, silently accepted an
  -- empty value with no error, and production never sets an `app.*` GUC
  -- at all — see supabase/tests/shim.sql's own note on this, where the
  -- fix is explained in full). The key now comes from Supabase Vault
  -- (`vault.decrypted_secrets`, real in production, shimmed locally) —
  -- read INSIDE this SECURITY DEFINER function body, which no other role
  -- can do (private_definer's own narrow, column-level grant on that
  -- view, 0018_pseudonym_vault.sql — anon/authenticated get none).
  --
  -- Rotation: EVERY row named `pseudonym_key%` in the vault is an
  -- "active" key (0018's own deploy-check note explains the naming
  -- convention). A pseudonym was computed, at WRITE time, with WHATEVER
  -- key was active then — so finding it again means trying every
  -- currently-active key, not just the newest one, or a row written
  -- under an older key becomes permanently unfindable the moment a new
  -- key is added. The loop below (right before the one place this
  -- function actually MATCHES rows by pseudonym, attestation_shift_log)
  -- does exactly that: for each active key, validate it, compute this
  -- user's pseudonym under it, and run the shift-log UPDATE once per
  -- key — safe to repeat (idempotent: a row already updated on an
  -- earlier key's pass no longer matches ANY later key's WHERE clause,
  -- since its own player_pseudonym column never changes).
  NULL; -- (the pseudonym-matching work itself now lives just above the
        -- attestation_shift_log UPDATE below, not here — see that block)

  -- The two derived GUCs the "special" policies (partner_invite,
  -- attestation_shift_log, public_profile_projection) match on — set once
  -- either value is known; empty string (not NULL) when there is nothing
  -- to match, so `current_setting(..., true)` never returns NULL into a
  -- `column = NULL` comparison (which would be neither true nor false and
  -- so would never permit a row — the intended, fail-closed behaviour when
  -- e.g. the account has no email on file).
  PERFORM set_config('app.delete_my_data.target_email', COALESCE(v_email, ''), true);
  PERFORM set_config('app.delete_my_data.target_handle', COALESCE(v_handle, ''), true);
  PERFORM set_config('app.delete_my_data.target_pseudonym', v_pseudonym, true);

  -- ==========================================================================
  -- Generic pass: every FK-to-auth.users column in `app`, driven by
  -- private.pii_retention_policy. Fails closed on anything unclassified.
  -- ==========================================================================
  FOR v_pol IN
    SELECT
      cl.relname AS table_name,
      a.attname AS column_name,
      pol.action,
      pol.reason
    FROM pg_constraint con
    JOIN pg_class cl ON cl.oid = con.conrelid
    JOIN pg_namespace n ON n.oid = cl.relnamespace
    JOIN pg_attribute a ON a.attrelid = con.conrelid AND a.attnum = ANY (con.conkey)
    LEFT JOIN private.pii_retention_policy pol
      ON pol.schema_name = 'app' AND pol.table_name = cl.relname AND pol.column_name = a.attname
    WHERE con.contype = 'f'
      AND n.nspname = 'app'
      AND con.confrelid = 'auth.users'::regclass
  LOOP
    IF v_pol.action IS NULL THEN
      RAISE EXCEPTION
        'delete_my_data: app.%.% references auth.users but has no private.pii_retention_policy row — classify it (delete_row / set_null / special) before this function can run',
        v_pol.table_name, v_pol.column_name;
    ELSIF v_pol.action = 'delete_row' THEN
      EXECUTE format('DELETE FROM app.%I WHERE %I = $1', v_pol.table_name, v_pol.column_name) USING p_user_id;
    ELSIF v_pol.action = 'set_null' THEN
      EXECUTE format('UPDATE app.%I SET %I = NULL WHERE %I = $1', v_pol.table_name, v_pol.column_name, v_pol.column_name) USING p_user_id;
    ELSIF v_pol.action = 'special' THEN
      CONTINUE; -- handled below, by name, not generically
    END IF;
  END LOOP;

  -- ==========================================================================
  -- Special cases (each cross-referenced to its private.pii_retention_policy
  -- row and reason).
  -- ==========================================================================

  -- entitlement: detach activated_device_id UNCONDITIONALLY, for every
  -- state (including `redeemed`, which is terminal and never voided) — the
  -- device row is about to be deleted by the generic pass above (device.
  -- user_id is a delete_row policy) and RESTRICT (the default) on
  -- entitlement.activated_device_id would otherwise block that delete.
  -- This is not a pii_retention_policy row because activated_device_id
  -- does not reference auth.users — it references app.device — so it is
  -- outside the auth.users-driven loop above by construction; called out
  -- here because it was exactly B3's "handle the RESTRICT FK on
  -- activated_device_id" finding.
  UPDATE app.entitlement SET activated_device_id = NULL, devicecheck_token_hash = NULL
    WHERE user_id = p_user_id;
  -- entitlement.play_id / offer_code.play_id (H1, post-P3a gate): also
  -- references app.play, which the generic pass below deletes (play.user_id
  -- = delete_row) — the FK itself is now ON DELETE SET NULL DEFERRABLE
  -- INITIALLY DEFERRED (0017), so this is belt-and-suspenders, not load-
  -- bearing, but detaching explicitly here matches activated_device_id's
  -- own pattern immediately above and keeps the intent visible at the
  -- call site rather than only in the FK definition.
  UPDATE app.entitlement SET play_id = NULL WHERE user_id = p_user_id;
  UPDATE app.offer_code SET play_id = NULL WHERE user_id = p_user_id;
  -- Then, per line 2759 / O9-O10: void any UNREDEEMED entitlement or stock
  -- voucher (redeemed stays redeemed — terminal, kept for the stock ledger).
  UPDATE app.entitlement
  SET state = 'void'
  WHERE user_id = p_user_id
    AND kind = 'special_marker'
    AND state IN ('earned', 'held_review', 'redeemable', 'vouchered');
  -- offer_code.activated_device_id has the same RESTRICT shape; offer_code
  -- rows for this user are deleted by the generic pass (offer_code.user_id
  -- = delete_row), so no separate detach is needed there — but another
  -- user's already-activated offer_code could in principle point at a
  -- device this user owns only if devices were ever shared, which they are
  -- not (app.device.user_id is 1:1 with the owning account) — no action
  -- needed.

  -- attestation.player_user_id (special): nulled, not deleted (line 841).
  UPDATE app.attestation SET player_user_id = NULL WHERE player_user_id = p_user_id;
  -- attestation.staff_user_id is handled by the generic pass above (it is
  -- now a plain `set_null` policy row, gate round 2 fix) — no bespoke code
  -- needed here; staff_pseudonym (populated at attest time, out of this
  -- stage's scope) survives so the row stays verifiable as "staff-attested".

  -- audit_log.actor_user_id (special): redacted via the trigger's one
  -- narrow exception (0006) — covers every historical row matching, "older
  -- audit_log rows" included, since the WHERE has no date bound.
  UPDATE app.audit_log SET actor_user_id = NULL WHERE actor_user_id = p_user_id;

  -- receipt_fingerprint.user_id (special): nulled, row kept (24-month
  -- fraud retention, line 835).
  UPDATE app.receipt_fingerprint SET user_id = NULL WHERE user_id = p_user_id;

  -- fraud_signal.user_id (special): nulled, row kept — an admin fraud
  -- record survives its subject's account deletion.
  UPDATE app.fraud_signal SET user_id = NULL WHERE user_id = p_user_id;

  -- partner_invite (special): deleted on EITHER match — the inviter
  -- deleting their account (invited_by), or the invite naming the deleted
  -- user's own verified email (invitee_email) — task instruction: "Cover
  -- ... partner_invite.invitee_email".
  DELETE FROM app.partner_invite
  WHERE invited_by = p_user_id
     OR (v_email IS NOT NULL AND invitee_email = v_email);

  -- attestation_shift_log: match by the durable player_pseudonym (HMAC of
  -- user_id), NOT by the current handle (B3 fix — a handle can change or
  -- be reused after being freed; the projection never stores a user id at
  -- all, line 842). A row logged before this stage's pseudonym column
  -- existed falls back to matching the pre-deletion handle.
  UPDATE app.attestation_shift_log
  SET player_handle_snapshot = 'deleted player'
  WHERE player_pseudonym = v_pseudonym
     OR (player_pseudonym IS NULL AND v_handle IS NOT NULL AND player_handle_snapshot = v_handle);

  -- receipt objects in storage.objects (task instruction: "receipt objects
  -- in storage.objects"). Matched by `owner` (set at upload time by the
  -- out-of-scope receipts Edge Function) and, defensively, by the
  -- `receipts/<user_id>/...` path convention (line 868) in case `owner`
  -- was never populated for an older object.
  DELETE FROM storage.objects
  WHERE bucket_id = 'receipts'
    AND (owner = p_user_id OR name LIKE 'receipts/' || p_user_id::text || '/%');

  -- public_profile_projection + profile: profile is deleted by the
  -- generic pass (delete_row); its projection has no FK (holds no user
  -- id, line 825) so it is removed here by the handle captured above,
  -- before profile's row (and therefore v_handle's source) is gone.
  IF v_handle IS NOT NULL THEN
    DELETE FROM app.public_profile_projection WHERE handle = v_handle;
  END IF;

  v_result := jsonb_build_object('user_id', p_user_id, 'deleted_at', now());
  -- Logged via a plain INSERT — this is a NEW audit row about the
  -- deletion event itself, not a mutation of an old one, so the
  -- insert-only trigger does not apply to it.
  INSERT INTO app.audit_log (actor_user_id, action, subject_table, subject_id, detail)
  VALUES (NULL, 'delete_my_data', 'app.profile', p_user_id::text, v_result);

  RETURN v_result;
END;
$$;

-- Not on the api.* RPC allowlist (§4.7 item 5) — this is called only from
-- the (out-of-scope-this-stage) `me-delete` Edge Function as service_role,
-- never directly by a client. No GRANT to anon/authenticated.
REVOKE EXECUTE ON FUNCTION private.delete_my_data(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.delete_my_data(uuid) TO service_role;
