-- 0022_delete_my_data_post_condition.sql
--
-- P3d gate round 2, should-fix 2: "`delete_my_data` post-condition. After
-- deletion, assert zero remaining subject rows per registry table and fail
-- closed, i.e. raise. Also, export must fail when a registry table has no
-- SELECT visibility. Close the pre-existing gap where a missing `_r`
-- companion policy made deletion report success while the row survived, and
-- extend `verify-function-inventory` so every delete/update policy for
-- `private_definer` has an `_r` companion. This touches 0015's function;
-- since 0015 is merged, redefine it in a new migration (0022). Use the same
-- definer ownership and allow-list conventions as in 0020."
--
-- Three parts:
--
-- 1. THIS FILE: redefines `private.delete_my_data` (0015_delete_my_data.sql,
--    already merged) via `CREATE OR REPLACE FUNCTION` with the SAME
--    signature (`p_user_id uuid`) — same OID, so the existing
--    `GRANT EXECUTE ... TO service_role` (0015) and ownership transfer to
--    `private_definer` (0016_private_definer.sql) both carry over
--    unchanged; nothing to re-grant. Ownership/schema-CREATE bracketing
--    below mirrors 0020_rate_limit_no_raise.sql's own pattern exactly (see
--    that file's header for why the bracket is needed at all: `CREATE OR
--    REPLACE FUNCTION` requires the CALLER to both own the function being
--    replaced AND hold CREATE on its schema, and `private_definer` is
--    deliberately left with USAGE-only on schema `private` the rest of the
--    time — 0016's own should-fix hardening).
--
-- 2. `tools/db/verify-function-inventory.mjs` (check 8, THIS round) and
--    `supabase/tests/matrix/10_function_inventory.sql` (check 11, THIS
--    round): a NEW, static, migration-time check — every table with a
--    DELETE/UPDATE(/ALL) policy applying to private_definer also has a
--    SELECT(/ALL) "_r companion" policy applying to private_definer on the
--    SAME table. A from-scratch parse of every `CREATE POLICY ... TO
--    private_definer` across every migration (this round) found ZERO live
--    violations among 98 such policies today — this is a protective,
--    regression-preventing check, not a fix for a currently-broken table.
--
-- 3. The runtime post-condition below (part of THIS file) is what #2 makes
--    TRUSTWORTHY: private_definer's own SELECT visibility (via the "_r
--    companion" policies #2 guarantees exist) is EXACTLY what both this
--    post-condition and `export_my_data` (0021) read through. Without a
--    guaranteed SELECT companion, a missing/misscoped DELETE or UPDATE
--    policy could let a delete silently affect 0 rows (Postgres does not
--    error on a 0-row DELETE/UPDATE) while a SELECT-based post-condition
--    ALSO sees 0 rows for the SAME reason (RLS hides the very evidence
--    needed to catch the bug) — reporting success while the row survives,
--    exactly the gap named above. With the companion guaranteed, the two
--    checks are independent: #2 is evaluated once per migration (schema
--    shape), the post-condition below is evaluated on every real deletion
--    (data shape) — either alone would miss a bug the other catches.
--
--    "Export must fail when a registry table has no SELECT visibility" is
--    addressed the SAME way, not by a separate runtime check inside
--    `export_my_data` itself: from inside plpgsql, a SELECT filtered to
--    zero rows by a missing policy is byte-for-byte indistinguishable from
--    a SELECT that correctly found no data for this user (RLS filters
--    silently, it does not raise) — there is no runtime signal to build a
--    "was this blocked or just empty" check on. `export_my_data` already
--    fails closed on a registry table with NO `pii_export_policy` mapping
--    at all (0021); #2's static check is what guarantees every table
--    `export_my_data` reads from has REAL SELECT visibility for
--    private_definer to read through in the first place, which is the only
--    place this class of bug is actually observable.
--
--    Post-condition scope: iterates `private.pii_retention_policy` itself
--    (schema_name = 'app') — the SAME registry `delete_my_data`'s own
--    generic pass (0015) already drives, so a table added there later is
--    automatically covered here too, with ONE deliberate, documented
--    exclusion: `entitlement.user_id` (action = 'special') is NEVER fully
--    deleted or nulled by design — 0015's own bespoke block only VOIDS
--    unredeemed/vouchered rows and leaves `redeemed` rows terminal and
--    intact (build plan line 2759, O9/O10) — asserting zero remaining rows
--    there would fail on every account that ever redeemed anything, which
--    is the intended, documented retention, not a bug.
--
-- 4. should-fix 3 ("rate-limit keys"): also folded into this same
--    redefinition (see the block inside the function body, right before
--    the post-condition, for the full reasoning) — purges every
--    `private.rate_limit_bucket` row prefixed with this user's own uid,
--    EXCEPT the in-flight `me-delete:user` bucket (kept so a retry of
--    this same call stays rate-limited).

GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

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
  v_key_id uuid;
  v_key_secret text;
  v_pseudonym_candidate text;
  v_post_pol record;
  v_remaining int;
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
  -- GUC any more (0015/0016's prior `current_setting('app.pseudonym_hmac')`
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
  -- Rotation: EVERY row named `pseudonym_hmac%` in the vault is an
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
  -- The two derived GUCs the "special" policies (partner_invite,
  -- public_profile_projection) match on — set once either value is
  -- known; empty string (not NULL) when there is nothing to match, so
  -- `current_setting(..., true)` never returns NULL into a `column =
  -- NULL` comparison (which would be neither true nor false and so
  -- would never permit a row — the intended, fail-closed behaviour when
  -- e.g. the account has no email on file). `target_pseudonym` is set
  -- per-key, in the loop right above the attestation_shift_log UPDATE
  -- below — see that block for why.
  PERFORM set_config('app.delete_my_data.target_email', COALESCE(v_email, ''), true);
  PERFORM set_config('app.delete_my_data.target_handle', COALESCE(v_handle, ''), true);

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
  --
  -- ⛔ FIX (should-fix, post-P3a re-gate: "key rotation ... match on each
  -- row's recorded hmac id and raise if that key is missing"): the PRIOR
  -- version tried every vault row whose NAME matched 'pseudonym_hmac%' —
  -- renaming a retired key out of that naming convention (e.g.
  -- 'pseudonym_hmac_v1' -> 'retired_v1') silently dropped it from this
  -- loop even though rows still carry its id in their OWN
  -- player_pseudonym_hmac_id column, "succeeding" while leaving that
  -- key's rows unredacted. This version drives the loop from the DATA
  -- instead of the vault's naming convention: every id ever recorded
  -- against a player_pseudonym/staff_pseudonym pair is resolved BY ID
  -- (name-independent, so a rename never matters), and a recorded id that
  -- no longer resolves in vault.decrypted_secrets at all (deleted, not
  -- merely renamed — should-fix "FK into vault.secrets", 0018, dropped
  -- the FK specifically so this can be validated here instead of relying
  -- on referential integrity to prevent it) RAISES rather than silently
  -- skipping that key's rows.
  --
  -- ⛔ FIX (should-fix 2, post-P3a re-gate): "replace the broad
  -- pd_shift_log_discover_hmac_id policy (USING(true)) with a small
  -- registry of key ids ever used ... deletion iterates the registry."
  -- The SOURCE of this loop's key ids is now private.
  -- pseudonym_key_registry (0018), populated at WRITE time by the
  -- app.attestation/app.attestation_shift_log validation triggers (also
  -- 0018) — NOT a live, row-unscoped SELECT over the wide
  -- attestation_shift_log table any more, which is what let the broad
  -- discovery policy this replaces be narrowed away entirely.
  FOR v_key_id IN
    SELECT key_id FROM private.pseudonym_key_registry
  LOOP
    SELECT decrypted_secret INTO v_key_secret FROM vault.decrypted_secrets WHERE id = v_key_id;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'delete_my_data: attestation_shift_log references pseudonym key id % that no longer resolves in vault.decrypted_secrets (deleted or otherwise gone) — cannot safely determine whether it matches this user', v_key_id;
    END IF;
    IF v_key_secret IS NULL OR length(v_key_secret) < 32 THEN
      RAISE EXCEPTION 'delete_my_data: pseudonym key % in vault.decrypted_secrets is NULL or shorter than 32 bytes', v_key_id;
    END IF;
    v_pseudonym_candidate := encode(public.hmac(p_user_id::text, v_key_secret, 'sha256'), 'hex');
    -- `app.delete_my_data.target_pseudonym` is re-set per key so
    -- 0016_private_definer.sql's RLS policy (which independently checks
    -- the same GUC, since private_definer reaches this table only
    -- through that policy) agrees with this statement's own WHERE clause
    -- on each pass.
    PERFORM set_config('app.delete_my_data.target_pseudonym', v_pseudonym_candidate, true);
    UPDATE app.attestation_shift_log
    SET player_handle_snapshot = 'deleted player'
    WHERE player_pseudonym_hmac_id = v_key_id AND player_pseudonym = v_pseudonym_candidate;
  END LOOP;
  -- Legacy fallback: a row logged before player_pseudonym/
  -- player_pseudonym_hmac_id existed at all has neither set — matched by
  -- the pre-deletion handle instead, same as always (0016's own RLS
  -- policy already has a SEPARATE branch for exactly this shape, keyed
  -- on target_handle, not target_pseudonym).
  UPDATE app.attestation_shift_log
  SET player_handle_snapshot = 'deleted player'
  WHERE player_pseudonym IS NULL AND player_pseudonym_hmac_id IS NULL
    AND v_handle IS NOT NULL AND player_handle_snapshot = v_handle;

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

  -- ==========================================================================
  -- P3d gate round 2, should-fix 3: "Rate-limit keys. During deletion,
  -- remove the user's own rate_limit_bucket keys, i.e. those prefixed with
  -- their uid, inside delete_my_data or me-delete. It's fine to keep the
  -- in-flight me-delete bucket so retries stay limited, if you document
  -- it. Or wire the purge. Say which you chose."
  --
  -- CHOSEN: inside delete_my_data (here), not me-delete's own handler —
  -- this is the same transaction as the deletion itself, so it is
  -- automatically atomic with (and rolls back together with) everything
  -- else in this function, and it fires for EVERY caller of this
  -- function, not only the me-delete Edge Function specifically.
  --
  -- Scope: every bucket_key `hitRateLimitForActor` (privileged.ts) ever
  -- writes for THIS user is prefixed `<uid>:...` (that function's own
  -- `scopedBucketKey = \`${actor.uid}:${bucketKey}\``) — so a LIKE-prefix
  -- match on `p_user_id::text || ':%'` covers every bucket this user has
  -- ever hit, across every endpoint, with no separate registry needed.
  --
  -- EXCLUDED, deliberately: the in-flight `me-delete:user` bucket itself
  -- (me-delete/index.ts's own `hitRateLimitForActor(actor, "me-delete:
  -- user", ...)`, scoped key `<uid>:me-delete:user`) — kept so a RETRY of
  -- THIS SAME deletion call (delete-handler.ts's own doc: the one
  -- legitimate reason to call this endpoint again in a short window,
  -- e.g. after a partial failure) stays rate-limited exactly the way a
  -- first attempt already is, rather than becoming unbounded the moment
  -- one successful run has purged its own counter. Every OTHER bucket —
  -- evidence submission, redemption, check-in, etc. — is purged: those
  -- limits exist to bound abuse by a live account, and this account no
  -- longer has personal data to abuse anything with.
  --
  -- No new RLS policy needed: private_definer already holds an unscoped
  -- DELETE policy on this table (`pd_rate_limit_purge`, 0016), the SAME
  -- one `private.purge_rate_limit_buckets`'s own nightly sweep already
  -- uses — its own `_r` companion (`pd_rate_limit_purge_r`) already
  -- exists too (confirmed by this round's own check 8/11, which found
  -- zero missing companions anywhere).
  DELETE FROM private.rate_limit_bucket
  WHERE bucket_key LIKE p_user_id::text || ':%'
    AND bucket_key <> p_user_id::text || ':me-delete:user';

  -- ==========================================================================
  -- P3d should-fix 2: fail-closed POST-CONDITION. Re-reads every table this
  -- function's own registry (private.pii_retention_policy) names, through
  -- private_definer's own SELECT visibility (guaranteed by the "_r
  -- companion" check — tools/db/verify-function-inventory.mjs check 8,
  -- supabase/tests/matrix/10_function_inventory.sql check 11) — and RAISES
  -- if ANY subject row still remains. See this file's own header for the
  -- full reasoning (why this is only trustworthy BECAUSE of the "_r
  -- companion" check, and why `entitlement.user_id` is the one deliberate
  -- exclusion).
  -- ==========================================================================
  FOR v_post_pol IN
    SELECT table_name, column_name
    FROM private.pii_retention_policy
    WHERE schema_name = 'app'
      AND NOT (table_name = 'entitlement' AND column_name = 'user_id')
  LOOP
    EXECUTE format('SELECT count(*) FROM app.%I WHERE %I = $1', v_post_pol.table_name, v_post_pol.column_name)
      INTO v_remaining USING p_user_id;
    IF v_remaining > 0 THEN
      RAISE EXCEPTION
        'delete_my_data: post-condition failed — % row(s) still remain in app.%.% for user % after deletion (fail-closed; a missing/misscoped RLS policy can let a DELETE/UPDATE silently affect 0 rows while reporting success — see private.pii_retention_policy and the "_r companion" check in tools/db/verify-function-inventory.mjs)',
        v_remaining, v_post_pol.table_name, v_post_pol.column_name, p_user_id;
    END IF;
  END LOOP;

  v_result := jsonb_build_object('user_id', p_user_id, 'deleted_at', now());
  -- Logged via a plain INSERT — this is a NEW audit row about the
  -- deletion event itself, not a mutation of an old one, so the
  -- insert-only trigger does not apply to it.
  INSERT INTO app.audit_log (actor_user_id, action, subject_table, subject_id, detail)
  VALUES (NULL, 'delete_my_data', 'app.profile', p_user_id::text, v_result);

  RETURN v_result;
END;
$$;

COMMENT ON FUNCTION private.delete_my_data(uuid) IS
  'Deletes/redacts all personal data for a user, driven by private.pii_retention_policy (0014), and RAISES (fail-closed) if a post-deletion re-check (private_definer''s own RLS SELECT visibility) still finds a subject row for any registry table other than the one documented exception (entitlement.user_id, which intentionally retains redeemed/terminal rows) — P3d gate round 2, should-fix 2.';

RESET ROLE;
-- Restore 0016's exact hardened end-state — private_definer keeps only
-- USAGE on schema private, never CREATE, once this migration finishes.
REVOKE CREATE ON SCHEMA private FROM private_definer;
