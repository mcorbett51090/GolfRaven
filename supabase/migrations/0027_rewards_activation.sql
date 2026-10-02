-- 0027_rewards_activation.sql
-- P3f: `POST /v1/rewards/{id}/activate` (Edge Function `rewards-activate`),
-- the §7.5 activation decision table, and the `held_review` semantics on
-- `offer_code` and `entitlement` (build plan §7.5, A2-08; P3 acceptance
-- test (9)).
--
-- What already existed (0003/0005/0006/0014/0016/0017) and is therefore NOT
-- recreated here:
--   - `held_review` as a value of BOTH `app.offer_code_state` and
--     `app.entitlement_state`;
--   - `offer_code`/`entitlement`.`activated_device_id`, `devicecheck_token_hash`,
--     `activated_at`; `offer_code.expiry_paused_at`; `offer.budget_reserved`
--     (+ `offer_budget_within_cap`);
--   - `app.device_reward_ledger` (FORCE RLS, no client policy, `user_id` already
--     classified `delete_row` in `private.pii_retention_policy` and `exclude`
--     in `private.pii_export_policy` — so this migration adds NO registry rows
--     and does NOT redefine `export_my_data` / `delete_my_data`);
--   - the play-guard constraint triggers (0017): a `held_review` play can only
--     back a `held_review` (or terminal) code/entitlement.
--
-- What this migration adds (ALL of it is "P3f additions"):
--   1. `app.device.attest_public_key` — the raw (uncompressed, 65-byte) P-256 key
--      an App Attest assertion is verified against. NULL until key registration
--      (attestation-object verification, NOT built in P3f) writes it; the
--      verifier treats a NULL key as `unattestable`, never as "verified".
--   2. `app.offer.face_value` and `app.offer_code.reserved_amount` — a held offer
--      code RESERVES its budget (`offer.budget_reserved`, §7.5): the amount is
--      the offer's per-code face value, snapshotted on the code so a later
--      release/consume uses exactly what was reserved.
--   3. `app.offer_code.rests_on_unattestable` / `app.entitlement.rests_on_unattestable`
--      — table row 3's input ("the reward rests on an `unattestable`
--      co-signal"). Written ONLY by the earning path (server side); activation
--      only reads it.
--   4. `UNIQUE (device_id, reward_kind, reward_id)` + a `user_id` index on the
--      ledger, so recording an activation is idempotent.
--   5. Five `app` functions that own the state transitions, so the money
--      semantics (state machine, budget reservation, expiry pause, ledger row,
--      row-2/row-3 backstops) live in ONE place in the database, not only in
--      the Edge Function:
--        app.activate_offer_code / app.activate_entitlement
--        app.resolve_held_offer_code / app.resolve_held_entitlement
--        app.release_account_reservations — account deletion must give back the
--          budget a deleted account's held codes were reserving (called by
--          `Repo#me.deleteMyData()` in the same transaction, BEFORE
--          private.delete_my_data removes the offer_code rows; `delete_my_data`
--          itself is deliberately NOT redefined here)
--      All five are plain (invoker-rights) functions, EXECUTE service_role only
--      — the same shape as 0017's `app.reserve_offer_budget`. They are NOT
--      SECURITY DEFINER, so no `private_definer` ownership bracket is needed.
--
-- The decision itself (which §7.5 row matched, and the DeviceCheck/Play
-- Integrity bits it rests on) is made in TypeScript
-- (`supabase/functions/_shared/rewards/decision-table.ts`) because the bits
-- come from a vendor, not the database. What the database enforces
-- INDEPENDENTLY of the caller is the part it can see: an `activate` decision is
-- refused (SQLSTATE 23514) when the reward rests on an unattestable co-signal
-- (row 3), when its backing play is held, or when the account has an open
-- `fraud_signal(attestation_failed)` (row 2). A bug (or a later builder's
-- code) that tries to activate through these functions cannot skip those rows.
--
-- Immutability: this file is NEW. No existing migration is edited.

-- ============================================================================
-- P3f additions — 1. device.attest_public_key
-- ============================================================================
ALTER TABLE app.device ADD COLUMN attest_public_key bytea;
ALTER TABLE app.device ADD CONSTRAINT device_attest_public_key_len
  CHECK (attest_public_key IS NULL OR octet_length(attest_public_key) = 65);
COMMENT ON COLUMN app.device.attest_public_key IS
  'Raw uncompressed P-256 point (0x04 || X || Y, 65 bytes) of this install''s App Attest key. Written ONLY by App Attest key registration (attestation-object verification against Apple''s root — not built in P3f). NULL means "no key registered": the assertion verifier returns unattestable, never verified. A public key, not a secret.';

-- ============================================================================
-- P3f additions — 2. budget reservation inputs
-- ============================================================================
-- IF NOT EXISTS on offer.face_value: another P3 builder may introduce the same
-- per-code face value (the settlement multiplier, §9.5); this must not make
-- the migration set fail to apply in either order.
ALTER TABLE app.offer ADD COLUMN IF NOT EXISTS face_value numeric(10, 2) NOT NULL DEFAULT 0 CHECK (face_value >= 0);
COMMENT ON COLUMN app.offer.face_value IS
  'Per-code face value in the offer''s currency (build plan §9.5 settlement: redemptions x face value). A held code reserves this much of budget_cap (offer.budget_reserved, §7.5). 0 = nothing reserved (legacy rows).';

ALTER TABLE app.offer_code ADD COLUMN reserved_amount numeric(10, 2) NOT NULL DEFAULT 0 CHECK (reserved_amount >= 0);
COMMENT ON COLUMN app.offer_code.reserved_amount IS
  'Amount of offer.budget_reserved this code holds (snapshot of offer.face_value taken when the code was first held). Set by app.activate_offer_code; released by app.resolve_held_offer_code on reject; kept on approve so the reservation pays for the redemption even if the offer has since ended (§7.5).';

-- ============================================================================
-- P3f additions — 3. table row 3's input
-- ============================================================================
ALTER TABLE app.offer_code ADD COLUMN rests_on_unattestable boolean NOT NULL DEFAULT false;
ALTER TABLE app.entitlement ADD COLUMN rests_on_unattestable boolean NOT NULL DEFAULT false;
COMMENT ON COLUMN app.offer_code.rests_on_unattestable IS
  '§7.5 table row 3 input: true when the reward rests on an unattestable co-signal (§4.5). Written ONLY by the server-side earning path; rewards-activate reads it (OR-ed with the backing play''s held_review) and the DB refuses to activate a code with this set.';
COMMENT ON COLUMN app.entitlement.rests_on_unattestable IS
  '§7.5 table row 3 input — see app.offer_code.rests_on_unattestable.';

-- ============================================================================
-- P3f additions — 4. ledger idempotency
-- ============================================================================
ALTER TABLE app.device_reward_ledger
  ADD CONSTRAINT device_reward_ledger_device_reward_key UNIQUE (device_id, reward_kind, reward_id);
CREATE INDEX device_reward_ledger_user_idx ON app.device_reward_ledger (user_id);

-- ============================================================================
-- P3f additions — 5. state-transition functions
-- ============================================================================
-- Error contract (SQLSTATEs the Edge layer maps; messages are diagnostics only):
--   22023  invalid parameter (bad p_decision / NULL p_approve)
--   P0002  no such reward for this user (the Edge layer has already answered 404)
--   42501  the device is not the caller's, or p_resolved_by is not an admin
--   55000  the reward's state does not allow this transition (terminal/expired)
--   23514  an `activate` decision was refused by a table-row backstop (rows 2/3)

CREATE FUNCTION app.activate_offer_code(
  p_code_id uuid, p_user_id uuid, p_device_id uuid, p_token_hash text, p_decision text
) RETURNS app.offer_code_state
LANGUAGE plpgsql
SET search_path = ''
AS $$
DECLARE
  v_code app.offer_code%ROWTYPE;
  v_offer app.offer%ROWTYPE;
  v_reserve numeric(10, 2) := 0;
BEGIN
  IF p_decision IS NULL OR p_decision NOT IN ('activate', 'held_review') THEN
    RAISE EXCEPTION 'activate_offer_code: p_decision must be ''activate'' or ''held_review'' (got %)', p_decision
      USING ERRCODE = '22023';
  END IF;

  SELECT * INTO v_code FROM app.offer_code WHERE id = p_code_id AND user_id = p_user_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'activate_offer_code: no offer_code % for this user', p_code_id USING ERRCODE = 'P0002';
  END IF;

  PERFORM 1 FROM app.device WHERE id = p_device_id AND user_id = p_user_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'activate_offer_code: device % is not owned by this user', p_device_id USING ERRCODE = '42501';
  END IF;

  -- A held code is awaiting a human (§9.2 SLA). Activation never releases it
  -- and never re-runs the table over it: idempotent no-op.
  IF v_code.state = 'held_review' THEN
    RETURN v_code.state;
  END IF;
  IF v_code.state NOT IN ('earned', 'issued') THEN
    RAISE EXCEPTION 'activate_offer_code: offer_code % is % and cannot be activated', p_code_id, v_code.state
      USING ERRCODE = '55000';
  END IF;
  IF v_code.expires_at IS NOT NULL AND v_code.expires_at <= now() AND v_code.expiry_paused_at IS NULL THEN
    RAISE EXCEPTION 'activate_offer_code: offer_code % has expired', p_code_id USING ERRCODE = '55000';
  END IF;

  IF p_decision = 'activate' THEN
    -- Table rows 2 and 3, enforced by the database independently of the
    -- caller (the decision is made in TypeScript; this is the backstop).
    IF v_code.rests_on_unattestable THEN
      RAISE EXCEPTION 'activate_offer_code: offer_code % rests on an unattestable co-signal (§7.5 row 3) and cannot be activated', p_code_id
        USING ERRCODE = '23514';
    END IF;
    IF v_code.play_id IS NOT NULL AND EXISTS (
      SELECT 1 FROM app.play WHERE id = v_code.play_id AND user_id = p_user_id AND held_review
    ) THEN
      RAISE EXCEPTION 'activate_offer_code: offer_code % is backed by a held_review play (§7.5 row 3) and cannot be activated', p_code_id
        USING ERRCODE = '23514';
    END IF;
    IF EXISTS (
      SELECT 1 FROM app.fraud_signal WHERE user_id = p_user_id AND kind = 'attestation_failed' AND cleared_at IS NULL
    ) THEN
      RAISE EXCEPTION 'activate_offer_code: the account has an open attestation_failed fraud_signal (§7.5 row 2); activations are held'
        USING ERRCODE = '23514';
    END IF;

    UPDATE app.offer_code SET
      state = 'issued',
      activated_device_id = coalesce(activated_device_id, p_device_id),
      devicecheck_token_hash = coalesce(devicecheck_token_hash, p_token_hash),
      activated_at = coalesce(activated_at, now())
    WHERE id = p_code_id;

    INSERT INTO app.device_reward_ledger (device_id, devicecheck_token_hash, user_id, reward_kind, reward_id)
    VALUES (p_device_id, p_token_hash, p_user_id, 'offer', p_code_id)
    ON CONFLICT (device_id, reward_kind, reward_id) DO NOTHING;
    RETURN 'issued';
  END IF;

  -- p_decision = 'held_review'. A held code RESERVES its budget and its expiry
  -- clock PAUSES (§7.5). The offer is deliberately NOT required to still be
  -- live: the code was earned while it was, and "if the offer ends ... during
  -- review, an approved code is still honoured".
  IF v_code.reserved_amount = 0 THEN
    SELECT * INTO v_offer FROM app.offer WHERE id = v_code.offer_id FOR UPDATE;
    IF v_offer.face_value > 0 THEN
      IF v_offer.budget_used + v_offer.budget_reserved + v_offer.face_value <= v_offer.budget_cap THEN
        UPDATE app.offer SET budget_reserved = budget_reserved + v_offer.face_value WHERE id = v_offer.id;
        v_reserve := v_offer.face_value;
      ELSE
        -- Never silently refused, never silently unreserved: a human sees it.
        INSERT INTO app.review_item (kind, subject_table, subject_id, detail)
        VALUES ('held_offer_budget_unreserved', 'offer_code', v_code.id,
                jsonb_build_object('offer_id', v_offer.id, 'face_value', v_offer.face_value));
      END IF;
    END IF;
  END IF;

  UPDATE app.offer_code SET
    state = 'held_review',
    reserved_amount = reserved_amount + v_reserve,
    expiry_paused_at = coalesce(expiry_paused_at, now()),
    activated_device_id = coalesce(activated_device_id, p_device_id),
    devicecheck_token_hash = coalesce(devicecheck_token_hash, p_token_hash),
    activated_at = coalesce(activated_at, now())
  WHERE id = p_code_id;
  RETURN 'held_review';
END;
$$;

CREATE FUNCTION app.activate_entitlement(
  p_entitlement_id uuid, p_user_id uuid, p_device_id uuid, p_token_hash text, p_decision text
) RETURNS app.entitlement_state
LANGUAGE plpgsql
SET search_path = ''
AS $$
DECLARE
  v_ent app.entitlement%ROWTYPE;
BEGIN
  IF p_decision IS NULL OR p_decision NOT IN ('activate', 'held_review') THEN
    RAISE EXCEPTION 'activate_entitlement: p_decision must be ''activate'' or ''held_review'' (got %)', p_decision
      USING ERRCODE = '22023';
  END IF;

  SELECT * INTO v_ent FROM app.entitlement WHERE id = p_entitlement_id AND user_id = p_user_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'activate_entitlement: no entitlement % for this user', p_entitlement_id USING ERRCODE = 'P0002';
  END IF;

  PERFORM 1 FROM app.device WHERE id = p_device_id AND user_id = p_user_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'activate_entitlement: device % is not owned by this user', p_device_id USING ERRCODE = '42501';
  END IF;

  IF v_ent.state = 'held_review' THEN
    RETURN v_ent.state;
  END IF;
  -- earned -> (first activation); redeemable -> (a second device re-runs the
  -- table). redeemed / void are terminal; vouchered is already past activation.
  IF v_ent.state NOT IN ('earned', 'redeemable') THEN
    RAISE EXCEPTION 'activate_entitlement: entitlement % is % and cannot be activated', p_entitlement_id, v_ent.state
      USING ERRCODE = '55000';
  END IF;

  IF p_decision = 'activate' THEN
    IF v_ent.rests_on_unattestable THEN
      RAISE EXCEPTION 'activate_entitlement: entitlement % rests on an unattestable co-signal (§7.5 row 3) and cannot be activated', p_entitlement_id
        USING ERRCODE = '23514';
    END IF;
    IF v_ent.play_id IS NOT NULL AND EXISTS (
      SELECT 1 FROM app.play WHERE id = v_ent.play_id AND user_id = p_user_id AND held_review
    ) THEN
      RAISE EXCEPTION 'activate_entitlement: entitlement % is backed by a held_review play (§7.5 row 3) and cannot be activated', p_entitlement_id
        USING ERRCODE = '23514';
    END IF;
    IF EXISTS (
      SELECT 1 FROM app.fraud_signal WHERE user_id = p_user_id AND kind = 'attestation_failed' AND cleared_at IS NULL
    ) THEN
      RAISE EXCEPTION 'activate_entitlement: the account has an open attestation_failed fraud_signal (§7.5 row 2); activations are held'
        USING ERRCODE = '23514';
    END IF;

    UPDATE app.entitlement SET
      state = 'redeemable',
      activated_device_id = coalesce(activated_device_id, p_device_id),
      devicecheck_token_hash = coalesce(devicecheck_token_hash, p_token_hash),
      activated_at = coalesce(activated_at, now())
    WHERE id = p_entitlement_id;

    INSERT INTO app.device_reward_ledger (device_id, devicecheck_token_hash, user_id, reward_kind, reward_id)
    VALUES (p_device_id, p_token_hash, p_user_id, 'special_marker', p_entitlement_id)
    ON CONFLICT (device_id, reward_kind, reward_id) DO NOTHING;
    RETURN 'redeemable';
  END IF;

  -- held_review: reserves no unit at any one shop (§7.5); it only counts in the
  -- trail's outstanding-redemption figure, which reads state = 'held_review'.
  UPDATE app.entitlement SET
    state = 'held_review',
    activated_device_id = coalesce(activated_device_id, p_device_id),
    devicecheck_token_hash = coalesce(devicecheck_token_hash, p_token_hash),
    activated_at = coalesce(activated_at, now())
  WHERE id = p_entitlement_id;
  RETURN 'held_review';
END;
$$;

-- The §9.2 review decision on a held offer code. Approve: the code becomes
-- `issued` with its FULL validity counted from the approval date, honoured even
-- if the offer has since ended or its budget is otherwise used up — the
-- reservation taken when it was held pays for it, so reserved_amount and
-- offer.budget_reserved are deliberately left untouched. Reject: `void`, and
-- the reservation is released. `p_resolved_by` must be an admin; the Edge layer
-- that eventually exposes this passes its own verified actor.
CREATE FUNCTION app.resolve_held_offer_code(p_code_id uuid, p_approve boolean, p_resolved_by uuid)
RETURNS app.offer_code_state
LANGUAGE plpgsql
SET search_path = ''
AS $$
DECLARE
  v_code app.offer_code%ROWTYPE;
  v_validity interval;
BEGIN
  IF p_approve IS NULL THEN
    RAISE EXCEPTION 'resolve_held_offer_code: p_approve must not be NULL' USING ERRCODE = '22023';
  END IF;
  IF p_resolved_by IS NULL OR NOT private.is_admin(p_resolved_by) THEN
    RAISE EXCEPTION 'resolve_held_offer_code: p_resolved_by is not an admin' USING ERRCODE = '42501';
  END IF;

  SELECT * INTO v_code FROM app.offer_code WHERE id = p_code_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'resolve_held_offer_code: no offer_code %', p_code_id USING ERRCODE = 'P0002';
  END IF;
  IF v_code.state <> 'held_review' THEN
    RAISE EXCEPTION 'resolve_held_offer_code: offer_code % is % (not held_review)', p_code_id, v_code.state
      USING ERRCODE = '55000';
  END IF;

  IF p_approve THEN
    IF v_code.expires_at IS NOT NULL AND v_code.expires_at > v_code.earned_at THEN
      v_validity := v_code.expires_at - v_code.earned_at;
    END IF;
    UPDATE app.offer_code SET
      state = 'issued',
      expires_at = CASE WHEN v_validity IS NULL THEN expires_at ELSE now() + v_validity END,
      expiry_paused_at = NULL
    WHERE id = p_code_id;
    IF v_code.activated_device_id IS NOT NULL THEN
      INSERT INTO app.device_reward_ledger (device_id, devicecheck_token_hash, user_id, reward_kind, reward_id)
      VALUES (v_code.activated_device_id, v_code.devicecheck_token_hash, v_code.user_id, 'offer', p_code_id)
      ON CONFLICT (device_id, reward_kind, reward_id) DO NOTHING;
    END IF;
    INSERT INTO app.audit_log (actor_user_id, action, subject_table, subject_id, detail)
    VALUES (p_resolved_by, 'held_reward_approved', 'offer_code', p_code_id::text,
            jsonb_build_object('reserved_amount', v_code.reserved_amount));
    RETURN 'issued';
  END IF;

  IF v_code.reserved_amount > 0 THEN
    PERFORM 1 FROM app.offer WHERE id = v_code.offer_id FOR UPDATE;
    UPDATE app.offer SET budget_reserved = greatest(budget_reserved - v_code.reserved_amount, 0)
    WHERE id = v_code.offer_id;
  END IF;
  UPDATE app.offer_code SET state = 'void', reserved_amount = 0 WHERE id = p_code_id;
  INSERT INTO app.audit_log (actor_user_id, action, subject_table, subject_id, detail)
  VALUES (p_resolved_by, 'held_reward_rejected', 'offer_code', p_code_id::text,
          jsonb_build_object('released_amount', v_code.reserved_amount));
  RETURN 'void';
END;
$$;

CREATE FUNCTION app.resolve_held_entitlement(p_entitlement_id uuid, p_approve boolean, p_resolved_by uuid)
RETURNS app.entitlement_state
LANGUAGE plpgsql
SET search_path = ''
AS $$
DECLARE
  v_ent app.entitlement%ROWTYPE;
BEGIN
  IF p_approve IS NULL THEN
    RAISE EXCEPTION 'resolve_held_entitlement: p_approve must not be NULL' USING ERRCODE = '22023';
  END IF;
  IF p_resolved_by IS NULL OR NOT private.is_admin(p_resolved_by) THEN
    RAISE EXCEPTION 'resolve_held_entitlement: p_resolved_by is not an admin' USING ERRCODE = '42501';
  END IF;

  SELECT * INTO v_ent FROM app.entitlement WHERE id = p_entitlement_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'resolve_held_entitlement: no entitlement %', p_entitlement_id USING ERRCODE = 'P0002';
  END IF;
  IF v_ent.state <> 'held_review' THEN
    RAISE EXCEPTION 'resolve_held_entitlement: entitlement % is % (not held_review)', p_entitlement_id, v_ent.state
      USING ERRCODE = '55000';
  END IF;

  IF p_approve THEN
    UPDATE app.entitlement SET state = 'redeemable' WHERE id = p_entitlement_id;
    IF v_ent.activated_device_id IS NOT NULL THEN
      INSERT INTO app.device_reward_ledger (device_id, devicecheck_token_hash, user_id, reward_kind, reward_id)
      VALUES (v_ent.activated_device_id, v_ent.devicecheck_token_hash, v_ent.user_id, 'special_marker', p_entitlement_id)
      ON CONFLICT (device_id, reward_kind, reward_id) DO NOTHING;
    END IF;
    INSERT INTO app.audit_log (actor_user_id, action, subject_table, subject_id, detail)
    VALUES (p_resolved_by, 'held_reward_approved', 'entitlement', p_entitlement_id::text, '{}'::jsonb);
    RETURN 'redeemable';
  END IF;

  UPDATE app.entitlement SET state = 'void' WHERE id = p_entitlement_id;
  INSERT INTO app.audit_log (actor_user_id, action, subject_table, subject_id, detail)
  VALUES (p_resolved_by, 'held_reward_rejected', 'entitlement', p_entitlement_id::text, '{}'::jsonb);
  RETURN 'void';
END;
$$;

-- Account deletion (AT 6) removes a player's offer_code rows. A held code is
-- RESERVING budget (offer.budget_reserved) and so is an approved-but-unredeemed
-- one (its reservation pays for the redemption); once the row is gone nothing
-- would ever release that, and the offer's budget would stay inflated forever.
-- This returns it. It touches only reservations still outstanding
-- (held_review / issued with reserved_amount > 0): a redeemed code's reservation
-- was consumed into budget_used, a rejected one's was released by
-- app.resolve_held_offer_code. Idempotent: a second call finds nothing to
-- release.
CREATE FUNCTION app.release_account_reservations(p_user_id uuid) RETURNS numeric
LANGUAGE plpgsql
SET search_path = ''
AS $$
DECLARE
  r record;
  v_total numeric := 0;
BEGIN
  IF p_user_id IS NULL THEN
    RAISE EXCEPTION 'release_account_reservations: p_user_id must not be NULL' USING ERRCODE = '22023';
  END IF;
  -- Ordered by offer id so two concurrent deletions lock offers in one order.
  FOR r IN
    SELECT id, offer_id, reserved_amount FROM app.offer_code
    WHERE user_id = p_user_id AND reserved_amount > 0 AND state IN ('held_review', 'issued')
    ORDER BY offer_id, id
    FOR UPDATE
  LOOP
    PERFORM 1 FROM app.offer WHERE id = r.offer_id FOR UPDATE;
    UPDATE app.offer SET budget_reserved = greatest(budget_reserved - r.reserved_amount, 0) WHERE id = r.offer_id;
    UPDATE app.offer_code SET reserved_amount = 0 WHERE id = r.id;
    v_total := v_total + r.reserved_amount;
  END LOOP;
  RETURN v_total;
END;
$$;

REVOKE EXECUTE ON FUNCTION app.activate_offer_code(uuid, uuid, uuid, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.activate_offer_code(uuid, uuid, uuid, text, text) TO service_role;
REVOKE EXECUTE ON FUNCTION app.activate_entitlement(uuid, uuid, uuid, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.activate_entitlement(uuid, uuid, uuid, text, text) TO service_role;
REVOKE EXECUTE ON FUNCTION app.resolve_held_offer_code(uuid, boolean, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.resolve_held_offer_code(uuid, boolean, uuid) TO service_role;
REVOKE EXECUTE ON FUNCTION app.resolve_held_entitlement(uuid, boolean, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.resolve_held_entitlement(uuid, boolean, uuid) TO service_role;
REVOKE EXECUTE ON FUNCTION app.release_account_reservations(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.release_account_reservations(uuid) TO service_role;

-- ============================================================================
-- P3f additions — 6. function inventory (derived check 10_function_inventory.sql
-- / verify-function-inventory.mjs fail CI on a missing row). The
-- `current_user_seed_function_inventory` INSERT policy was created by 0017 and
-- is still in place (0018 and 0021 insert the same way).
-- ============================================================================
INSERT INTO private.function_inventory
  (schema_name, function_name, identity_args, expected_anon, expected_authenticated, expected_service_role, note)
VALUES
  ('app', 'activate_offer_code', 'p_code_id uuid, p_user_id uuid, p_device_id uuid, p_token_hash text, p_decision text', false, false, true, 'P3f: the offer_code activation state machine (§7.5): earned/issued -> issued | held_review, held code reserves budget + pauses expiry, ledger row; rows 2/3 backstop. Called by rewards-activate through withOwnership as service_role; plain invoker function, not SECURITY DEFINER'),
  ('app', 'activate_entitlement', 'p_entitlement_id uuid, p_user_id uuid, p_device_id uuid, p_token_hash text, p_decision text', false, false, true, 'P3f: the entitlement activation state machine (§7.5): earned/redeemable -> redeemable | held_review, ledger row; rows 2/3 backstop. service_role only'),
  ('app', 'resolve_held_offer_code', 'p_code_id uuid, p_approve boolean, p_resolved_by uuid', false, false, true, 'P3f: the §9.2 review decision on a held offer code (approve -> issued with full validity from approval, reservation kept; reject -> void, reservation released); p_resolved_by must be an admin. No Edge Function exposes it yet (P5.1a review queue). service_role only'),
  ('app', 'resolve_held_entitlement', 'p_entitlement_id uuid, p_approve boolean, p_resolved_by uuid', false, false, true, 'P3f: the §9.2 review decision on a held entitlement (approve -> redeemable, reject -> void); p_resolved_by must be an admin. No Edge Function exposes it yet (P5.1a review queue). service_role only'),
  ('app', 'release_account_reservations', 'p_user_id uuid', false, false, true, 'P3f: returns the offer budget a deleted account''s held/approved-unredeemed codes were reserving; called by Repo#me.deleteMyData() in the delete transaction, before private.delete_my_data. Idempotent. service_role only');
