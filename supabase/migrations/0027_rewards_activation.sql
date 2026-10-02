-- 0027_rewards_activation.sql
-- P3f: `POST /v1/rewards/{id}/activate` (Edge Function `rewards-activate`),
-- the §7.5 activation decision table, and the `held_review` semantics on
-- `offer_code` and `entitlement` (build plan §7.5, A2-08; P3 acceptance
-- test (9)).
--
-- What already existed (0003/0005/0006/0014/0016/0017/0022) and is NOT recreated:
--   - `held_review` as a value of BOTH `app.offer_code_state` and
--     `app.entitlement_state`;
--   - `activated_device_id`, `devicecheck_token_hash`, `activated_at` on both;
--     `offer_code.expiry_paused_at`; `offer.budget_reserved` (+ the cap CHECK);
--   - `app.device_reward_ledger` (FORCE RLS, no client policy);
--   - the play-guard constraint triggers and the play-hold cascade (0017).
--
-- ============================================================================
-- THE BUDGET MODEL (pinned here; M3)
-- ============================================================================
-- Reservation = the offer's claim on `budget_cap` for ONE code, recorded twice
-- and kept equal: `offer_code.reserved_amount` (this code's share) and
-- `offer.budget_reserved` (the sum). One idempotent primitive takes it
-- (`app.reserve_offer_for_code`): a no-op for a code that already holds one.
--
--   Who takes it, in order of precedence:
--     1. THE EARNING PATH, at earn time, via `app.reserve_offer_budget` (0017)
--        — NOT BUILT. Today nothing in the repository inserts an offer_code, so
--        in this codebase the earn path reserves nothing; every reservation is
--        taken by 2 or 3 below. **When the earning path is built it MUST reserve
--        at earn time** (so a code the cap cannot pay is never earned); setting
--        `reserved_amount` is all it needs to do: 2 and 3 then find it and skip.
--     2. ACTIVATION of an `earned` code that holds none (decision `activate`):
--        `app.activate_offer_code` reserves its face value as it issues it — and
--        HOLDS the code instead of issuing it when the cap cannot cover it.
--     3. ENTRY INTO `held_review` BY ANY PATH — the row trigger
--        `app.offer_code_reservation_sync` — including the 0017 play-hold
--        cascade, which only writes `state` and used to reserve nothing (F13).
--        It reserves and pauses the expiry clock.
--   Who gives it back: transition to `void` / `expired` (same trigger, from the
--   code's OWN reserved_amount, so a reviewer reject releases exactly once);
--   DELETE of the row (same trigger, when the deleting role may update
--   app.offer — `private.delete_my_data` runs as `private_definer`, which holds
--   no grant on app.offer and must not be given one, so account deletion calls
--   `app.release_account_reservations` first, in the same transaction, locking
--   EVERY row of the account); redemption (`app.consume_offer_budget`, the
--   redeem path's job). Approval keeps it: the reservation pays for the
--   redemption even if the offer has ended.
--
--   What it never does: refuse. If `budget_cap` cannot cover a reservation:
--     - a code entering `held_review` (any path) is still held, UNRESERVED, and
--       a `review_item` (`held_offer_budget_unreserved`, one per code) says so —
--       a held code is not payable until a human resolves it, so nothing is owed;
--     - a CLEAN activation is NOT issued: it is HELD instead (N1). An issued code
--       is payable, and issuing one that holds no reservation lets the offer pay
--       out more than its cap (two codes on a cap that covers one: both issued,
--       one unreserved, and `consume_offer_budget` for the second then fails with
--       23514 at the till). Held with the same `review_item`, it is the
--       reviewer's decision whether to raise the cap, void it, or approve it.
--
--   Does an ended offer block activation? NO. `offer.status` / `valid_from` /
--   `valid_to` gate EARNING (the earn path) and REDEMPTION; a code earned while
--   the offer was live is honoured, exactly as §7.5 honours an approved held
--   code. The code's own `expires_at` is what bounds its life, and the
--   handler refuses an expired one (409). Tested both ways.
--
--   Outstanding reservations are those of codes in earned / held_review /
--   issued. A redeemed code's reservation was consumed into budget_used.
--   `expired` needs an expiry sweeper (not built, F11): moving a code to
--   `expired` through the trigger releases it.
--
-- ============================================================================
-- What this migration adds
-- ============================================================================
--   1. device: `attest_public_key`; `install_link_hash` + `fraud_voided_at`
--      (the Android A20 substitute's inputs, §7.5 "Android").
--   2. offer.face_value; offer_code.reserved_amount.
--   3. rests_on_unattestable (row 3's input), review_cleared_at (H2),
--      hold_detail (what the reviewer sees), issued_before_hold /
--      expiry_remaining (restore remaining validity after a self-induced
--      re-hold).
--   4. ledger idempotency.
--   5. functions (plain invoker-rights, EXECUTE service_role only, none
--      SECURITY DEFINER, so no private_definer bracket):
--        app.activate_offer_code / app.activate_entitlement
--        app.resolve_held_offer_code / app.resolve_held_entitlement
--        app.release_account_reservations
--        app.reserve_offer_for_code            (the idempotent primitive)
--        app.device_link_signals               (Android A20 substitute)
--        app.mark_account_devices_fraud_voided (admin; sets the substitute's bit1)
--      and the trigger app.offer_code_reservation_sync.
--
-- The decision itself (which §7.5 rows matched, and the vendor bits) is made in
-- TypeScript; what the database enforces independently of its caller is what it
-- can see: an `activate` is refused (23514) when the reward rests on an
-- unattestable co-signal (unless a reviewer cleared it), its backing play is
-- held, or the account has an open `attestation_failed` signal (row 2: released
-- only by the signal being CLEARED — a review of one reward never waives an
-- account-level signal, N3).
--
-- `export_my_data` / `delete_my_data` are NOT redefined here (see 0028 for the
-- ledger export projection). This file is NEW: no existing migration is edited.
--
-- Gate round 2 additions (all in this file, which is unmerged):
--   N1  a clean activation the cap cannot reserve for is HELD, not issued;
--   N3  review_cleared_at waives row 3 ONLY; row 2 needs the signal cleared;
--   N4  app.install_link_account: a pseudonymous install-link tombstone that
--       SURVIVES account deletion (a documented retention exception), so the
--       Android substitute cannot be erased by deleting the accounts it counts;
--   N5  app.play_held_review_cascade (0017) redefined to take its locks in ONE
--       global order: the play's codes (id order), then their offers (id order).

-- ============================================================================
-- 1. device
-- ============================================================================
ALTER TABLE app.device ADD COLUMN attest_public_key bytea;
ALTER TABLE app.device ADD CONSTRAINT device_attest_public_key_len
  CHECK (attest_public_key IS NULL OR octet_length(attest_public_key) = 65);
COMMENT ON COLUMN app.device.attest_public_key IS
  'Raw uncompressed P-256 point (0x04 || X || Y, 65 bytes) of this install''s App Attest key. Written ONLY by App Attest key registration (attestation-object verification against Apple''s root — not built in P3f). NULL means "no key registered": the assertion verifier returns unattestable, never verified. A public key, not a secret.';

ALTER TABLE app.device ADD COLUMN install_link_hash text;
ALTER TABLE app.device ADD CONSTRAINT device_install_link_hash_shape
  CHECK (install_link_hash IS NULL OR install_link_hash ~ '^[0-9a-f]{64}$');
ALTER TABLE app.device ADD COLUMN fraud_voided_at timestamptz;
CREATE INDEX device_install_link_idx ON app.device (install_link_hash) WHERE install_link_hash IS NOT NULL;
CREATE INDEX device_attest_key_idx ON app.device (attest_key_id) WHERE attest_key_id IS NOT NULL;
COMMENT ON COLUMN app.device.install_link_hash IS
  'SHA-256 hex of an opaque, client-supplied install identifier (Android). Links device rows of different accounts for the §7.5 Android substitute (A20): "this install has been seen on > 2 accounts". An UNAUTHENTICATED hint — a factory reset or a rotated id evades it, which §7.5 accepts because the table routes to review rather than refusing. Never exported.';
COMMENT ON COLUMN app.device.fraud_voided_at IS
  'Set by app.mark_account_devices_fraud_voided (an admin fraud decision) on every device of a voided account: the Android substitute for DeviceCheck bit1, "an account voided for fraud used this install".';

-- ============================================================================
-- 2. budget reservation inputs
-- ============================================================================
-- IF NOT EXISTS on face_value: another P3 builder may introduce the same
-- per-code face value; this must not make the migration set fail in either order.
ALTER TABLE app.offer ADD COLUMN IF NOT EXISTS face_value numeric(10, 2) NOT NULL DEFAULT 0 CHECK (face_value >= 0);
COMMENT ON COLUMN app.offer.face_value IS
  'Per-code face value in the offer''s currency (build plan §9.5 settlement: redemptions x face value). A code reserves this much of budget_cap. 0 = nothing reserved (legacy rows).';

ALTER TABLE app.offer_code ADD COLUMN reserved_amount numeric(10, 2) NOT NULL DEFAULT 0 CHECK (reserved_amount >= 0);
COMMENT ON COLUMN app.offer_code.reserved_amount IS
  'Amount of offer.budget_reserved this code holds (offer.face_value at the time it was taken). Taken by the earn path, by activation, or by entry into held_review (app.offer_code_reservation_sync); released on void / expired / delete / account deletion; kept on approval so the reservation pays for the redemption even if the offer has ended (§7.5). See this migration''s header for the model.';

-- ============================================================================
-- 3. per-reward review state
-- ============================================================================
ALTER TABLE app.offer_code ADD COLUMN rests_on_unattestable boolean NOT NULL DEFAULT false;
ALTER TABLE app.entitlement ADD COLUMN rests_on_unattestable boolean NOT NULL DEFAULT false;
ALTER TABLE app.offer_code ADD COLUMN review_cleared_at timestamptz;
ALTER TABLE app.entitlement ADD COLUMN review_cleared_at timestamptz;
ALTER TABLE app.offer_code ADD COLUMN hold_detail jsonb;
ALTER TABLE app.entitlement ADD COLUMN hold_detail jsonb;
ALTER TABLE app.offer_code ADD COLUMN issued_before_hold boolean NOT NULL DEFAULT false;
ALTER TABLE app.offer_code ADD COLUMN expiry_remaining interval;
COMMENT ON COLUMN app.offer_code.rests_on_unattestable IS
  '§7.5 table row 3 input: true when the reward rests on an unattestable co-signal (§4.5). Written ONLY by the server-side earning path; rewards-activate reads it (OR-ed with the backing play''s held_review).';
COMMENT ON COLUMN app.entitlement.rests_on_unattestable IS
  '§7.5 table row 3 input — see app.offer_code.rests_on_unattestable.';
COMMENT ON COLUMN app.offer_code.review_cleared_at IS
  'Set when a reviewer APPROVES a held code that never ran the §7.5 table on a device (activated_device_id IS NULL): the code returns to `earned` with rows 2 and 3 cleared for it (the unattestable basis, and any attestation_failed signal raised BEFORE this time), but rows 1 and 4-6 still run on a real device at activation. A held code that did run on a device is issued directly.';
COMMENT ON COLUMN app.entitlement.review_cleared_at IS 'See app.offer_code.review_cleared_at.';
COMMENT ON COLUMN app.offer_code.hold_detail IS
  'What the reviewer sees (§7.5): {bits, matchedRows, primaryRow, deviceCheckLastUpdateMonth, platform, grade, at}, written by activation when it holds the code. NULL for a code held by the play-hold cascade (no device was involved). Never exported, never in a player-facing view.';
COMMENT ON COLUMN app.entitlement.hold_detail IS 'See app.offer_code.hold_detail.';
COMMENT ON COLUMN app.offer_code.issued_before_hold IS
  'True when the code was `issued` at the moment it entered held_review (a second device was flagged, or a play was held after issuance). On approval such a code gets its REMAINING validity back, not a fresh full one.';
COMMENT ON COLUMN app.offer_code.expiry_remaining IS
  'Validity left when an issued code entered held_review; restored on approval (see issued_before_hold).';

-- ============================================================================
-- 4. ledger idempotency
-- ============================================================================
ALTER TABLE app.device_reward_ledger
  ADD CONSTRAINT device_reward_ledger_device_reward_key UNIQUE (device_id, reward_kind, reward_id);
CREATE INDEX device_reward_ledger_user_idx ON app.device_reward_ledger (user_id);

-- ============================================================================
-- 5. functions
-- ============================================================================
-- Error contract (SQLSTATEs the Edge layer maps; messages are diagnostics only):
--   22023  invalid parameter
--   P0002  no such reward for this user (the Edge layer has already answered 404)
--   42501  the device is not the caller's, or p_resolved_by is not an admin
--   55000  the reward's state does not allow this transition (terminal/expired)
--   23514  an `activate` decision was refused by a table-row backstop (rows 2/3)

-- 5a. The idempotent reservation primitive. Touches only app.offer and
-- app.review_item; the CALLER records the returned amount on the code.
--   returns the amount reserved (> 0);
--   returns 0 when there is nothing to reserve (no such offer, face_value 0);
--   returns NULL when the cap CANNOT cover it — a `review_item` (one open item
--     per code and kind) says so, and the caller decides what that means: the
--     trigger holds the code unreserved, a clean activation HOLDS instead of
--     issuing (N1).
CREATE FUNCTION app.reserve_offer_for_code(p_offer_id uuid, p_code_id uuid, p_review_kind text)
RETURNS numeric
LANGUAGE plpgsql
SET search_path = ''
AS $$
DECLARE
  v_offer app.offer%ROWTYPE;
BEGIN
  SELECT * INTO v_offer FROM app.offer WHERE id = p_offer_id FOR UPDATE;
  IF NOT FOUND OR v_offer.face_value <= 0 THEN
    RETURN 0;
  END IF;
  -- Deliberately NOT gated on offer.status / valid_to (see the header: earned
  -- while live = honoured).
  IF v_offer.budget_used + v_offer.budget_reserved + v_offer.face_value <= v_offer.budget_cap THEN
    UPDATE app.offer SET budget_reserved = budget_reserved + v_offer.face_value WHERE id = p_offer_id;
    RETURN v_offer.face_value;
  END IF;
  -- Never refused, never silently unreserved: a human is told (once).
  IF NOT EXISTS (
    SELECT 1 FROM app.review_item
    WHERE kind = p_review_kind AND subject_table = 'offer_code' AND subject_id = p_code_id AND resolved_at IS NULL
  ) THEN
    INSERT INTO app.review_item (kind, subject_table, subject_id, detail)
    VALUES (p_review_kind, 'offer_code', p_code_id,
            jsonb_build_object('offer_id', v_offer.id, 'face_value', v_offer.face_value));
  END IF;
  RETURN NULL;
END;
$$;

-- 5b. The row trigger: held_review (by ANY path) reserves + pauses; void /
-- expired / DELETE release.
CREATE FUNCTION app.offer_code_reservation_sync() RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    -- private.delete_my_data runs as private_definer, which has no UPDATE on
    -- app.offer (and must not get one): that path releases through
    -- app.release_account_reservations first. Every role that CAN update the
    -- offer releases here.
    IF OLD.reserved_amount > 0 AND OLD.state IN ('earned', 'held_review', 'issued')
       AND has_table_privilege('app.offer', 'UPDATE') THEN
      PERFORM app.release_offer_budget(OLD.offer_id, OLD.reserved_amount);
    END IF;
    RETURN OLD;
  END IF;

  IF TG_OP = 'INSERT' THEN
    IF NEW.state = 'held_review' THEN
      NEW.expiry_paused_at := coalesce(NEW.expiry_paused_at, now());
      IF NEW.reserved_amount = 0 THEN
        NEW.reserved_amount := coalesce(app.reserve_offer_for_code(NEW.offer_id, NEW.id, 'held_offer_budget_unreserved'), 0);
      END IF;
    END IF;
    RETURN NEW;
  END IF;

  -- UPDATE OF state
  IF NEW.state IS NOT DISTINCT FROM OLD.state THEN
    RETURN NEW;
  END IF;
  IF NEW.state = 'held_review' THEN
    NEW.issued_before_hold := (OLD.state = 'issued');
    NEW.expiry_remaining := CASE
      WHEN OLD.state = 'issued' AND OLD.expires_at IS NOT NULL THEN greatest(OLD.expires_at - now(), interval '0')
      ELSE NULL END;
    NEW.expiry_paused_at := coalesce(NEW.expiry_paused_at, now());
    IF NEW.reserved_amount = 0 THEN
      NEW.reserved_amount := coalesce(app.reserve_offer_for_code(NEW.offer_id, NEW.id, 'held_offer_budget_unreserved'), 0);
    END IF;
  ELSIF NEW.state IN ('void', 'expired') THEN
    IF OLD.reserved_amount > 0 AND OLD.state IN ('earned', 'held_review', 'issued') THEN
      PERFORM app.release_offer_budget(OLD.offer_id, OLD.reserved_amount);
      NEW.reserved_amount := 0;
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER offer_code_reservation_sync_trg
BEFORE INSERT OR UPDATE OF state OR DELETE ON app.offer_code
FOR EACH ROW EXECUTE FUNCTION app.offer_code_reservation_sync();

-- 5c. activation
CREATE FUNCTION app.activate_offer_code(
  p_code_id uuid, p_user_id uuid, p_device_id uuid, p_token_hash text, p_decision text,
  p_hold_detail jsonb DEFAULT NULL
) RETURNS app.offer_code_state
LANGUAGE plpgsql
SET search_path = ''
AS $$
DECLARE
  v_code app.offer_code%ROWTYPE;
  v_reserve numeric := 0;
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
    -- Table rows 2 and 3, enforced by the database independently of the caller.
    IF v_code.rests_on_unattestable AND v_code.review_cleared_at IS NULL THEN
      RAISE EXCEPTION 'activate_offer_code: offer_code % rests on an unattestable co-signal (§7.5 row 3) and cannot be activated', p_code_id
        USING ERRCODE = '23514';
    END IF;
    IF v_code.play_id IS NOT NULL AND EXISTS (
      SELECT 1 FROM app.play WHERE id = v_code.play_id AND user_id = p_user_id AND held_review
    ) THEN
      RAISE EXCEPTION 'activate_offer_code: offer_code % is backed by a held_review play (§7.5 row 3) and cannot be activated', p_code_id
        USING ERRCODE = '23514';
    END IF;
    -- Row 2 is an ACCOUNT-level condition: only the signal being cleared
    -- (cleared_at) releases it. review_cleared_at deliberately plays no part
    -- here (N3): a reviewer approving ONE reward must not waive a signal about
    -- the account's attestation.
    IF EXISTS (
      SELECT 1 FROM app.fraud_signal
      WHERE user_id = p_user_id AND kind = 'attestation_failed' AND cleared_at IS NULL
    ) THEN
      RAISE EXCEPTION 'activate_offer_code: the account has an open attestation_failed fraud_signal (§7.5 row 2); activations are held'
        USING ERRCODE = '23514';
    END IF;

    -- Issuing a code that holds no reservation takes one (header: model, step 2).
    -- If the cap cannot cover it the code is HELD, never issued unreserved (N1):
    -- an issued code is payable.
    IF v_code.state = 'earned' AND v_code.reserved_amount = 0 THEN
      v_reserve := app.reserve_offer_for_code(v_code.offer_id, v_code.id, 'held_offer_budget_unreserved');
      IF v_reserve IS NULL THEN
        UPDATE app.offer_code SET
          state = 'held_review',
          hold_detail = coalesce(p_hold_detail, '{}'::jsonb) || jsonb_build_object('heldFor', 'offer_budget'),
          activated_device_id = coalesce(activated_device_id, p_device_id),
          devicecheck_token_hash = coalesce(devicecheck_token_hash, p_token_hash),
          activated_at = coalesce(activated_at, now())
        WHERE id = p_code_id;
        RETURN 'held_review';
      END IF;
    END IF;

    UPDATE app.offer_code SET
      state = 'issued',
      reserved_amount = reserved_amount + v_reserve,
      activated_device_id = coalesce(activated_device_id, p_device_id),
      devicecheck_token_hash = coalesce(devicecheck_token_hash, p_token_hash),
      activated_at = coalesce(activated_at, now())
    WHERE id = p_code_id;

    INSERT INTO app.device_reward_ledger (device_id, devicecheck_token_hash, user_id, reward_kind, reward_id)
    VALUES (p_device_id, p_token_hash, p_user_id, 'offer', p_code_id)
    ON CONFLICT (device_id, reward_kind, reward_id) DO NOTHING;
    RETURN 'issued';
  END IF;

  -- held_review. app.offer_code_reservation_sync reserves the budget and pauses
  -- the expiry clock on the state change — the same path the play-hold cascade
  -- takes, so there is exactly one implementation.
  UPDATE app.offer_code SET
    state = 'held_review',
    hold_detail = coalesce(p_hold_detail, hold_detail),
    activated_device_id = coalesce(activated_device_id, p_device_id),
    devicecheck_token_hash = coalesce(devicecheck_token_hash, p_token_hash),
    activated_at = coalesce(activated_at, now())
  WHERE id = p_code_id;
  RETURN 'held_review';
END;
$$;

CREATE FUNCTION app.activate_entitlement(
  p_entitlement_id uuid, p_user_id uuid, p_device_id uuid, p_token_hash text, p_decision text,
  p_hold_detail jsonb DEFAULT NULL
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
    IF v_ent.rests_on_unattestable AND v_ent.review_cleared_at IS NULL THEN
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
      SELECT 1 FROM app.fraud_signal
      WHERE user_id = p_user_id AND kind = 'attestation_failed' AND cleared_at IS NULL
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
    hold_detail = coalesce(p_hold_detail, hold_detail),
    activated_device_id = coalesce(activated_device_id, p_device_id),
    devicecheck_token_hash = coalesce(devicecheck_token_hash, p_token_hash),
    activated_at = coalesce(activated_at, now())
  WHERE id = p_entitlement_id;
  RETURN 'held_review';
END;
$$;

-- 5d. The §9.2 review decision on a held offer code.
--   APPROVE, and the code RAN the table on a device (activated_device_id is
--     set): `issued`, validity restored — FULL validity counted from the
--     approval date for a code that was never issued (§7.5), the REMAINING
--     validity for one that was issued before it was held (a self-induced
--     re-hold must not be a free renewal). Honoured even if the offer ended;
--     the reservation is untouched.
--   APPROVE, and no device ever ran the table on it (a play-hold cascade, an
--     earn-time hold): the code returns to `earned` with review_cleared_at set.
--     It is NOT issued — it has no device and §7.5 has not run — and it does
--     not make the account a "repeat user": rows 1 and 4-6 still run, on a
--     real device, at activation. Review clears ROW 3 for the reward and
--     NOTHING ELSE: an open attestation_failed signal on the account (row 2)
--     still holds it until the signal itself is cleared (N3).
--   REJECT: `void`; app.offer_code_reservation_sync releases the reservation.
CREATE FUNCTION app.resolve_held_offer_code(p_code_id uuid, p_approve boolean, p_resolved_by uuid)
RETURNS app.offer_code_state
LANGUAGE plpgsql
SET search_path = ''
AS $$
DECLARE
  v_code app.offer_code%ROWTYPE;
  v_expires timestamptz;
  v_new app.offer_code_state;
  v_reserve numeric;
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
    -- An approved code is payable. If it holds no reservation (it was held
    -- because the cap could not cover it, N1), take one now — and if the cap STILL
    -- cannot cover it, refuse the approval (23514) rather than issue a code the
    -- offer cannot pay: raise the cap, or reject the code.
    IF v_code.reserved_amount = 0 THEN
      v_reserve := app.reserve_offer_for_code(v_code.offer_id, v_code.id, 'held_offer_budget_unreserved');
      IF v_reserve IS NULL THEN
        RAISE EXCEPTION 'resolve_held_offer_code: offer % cannot cover this code''s face value; raise its budget_cap or reject the code', v_code.offer_id
          USING ERRCODE = '23514';
      END IF;
      v_code.reserved_amount := v_reserve;
    END IF;
    v_expires := CASE
      WHEN v_code.issued_before_hold AND v_code.expiry_remaining IS NOT NULL THEN now() + v_code.expiry_remaining
      WHEN v_code.expires_at IS NOT NULL AND v_code.expires_at > v_code.earned_at THEN now() + (v_code.expires_at - v_code.earned_at)
      ELSE v_code.expires_at END;
    v_new := CASE WHEN v_code.activated_device_id IS NULL THEN 'earned'::app.offer_code_state ELSE 'issued'::app.offer_code_state END;
    UPDATE app.offer_code SET
      state = v_new,
      expires_at = v_expires,
      expiry_paused_at = NULL,
      issued_before_hold = false,
      expiry_remaining = NULL,
      reserved_amount = v_code.reserved_amount,
      review_cleared_at = CASE WHEN v_new = 'earned' THEN now() ELSE review_cleared_at END
    WHERE id = p_code_id;
    IF v_new = 'issued' THEN
      INSERT INTO app.device_reward_ledger (device_id, devicecheck_token_hash, user_id, reward_kind, reward_id)
      VALUES (v_code.activated_device_id, v_code.devicecheck_token_hash, v_code.user_id, 'offer', p_code_id)
      ON CONFLICT (device_id, reward_kind, reward_id) DO NOTHING;
    END IF;
    INSERT INTO app.audit_log (actor_user_id, action, subject_table, subject_id, detail)
    VALUES (p_resolved_by, 'held_reward_approved', 'offer_code', p_code_id::text,
            jsonb_build_object('reserved_amount', v_code.reserved_amount, 'resulting_state', v_new));
    RETURN v_new;
  END IF;

  UPDATE app.offer_code SET state = 'void' WHERE id = p_code_id; -- the trigger releases the reservation
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
  v_new app.entitlement_state;
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
    -- Same rule as offer codes: no device ever ran §7.5 on it -> back to earned, review-cleared.
    v_new := CASE WHEN v_ent.activated_device_id IS NULL THEN 'earned'::app.entitlement_state ELSE 'redeemable'::app.entitlement_state END;
    UPDATE app.entitlement SET
      state = v_new,
      review_cleared_at = CASE WHEN v_new = 'earned' THEN now() ELSE review_cleared_at END
    WHERE id = p_entitlement_id;
    IF v_new = 'redeemable' THEN
      INSERT INTO app.device_reward_ledger (device_id, devicecheck_token_hash, user_id, reward_kind, reward_id)
      VALUES (v_ent.activated_device_id, v_ent.devicecheck_token_hash, v_ent.user_id, 'special_marker', p_entitlement_id)
      ON CONFLICT (device_id, reward_kind, reward_id) DO NOTHING;
    END IF;
    INSERT INTO app.audit_log (actor_user_id, action, subject_table, subject_id, detail)
    VALUES (p_resolved_by, 'held_reward_approved', 'entitlement', p_entitlement_id::text, jsonb_build_object('resulting_state', v_new));
    RETURN v_new;
  END IF;

  UPDATE app.entitlement SET state = 'void' WHERE id = p_entitlement_id;
  INSERT INTO app.audit_log (actor_user_id, action, subject_table, subject_id, detail)
  VALUES (p_resolved_by, 'held_reward_rejected', 'entitlement', p_entitlement_id::text, '{}'::jsonb);
  RETURN 'void';
END;
$$;

-- 5e. Account deletion hands back what the account's codes reserve. TWO phases:
--   phase 1 locks EVERY offer_code row of the account (no predicate, `ORDER BY
--     id`) and waits for each. A `FOR UPDATE ... WHERE reserved_amount > 0` would
--     SKIP (not wait for) a row a concurrent activation has locked but not yet
--     committed, and the deletion that follows would then remove a row that
--     committed WITH a reservation (M1);
--   phase 2 is a NEW statement, so it reads the rows as they were committed once
--     phase 1 got every lock, and releases from those. Because every code lock is
--     taken BEFORE the first offer lock, a concurrent activation (code lock ->
--     offer lock) cannot form a cycle with this function (offer lock held here
--     while waiting for a code lock there).
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
  PERFORM 1 FROM app.offer_code WHERE user_id = p_user_id ORDER BY id FOR UPDATE;
  FOR r IN
    SELECT id, offer_id, reserved_amount, state FROM app.offer_code
    WHERE user_id = p_user_id AND reserved_amount > 0 AND state IN ('earned', 'held_review', 'issued')
    ORDER BY offer_id, id
  LOOP
    PERFORM app.release_offer_budget(r.offer_id, r.reserved_amount);
    UPDATE app.offer_code SET reserved_amount = 0 WHERE id = r.id;
    v_total := v_total + r.reserved_amount;
  END LOOP;
  RETURN v_total;
END;
$$;

-- 5f. The cascade, in ONE lock order (N5).
-- 0017's app.play_held_review_cascade ran `UPDATE app.offer_code ... WHERE
-- play_id = NEW.id` and, per row (through app.offer_code_reservation_sync), took
-- each code's OFFER lock as it went — so the order the offers were locked in was
-- the order the codes happened to be scanned in. Two plays whose codes sit on the
-- same two offers in opposite scan order deadlocked (40P01) inside
-- reserve_offer_for_code. The cascade now takes every lock it will need up front,
-- in the one global order every writer of these tables uses:
--     offer_code rows (ORDER BY id)  ->  their offers (ORDER BY id)  ->  entitlements (ORDER BY id)
-- Activation is the same shape (its reward row, then the offer); account deletion
-- locks all of an account's codes before any offer and releases in offer-id order.
-- Same signature, same trigger, same grants (CREATE OR REPLACE); plain
-- invoker-rights, so no ownership bracket. `search_path` is now pinned too.
CREATE OR REPLACE FUNCTION app.play_held_review_cascade() RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
  IF NEW.held_review AND NOT OLD.held_review THEN
    PERFORM 1 FROM app.offer_code
      WHERE play_id = NEW.id AND state NOT IN ('held_review', 'redeemed', 'void', 'expired')
      ORDER BY id FOR UPDATE;
    PERFORM 1 FROM app.offer
      WHERE id IN (
        SELECT offer_id FROM app.offer_code
        WHERE play_id = NEW.id AND state NOT IN ('held_review', 'redeemed', 'void', 'expired')
      )
      ORDER BY id FOR UPDATE;
    PERFORM 1 FROM app.entitlement
      WHERE play_id = NEW.id AND state NOT IN ('held_review', 'redeemed', 'void')
      ORDER BY id FOR UPDATE;
    UPDATE app.offer_code SET state = 'held_review'
      WHERE play_id = NEW.id AND state NOT IN ('held_review', 'redeemed', 'void', 'expired');
    UPDATE app.entitlement SET state = 'held_review'
      WHERE play_id = NEW.id AND state NOT IN ('held_review', 'redeemed', 'void');
  END IF;
  RETURN NEW;
END;
$$;

-- 5g. The install-link tombstone (N4).
-- The Android A20 substitute counted device rows, and account deletion deletes
-- them (device is `delete_row`): the next account on the same install saw a clean
-- count, and a fraud-voided account that deleted itself took its `fraud_voided_at`
-- mark with it. So the substitute's two facts now live ALSO in a pseudonymous
-- record that deliberately SURVIVES account deletion:
--     (install_link_hash, account_pseudonym, account_pseudonym_hmac_id,
--      first_seen_at, fraud_voided_at)
-- — NO user id and no FK to auth.users. `account_pseudonym` is the vault-keyed
-- HMAC of the account id, exactly the scheme app.attestation.player_pseudonym
-- uses (0004/0018): the key id is registered in private.pseudonym_key_registry,
-- the write-time trigger validates it, and the HMAC itself is computed by a
-- SECURITY DEFINER function owned by private_definer (the only role that may read
-- the vault). One row per (install, account): the row COUNT is the "seen on > N
-- accounts" count, and it does not shrink when an account deletes itself.
--
-- RETENTION EXCEPTION (documented in docs/security/p3-money-path-requirements.md):
-- private.delete_my_data does not touch this table and must not — it is a FRAUD
-- tombstone, the same class as app.receipt_fingerprint's 24-month cross-account
-- fingerprint (0003/0014: "must survive account deletion"). It holds no user id,
-- no email, no raw install id (the install id is stored only as its SHA-256), and
-- cannot be tied back to a person without the vault key AND the account id. It is
-- not exported (it is not the subject's own record: it names nobody). Because it
-- has no column referencing auth.users, private.pii_retention_policy (which is
-- derived from those FKs) has nothing to classify here — pgTAP asserts that, so a
-- future change that adds a user reference to it fails the matrix instead of
-- silently turning a tombstone into a personal row.
CREATE TABLE app.install_link_account (
  install_link_hash text NOT NULL CHECK (install_link_hash ~ '^[0-9a-f]{64}$'),
  account_pseudonym text NOT NULL CHECK (account_pseudonym ~ '^[0-9a-f]{64}$'),
  account_pseudonym_hmac_id uuid NOT NULL REFERENCES private.pseudonym_key_registry (key_id),
  first_seen_at timestamptz NOT NULL DEFAULT now(),
  fraud_voided_at timestamptz,
  PRIMARY KEY (install_link_hash, account_pseudonym)
);
ALTER TABLE app.install_link_account ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.install_link_account FORCE ROW LEVEL SECURITY;
REVOKE ALL ON app.install_link_account FROM PUBLIC, anon, authenticated;
GRANT SELECT, INSERT, UPDATE ON app.install_link_account TO service_role;
COMMENT ON TABLE app.install_link_account IS
  'Pseudonymous install-link tombstone for the §7.5 Android substitute (A20). SURVIVES account deletion by design (a fraud-prevention retention exception, like app.receipt_fingerprint): no user id, no FK to auth.users, the install id only as its SHA-256, the account only as a vault-keyed HMAC. Never exported, never returned to a client. See 0027 section 5g.';

CREATE FUNCTION app.install_link_account_validate_hmac_id() RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
  PERFORM private.validate_and_register_pseudonym_hmac_id(NEW.account_pseudonym_hmac_id);
  RETURN NEW;
END;
$$;
CREATE TRIGGER install_link_account_validate_hmac_id_trg
BEFORE INSERT ON app.install_link_account
FOR EACH ROW EXECUTE FUNCTION app.install_link_account_validate_hmac_id();

-- The account pseudonym under EVERY active vault key (a row written under an
-- older key must stay findable after a rotation — the same rule delete_my_data
-- follows), flagged `preferred` for the newest key (the one a NEW row is written
-- under). Fail closed with no usable key. SECURITY DEFINER, owned by
-- private_definer (the only role granted vault.decrypted_secrets); EXECUTE
-- service_role only; reads nothing but the vault.
CREATE FUNCTION private.account_pseudonyms(p_user_id uuid)
RETURNS TABLE (key_id uuid, pseudonym text, preferred boolean)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  IF p_user_id IS NULL THEN
    RAISE EXCEPTION 'account_pseudonyms: p_user_id must not be NULL' USING ERRCODE = '22023';
  END IF;
  IF EXISTS (
    SELECT 1 FROM vault.decrypted_secrets
    WHERE name LIKE 'pseudonym_hmac%' AND (decrypted_secret IS NULL OR length(decrypted_secret) < 32)
  ) OR NOT EXISTS (SELECT 1 FROM vault.decrypted_secrets WHERE name LIKE 'pseudonym_hmac%') THEN
    RAISE EXCEPTION 'account_pseudonyms: no valid (>=32 byte) pseudonym_hmac key in vault.decrypted_secrets' USING ERRCODE = '55000';
  END IF;
  RETURN QUERY
    SELECT v.id, encode(public.hmac(p_user_id::text, v.decrypted_secret, 'sha256'), 'hex'),
           v.name = max(v.name) OVER ()
    FROM vault.decrypted_secrets v
    WHERE v.name LIKE 'pseudonym_hmac%';
END;
$$;
REVOKE EXECUTE ON FUNCTION private.account_pseudonyms(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.account_pseudonyms(uuid) TO service_role;
GRANT CREATE ON SCHEMA private TO private_definer;
ALTER FUNCTION private.account_pseudonyms(uuid) OWNER TO private_definer;
REVOKE CREATE ON SCHEMA private FROM private_definer;

-- Records that this account used this install: stamps the link on the device row
-- (first writer wins) and writes the tombstone row for (install, account) unless
-- the account already has one under ANY active key (so a key rotation does not
-- count one account twice).
CREATE FUNCTION app.record_install_link(p_user_id uuid, p_device_id uuid, p_link_hash text) RETURNS void
LANGUAGE plpgsql
SET search_path = ''
AS $$
DECLARE
  v_hash text;
BEGIN
  IF p_link_hash IS NULL OR p_link_hash !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'record_install_link: p_link_hash must be 64 lowercase hex characters' USING ERRCODE = '22023';
  END IF;
  UPDATE app.device SET install_link_hash = coalesce(install_link_hash, p_link_hash)
  WHERE id = p_device_id AND user_id = p_user_id
  RETURNING install_link_hash INTO v_hash;
  IF v_hash IS NULL THEN
    RAISE EXCEPTION 'record_install_link: device % is not owned by this user', p_device_id USING ERRCODE = '42501';
  END IF;
  IF EXISTS (
    SELECT 1 FROM app.install_link_account t
    JOIN private.account_pseudonyms(p_user_id) a ON a.pseudonym = t.account_pseudonym
    WHERE t.install_link_hash = v_hash
  ) THEN
    RETURN;
  END IF;
  INSERT INTO app.install_link_account (install_link_hash, account_pseudonym, account_pseudonym_hmac_id)
  SELECT v_hash, a.pseudonym, a.key_id FROM private.account_pseudonyms(p_user_id) a WHERE a.preferred
  ON CONFLICT DO NOTHING;
END;
$$;

-- 5h. The Android A20 substitute's two signals (§7.5): "device rows linked by
-- install id, attest key id and account give two signals". bit0-ish: the install
-- has been seen on MORE THAN 2 accounts; bit1-ish: an account voided for fraud
-- used it. Two sources, combined conservatively:
--   - the tombstone (link hash equal): survives account deletion;
--   - live device rows (an equal install_link_hash OR an equal attest_key_id, or
--     this row itself): the only place attest-key linkage exists.
-- accounts_on_install is the LARGER of the two counts (the sources identify
-- accounts differently — user id vs pseudonym — so they cannot be merged
-- exactly, and the larger is the safe side), and voided is the OR.
CREATE FUNCTION app.device_link_signals(p_device_id uuid)
RETURNS TABLE (accounts_on_install int, voided_account_used_install boolean)
LANGUAGE sql
STABLE
SET search_path = ''
AS $$
  WITH me AS (
    SELECT id, install_link_hash, attest_key_id FROM app.device WHERE id = p_device_id
  ), live AS (
    SELECT d.user_id, d.fraud_voided_at
    FROM app.device d JOIN me ON d.id = me.id
       OR (me.install_link_hash IS NOT NULL AND d.install_link_hash = me.install_link_hash)
       OR (me.attest_key_id IS NOT NULL AND d.attest_key_id = me.attest_key_id)
  ), tomb AS (
    SELECT t.account_pseudonym, t.fraud_voided_at
    FROM app.install_link_account t JOIN me ON t.install_link_hash = me.install_link_hash
  )
  SELECT greatest((SELECT count(DISTINCT user_id) FROM live), (SELECT count(DISTINCT account_pseudonym) FROM tomb))::int,
         coalesce((SELECT bool_or(fraud_voided_at IS NOT NULL) FROM live), false)
           OR coalesce((SELECT bool_or(fraud_voided_at IS NOT NULL) FROM tomb), false);
$$;

-- 5i. The admin fraud decision's device side: marks every device of a voided
-- account AND its tombstone rows (found by the account's pseudonym under every
-- active key), which is the Android substitute's bit1 for every install linked to
-- them — and survives the account deleting itself afterwards. Works for an
-- account whose auth row is already gone (it needs only the id), so the decision
-- can still be recorded after a deletion. (The iOS DeviceCheck bit1 write is the
-- same admin tool's job, not built.)
CREATE FUNCTION app.mark_account_devices_fraud_voided(p_user_id uuid, p_resolved_by uuid) RETURNS int
LANGUAGE plpgsql
SET search_path = ''
AS $$
DECLARE
  v_n int;
  v_t int;
BEGIN
  IF p_user_id IS NULL OR p_resolved_by IS NULL OR NOT private.is_admin(p_resolved_by) THEN
    RAISE EXCEPTION 'mark_account_devices_fraud_voided: p_resolved_by is not an admin' USING ERRCODE = '42501';
  END IF;
  UPDATE app.device SET fraud_voided_at = coalesce(fraud_voided_at, now()) WHERE user_id = p_user_id;
  GET DIAGNOSTICS v_n = ROW_COUNT;
  UPDATE app.install_link_account SET fraud_voided_at = coalesce(fraud_voided_at, now())
  WHERE account_pseudonym IN (SELECT a.pseudonym FROM private.account_pseudonyms(p_user_id) a);
  GET DIAGNOSTICS v_t = ROW_COUNT;
  INSERT INTO app.audit_log (actor_user_id, action, subject_table, subject_id, detail)
  VALUES (p_resolved_by, 'account_devices_fraud_voided', 'device', p_user_id::text, jsonb_build_object('devices', v_n, 'install_links', v_t));
  RETURN v_n;
END;
$$;

REVOKE EXECUTE ON FUNCTION app.reserve_offer_for_code(uuid, uuid, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.reserve_offer_for_code(uuid, uuid, text) TO service_role;
REVOKE EXECUTE ON FUNCTION app.offer_code_reservation_sync() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION app.install_link_account_validate_hmac_id() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION app.activate_offer_code(uuid, uuid, uuid, text, text, jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.activate_offer_code(uuid, uuid, uuid, text, text, jsonb) TO service_role;
REVOKE EXECUTE ON FUNCTION app.activate_entitlement(uuid, uuid, uuid, text, text, jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.activate_entitlement(uuid, uuid, uuid, text, text, jsonb) TO service_role;
REVOKE EXECUTE ON FUNCTION app.resolve_held_offer_code(uuid, boolean, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.resolve_held_offer_code(uuid, boolean, uuid) TO service_role;
REVOKE EXECUTE ON FUNCTION app.resolve_held_entitlement(uuid, boolean, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.resolve_held_entitlement(uuid, boolean, uuid) TO service_role;
REVOKE EXECUTE ON FUNCTION app.release_account_reservations(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.release_account_reservations(uuid) TO service_role;
REVOKE EXECUTE ON FUNCTION app.record_install_link(uuid, uuid, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.record_install_link(uuid, uuid, text) TO service_role;
REVOKE EXECUTE ON FUNCTION app.device_link_signals(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.device_link_signals(uuid) TO service_role;
REVOKE EXECUTE ON FUNCTION app.mark_account_devices_fraud_voided(uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.mark_account_devices_fraud_voided(uuid, uuid) TO service_role;

-- ============================================================================
-- 6. function inventory (the `current_user_seed_function_inventory` INSERT
-- policy was created by 0017 and is still in place).
-- ============================================================================
INSERT INTO private.function_inventory
  (schema_name, function_name, identity_args, expected_anon, expected_authenticated, expected_service_role, note)
VALUES
  ('app', 'reserve_offer_for_code', 'p_offer_id uuid, p_code_id uuid, p_review_kind text', false, false, true, 'P3f: the idempotent budget-reservation primitive (locks the offer, cap-checked; returns the amount, 0 for nothing to reserve, NULL when the cap cannot cover it, with one open review_item per code); called from the activation functions and the reservation trigger as service_role'),
  ('app', 'offer_code_reservation_sync', '', false, false, false, 'trigger function (app.offer_code_reservation_sync_trg) -- held_review by ANY path reserves + pauses; void/expired/DELETE release; never EXECUTEd directly by any role'),
  ('app', 'install_link_account_validate_hmac_id', '', false, false, false, 'trigger function (app.install_link_account_validate_hmac_id_trg) -- validates + registers the pseudonym key id of an install-link tombstone row; never EXECUTEd directly by any role'),
  ('app', 'activate_offer_code', 'p_code_id uuid, p_user_id uuid, p_device_id uuid, p_token_hash text, p_decision text, p_hold_detail jsonb', false, false, true, 'P3f: the offer_code activation state machine (§7.5); earned/issued -> issued | held_review, reservation (a clean activation the cap cannot cover is HELD), ledger row, rows 2/3 backstop. Called by rewards-activate through withOwnership as service_role; plain invoker function, not SECURITY DEFINER'),
  ('app', 'activate_entitlement', 'p_entitlement_id uuid, p_user_id uuid, p_device_id uuid, p_token_hash text, p_decision text, p_hold_detail jsonb', false, false, true, 'P3f: the entitlement activation state machine (§7.5); earned/redeemable -> redeemable | held_review, ledger row, rows 2/3 backstop. service_role only'),
  ('app', 'resolve_held_offer_code', 'p_code_id uuid, p_approve boolean, p_resolved_by uuid', false, false, true, 'P3f: the §9.2 review decision on a held offer code (approve -> issued, or back to earned review-cleared (row 3 only) if no device ever ran the table; reject -> void); p_resolved_by must be an admin. No Edge Function exposes it yet (P5.1a review queue). service_role only'),
  ('app', 'resolve_held_entitlement', 'p_entitlement_id uuid, p_approve boolean, p_resolved_by uuid', false, false, true, 'P3f: the §9.2 review decision on a held entitlement; p_resolved_by must be an admin. No Edge Function exposes it yet (P5.1a review queue). service_role only'),
  ('app', 'release_account_reservations', 'p_user_id uuid', false, false, true, 'P3f: returns the offer budget a deleted account''s codes were reserving, locking EVERY offer_code row of the account first and releasing in offer-id order; called by Repo#me.deleteMyData() in the delete transaction, before private.delete_my_data. Idempotent. service_role only'),
  ('app', 'record_install_link', 'p_user_id uuid, p_device_id uuid, p_link_hash text', false, false, true, 'P3f: stamps the (hashed) install link on the device row, first writer wins, and writes the account''s pseudonymous install-link tombstone row (survives account deletion). Called by rewards-activate for Android. service_role only'),
  ('app', 'device_link_signals', 'p_device_id uuid', false, false, true, 'P3f: the §7.5 Android A20 substitute: accounts seen on the install (tombstone + live device rows linked by install_link_hash / attest_key_id) and whether a fraud-voided account used it. service_role only'),
  ('app', 'mark_account_devices_fraud_voided', 'p_user_id uuid, p_resolved_by uuid', false, false, true, 'P3f: the admin fraud decision''s device side (sets fraud_voided_at on every device of the account and on its install-link tombstone rows); p_resolved_by must be an admin. No Edge Function exposes it yet. service_role only'),
  ('private', 'account_pseudonyms', 'p_user_id uuid', false, false, true, 'P3f: the vault-keyed HMAC pseudonym of an account id under every active pseudonym_hmac key (the scheme app.attestation.player_pseudonym uses); SECURITY DEFINER owned by private_definer (the only vault reader); called by app.record_install_link / app.mark_account_devices_fraud_voided as service_role');
