-- 0014_delete_my_data.sql
-- build plan §10 P3 AT(6) (docs/golf-trails/02-build-plan.md:2759):
-- "DELETE /v1/me removes all personal rows (asserted by query), revokes
-- connectors and deletes push tokens; an unredeemed special-marker
-- entitlement or stock voucher is voided at once, and no address exists to
-- retain (O9/O10)." Task instruction (P3 stage a): build the SQL function;
-- the endpoint itself (the Edge Function calling it, plus the Apple/Google
-- provider-revocation calls) is P4-tested (AT(19)) and out of this stage's
-- scope.
--
-- This migration builds ONLY `private.delete_my_data(uuid)`: the DB-side
-- personal-row removal. It does not call any provider API (connector
-- revocation is an Edge Function network call, out of scope — "deploys and
-- any network access" is explicitly excluded this stage); it deletes
-- `app.connector_account` / `app.signin_provider_token` rows, which is the
-- DB half of "revokes connectors" (the Edge Function is responsible for
-- calling the provider to actually revoke the grant before or after this
-- runs).
--
-- SCOPE DECISION (see AMBIGUITIES in the handback report): "personal rows"
-- is taken to mean every table whose §4.4 "Client read" column is "own"
-- (i.e., the player's own data), MINUS the two tables the plan explicitly
-- carves out different handling for:
--   - app.entitlement: voided (state = 'void'), never deleted — its stock
--     ledger FK (special_marker_stock_movement.entitlement_id) must
--     survive for the trail's inventory audit trail.
--   - app.receipt_fingerprint: user_id nulled, row kept — the plan states
--     an explicit 24-month retention for cross-account fraud matching
--     (line 835) that account deletion must not defeat.
-- app.attestation and app.fraud_signal are nulled, not deleted, because
-- the plan itself already describes this exact handling for attestation
-- ("player_user_id → nulled on account deletion", line 841) and the same
-- reasoning applies to fraud_signal (an admin fraud record whose subject
-- happens to have deleted their account is still a record admin needs).

CREATE OR REPLACE FUNCTION private.delete_my_data(p_user_id uuid)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_handle text;
  v_result jsonb := '{}'::jsonb;
BEGIN
  IF p_user_id IS NULL THEN
    RAISE EXCEPTION 'delete_my_data: user_id is required';
  END IF;

  SELECT handle INTO v_handle FROM app.profile WHERE user_id = p_user_id;

  -- Shift-log projection: replace the snapshot, not delete the row (line
  -- 842: "DELETE /v1/me replaces the snapshot with 'deleted player'"). Must
  -- run before app.profile is deleted, while v_handle is still known.
  IF v_handle IS NOT NULL THEN
    UPDATE app.attestation_shift_log
    SET player_handle_snapshot = 'deleted player'
    WHERE player_handle_snapshot = v_handle;
  END IF;

  -- Nulled, not deleted (see SCOPE DECISION above).
  UPDATE app.attestation SET player_user_id = NULL WHERE player_user_id = p_user_id;
  UPDATE app.fraud_signal SET user_id = NULL WHERE user_id = p_user_id;
  UPDATE app.receipt_fingerprint SET user_id = NULL WHERE user_id = p_user_id;
  UPDATE app.course_qr_token SET used_by_user = NULL WHERE used_by_user = p_user_id;

  -- Voided, not deleted (O9/O10, line 2759's exact wording): any
  -- unredeemed special-marker entitlement or stock voucher.
  UPDATE app.entitlement
  SET state = 'void'
  WHERE user_id = p_user_id
    AND kind = 'special_marker'
    AND state IN ('earned', 'held_review', 'redeemable', 'vouchered');

  -- Every other "own"-read personal table: deleted outright. Ordered
  -- child-before-parent for the tables that FK to app.device (RESTRICT by
  -- default: evidence.device_id, checkin_challenge.device_id,
  -- device_reward_ledger.device_id, push_token.device_id) — app.device
  -- itself is deleted last among these, once nothing still points at it.
  DELETE FROM app.play WHERE user_id = p_user_id; -- app.play_evidence cascades via its FK to play
  DELETE FROM app.evidence WHERE user_id = p_user_id;
  DELETE FROM app.marker_credit WHERE user_id = p_user_id; -- FKs to purchase_evidence: delete before it
  DELETE FROM app.purchase_evidence WHERE user_id = p_user_id;
  DELETE FROM app.user_achievement WHERE user_id = p_user_id;
  DELETE FROM app.device_reward_ledger WHERE user_id = p_user_id;
  DELETE FROM app.checkin_challenge WHERE user_id = p_user_id;
  DELETE FROM app.offer_code WHERE user_id = p_user_id;
  DELETE FROM app.connector_account WHERE user_id = p_user_id;
  DELETE FROM app.signin_provider_token WHERE user_id = p_user_id;
  DELETE FROM app.booking WHERE user_id = p_user_id;
  DELETE FROM app.push_token WHERE user_id = p_user_id;
  DELETE FROM app.device WHERE user_id = p_user_id;

  IF v_handle IS NOT NULL THEN
    DELETE FROM app.public_profile_projection WHERE handle = v_handle;
  END IF;
  DELETE FROM app.profile WHERE user_id = p_user_id;

  v_result := jsonb_build_object('user_id', p_user_id, 'deleted_at', now());
  INSERT INTO app.audit_log (actor_user_id, action, subject_table, subject_id, detail)
  VALUES (p_user_id, 'delete_my_data', 'app.profile', p_user_id::text, v_result);

  RETURN v_result;
END;
$$;

-- Not on the api.* RPC allowlist (§4.7 item 5) — this is called only from
-- the (out-of-scope-this-stage) `me-delete` Edge Function as service_role,
-- never directly by a client. No GRANT to anon/authenticated.
REVOKE EXECUTE ON FUNCTION private.delete_my_data(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.delete_my_data(uuid) TO service_role;
