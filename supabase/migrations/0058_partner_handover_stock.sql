-- 0058_partner_handover_stock.sql
--
-- P5.1a, slice S5 (database half): HAND-OVER AND STOCK. docs/security/partner-auth-design.md section 12 (S5), 12.1 (AT(8), AT(21): the race for the last unit and the voucher path), 6.3 (class A1 for a hand-over
-- and for a stock movement, A0 for a read), 8c (the guard-read windows are closed under a partner binding, so the partner redeem needs binding-keyed policies of its own) and 26.3 ("special-marker hand-over:
-- S5") are the specification; its "As built: S5" section (design 28) is the reading guide for this file. Migrations 0001-0057 are untouched (0055 belongs to the parallel S2b slice and is not created here).
--
-- WHAT THIS ADDS (all of it partner-bound: every `_for_partner` definer begins with private.partner_authorize)
--   1. private.partner_stock_read_for_partner(facility): class A0, staff or manager. The facility's stock rows: trail, on_hand, low_threshold, availability status, last_counted_at.
--   2. private.partner_stock_move_for_partner(facility, trail, kind, qty, note): class A1, staff or manager. delivered | transfer_in | transfer_out | count_adjustment | damaged (NOT redeemed / voucher_redeemed:
--      those are written only by the redeem path). The stock row is locked FOR UPDATE, the signed delta applied, a refusal that would take on_hand below zero is a STATUS (short), one movement row is written
--      (the signed delta, so on_hand = the sum of the movements, the nightly reconciliation of plan line 850) and the availability projection refreshed.
--   3. private.partner_stock_availability_refresh(trail, facility): the projection writer (out when on_hand is 0, low when on_hand is at or under low_threshold, else in_stock). EXECUTE for nobody but its owner.
--   4. private.partner_entitlement_queue_for_partner(facility): class A0, staff or manager. The redeemable special-marker entitlements of the trails the facility stocks, and the vouchered ones owed AT this
--      facility: the entitlement id, trail, state and the player handle (the shift log precedent), never an email, a device or a hash.
--   5. app.partner_handover_token: the hand-over token, HASH ONLY (the Edge generates the token and passes its SHA-256; the database never sees the plaintext). FORCE RLS, no grant to any edge role.
--      private.partner_handover_mint_for_partner(facility, entitlement, token_hash): class A1; a 15 minute single-use token for a redeemable (or vouchered-here) entitlement of a trail the facility stocks.
--   6. private.partner_entitlement_redeem_for_partner(facility, entitlement, method, credential): class A1. method staff_scan (the credential is the player's own checkin_token jti, consumed under the
--      attest lane's advisory lock with a consumed_nonce row of source entitlement_redeem) or hand_over_token (the credential is the token hash: it must match the entitlement and the facility, be unexpired and
--      unconsumed). offline_code is refused 22023 in this slice. Both stock rows and the entitlement are locked; if on_hand is under 1 the answer is the STATUS out_of_stock and NOTHING changes (the voucher is a
--      separate call). Otherwise: one attestation of kind special_marker_handover (the 0056 writer), the credential consumed, on_hand - 1, one movement (redeemed, or voucher_redeemed for a vouchered
--      entitlement), the entitlement redeemed with staff / facility / method / jti, the projection refreshed, an audit row. The CHECK (on_hand >= 0) and the row lock make the race for the last unit one ok
--      and one out_of_stock.
--   7. private.partner_entitlement_voucher_for_partner(facility, entitlement): class A1. redeemable -> vouchered, owed at this facility (voucher_facility_id, voucher_issued_at), for a trail the facility stocks.
--   8. BINDING-KEYED POLICIES (design 8c): stock, movement, availability, entitlement, the player-play guard read, the hand-over token, the consumed_nonce rows of source entitlement_redeem and the attestation of
--      kind special_marker_handover. Each is keyed on the transaction's partner BINDING and a facility predicate (private.partner_bound_staff_at, or private.partner_stocks_trail, which reads the stock policy),
--      never on a settable GUC (the HARD RULE of the money doc). Each is registered in definer_policy_allowlist and its checked-in fixture.
--
-- DELIBERATELY NOT HERE (see design 28 "Not built, honestly"): the Edge handlers (partner-entitlements-redeem, entitlements-collect, stock-admin); offers-redeem (P5.1b); the offline_code redemption method; creating a
-- stock row (rows come from the catalog import / ops; a move at a facility with no row is the status no_stock_row); a paired transfer (a transfer_out here and a transfer_in there are two moves).
--
-- CHECK 14: every `_for_partner` body begins with private.partner_authorize (a string-literal class), holds no dollar sign, double quote, backslash or E-string, and no EXCEPTION block; comments inside the
-- bodies obey the same lexing (no apostrophes there). Outcomes are STATUS rows; only malformed arguments and a self-redeem (22023) and a missing authority (42501) raise.
-- OWNERSHIP BRACKET as 0054 / 0056 / 0057: GRANT CREATE ON SCHEMA private TO private_definer; SET ROLE private_definer; CREATE FUNCTION ...; RESET ROLE; REVOKE CREATE.

-- ============================================================================
-- 1. The hand-over token table: hash only, FORCE RLS, nothing for any edge role. issued_by and consumed_by_staff are plain uuids (no FK to auth.users: a 15 minute artefact that carries no retention
--    classification; rows are purged a day after expiry).
-- ============================================================================
CREATE TABLE app.partner_handover_token (
  token_hash text PRIMARY KEY CHECK (token_hash ~ '^[0-9a-f]{64}$'),
  entitlement_id uuid NOT NULL REFERENCES app.entitlement (id) ON DELETE CASCADE,
  facility_id text NOT NULL REFERENCES app.catalog_facility (id),
  issued_by uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  consumed_by_staff uuid,
  CHECK (expires_at > created_at AND expires_at <= created_at + interval '15 minutes'),
  CHECK ((consumed_at IS NULL) = (consumed_by_staff IS NULL))
);
CREATE INDEX partner_handover_token_entitlement_idx ON app.partner_handover_token (entitlement_id);
ALTER TABLE app.partner_handover_token ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.partner_handover_token FORCE ROW LEVEL SECURITY;
REVOKE ALL ON app.partner_handover_token FROM PUBLIC, anon, authenticated, service_role;
COMMENT ON TABLE app.partner_handover_token IS
  '0058 (S5). Single-use 15 minute hand-over tokens for a special-marker entitlement at a facility. Only the SHA-256 of the token is stored (the Edge generates the token). Written only by the S5 definers under a partner binding; no edge role holds a privilege on it.';

-- ============================================================================
-- 2. Binding-keyed predicate (EXECUTE for nobody: the entitlement policies, evaluated as private_definer, call it). It reads no binding itself: the stock policy it goes through is the binding-keyed guard.
-- ============================================================================
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

-- true iff private_definer can SEE a stock row for the trail: under a partner binding that is a trail some facility the bound member is staff or manager of stocks (pd_partner_stock_select). Anywhere else it is false.
CREATE FUNCTION private.partner_stocks_trail(p_trail_id text)
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT EXISTS (SELECT 1 FROM app.special_marker_stock s WHERE s.trail_id = p_trail_id);
$$;

REVOKE EXECUTE ON FUNCTION private.partner_stocks_trail(text) FROM PUBLIC;
COMMENT ON FUNCTION private.partner_stocks_trail(text) IS
  '0058. Policy predicate: a stock row of the trail is visible to private_definer, which under a partner binding means a facility the bound member is staff or manager of stocks it (the stock policy is the binding-keyed guard). No role holds EXECUTE but the owner.';
RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

-- ============================================================================
-- 3. Grants and policies (private_definer). Column-level wherever a whole-row grant would reach more than the definers use. Every policy is keyed on the binding and a facility predicate.
-- ============================================================================
-- 3a. stock: the row the definers lock and decrement (SELECT, and UPDATE of the three columns they move)
GRANT SELECT, UPDATE (on_hand, last_counted_at, updated_at) ON app.special_marker_stock TO private_definer;
CREATE POLICY pd_partner_stock_select ON app.special_marker_stock FOR SELECT TO private_definer
  USING ((SELECT private.partner_binding_kind()) = 'partner' AND private.partner_bound_staff_at(facility_id));
CREATE POLICY pd_partner_stock_update ON app.special_marker_stock FOR UPDATE TO private_definer
  USING ((SELECT private.partner_binding_kind()) = 'partner' AND private.partner_bound_staff_at(facility_id))
  WITH CHECK ((SELECT private.partner_binding_kind()) = 'partner' AND private.partner_bound_staff_at(facility_id));

-- 3b. stock movement: INSERT of the bound member's own movement at a facility they work at (0016 already grants private_definer SELECT, UPDATE for delete_my_data's set_null pass)
GRANT INSERT (trail_id, facility_id, kind, qty, entitlement_id, by_member, note) ON app.special_marker_stock_movement TO private_definer;
CREATE POLICY pd_partner_stock_movement_insert ON app.special_marker_stock_movement FOR INSERT TO private_definer
  WITH CHECK ((SELECT private.partner_binding_kind()) = 'partner' AND by_member = (SELECT private.partner_binding_user()) AND private.partner_bound_staff_at(facility_id));

-- 3c. availability projection: read (the stock read joins it), insert and update (the refresh)
GRANT SELECT, INSERT (trail_id, facility_id, status, updated_at), UPDATE (status, updated_at) ON app.special_marker_availability TO private_definer;
CREATE POLICY pd_partner_availability_select ON app.special_marker_availability FOR SELECT TO private_definer
  USING ((SELECT private.partner_binding_kind()) = 'partner' AND private.partner_bound_staff_at(facility_id));
CREATE POLICY pd_partner_availability_insert ON app.special_marker_availability FOR INSERT TO private_definer
  WITH CHECK ((SELECT private.partner_binding_kind()) = 'partner' AND private.partner_bound_staff_at(facility_id));
CREATE POLICY pd_partner_availability_update ON app.special_marker_availability FOR UPDATE TO private_definer
  USING ((SELECT private.partner_binding_kind()) = 'partner' AND private.partner_bound_staff_at(facility_id))
  WITH CHECK ((SELECT private.partner_binding_kind()) = 'partner' AND private.partner_bound_staff_at(facility_id));

-- 3d. entitlement (0016 grants private_definer SELECT, UPDATE on the table): the redeemable and vouchered rows of a trail the bound member's facility stocks, and the two transitions the S5 definers make
-- (redeemable -> vouchered, redeemable / vouchered -> redeemed by the bound member). redeemed stays visible so the row can be read back and the 0017 play guard can re-read it.
CREATE POLICY pd_partner_handover_entitlement_select ON app.entitlement FOR SELECT TO private_definer
  USING ((SELECT private.partner_binding_kind()) = 'partner' AND state IN ('redeemable', 'vouchered', 'redeemed') AND private.partner_stocks_trail(trail_id));
CREATE POLICY pd_partner_handover_entitlement_update ON app.entitlement FOR UPDATE TO private_definer
  USING ((SELECT private.partner_binding_kind()) = 'partner' AND state IN ('redeemable', 'vouchered') AND private.partner_stocks_trail(trail_id))
  WITH CHECK ((SELECT private.partner_binding_kind()) = 'partner' AND state IN ('vouchered', 'redeemed') AND private.partner_stocks_trail(trail_id)
              AND (state <> 'redeemed' OR redeemed_by_staff = (SELECT private.partner_binding_user())));

-- 3e. the 0017 entitlement_play_guard (a constraint trigger on state) re-reads the backing play; its GUC window (pd_play_guard_read) is closed under a partner binding (design 8c), so a redeem of an
-- entitlement that has a play needs this binding-keyed read: the plays that back an entitlement the S5 policy above lets private_definer see, nothing else.
CREATE POLICY pd_partner_handover_play_guard_read ON app.play FOR SELECT TO private_definer
  USING ((SELECT private.partner_binding_kind()) = 'partner'
         AND EXISTS (SELECT 1 FROM app.entitlement e WHERE e.play_id = play.id AND e.user_id = play.user_id));

-- 3f. the hand-over token: insert (the bound member mints it, at a facility they work at), the facility's rows, the consume (a one-way UPDATE of two columns), and the purge of rows a day past expiry
GRANT SELECT, INSERT (token_hash, entitlement_id, facility_id, issued_by, created_at, expires_at), UPDATE (consumed_at, consumed_by_staff), DELETE ON app.partner_handover_token TO private_definer;
CREATE POLICY pd_partner_handover_token_insert ON app.partner_handover_token FOR INSERT TO private_definer
  WITH CHECK ((SELECT private.partner_binding_kind()) = 'partner' AND issued_by = (SELECT private.partner_binding_user()) AND consumed_at IS NULL AND private.partner_bound_staff_at(facility_id));
CREATE POLICY pd_partner_handover_token_select ON app.partner_handover_token FOR SELECT TO private_definer
  USING ((SELECT private.partner_binding_kind()) = 'partner' AND private.partner_bound_staff_at(facility_id));
CREATE POLICY pd_partner_handover_token_update ON app.partner_handover_token FOR UPDATE TO private_definer
  USING ((SELECT private.partner_binding_kind()) = 'partner' AND consumed_at IS NULL AND private.partner_bound_staff_at(facility_id))
  WITH CHECK ((SELECT private.partner_binding_kind()) = 'partner' AND consumed_by_staff = (SELECT private.partner_binding_user()) AND private.partner_bound_staff_at(facility_id));
CREATE POLICY pd_partner_handover_token_purge ON app.partner_handover_token FOR DELETE TO private_definer
  USING ((SELECT private.partner_binding_kind()) = 'partner' AND expires_at < pg_catalog.now() - interval '1 day');
CREATE POLICY pd_partner_handover_token_purge_r ON app.partner_handover_token FOR SELECT TO private_definer
  USING ((SELECT private.partner_binding_kind()) = 'partner' AND expires_at < pg_catalog.now() - interval '1 day');

-- 3g. the check-in token consumed by a staff_scan redeem: a consumed_nonce row of source entitlement_redeem, written and read under a partner binding (the 0056 policies cover source attestation only)
CREATE POLICY pd_partner_handover_nonce_insert ON private.consumed_nonce FOR INSERT TO private_definer
  WITH CHECK ((SELECT private.partner_binding_kind()) = 'partner' AND source = 'entitlement_redeem');
CREATE POLICY pd_partner_handover_nonce_select ON private.consumed_nonce FOR SELECT TO private_definer
  USING ((SELECT private.partner_binding_kind()) = 'partner' AND source = 'entitlement_redeem');

-- 3h. the attestation of a hand-over (the 0056 insert policy allows presence and marker_purchase only)
CREATE POLICY pd_partner_handover_attest_insert ON app.attestation FOR INSERT TO private_definer
  WITH CHECK ((SELECT private.partner_binding_kind()) = 'partner' AND staff_user_id = (SELECT private.partner_binding_user())
              AND kind = 'special_marker_handover' AND private.partner_bound_staff_at(facility_id));

-- ============================================================================
-- 4. The projection writer and the six partner definers.
-- ============================================================================
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

-- 4a. THE PROJECTION WRITER. Reads no binding (the policies are the guard rail, the callers hold the stock row). Returns the status written, or NULL when there is no stock row.
CREATE FUNCTION private.partner_stock_availability_refresh(p_trail_id text, p_facility_id text)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_on integer;
  v_low integer;
  v_status app.availability_status;
BEGIN
  SELECT s.on_hand, s.low_threshold INTO v_on, v_low FROM app.special_marker_stock s WHERE s.trail_id = p_trail_id AND s.facility_id = p_facility_id;
  IF NOT FOUND THEN
    RETURN NULL;
  END IF;
  v_status := (CASE WHEN v_on <= 0 THEN 'out' WHEN v_on <= v_low THEN 'low' ELSE 'in_stock' END)::app.availability_status;
  INSERT INTO app.special_marker_availability (trail_id, facility_id, status, updated_at)
  VALUES (p_trail_id, p_facility_id, v_status, pg_catalog.clock_timestamp())
  ON CONFLICT (trail_id, facility_id) DO UPDATE SET status = EXCLUDED.status, updated_at = EXCLUDED.updated_at;
  RETURN v_status::text;
END
$$;

-- 4b. GET stock (class A0: staff or manager at the facility): the facility's stock rows with the projected availability.
CREATE FUNCTION private.partner_stock_read_for_partner(p_facility_id text)
RETURNS TABLE (o_trail_id text, o_on_hand integer, o_low_threshold integer, o_status text, o_last_counted_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
BEGIN
  v_uid := private.partner_authorize(p_facility_id, NULL, ARRAY['staff', 'manager']::app.partner_role[], 'A0');
  IF p_facility_id IS NULL OR pg_catalog.btrim(p_facility_id) = '' THEN
    RAISE EXCEPTION 'partner_stock_read_for_partner: a facility is required' USING ERRCODE = '22023';
  END IF;
  RETURN QUERY
  SELECT s.trail_id, s.on_hand, s.low_threshold, a.status::text, s.last_counted_at
  FROM app.special_marker_stock s
  LEFT JOIN app.special_marker_availability a ON a.trail_id = s.trail_id AND a.facility_id = s.facility_id
  WHERE s.facility_id = p_facility_id
  ORDER BY s.trail_id;
END
$$;

-- 4c. POST stock movement (class A1: staff or manager at the facility). Statuses (all commit): ok | no_stock_row | short | over_cap. Raises: 42501, 22023 (malformed arguments).
-- delivered and transfer_in add qty, transfer_out and damaged subtract it (qty is a positive count), count_adjustment applies qty as a signed, non-zero delta and stamps last_counted_at. The movement row stores the
-- signed delta. redeemed and voucher_redeemed are not accepted here: they are written only by the redeem path.
CREATE FUNCTION private.partner_stock_move_for_partner(p_facility_id text, p_trail_id text, p_kind text, p_qty integer, p_note text)
RETURNS TABLE (o_status text, o_on_hand integer, o_availability text)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_on integer;
  v_delta integer;
  v_avail text;
BEGIN
  v_uid := private.partner_authorize(p_facility_id, NULL, ARRAY['staff', 'manager']::app.partner_role[], 'A1');
  IF p_facility_id IS NULL OR pg_catalog.btrim(p_facility_id) = '' OR p_trail_id IS NULL OR pg_catalog.btrim(p_trail_id) = ''
     OR p_kind IS NULL OR p_kind NOT IN ('delivered', 'transfer_in', 'transfer_out', 'count_adjustment', 'damaged')
     OR p_qty IS NULL OR p_qty = 0 OR p_qty > 100000 OR p_qty < -100000
     OR (p_kind <> 'count_adjustment' AND p_qty < 0)
     OR (p_note IS NOT NULL AND pg_catalog.char_length(p_note) > 200) THEN
    RAISE EXCEPTION 'partner_stock_move_for_partner: a facility, a trail, a kind (delivered, transfer_in, transfer_out, count_adjustment, damaged) and a non-zero quantity (positive unless count_adjustment, at most 100000) are required' USING ERRCODE = '22023';
  END IF;
  v_delta := CASE WHEN p_kind IN ('transfer_out', 'damaged') THEN -p_qty ELSE p_qty END;
  SELECT s.on_hand INTO v_on FROM app.special_marker_stock s WHERE s.trail_id = p_trail_id AND s.facility_id = p_facility_id FOR UPDATE;
  IF NOT FOUND THEN
    RETURN QUERY SELECT 'no_stock_row'::text, NULL::integer, NULL::text;
    RETURN;
  END IF;
  IF v_on + v_delta < 0 THEN
    RETURN QUERY SELECT 'short'::text, v_on, NULL::text;
    RETURN;
  END IF;
  IF v_on + v_delta > 1000000 THEN
    RETURN QUERY SELECT 'over_cap'::text, v_on, NULL::text;
    RETURN;
  END IF;
  UPDATE app.special_marker_stock
  SET on_hand = v_on + v_delta,
      updated_at = pg_catalog.clock_timestamp(),
      last_counted_at = CASE WHEN p_kind = 'count_adjustment' THEN pg_catalog.clock_timestamp() ELSE last_counted_at END
  WHERE trail_id = p_trail_id AND facility_id = p_facility_id;
  INSERT INTO app.special_marker_stock_movement (trail_id, facility_id, kind, qty, entitlement_id, by_member, note)
  VALUES (p_trail_id, p_facility_id, p_kind::app.stock_movement_kind, v_delta, NULL, v_uid, p_note);
  v_avail := private.partner_stock_availability_refresh(p_trail_id, p_facility_id);
  PERFORM private.partner_audit_write('partner.stock_move', 'app.special_marker_stock', p_trail_id || ':' || p_facility_id,
    pg_catalog.jsonb_build_object('facility', p_facility_id, 'trail', p_trail_id, 'kind', p_kind, 'delta', v_delta, 'on_hand', v_on + v_delta));
  RETURN QUERY SELECT 'ok'::text, v_on + v_delta, v_avail;
END
$$;

-- 4d. GET collect queue (class A0: staff or manager at the facility): the redeemable entitlements of the trails the facility stocks, and the vouchered ones owed at this facility. The player is shown by
-- handle only. The review account is never listed.
CREATE FUNCTION private.partner_entitlement_queue_for_partner(p_facility_id text)
RETURNS TABLE (o_entitlement_id uuid, o_trail_id text, o_state text, o_player_handle text, o_activated_at timestamptz, o_voucher_issued_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
BEGIN
  v_uid := private.partner_authorize(p_facility_id, NULL, ARRAY['staff', 'manager']::app.partner_role[], 'A0');
  IF p_facility_id IS NULL OR pg_catalog.btrim(p_facility_id) = '' THEN
    RAISE EXCEPTION 'partner_entitlement_queue_for_partner: a facility is required' USING ERRCODE = '22023';
  END IF;
  RETURN QUERY
  SELECT e.id, e.trail_id, e.state::text, p.handle, e.activated_at, e.voucher_issued_at
  FROM app.entitlement e
  JOIN app.special_marker_stock s ON s.trail_id = e.trail_id AND s.facility_id = p_facility_id
  LEFT JOIN app.profile p ON p.user_id = e.user_id
  WHERE (e.state = 'redeemable' OR (e.state = 'vouchered' AND e.voucher_facility_id = p_facility_id))
    AND NOT private.is_demo_account(e.user_id)
  ORDER BY (e.state = 'vouchered') DESC, e.activated_at NULLS LAST, e.id
  LIMIT 200;
END
$$;

-- 4e. POST hand-over token (class A1): the Edge generated a random token and passes its SHA-256 (lower-case hex, 64). Statuses (all commit): ok | not_found | not_redeemable | wrong_facility | no_stock_row |
-- token_exists. Raises: 42501, 22023 (malformed arguments; self_redeem_refused: a staff member cannot mint for their own account). Expired rows a day old are purged here.
CREATE FUNCTION private.partner_handover_mint_for_partner(p_facility_id text, p_entitlement_id uuid, p_token_hash text)
RETURNS TABLE (o_status text, o_expires_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_ent record;
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_n integer;
BEGIN
  v_uid := private.partner_authorize(p_facility_id, NULL, ARRAY['staff', 'manager']::app.partner_role[], 'A1');
  IF p_facility_id IS NULL OR pg_catalog.btrim(p_facility_id) = '' OR p_entitlement_id IS NULL OR p_token_hash IS NULL OR pg_catalog.char_length(p_token_hash) <> 64 OR p_token_hash ~ '[^0-9a-f]' THEN
    RAISE EXCEPTION 'partner_handover_mint_for_partner: a facility, an entitlement and a lower-case hex SHA-256 token hash are required' USING ERRCODE = '22023';
  END IF;
  SELECT e.user_id, e.trail_id, e.state, e.voucher_facility_id INTO v_ent FROM app.entitlement e WHERE e.id = p_entitlement_id;
  IF NOT FOUND THEN
    RETURN QUERY SELECT 'not_found'::text, NULL::timestamptz;
    RETURN;
  END IF;
  IF v_ent.user_id = v_uid THEN
    RAISE EXCEPTION 'self_redeem_refused: a staff member cannot hand over to their own account' USING ERRCODE = '22023';
  END IF;
  IF v_ent.state NOT IN ('redeemable', 'vouchered') OR private.is_demo_account(v_ent.user_id) THEN
    RETURN QUERY SELECT 'not_redeemable'::text, NULL::timestamptz;
    RETURN;
  END IF;
  IF v_ent.state = 'vouchered' AND v_ent.voucher_facility_id IS DISTINCT FROM p_facility_id THEN
    RETURN QUERY SELECT 'wrong_facility'::text, NULL::timestamptz;
    RETURN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM app.special_marker_stock s WHERE s.trail_id = v_ent.trail_id AND s.facility_id = p_facility_id) THEN
    RETURN QUERY SELECT 'no_stock_row'::text, NULL::timestamptz;
    RETURN;
  END IF;
  DELETE FROM app.partner_handover_token t WHERE t.expires_at < v_now - interval '1 day';
  INSERT INTO app.partner_handover_token (token_hash, entitlement_id, facility_id, issued_by, created_at, expires_at)
  VALUES (p_token_hash, p_entitlement_id, p_facility_id, v_uid, v_now, v_now + interval '15 minutes')
  ON CONFLICT (token_hash) DO NOTHING;
  GET DIAGNOSTICS v_n = ROW_COUNT;
  IF v_n <> 1 THEN
    RETURN QUERY SELECT 'token_exists'::text, NULL::timestamptz;
    RETURN;
  END IF;
  PERFORM private.partner_audit_write('partner.handover_mint', 'app.entitlement', p_entitlement_id::text,
    pg_catalog.jsonb_build_object('facility', p_facility_id, 'trail', v_ent.trail_id));
  RETURN QUERY SELECT 'ok'::text, v_now + interval '15 minutes';
END
$$;

-- 4f. POST redeem (class A1). p_method: staff_scan (p_credential is the player checkin_token jti, a uuid) or hand_over_token (p_credential is the token SHA-256, lower-case hex); offline_code is 22023 in this slice.
-- Statuses (all commit): ok | not_found | not_redeemable | wrong_facility | token_invalid | wrong_player | replayed | no_stock_row | out_of_stock | no_facility | cold_start_cap. Raises: 42501, 22023 (malformed
-- arguments; self_redeem_refused). ORDER: the entitlement and the credential are only READ, the stock row is locked and checked, the attestation is written (a refusal of the writer changes nothing), and only then are
-- the credential consumed, the unit taken and the entitlement redeemed. An out_of_stock therefore burns neither the token nor the entitlement (the voucher is a separate call).
CREATE FUNCTION private.partner_entitlement_redeem_for_partner(p_facility_id text, p_entitlement_id uuid, p_method text, p_credential text)
RETURNS TABLE (o_status text, o_attestation_id uuid, o_movement text, o_availability text)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_ent record;
  v_cred text;
  v_jti uuid;
  v_tok record;
  v_stock record;
  v_w record;
  v_kind text;
  v_avail text;
  v_ref text;
  v_now timestamptz := pg_catalog.clock_timestamp();
BEGIN
  v_uid := private.partner_authorize(p_facility_id, NULL, ARRAY['staff', 'manager']::app.partner_role[], 'A1');
  IF p_method = 'offline_code' THEN
    RAISE EXCEPTION 'partner_entitlement_redeem_for_partner: offline_code redemption is not supported in this slice' USING ERRCODE = '22023';
  END IF;
  v_cred := pg_catalog.lower(p_credential);
  IF p_facility_id IS NULL OR pg_catalog.btrim(p_facility_id) = '' OR p_entitlement_id IS NULL OR p_method IS NULL OR p_method NOT IN ('staff_scan', 'hand_over_token') OR v_cred IS NULL
     OR (p_method = 'staff_scan' AND (pg_catalog.char_length(v_cred) <> 36 OR v_cred !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'))
     OR (p_method = 'hand_over_token' AND (pg_catalog.char_length(v_cred) <> 64 OR v_cred ~ '[^0-9a-f]')) THEN
    RAISE EXCEPTION 'partner_entitlement_redeem_for_partner: a facility, an entitlement, a method (staff_scan or hand_over_token) and a credential of that method are required' USING ERRCODE = '22023';
  END IF;

  -- Read without FOR UPDATE first: SELECT FOR UPDATE also applies UPDATE RLS, and the UPDATE
  -- policy only opens redeemable/vouchered rows, so a redeemed row would look like not_found.
  SELECT e.user_id, e.trail_id, e.state, e.voucher_facility_id INTO v_ent FROM app.entitlement e WHERE e.id = p_entitlement_id;
  IF NOT FOUND THEN
    RETURN QUERY SELECT 'not_found'::text, NULL::uuid, NULL::text, NULL::text;
    RETURN;
  END IF;
  IF v_ent.user_id = v_uid THEN
    RAISE EXCEPTION 'self_redeem_refused: a staff member cannot redeem their own account' USING ERRCODE = '22023';
  END IF;
  IF v_ent.state NOT IN ('redeemable', 'vouchered') OR private.is_demo_account(v_ent.user_id) THEN
    RETURN QUERY SELECT 'not_redeemable'::text, NULL::uuid, NULL::text, NULL::text;
    RETURN;
  END IF;
  IF v_ent.state = 'vouchered' AND v_ent.voucher_facility_id IS DISTINCT FROM p_facility_id THEN
    RETURN QUERY SELECT 'wrong_facility'::text, NULL::uuid, NULL::text, NULL::text;
    RETURN;
  END IF;

  IF p_method = 'staff_scan' THEN
    v_jti := v_cred::uuid;
    -- the lock key of the attest lane: a redeem and an attest of ONE token are serialised
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('partner-attest:' || v_jti::text, 0));
    SELECT t.user_id, t.facility_id, t.expires_at INTO v_tok FROM app.checkin_token t WHERE t.jti = v_jti;
    IF NOT FOUND OR v_tok.expires_at <= v_now OR (v_tok.facility_id IS NOT NULL AND v_tok.facility_id <> p_facility_id) THEN
      RETURN QUERY SELECT 'token_invalid'::text, NULL::uuid, NULL::text, NULL::text;
      RETURN;
    END IF;
    IF v_tok.user_id <> v_ent.user_id THEN
      RETURN QUERY SELECT 'wrong_player'::text, NULL::uuid, NULL::text, NULL::text;
      RETURN;
    END IF;
    IF EXISTS (SELECT 1 FROM private.consumed_nonce n WHERE n.nonce_hash = v_jti::text) THEN
      RETURN QUERY SELECT 'replayed'::text, NULL::uuid, NULL::text, NULL::text;
      RETURN;
    END IF;
    v_ref := v_jti::text;
  ELSE
    SELECT h.entitlement_id, h.facility_id, h.expires_at, h.consumed_at INTO v_tok FROM app.partner_handover_token h WHERE h.token_hash = v_cred;
    IF NOT FOUND OR v_tok.entitlement_id <> p_entitlement_id OR v_tok.facility_id <> p_facility_id OR v_tok.expires_at <= v_now THEN
      RETURN QUERY SELECT 'token_invalid'::text, NULL::uuid, NULL::text, NULL::text;
      RETURN;
    END IF;
    IF v_tok.consumed_at IS NOT NULL THEN
      RETURN QUERY SELECT 'replayed'::text, NULL::uuid, NULL::text, NULL::text;
      RETURN;
    END IF;
    v_ref := 'handover:' || v_cred;
  END IF;

  -- Lock the entitlement (UPDATE RLS allows redeemable/vouchered) and re-check state after the credential work
  SELECT e.user_id, e.trail_id, e.state, e.voucher_facility_id INTO v_ent FROM app.entitlement e WHERE e.id = p_entitlement_id FOR UPDATE;
  IF NOT FOUND OR v_ent.state NOT IN ('redeemable', 'vouchered') THEN
    RETURN QUERY SELECT 'not_redeemable'::text, NULL::uuid, NULL::text, NULL::text;
    RETURN;
  END IF;

  SELECT s.on_hand INTO v_stock FROM app.special_marker_stock s WHERE s.trail_id = v_ent.trail_id AND s.facility_id = p_facility_id FOR UPDATE;
  IF NOT FOUND THEN
    RETURN QUERY SELECT 'no_stock_row'::text, NULL::uuid, NULL::text, NULL::text;
    RETURN;
  END IF;
  IF v_stock.on_hand < 1 THEN
    RETURN QUERY SELECT 'out_of_stock'::text, NULL::uuid, NULL::text, 'out'::text;
    RETURN;
  END IF;

  -- attestation.token_jti is UNIQUE and tombstoned (0017). Prefix smh: so the tombstone does not collide with the check-in jti the staff_scan path also inserts under source entitlement_redeem (same PK).
  SELECT w.o_status, w.o_attestation_id INTO v_w
  FROM private.partner_attest_write(v_uid, p_facility_id, v_ent.user_id, 'special_marker_handover', 'smh:' || v_ref, v_ref, false, false, v_now, v_now) w;
  IF v_w.o_status <> 'ok' THEN
    RETURN QUERY SELECT v_w.o_status, NULL::uuid, NULL::text, NULL::text;
    RETURN;
  END IF;

  IF p_method = 'staff_scan' THEN
    INSERT INTO private.consumed_nonce (nonce_hash, source) VALUES (v_jti::text, 'entitlement_redeem');
  ELSE
    UPDATE app.partner_handover_token SET consumed_at = v_now, consumed_by_staff = v_uid WHERE token_hash = v_cred AND consumed_at IS NULL;
  END IF;

  v_kind := CASE WHEN v_ent.state = 'vouchered' THEN 'voucher_redeemed' ELSE 'redeemed' END;
  UPDATE app.special_marker_stock SET on_hand = on_hand - 1, updated_at = v_now WHERE trail_id = v_ent.trail_id AND facility_id = p_facility_id;
  INSERT INTO app.special_marker_stock_movement (trail_id, facility_id, kind, qty, entitlement_id, by_member, note)
  VALUES (v_ent.trail_id, p_facility_id, v_kind::app.stock_movement_kind, -1, p_entitlement_id, v_uid, p_method);
  UPDATE app.entitlement
  SET state = 'redeemed', redeemed_at = v_now, redeemed_facility_id = p_facility_id, redeemed_by_staff = v_uid,
      redemption_method = p_method::app.redemption_method, redemption_jti = v_ref
  WHERE id = p_entitlement_id;
  v_avail := private.partner_stock_availability_refresh(v_ent.trail_id, p_facility_id);
  PERFORM private.partner_audit_write('partner.entitlement_redeem', 'app.entitlement', p_entitlement_id::text,
    pg_catalog.jsonb_build_object('facility', p_facility_id, 'trail', v_ent.trail_id, 'method', p_method, 'movement', v_kind));
  RETURN QUERY SELECT 'ok'::text, v_w.o_attestation_id, v_kind, v_avail;
END
$$;

-- 4g. POST voucher (class A1): a redeemable entitlement becomes owed at this facility (out of stock, or the staff member chooses). Statuses (all commit): ok | not_found | not_redeemable | no_stock_row.
-- Raises: 42501, 22023 (malformed arguments; self_redeem_refused).
CREATE FUNCTION private.partner_entitlement_voucher_for_partner(p_facility_id text, p_entitlement_id uuid)
RETURNS TABLE (o_status text, o_voucher_issued_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_ent record;
  v_now timestamptz := pg_catalog.clock_timestamp();
BEGIN
  v_uid := private.partner_authorize(p_facility_id, NULL, ARRAY['staff', 'manager']::app.partner_role[], 'A1');
  IF p_facility_id IS NULL OR pg_catalog.btrim(p_facility_id) = '' OR p_entitlement_id IS NULL THEN
    RAISE EXCEPTION 'partner_entitlement_voucher_for_partner: a facility and an entitlement are required' USING ERRCODE = '22023';
  END IF;
  SELECT e.user_id, e.trail_id, e.state INTO v_ent FROM app.entitlement e WHERE e.id = p_entitlement_id;
  IF NOT FOUND THEN
    RETURN QUERY SELECT 'not_found'::text, NULL::timestamptz;
    RETURN;
  END IF;
  IF v_ent.user_id = v_uid THEN
    RAISE EXCEPTION 'self_redeem_refused: a staff member cannot voucher their own account' USING ERRCODE = '22023';
  END IF;
  IF v_ent.state <> 'redeemable' OR private.is_demo_account(v_ent.user_id) THEN
    RETURN QUERY SELECT 'not_redeemable'::text, NULL::timestamptz;
    RETURN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM app.special_marker_stock s WHERE s.trail_id = v_ent.trail_id AND s.facility_id = p_facility_id) THEN
    RETURN QUERY SELECT 'no_stock_row'::text, NULL::timestamptz;
    RETURN;
  END IF;
  SELECT e.user_id, e.trail_id, e.state INTO v_ent FROM app.entitlement e WHERE e.id = p_entitlement_id FOR UPDATE;
  IF NOT FOUND OR v_ent.state <> 'redeemable' THEN
    RETURN QUERY SELECT 'not_redeemable'::text, NULL::timestamptz;
    RETURN;
  END IF;
  UPDATE app.entitlement SET state = 'vouchered', voucher_facility_id = p_facility_id, voucher_issued_at = v_now WHERE id = p_entitlement_id;
  PERFORM private.partner_audit_write('partner.entitlement_voucher', 'app.entitlement', p_entitlement_id::text,
    pg_catalog.jsonb_build_object('facility', p_facility_id, 'trail', v_ent.trail_id));
  RETURN QUERY SELECT 'ok'::text, v_now;
END
$$;

-- 4h. EXECUTE grants (PUBLIC revoked first). The projection writer: nobody but its owner. The six partner definers: edge_partner.
REVOKE EXECUTE ON FUNCTION private.partner_stock_availability_refresh(text, text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.partner_stock_read_for_partner(text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.partner_stock_move_for_partner(text, text, text, integer, text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.partner_entitlement_queue_for_partner(text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.partner_handover_mint_for_partner(text, uuid, text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.partner_entitlement_redeem_for_partner(text, uuid, text, text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.partner_entitlement_voucher_for_partner(text, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.partner_stock_read_for_partner(text) TO edge_partner;
GRANT EXECUTE ON FUNCTION private.partner_stock_move_for_partner(text, text, text, integer, text) TO edge_partner;
GRANT EXECUTE ON FUNCTION private.partner_entitlement_queue_for_partner(text) TO edge_partner;
GRANT EXECUTE ON FUNCTION private.partner_handover_mint_for_partner(text, uuid, text) TO edge_partner;
GRANT EXECUTE ON FUNCTION private.partner_entitlement_redeem_for_partner(text, uuid, text, text) TO edge_partner;
GRANT EXECUTE ON FUNCTION private.partner_entitlement_voucher_for_partner(text, uuid) TO edge_partner;
COMMENT ON FUNCTION private.partner_stock_availability_refresh(text, text) IS
  '0058. The availability projection writer: out when on_hand is 0, low when on_hand is at or under low_threshold, else in_stock. Reads no binding; EXECUTE for nobody but the owner.';
COMMENT ON FUNCTION private.partner_stock_read_for_partner(text) IS
  '0058 (S5). edge_partner only; class A0 (staff or manager at the facility). The facility''s stock rows with the projected availability.';
COMMENT ON FUNCTION private.partner_stock_move_for_partner(text, text, text, integer, text) IS
  '0058 (S5). edge_partner only; class A1 (staff or manager at the facility). One stock movement (delivered, transfer_in, transfer_out, count_adjustment, damaged), the signed delta stored, never below zero. Statuses: ok | no_stock_row | short | over_cap.';
COMMENT ON FUNCTION private.partner_entitlement_queue_for_partner(text) IS
  '0058 (S5). edge_partner only; class A0 (staff or manager at the facility). The redeemable and the vouchered-here special-marker entitlements of the trails the facility stocks, by player handle.';
COMMENT ON FUNCTION private.partner_handover_mint_for_partner(text, uuid, text) IS
  '0058 (S5). edge_partner only; class A1. Stores the SHA-256 of an Edge-generated hand-over token (15 minutes, single use) for a redeemable entitlement at a facility that stocks the trail. Statuses: ok | not_found | not_redeemable | wrong_facility | no_stock_row | token_exists.';
COMMENT ON FUNCTION private.partner_entitlement_redeem_for_partner(text, uuid, text, text) IS
  '0058 (S5, AT(8), AT(21)). edge_partner only; class A1. The hand-over: staff_scan (checkin_token jti) or hand_over_token (token hash), one unit of stock, one movement, one special_marker_handover attestation. out_of_stock changes nothing. Statuses: ok | not_found | not_redeemable | wrong_facility | token_invalid | wrong_player | replayed | no_stock_row | out_of_stock | no_facility | cold_start_cap.';
COMMENT ON FUNCTION private.partner_entitlement_voucher_for_partner(text, uuid) IS
  '0058 (S5, AT(21)). edge_partner only; class A1. redeemable -> vouchered, owed at the facility. Statuses: ok | not_found | not_redeemable | no_stock_row.';
RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

-- ============================================================================
-- 5. Registries
-- ============================================================================
-- 5a. private.function_inventory
INSERT INTO private.function_inventory
  (schema_name, function_name, identity_args, expected_anon, expected_authenticated, expected_service_role, expected_edge_actor, expected_edge_system, expected_edge_partner, expected_edge_partner_minter, note)
VALUES
  ('private', 'partner_stocks_trail', 'p_trail_id text', false, false, false, false, false, false, false, '0058 (S5): policy predicate, a stock row of the trail is visible to private_definer (a facility the bound member works at stocks it); EXECUTE for nobody but the owner'),
  ('private', 'partner_stock_availability_refresh', 'p_trail_id text, p_facility_id text', false, false, false, false, false, false, false, '0058 (S5): the availability projection writer; reads no binding; EXECUTE for nobody but the owner'),
  ('private', 'partner_stock_read_for_partner', 'p_facility_id text', false, false, false, false, false, true, false, '0058 (S5): edge_partner only; class A0; the facility stock read'),
  ('private', 'partner_stock_move_for_partner', 'p_facility_id text, p_trail_id text, p_kind text, p_qty integer, p_note text', false, false, false, false, false, true, false, '0058 (S5): edge_partner only; class A1; one stock movement'),
  ('private', 'partner_entitlement_queue_for_partner', 'p_facility_id text', false, false, false, false, false, true, false, '0058 (S5): edge_partner only; class A0; the collect queue of a facility'),
  ('private', 'partner_handover_mint_for_partner', 'p_facility_id text, p_entitlement_id uuid, p_token_hash text', false, false, false, false, false, true, false, '0058 (S5): edge_partner only; class A1; stores a hand-over token hash'),
  ('private', 'partner_entitlement_redeem_for_partner', 'p_facility_id text, p_entitlement_id uuid, p_method text, p_credential text', false, false, false, false, false, true, false, '0058 (S5): edge_partner only; class A1; the special-marker hand-over'),
  ('private', 'partner_entitlement_voucher_for_partner', 'p_facility_id text, p_entitlement_id uuid', false, false, false, false, false, true, false, '0058 (S5): edge_partner only; class A1; redeemable to vouchered');

-- 5b. private.definer_policy_allowlist: every private_definer policy this file adds, expressions derived from the live policies (supabase/tests/fixtures/definer_policy_exprs.txt is the checked-in twin).
GRANT INSERT, UPDATE ON private.definer_policy_allowlist TO CURRENT_USER;
CREATE POLICY current_user_seed_definer_policy_allowlist_0058 ON private.definer_policy_allowlist
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
INSERT INTO private.definer_policy_allowlist (schema_name, table_name, policy_name, command, scoped, note, role_name) VALUES
  ('app', 'special_marker_stock', 'pd_partner_stock_select', 'SELECT', true, 'S5: the stock rows of a facility the bound partner member is staff or manager of', 'private_definer'),
  ('app', 'special_marker_stock', 'pd_partner_stock_update', 'UPDATE', true, 'S5: the stock row of a facility the bound member works at (UPDATE (on_hand, last_counted_at, updated_at) only)', 'private_definer'),
  ('app', 'special_marker_stock_movement', 'pd_partner_stock_movement_insert', 'INSERT', true, 'S5: the bound member''s own movement at a facility they work at (the redeem path writes redeemed / voucher_redeemed, the move definer the other kinds)', 'private_definer'),
  ('app', 'special_marker_availability', 'pd_partner_availability_select', 'SELECT', true, 'S5: the projection rows of a facility the bound member works at (the stock read joins them; INSERT ... ON CONFLICT needs them visible)', 'private_definer'),
  ('app', 'special_marker_availability', 'pd_partner_availability_insert', 'INSERT', true, 'S5: the projection refresh inserts a row for a facility the bound member works at', 'private_definer'),
  ('app', 'special_marker_availability', 'pd_partner_availability_update', 'UPDATE', true, 'S5: the projection refresh updates status and updated_at at a facility the bound member works at', 'private_definer'),
  ('app', 'entitlement', 'pd_partner_handover_entitlement_select', 'SELECT', true, 'S5: redeemable, vouchered and redeemed entitlements of a trail a facility the bound member works at stocks (design 8c: the 0017 guard window is closed under a partner binding)', 'private_definer'),
  ('app', 'entitlement', 'pd_partner_handover_entitlement_update', 'UPDATE', true, 'S5: redeemable -> vouchered, and redeemable / vouchered -> redeemed by the bound member, for a trail a facility the bound member works at stocks', 'private_definer'),
  ('app', 'play', 'pd_partner_handover_play_guard_read', 'SELECT', true, 'S5: the 0017 entitlement_play_guard re-reads the backing play of an entitlement the S5 policy shows; the GUC window pd_play_guard_read is closed under a partner binding', 'private_definer'),
  ('app', 'partner_handover_token', 'pd_partner_handover_token_insert', 'INSERT', true, 'S5: the bound member mints a hand-over token hash at a facility they work at', 'private_definer'),
  ('app', 'partner_handover_token', 'pd_partner_handover_token_select', 'SELECT', true, 'S5: the hand-over tokens of a facility the bound member works at', 'private_definer'),
  ('app', 'partner_handover_token', 'pd_partner_handover_token_update', 'UPDATE', true, 'S5: the one-way consume of an unconsumed token by the bound member (UPDATE (consumed_at, consumed_by_staff) only)', 'private_definer'),
  ('app', 'partner_handover_token', 'pd_partner_handover_token_purge', 'DELETE', true, 'S5: purge of tokens a day past expiry (data-derived, no GUC)', 'private_definer'),
  ('app', 'partner_handover_token', 'pd_partner_handover_token_purge_r', 'SELECT', true, 'row-visibility companion to pd_partner_handover_token_purge', 'private_definer'),
  ('private', 'consumed_nonce', 'pd_partner_handover_nonce_insert', 'INSERT', true, 'S5: the check-in token a staff_scan redeem consumes, source entitlement_redeem, under a partner binding', 'private_definer'),
  ('private', 'consumed_nonce', 'pd_partner_handover_nonce_select', 'SELECT', true, 'S5: the replay check of a staff_scan redeem, source entitlement_redeem only, under a partner binding', 'private_definer'),
  ('app', 'attestation', 'pd_partner_handover_attest_insert', 'INSERT', true, 'S5: a special_marker_handover attestation by the BOUND partner member (staff_user_id = the binding) at a facility the member works at', 'private_definer');
UPDATE private.definer_policy_allowlist al
SET using_expr = pg_get_expr(pol.polqual, pol.polrelid),
    with_check_expr = pg_get_expr(pol.polwithcheck, pol.polrelid)
FROM pg_policy pol
JOIN pg_class cl ON cl.oid = pol.polrelid
JOIN pg_namespace n ON n.oid = cl.relnamespace
WHERE n.nspname = al.schema_name AND cl.relname = al.table_name AND pol.polname = al.policy_name
  AND al.policy_name IN (
    'pd_partner_stock_select', 'pd_partner_stock_update', 'pd_partner_stock_movement_insert', 'pd_partner_availability_select', 'pd_partner_availability_insert', 'pd_partner_availability_update',
    'pd_partner_handover_entitlement_select', 'pd_partner_handover_entitlement_update', 'pd_partner_handover_play_guard_read', 'pd_partner_handover_token_insert', 'pd_partner_handover_token_select',
    'pd_partner_handover_token_update', 'pd_partner_handover_token_purge', 'pd_partner_handover_token_purge_r', 'pd_partner_handover_nonce_insert', 'pd_partner_handover_nonce_select',
    'pd_partner_handover_attest_insert');
DO $assert_0058_allowlist$
BEGIN
  IF (SELECT count(*) FROM private.definer_policy_allowlist WHERE policy_name IN (
    'pd_partner_stock_select', 'pd_partner_stock_update', 'pd_partner_stock_movement_insert', 'pd_partner_availability_select', 'pd_partner_availability_insert', 'pd_partner_availability_update',
    'pd_partner_handover_entitlement_select', 'pd_partner_handover_entitlement_update', 'pd_partner_handover_play_guard_read', 'pd_partner_handover_token_insert', 'pd_partner_handover_token_select',
    'pd_partner_handover_token_update', 'pd_partner_handover_token_purge', 'pd_partner_handover_token_purge_r', 'pd_partner_handover_nonce_insert', 'pd_partner_handover_nonce_select',
    'pd_partner_handover_attest_insert')
        AND (using_expr IS NOT NULL OR with_check_expr IS NOT NULL)) <> 17 THEN
    RAISE EXCEPTION '0058: an allowlist row names no live policy (its expressions were not derived)';
  END IF;
END
$assert_0058_allowlist$;
DROP POLICY current_user_seed_definer_policy_allowlist_0058 ON private.definer_policy_allowlist;
REVOKE INSERT, UPDATE ON private.definer_policy_allowlist FROM CURRENT_USER;
