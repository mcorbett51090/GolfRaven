-- 0059_partner_programme_sponsors.sql
--
-- P5.1a, slice S6 (database half): PROGRAMME AND SPONSORS. docs/security/partner-auth-design.md section 12 (S6), 12.1 (AT(10), AT(14), AT(17), AT(20)), 6.3 (class A3 for programme / offer / sponsorship writes, A0 for reads), 8c (binding-keyed policies, never a GUC) and the money doc's D12 (partner offer read leaves PostgREST) are the specification; its "As built: S6" section (design 30) is the reading guide for this file. Migrations 0001-0058 are untouched (0055 belongs to the parallel S2b slice and is not created here).
--
-- WHAT THIS ADDS (all of it partner-bound: every `_for_partner` definer begins with private.partner_authorize)
--   1. private.partner_bound_operator_at_trail(trail): policy predicate; a partner binding whose member is an operator of the trail (or admin via has_trail_scope). EXECUTE for nobody.
--   2. private.partner_trail_programme_read_for_partner / partner_facility_programme_list_for_partner: class A0, operator of the trail. Full programme columns the portal needs.
--   3. private.partner_trail_programme_upsert_for_partner / partner_facility_programme_upsert_for_partner: class A3. web_player_flow true is 22023. facility upsert refuses with status no_trail when trail_programme is missing.
--   4. private.partner_offers_list_for_partner / partner_offer_upsert_for_partner / partner_offer_approve_for_partner / partner_offer_end_for_partner: A0 list (full budget columns); A3 draft create/edit; A3 admin-only approve (draft to live); A3 end (live to ended) for operator of the trail or admin.
--   5. private.partner_sponsorships_list_for_partner / partner_sponsorship_upsert_for_partner / partner_sponsorship_approve_for_partner: A0 list; A3 draft create/edit (sponsor_org must be kind sponsor); A3 approve (draft to live) with AT(20) stock-everywhere check (status stock_short, no raise).
--   6. private.partner_operator_rollup_for_partner / partner_sponsor_rollup_for_partner: class A0 rollup reads.
--   7. BINDING-KEYED POLICIES on trail_programme, facility_programme, offer, sponsorship, operator_rollup, sponsor_rollup and special_marker_stock, each keyed on partner_binding_kind and partner_bound_operator_at_trail / partner_bound_admin, never a GUC. Existing actor-lane and review policies stay.
--
-- DELIBERATELY NOT HERE (see design 30 "Not built, honestly"): Edge handlers (programme-config, offers-admin, sponsorships-admin); settlement-export AT(17); rollups-refresh writer; offers-redeem; issuance staff gate AT(10); S7d UI.
--
-- CHECK 14: every `_for_partner` body begins with private.partner_authorize (a string-literal class), holds no dollar sign, double quote, backslash or E-string, and no EXCEPTION block; comments inside the bodies obey the same lexing (no apostrophes there). Outcomes are STATUS rows; only malformed arguments (22023) and a missing authority (42501) raise.
-- OWNERSHIP BRACKET as 0054 / 0056 / 0057 / 0058: GRANT CREATE ON SCHEMA private TO private_definer; SET ROLE private_definer; CREATE FUNCTION ...; RESET ROLE; REVOKE CREATE.

-- ============================================================================
-- 1. Binding-keyed predicate (EXECUTE for nobody: policies and sibling definers owned by private_definer evaluate it)
-- ============================================================================
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

-- true iff THIS transaction carries a partner binding whose member is an operator of p_trail_id (or an admin: has_trail_scope includes is_admin). Keyed on the binding, not a GUC.
CREATE FUNCTION private.partner_bound_operator_at_trail(p_trail_id text)
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM private.actor_binding b
    WHERE b.backend_pid = pg_catalog.pg_backend_pid()
      AND b.xact = pg_catalog.pg_current_xact_id_if_assigned()
      AND b.kind = 'partner'
      AND private.has_trail_scope(b.actor_uid, p_trail_id, ARRAY['operator']::app.partner_role[])
  );
$$;

REVOKE EXECUTE ON FUNCTION private.partner_bound_operator_at_trail(text) FROM PUBLIC;
COMMENT ON FUNCTION private.partner_bound_operator_at_trail(text) IS
  '0059. Policy predicate: a partner binding is bound in THIS transaction and its member is an operator of the trail (or an admin). Keyed on the binding, not a GUC. No role holds EXECUTE but the owner.';
RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

-- ============================================================================
-- 2. Grants and policies (private_definer). Every new policy is keyed on the binding and operator-at-trail (or admin). Existing pd_marker_scan_*, pd_partner_attest_*, pd_partner_review_*, pd_read_* stay.
-- ============================================================================
-- 2a. trail_programme: full SELECT / INSERT / UPDATE for the programme writers (0046 column-narrow SELECT stays; this widens)
GRANT SELECT, INSERT, UPDATE ON app.trail_programme TO private_definer;
CREATE POLICY pd_partner_programme_trail_select ON app.trail_programme FOR SELECT TO private_definer
  USING ((SELECT private.partner_binding_kind()) = 'partner' AND (private.partner_bound_admin() OR private.partner_bound_operator_at_trail(trail_id)));
CREATE POLICY pd_partner_programme_trail_insert ON app.trail_programme FOR INSERT TO private_definer
  WITH CHECK ((SELECT private.partner_binding_kind()) = 'partner' AND (private.partner_bound_admin() OR private.partner_bound_operator_at_trail(trail_id)));
CREATE POLICY pd_partner_programme_trail_update ON app.trail_programme FOR UPDATE TO private_definer
  USING ((SELECT private.partner_binding_kind()) = 'partner' AND (private.partner_bound_admin() OR private.partner_bound_operator_at_trail(trail_id)))
  WITH CHECK ((SELECT private.partner_binding_kind()) = 'partner' AND (private.partner_bound_admin() OR private.partner_bound_operator_at_trail(trail_id)));

-- 2b. facility_programme: INSERT and UPDATE of programme columns (NOT pin_epoch: the 0046 epoch grant and policy stay). SELECT already USING(true).
GRANT INSERT (trail_id, facility_id, participation, stocks_markers, holds_special_marker, connectivity, staff_network, wifi_note, qr_mode) ON app.facility_programme TO private_definer;
GRANT UPDATE (participation, stocks_markers, holds_special_marker, connectivity, staff_network, wifi_note, qr_mode) ON app.facility_programme TO private_definer;
CREATE POLICY pd_partner_programme_facility_insert ON app.facility_programme FOR INSERT TO private_definer
  WITH CHECK ((SELECT private.partner_binding_kind()) = 'partner' AND (private.partner_bound_admin() OR private.partner_bound_operator_at_trail(trail_id)));
CREATE POLICY pd_partner_programme_facility_update ON app.facility_programme FOR UPDATE TO private_definer
  USING ((SELECT private.partner_binding_kind()) = 'partner' AND (private.partner_bound_admin() OR private.partner_bound_operator_at_trail(trail_id)))
  WITH CHECK ((SELECT private.partner_binding_kind()) = 'partner' AND (private.partner_bound_admin() OR private.partner_bound_operator_at_trail(trail_id)));

-- 2c. offer: INSERT and broader UPDATE for programme writers; SELECT under operator-at-trail (pd_partner_review_* admin policies stay)
GRANT INSERT (id, terms_id, trail_id, facility_id, eligibility, funder, sponsorship_id, budget_cap, max_redemptions, face_value, valid_from, valid_to, status) ON app.offer TO private_definer;
GRANT UPDATE (eligibility, funder, sponsorship_id, budget_cap, max_redemptions, face_value, valid_from, valid_to, status, facility_id) ON app.offer TO private_definer;
CREATE POLICY pd_partner_programme_offer_select ON app.offer FOR SELECT TO private_definer
  USING ((SELECT private.partner_binding_kind()) = 'partner' AND (private.partner_bound_admin() OR private.partner_bound_operator_at_trail(trail_id))
         AND status IN ('draft', 'approved', 'live', 'ended'));
CREATE POLICY pd_partner_programme_offer_insert ON app.offer FOR INSERT TO private_definer
  WITH CHECK ((SELECT private.partner_binding_kind()) = 'partner' AND (private.partner_bound_admin() OR private.partner_bound_operator_at_trail(trail_id))
              AND status IN ('draft', 'approved', 'live', 'ended'));
CREATE POLICY pd_partner_programme_offer_update ON app.offer FOR UPDATE TO private_definer
  USING ((SELECT private.partner_binding_kind()) = 'partner' AND (private.partner_bound_admin() OR private.partner_bound_operator_at_trail(trail_id))
         AND status IN ('draft', 'approved', 'live', 'ended'))
  WITH CHECK ((SELECT private.partner_binding_kind()) = 'partner' AND (private.partner_bound_admin() OR private.partner_bound_operator_at_trail(trail_id))
              AND status IN ('draft', 'approved', 'live', 'ended'));

-- 2d. sponsorship: INSERT / UPDATE; SELECT already granted (pd_read_sponsorship USING(true) stays for actor helpers). Binding-keyed policies for the programme writers.
GRANT INSERT (id, sponsor_org_id, trail_id, category, scope, attribution_name, attribution_asset, placement_fee, starts_on, ends_on, operator_approved_at, status) ON app.sponsorship TO private_definer;
GRANT UPDATE (sponsor_org_id, category, scope, attribution_name, attribution_asset, placement_fee, starts_on, ends_on, operator_approved_at, status) ON app.sponsorship TO private_definer;
CREATE POLICY pd_partner_programme_sponsorship_select ON app.sponsorship FOR SELECT TO private_definer
  USING ((SELECT private.partner_binding_kind()) = 'partner' AND (private.partner_bound_admin() OR private.partner_bound_operator_at_trail(trail_id)));
CREATE POLICY pd_partner_programme_sponsorship_insert ON app.sponsorship FOR INSERT TO private_definer
  WITH CHECK ((SELECT private.partner_binding_kind()) = 'partner' AND (private.partner_bound_admin() OR private.partner_bound_operator_at_trail(trail_id)));
CREATE POLICY pd_partner_programme_sponsorship_update ON app.sponsorship FOR UPDATE TO private_definer
  USING ((SELECT private.partner_binding_kind()) = 'partner' AND (private.partner_bound_admin() OR private.partner_bound_operator_at_trail(trail_id)))
  WITH CHECK ((SELECT private.partner_binding_kind()) = 'partner' AND (private.partner_bound_admin() OR private.partner_bound_operator_at_trail(trail_id)));

-- 2e. rollups: SELECT under operator-at-trail / admin (sponsor_rollup joins via sponsorship.trail_id)
GRANT SELECT ON app.operator_rollup TO private_definer;
GRANT SELECT ON app.sponsor_rollup TO private_definer;
CREATE POLICY pd_partner_programme_operator_rollup_select ON app.operator_rollup FOR SELECT TO private_definer
  USING ((SELECT private.partner_binding_kind()) = 'partner' AND (private.partner_bound_admin() OR private.partner_bound_operator_at_trail(trail_id)));
CREATE POLICY pd_partner_programme_sponsor_rollup_select ON app.sponsor_rollup FOR SELECT TO private_definer
  USING ((SELECT private.partner_binding_kind()) = 'partner' AND (
    private.partner_bound_admin()
    OR EXISTS (
      SELECT 1 FROM app.sponsorship s
      WHERE s.id = sponsorship_id AND private.partner_bound_operator_at_trail(s.trail_id)
    )
  ));

-- 2f. special_marker_stock SELECT for the AT(20) stock-everywhere check on sponsorship approve (staff policy alone will not open rows for an operator)
CREATE POLICY pd_partner_programme_stock_select ON app.special_marker_stock FOR SELECT TO private_definer
  USING ((SELECT private.partner_binding_kind()) = 'partner' AND (private.partner_bound_admin() OR private.partner_bound_operator_at_trail(trail_id)));

-- partner_org SELECT (id, kind) already granted with pd_read_partner_org_kind USING(true); no new policy.

-- ============================================================================
-- 3. The partner definers
-- ============================================================================
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

-- 3a. GET trail programme (class A0)
CREATE FUNCTION private.partner_trail_programme_read_for_partner(p_trail_id text)
RETURNS TABLE (
  o_status text,
  o_trail_id text,
  o_programme_status text,
  o_marker_source text,
  o_marker_requires_completion boolean,
  o_special_marker_funded_by text,
  o_special_marker_low_threshold integer,
  o_web_player_flow boolean,
  o_special_marker_sku text,
  o_special_marker_sponsorship_id uuid,
  o_fee_model text,
  o_fee_amount numeric,
  o_starts_on date,
  o_ends_on date
)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
BEGIN
  v_uid := private.partner_authorize(NULL, p_trail_id, ARRAY['operator']::app.partner_role[], 'A0');
  IF p_trail_id IS NULL OR pg_catalog.btrim(p_trail_id) = '' THEN
    RAISE EXCEPTION 'partner_trail_programme_read_for_partner: a trail is required' USING ERRCODE = '22023';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM app.trail_programme t WHERE t.trail_id = p_trail_id) THEN
    RETURN QUERY SELECT 'not_found'::text, NULL::text, NULL::text, NULL::text, NULL::boolean,
                        NULL::text, NULL::integer, NULL::boolean, NULL::text, NULL::uuid,
                        NULL::text, NULL::numeric, NULL::date, NULL::date;
    RETURN;
  END IF;
  RETURN QUERY
  SELECT 'ok'::text, t.trail_id, t.status::text, t.marker_source::text, t.marker_requires_completion,
         t.special_marker_funded_by::text, t.special_marker_low_threshold, t.web_player_flow, t.special_marker_sku,
         t.special_marker_sponsorship_id, t.fee_model::text, t.fee_amount, t.starts_on, t.ends_on
  FROM app.trail_programme t
  WHERE t.trail_id = p_trail_id;
END
$$;

-- 3b. GET facility programme rows for a trail (class A0)
CREATE FUNCTION private.partner_facility_programme_list_for_partner(p_trail_id text)
RETURNS TABLE (
  o_facility_id text,
  o_participation text,
  o_stocks_markers boolean,
  o_holds_special_marker boolean,
  o_connectivity text,
  o_staff_network boolean,
  o_wifi_note text,
  o_qr_mode text,
  o_pin_epoch integer
)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
BEGIN
  v_uid := private.partner_authorize(NULL, p_trail_id, ARRAY['operator']::app.partner_role[], 'A0');
  IF p_trail_id IS NULL OR pg_catalog.btrim(p_trail_id) = '' THEN
    RAISE EXCEPTION 'partner_facility_programme_list_for_partner: a trail is required' USING ERRCODE = '22023';
  END IF;
  RETURN QUERY
  SELECT f.facility_id, f.participation::text, f.stocks_markers, f.holds_special_marker,
         f.connectivity::text, f.staff_network, f.wifi_note, f.qr_mode::text, f.pin_epoch
  FROM app.facility_programme f
  WHERE f.trail_id = p_trail_id
  ORDER BY f.facility_id;
END
$$;

-- 3c. POST trail programme upsert (class A3)
CREATE FUNCTION private.partner_trail_programme_upsert_for_partner(
  p_trail_id text,
  p_status text,
  p_marker_source text,
  p_marker_requires_completion boolean,
  p_special_marker_funded_by text,
  p_special_marker_low_threshold integer,
  p_web_player_flow boolean,
  p_special_marker_sku text,
  p_special_marker_sponsorship_id uuid,
  p_fee_model text,
  p_fee_amount numeric,
  p_starts_on date,
  p_ends_on date
)
RETURNS TABLE (o_status text)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  n integer;
BEGIN
  v_uid := private.partner_authorize(NULL, p_trail_id, ARRAY['operator']::app.partner_role[], 'A3');
  IF p_trail_id IS NULL OR pg_catalog.btrim(p_trail_id) = ''
     OR p_status IS NULL OR p_status NOT IN ('off', 'pilot', 'live')
     OR p_marker_source IS NULL OR p_marker_source NOT IN ('any_purchase', 'programme_marker')
     OR p_marker_requires_completion IS NULL
     OR (p_special_marker_funded_by IS NOT NULL AND p_special_marker_funded_by NOT IN ('trail', 'sponsor'))
     OR p_special_marker_low_threshold IS NULL OR p_special_marker_low_threshold < 0 OR p_special_marker_low_threshold > 100000
     OR (p_fee_model IS NOT NULL AND p_fee_model NOT IN ('flat', 'per_redemption', 'none'))
     OR (p_special_marker_sku IS NOT NULL AND pg_catalog.char_length(p_special_marker_sku) > 120) THEN
    RAISE EXCEPTION 'partner_trail_programme_upsert_for_partner: a trail, status, marker_source, marker_requires_completion and a non-negative low_threshold are required' USING ERRCODE = '22023';
  END IF;
  IF p_web_player_flow IS TRUE THEN
    RAISE EXCEPTION 'partner_trail_programme_upsert_for_partner: web_player_flow must stay false' USING ERRCODE = '22023';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM app.catalog_id_ledger l WHERE l.id = p_trail_id AND l.kind = 'trail') THEN
    RETURN QUERY SELECT 'not_found'::text;
    RETURN;
  END IF;
  INSERT INTO app.trail_programme (
    trail_id, status, marker_source, marker_requires_completion, special_marker_funded_by,
    special_marker_low_threshold, web_player_flow, special_marker_sku, special_marker_sponsorship_id,
    fee_model, fee_amount, starts_on, ends_on
  ) VALUES (
    p_trail_id, p_status::app.programme_status, p_marker_source::app.marker_source, p_marker_requires_completion,
    p_special_marker_funded_by::app.special_marker_funded_by, p_special_marker_low_threshold, false,
    p_special_marker_sku, p_special_marker_sponsorship_id, p_fee_model::app.fee_model, p_fee_amount, p_starts_on, p_ends_on
  )
  ON CONFLICT (trail_id) DO UPDATE SET
    status = EXCLUDED.status,
    marker_source = EXCLUDED.marker_source,
    marker_requires_completion = EXCLUDED.marker_requires_completion,
    special_marker_funded_by = EXCLUDED.special_marker_funded_by,
    special_marker_low_threshold = EXCLUDED.special_marker_low_threshold,
    web_player_flow = false,
    special_marker_sku = EXCLUDED.special_marker_sku,
    special_marker_sponsorship_id = EXCLUDED.special_marker_sponsorship_id,
    fee_model = EXCLUDED.fee_model,
    fee_amount = EXCLUDED.fee_amount,
    starts_on = EXCLUDED.starts_on,
    ends_on = EXCLUDED.ends_on;
  GET DIAGNOSTICS n = ROW_COUNT;
  IF n <> 1 THEN
    RETURN QUERY SELECT 'not_found'::text;
    RETURN;
  END IF;
  PERFORM private.partner_audit_write('partner.trail_programme_upsert', 'app.trail_programme', p_trail_id,
    pg_catalog.jsonb_build_object('status', p_status, 'marker_source', p_marker_source));
  RETURN QUERY SELECT 'ok'::text;
END
$$;

-- 3d. POST facility programme upsert (class A3)
CREATE FUNCTION private.partner_facility_programme_upsert_for_partner(
  p_trail_id text,
  p_facility_id text,
  p_participation text,
  p_stocks_markers boolean,
  p_holds_special_marker boolean,
  p_connectivity text,
  p_staff_network boolean,
  p_wifi_note text,
  p_qr_mode text
)
RETURNS TABLE (o_status text)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
BEGIN
  v_uid := private.partner_authorize(NULL, p_trail_id, ARRAY['operator']::app.partner_role[], 'A3');
  IF p_trail_id IS NULL OR pg_catalog.btrim(p_trail_id) = '' OR p_facility_id IS NULL OR pg_catalog.btrim(p_facility_id) = ''
     OR p_participation IS NULL OR p_participation NOT IN ('invited', 'accepted', 'declined', 'left')
     OR (p_connectivity IS NOT NULL AND p_connectivity NOT IN ('ok', 'weak', 'none'))
     OR p_qr_mode IS NULL OR p_qr_mode NOT IN ('rotating', 'static_pin', 'both')
     OR (p_wifi_note IS NOT NULL AND pg_catalog.char_length(p_wifi_note) > 500) THEN
    RAISE EXCEPTION 'partner_facility_programme_upsert_for_partner: a trail, a facility, participation and qr_mode are required' USING ERRCODE = '22023';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM app.trail_programme t WHERE t.trail_id = p_trail_id) THEN
    RETURN QUERY SELECT 'no_trail'::text;
    RETURN;
  END IF;
  INSERT INTO app.facility_programme (
    trail_id, facility_id, participation, stocks_markers, holds_special_marker,
    connectivity, staff_network, wifi_note, qr_mode
  ) VALUES (
    p_trail_id, p_facility_id, p_participation::app.programme_participation, p_stocks_markers, p_holds_special_marker,
    p_connectivity::app.connectivity, p_staff_network, p_wifi_note, p_qr_mode::app.qr_mode
  )
  ON CONFLICT (trail_id, facility_id) DO UPDATE SET
    participation = EXCLUDED.participation,
    stocks_markers = EXCLUDED.stocks_markers,
    holds_special_marker = EXCLUDED.holds_special_marker,
    connectivity = EXCLUDED.connectivity,
    staff_network = EXCLUDED.staff_network,
    wifi_note = EXCLUDED.wifi_note,
    qr_mode = EXCLUDED.qr_mode;
  PERFORM private.partner_audit_write('partner.facility_programme_upsert', 'app.facility_programme', p_trail_id || ':' || p_facility_id,
    pg_catalog.jsonb_build_object('facility', p_facility_id, 'participation', p_participation));
  RETURN QUERY SELECT 'ok'::text;
END
$$;

-- 3e. GET offers for a trail (class A0): full columns, every status
CREATE FUNCTION private.partner_offers_list_for_partner(p_trail_id text)
RETURNS TABLE (
  o_id uuid,
  o_terms_id text,
  o_trail_id text,
  o_facility_id text,
  o_eligibility jsonb,
  o_funder text,
  o_sponsorship_id uuid,
  o_budget_cap numeric,
  o_budget_used numeric,
  o_budget_reserved numeric,
  o_max_redemptions integer,
  o_face_value numeric,
  o_valid_from date,
  o_valid_to date,
  o_status text
)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
BEGIN
  v_uid := private.partner_authorize(NULL, p_trail_id, ARRAY['operator']::app.partner_role[], 'A0');
  IF p_trail_id IS NULL OR pg_catalog.btrim(p_trail_id) = '' THEN
    RAISE EXCEPTION 'partner_offers_list_for_partner: a trail is required' USING ERRCODE = '22023';
  END IF;
  RETURN QUERY
  SELECT o.id, o.terms_id, o.trail_id, o.facility_id, o.eligibility, o.funder::text, o.sponsorship_id,
         o.budget_cap, o.budget_used, o.budget_reserved, o.max_redemptions, o.face_value,
         o.valid_from, o.valid_to, o.status::text
  FROM app.offer o
  WHERE o.trail_id = p_trail_id
  ORDER BY o.valid_from DESC, o.id
  LIMIT 500;
END
$$;

-- 3f. POST offer upsert draft (class A3)
CREATE FUNCTION private.partner_offer_upsert_for_partner(
  p_id uuid,
  p_trail_id text,
  p_facility_id text,
  p_eligibility jsonb,
  p_funder text,
  p_sponsorship_id uuid,
  p_budget_cap numeric,
  p_max_redemptions integer,
  p_face_value numeric,
  p_valid_from date,
  p_valid_to date
)
RETURNS TABLE (o_status text, o_id uuid)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_row record;
  v_id uuid;
BEGIN
  v_uid := private.partner_authorize(NULL, p_trail_id, ARRAY['operator']::app.partner_role[], 'A3');
  IF p_trail_id IS NULL OR pg_catalog.btrim(p_trail_id) = '' OR p_facility_id IS NULL OR pg_catalog.btrim(p_facility_id) = ''
     OR p_eligibility IS NULL OR p_funder IS NULL OR p_budget_cap IS NULL OR p_budget_cap < 0
     OR p_face_value IS NULL OR p_face_value < 0 OR p_valid_from IS NULL OR p_valid_to IS NULL
     OR p_valid_to < p_valid_from
     OR (p_max_redemptions IS NOT NULL AND p_max_redemptions < 0) THEN
    RAISE EXCEPTION 'partner_offer_upsert_for_partner: a trail, facility, eligibility, funder, budget_cap, face_value and a valid date range are required' USING ERRCODE = '22023';
  END IF;
  IF p_funder NOT IN ('course', 'operator', 'sponsor') THEN
    RETURN QUERY SELECT 'bad_funder'::text, NULL::uuid;
    RETURN;
  END IF;
  IF p_funder = 'sponsor' AND p_sponsorship_id IS NULL THEN
    RETURN QUERY SELECT 'bad_funder'::text, NULL::uuid;
    RETURN;
  END IF;
  IF p_funder <> 'sponsor' AND p_sponsorship_id IS NOT NULL THEN
    RETURN QUERY SELECT 'bad_funder'::text, NULL::uuid;
    RETURN;
  END IF;
  IF p_id IS NULL THEN
    v_id := pg_catalog.gen_random_uuid();
    INSERT INTO app.offer (
      id, trail_id, facility_id, eligibility, funder, sponsorship_id, budget_cap,
      max_redemptions, face_value, valid_from, valid_to, status
    ) VALUES (
      v_id, p_trail_id, p_facility_id, p_eligibility, p_funder::app.offer_funder, p_sponsorship_id, p_budget_cap,
      p_max_redemptions, p_face_value, p_valid_from, p_valid_to, 'draft'
    );
    PERFORM private.partner_audit_write('partner.offer_upsert', 'app.offer', v_id::text,
      pg_catalog.jsonb_build_object('trail', p_trail_id, 'status', 'draft'));
    RETURN QUERY SELECT 'ok'::text, v_id;
    RETURN;
  END IF;
  SELECT o.status INTO v_row FROM app.offer o WHERE o.id = p_id AND o.trail_id = p_trail_id;
  IF NOT FOUND THEN
    RETURN QUERY SELECT 'not_found'::text, NULL::uuid;
    RETURN;
  END IF;
  IF v_row.status <> 'draft' THEN
    RETURN QUERY SELECT 'not_draft'::text, p_id;
    RETURN;
  END IF;
  UPDATE app.offer SET
    facility_id = p_facility_id,
    eligibility = p_eligibility,
    funder = p_funder::app.offer_funder,
    sponsorship_id = p_sponsorship_id,
    budget_cap = p_budget_cap,
    max_redemptions = p_max_redemptions,
    face_value = p_face_value,
    valid_from = p_valid_from,
    valid_to = p_valid_to
  WHERE id = p_id AND status = 'draft';
  PERFORM private.partner_audit_write('partner.offer_upsert', 'app.offer', p_id::text,
    pg_catalog.jsonb_build_object('trail', p_trail_id, 'status', 'draft'));
  RETURN QUERY SELECT 'ok'::text, p_id;
END
$$;

-- 3g. POST offer approve (class A3, ADMIN only): draft to live
CREATE FUNCTION private.partner_offer_approve_for_partner(p_id uuid)
RETURNS TABLE (o_status text)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_row record;
BEGIN
  v_uid := private.partner_authorize(NULL, NULL, ARRAY['operator']::app.partner_role[], 'A3');
  IF NOT private.is_admin(v_uid) THEN
    RAISE EXCEPTION 'partner_offer_approve_for_partner: only an admin may approve an offer' USING ERRCODE = '42501';
  END IF;
  IF p_id IS NULL THEN
    RAISE EXCEPTION 'partner_offer_approve_for_partner: an offer id is required' USING ERRCODE = '22023';
  END IF;
  SELECT o.status, o.trail_id INTO v_row FROM app.offer o WHERE o.id = p_id;
  IF NOT FOUND THEN
    RETURN QUERY SELECT 'not_found'::text;
    RETURN;
  END IF;
  IF v_row.status <> 'draft' THEN
    RETURN QUERY SELECT 'not_draft'::text;
    RETURN;
  END IF;
  UPDATE app.offer SET status = 'live' WHERE id = p_id AND status = 'draft';
  PERFORM private.partner_audit_write('partner.offer_approve', 'app.offer', p_id::text,
    pg_catalog.jsonb_build_object('trail', v_row.trail_id));
  RETURN QUERY SELECT 'ok'::text;
END
$$;

-- 3h. POST offer end (class A3): live to ended; operator of the trail or admin
CREATE FUNCTION private.partner_offer_end_for_partner(p_id uuid)
RETURNS TABLE (o_status text)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_row record;
BEGIN
  v_uid := private.partner_authorize(NULL, NULL, ARRAY['operator']::app.partner_role[], 'A3');
  IF p_id IS NULL THEN
    RAISE EXCEPTION 'partner_offer_end_for_partner: an offer id is required' USING ERRCODE = '22023';
  END IF;
  SELECT o.status, o.trail_id INTO v_row FROM app.offer o WHERE o.id = p_id;
  IF NOT FOUND THEN
    RETURN QUERY SELECT 'not_found'::text;
    RETURN;
  END IF;
  IF NOT private.has_trail_scope(v_uid, v_row.trail_id, ARRAY['operator']::app.partner_role[]) THEN
    RAISE EXCEPTION 'partner_authorize: no scope' USING ERRCODE = '42501';
  END IF;
  IF v_row.status <> 'live' THEN
    RETURN QUERY SELECT 'not_live'::text;
    RETURN;
  END IF;
  UPDATE app.offer SET status = 'ended' WHERE id = p_id AND status = 'live';
  PERFORM private.partner_audit_write('partner.offer_end', 'app.offer', p_id::text,
    pg_catalog.jsonb_build_object('trail', v_row.trail_id));
  RETURN QUERY SELECT 'ok'::text;
END
$$;

-- 3i. GET sponsorships for a trail (class A0)
CREATE FUNCTION private.partner_sponsorships_list_for_partner(p_trail_id text)
RETURNS TABLE (
  o_id uuid,
  o_sponsor_org_id uuid,
  o_trail_id text,
  o_category text,
  o_scope text,
  o_attribution_name text,
  o_attribution_asset text,
  o_placement_fee numeric,
  o_starts_on date,
  o_ends_on date,
  o_operator_approved_at timestamptz,
  o_status text
)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
BEGIN
  v_uid := private.partner_authorize(NULL, p_trail_id, ARRAY['operator']::app.partner_role[], 'A0');
  IF p_trail_id IS NULL OR pg_catalog.btrim(p_trail_id) = '' THEN
    RAISE EXCEPTION 'partner_sponsorships_list_for_partner: a trail is required' USING ERRCODE = '22023';
  END IF;
  RETURN QUERY
  SELECT s.id, s.sponsor_org_id, s.trail_id, s.category::text, s.scope::text, s.attribution_name, s.attribution_asset,
         s.placement_fee, s.starts_on, s.ends_on, s.operator_approved_at, s.status::text
  FROM app.sponsorship s
  WHERE s.trail_id = p_trail_id
  ORDER BY s.id
  LIMIT 500;
END
$$;

-- 3j. POST sponsorship upsert draft (class A3)
CREATE FUNCTION private.partner_sponsorship_upsert_for_partner(
  p_id uuid,
  p_sponsor_org_id uuid,
  p_trail_id text,
  p_category text,
  p_scope text,
  p_attribution_name text,
  p_attribution_asset text,
  p_placement_fee numeric,
  p_starts_on date,
  p_ends_on date
)
RETURNS TABLE (o_status text, o_id uuid)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_row record;
  v_id uuid;
  v_kind text;
BEGIN
  v_uid := private.partner_authorize(NULL, p_trail_id, ARRAY['operator']::app.partner_role[], 'A3');
  IF p_sponsor_org_id IS NULL OR p_trail_id IS NULL OR pg_catalog.btrim(p_trail_id) = ''
     OR p_category IS NULL OR p_category NOT IN ('equipment', 'apparel', 'tourism', 'other')
     OR p_scope IS NULL OR p_scope NOT IN ('special_marker', 'offers', 'both')
     OR p_attribution_name IS NULL OR pg_catalog.btrim(p_attribution_name) = ''
     OR pg_catalog.char_length(p_attribution_name) > 200
     OR (p_attribution_asset IS NOT NULL AND pg_catalog.char_length(p_attribution_asset) > 500)
     OR (p_placement_fee IS NOT NULL AND p_placement_fee < 0) THEN
    RAISE EXCEPTION 'partner_sponsorship_upsert_for_partner: a sponsor org, trail, category, scope and attribution_name are required' USING ERRCODE = '22023';
  END IF;
  SELECT o.kind::text INTO v_kind FROM app.partner_org o WHERE o.id = p_sponsor_org_id;
  IF NOT FOUND OR v_kind <> 'sponsor' THEN
    RETURN QUERY SELECT 'bad_sponsor'::text, NULL::uuid;
    RETURN;
  END IF;
  IF p_id IS NULL THEN
    v_id := pg_catalog.gen_random_uuid();
    INSERT INTO app.sponsorship (
      id, sponsor_org_id, trail_id, category, scope, attribution_name, attribution_asset,
      placement_fee, starts_on, ends_on, status
    ) VALUES (
      v_id, p_sponsor_org_id, p_trail_id, p_category::app.sponsorship_category, p_scope::app.sponsorship_scope,
      p_attribution_name, p_attribution_asset, p_placement_fee, p_starts_on, p_ends_on, 'draft'
    );
    PERFORM private.partner_audit_write('partner.sponsorship_upsert', 'app.sponsorship', v_id::text,
      pg_catalog.jsonb_build_object('trail', p_trail_id, 'status', 'draft'));
    RETURN QUERY SELECT 'ok'::text, v_id;
    RETURN;
  END IF;
  SELECT s.status INTO v_row FROM app.sponsorship s WHERE s.id = p_id AND s.trail_id = p_trail_id;
  IF NOT FOUND THEN
    RETURN QUERY SELECT 'not_found'::text, NULL::uuid;
    RETURN;
  END IF;
  IF v_row.status <> 'draft' THEN
    RETURN QUERY SELECT 'not_draft'::text, p_id;
    RETURN;
  END IF;
  UPDATE app.sponsorship SET
    sponsor_org_id = p_sponsor_org_id,
    category = p_category::app.sponsorship_category,
    scope = p_scope::app.sponsorship_scope,
    attribution_name = p_attribution_name,
    attribution_asset = p_attribution_asset,
    placement_fee = p_placement_fee,
    starts_on = p_starts_on,
    ends_on = p_ends_on
  WHERE id = p_id AND status = 'draft';
  PERFORM private.partner_audit_write('partner.sponsorship_upsert', 'app.sponsorship', p_id::text,
    pg_catalog.jsonb_build_object('trail', p_trail_id, 'status', 'draft'));
  RETURN QUERY SELECT 'ok'::text, p_id;
END
$$;

-- 3k. POST sponsorship approve (class A3): draft to live; AT(20) stock-everywhere for special_marker / both
CREATE FUNCTION private.partner_sponsorship_approve_for_partner(p_id uuid)
RETURNS TABLE (o_status text)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_row record;
  v_now timestamptz := pg_catalog.clock_timestamp();
BEGIN
  v_uid := private.partner_authorize(NULL, NULL, ARRAY['operator']::app.partner_role[], 'A3');
  IF p_id IS NULL THEN
    RAISE EXCEPTION 'partner_sponsorship_approve_for_partner: a sponsorship id is required' USING ERRCODE = '22023';
  END IF;
  SELECT s.status, s.trail_id, s.scope INTO v_row FROM app.sponsorship s WHERE s.id = p_id;
  IF NOT FOUND THEN
    RETURN QUERY SELECT 'not_found'::text;
    RETURN;
  END IF;
  IF NOT private.has_trail_scope(v_uid, v_row.trail_id, ARRAY['operator']::app.partner_role[]) THEN
    RAISE EXCEPTION 'partner_authorize: no scope' USING ERRCODE = '42501';
  END IF;
  IF v_row.status <> 'draft' THEN
    RETURN QUERY SELECT 'not_draft'::text;
    RETURN;
  END IF;
  IF v_row.scope IN ('special_marker', 'both') THEN
    IF EXISTS (
      SELECT 1
      FROM app.facility_programme fp
      WHERE fp.trail_id = v_row.trail_id
        AND fp.holds_special_marker IS TRUE
        AND NOT EXISTS (
          SELECT 1 FROM app.special_marker_stock st
          WHERE st.trail_id = fp.trail_id AND st.facility_id = fp.facility_id AND st.on_hand >= 1
        )
    ) THEN
      RETURN QUERY SELECT 'stock_short'::text;
      RETURN;
    END IF;
  END IF;
  UPDATE app.sponsorship
  SET status = 'live', operator_approved_at = v_now
  WHERE id = p_id AND status = 'draft';
  PERFORM private.partner_audit_write('partner.sponsorship_approve', 'app.sponsorship', p_id::text,
    pg_catalog.jsonb_build_object('trail', v_row.trail_id));
  RETURN QUERY SELECT 'ok'::text;
END
$$;

-- 3l. GET operator rollup (class A0)
CREATE FUNCTION private.partner_operator_rollup_for_partner(p_trail_id text)
RETURNS TABLE (o_trail_id text, o_month date, o_metric text, o_value numeric, o_cohort_n integer)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
BEGIN
  v_uid := private.partner_authorize(NULL, p_trail_id, ARRAY['operator']::app.partner_role[], 'A0');
  IF p_trail_id IS NULL OR pg_catalog.btrim(p_trail_id) = '' THEN
    RAISE EXCEPTION 'partner_operator_rollup_for_partner: a trail is required' USING ERRCODE = '22023';
  END IF;
  RETURN QUERY
  SELECT r.trail_id, r.month, r.metric, r.value, r.cohort_n
  FROM app.operator_rollup r
  WHERE r.trail_id = p_trail_id
  ORDER BY r.month DESC, r.metric
  LIMIT 500;
END
$$;

-- 3m. GET sponsor rollup (class A0): authorize via the sponsorship trail
CREATE FUNCTION private.partner_sponsor_rollup_for_partner(p_sponsorship_id uuid)
RETURNS TABLE (o_sponsorship_id uuid, o_month date, o_metric text, o_value numeric, o_cohort_n integer)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_trail text;
BEGIN
  v_uid := private.partner_authorize(NULL, NULL, ARRAY['operator']::app.partner_role[], 'A0');
  IF p_sponsorship_id IS NULL THEN
    RAISE EXCEPTION 'partner_sponsor_rollup_for_partner: a sponsorship id is required' USING ERRCODE = '22023';
  END IF;
  SELECT s.trail_id INTO v_trail FROM app.sponsorship s WHERE s.id = p_sponsorship_id;
  IF NOT FOUND THEN
    RETURN;
  END IF;
  IF NOT private.has_trail_scope(v_uid, v_trail, ARRAY['operator']::app.partner_role[]) THEN
    RAISE EXCEPTION 'partner_authorize: no scope' USING ERRCODE = '42501';
  END IF;
  RETURN QUERY
  SELECT r.sponsorship_id, r.month, r.metric, r.value, r.cohort_n
  FROM app.sponsor_rollup r
  WHERE r.sponsorship_id = p_sponsorship_id
  ORDER BY r.month DESC, r.metric
  LIMIT 500;
END
$$;

-- 3n. EXECUTE grants
REVOKE EXECUTE ON FUNCTION private.partner_trail_programme_read_for_partner(text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.partner_facility_programme_list_for_partner(text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.partner_trail_programme_upsert_for_partner(text, text, text, boolean, text, integer, boolean, text, uuid, text, numeric, date, date) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.partner_facility_programme_upsert_for_partner(text, text, text, boolean, boolean, text, boolean, text, text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.partner_offers_list_for_partner(text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.partner_offer_upsert_for_partner(uuid, text, text, jsonb, text, uuid, numeric, integer, numeric, date, date) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.partner_offer_approve_for_partner(uuid) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.partner_offer_end_for_partner(uuid) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.partner_sponsorships_list_for_partner(text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.partner_sponsorship_upsert_for_partner(uuid, uuid, text, text, text, text, text, numeric, date, date) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.partner_sponsorship_approve_for_partner(uuid) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.partner_operator_rollup_for_partner(text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.partner_sponsor_rollup_for_partner(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.partner_trail_programme_read_for_partner(text) TO edge_partner;
GRANT EXECUTE ON FUNCTION private.partner_facility_programme_list_for_partner(text) TO edge_partner;
GRANT EXECUTE ON FUNCTION private.partner_trail_programme_upsert_for_partner(text, text, text, boolean, text, integer, boolean, text, uuid, text, numeric, date, date) TO edge_partner;
GRANT EXECUTE ON FUNCTION private.partner_facility_programme_upsert_for_partner(text, text, text, boolean, boolean, text, boolean, text, text) TO edge_partner;
GRANT EXECUTE ON FUNCTION private.partner_offers_list_for_partner(text) TO edge_partner;
GRANT EXECUTE ON FUNCTION private.partner_offer_upsert_for_partner(uuid, text, text, jsonb, text, uuid, numeric, integer, numeric, date, date) TO edge_partner;
GRANT EXECUTE ON FUNCTION private.partner_offer_approve_for_partner(uuid) TO edge_partner;
GRANT EXECUTE ON FUNCTION private.partner_offer_end_for_partner(uuid) TO edge_partner;
GRANT EXECUTE ON FUNCTION private.partner_sponsorships_list_for_partner(text) TO edge_partner;
GRANT EXECUTE ON FUNCTION private.partner_sponsorship_upsert_for_partner(uuid, uuid, text, text, text, text, text, numeric, date, date) TO edge_partner;
GRANT EXECUTE ON FUNCTION private.partner_sponsorship_approve_for_partner(uuid) TO edge_partner;
GRANT EXECUTE ON FUNCTION private.partner_operator_rollup_for_partner(text) TO edge_partner;
GRANT EXECUTE ON FUNCTION private.partner_sponsor_rollup_for_partner(uuid) TO edge_partner;
COMMENT ON FUNCTION private.partner_trail_programme_read_for_partner(text) IS
  '0059 (S6). edge_partner only; class A0 (operator of the trail). The trail_programme row (full columns). Statuses: ok | not_found.';
COMMENT ON FUNCTION private.partner_facility_programme_list_for_partner(text) IS
  '0059 (S6). edge_partner only; class A0 (operator of the trail). facility_programme rows for the trail.';
COMMENT ON FUNCTION private.partner_trail_programme_upsert_for_partner(text, text, text, boolean, text, integer, boolean, text, uuid, text, numeric, date, date) IS
  '0059 (S6). edge_partner only; class A3 (operator of the trail). INSERT or UPDATE trail_programme. web_player_flow true is 22023. Statuses: ok | not_found.';
COMMENT ON FUNCTION private.partner_facility_programme_upsert_for_partner(text, text, text, boolean, boolean, text, boolean, text, text) IS
  '0059 (S6). edge_partner only; class A3 (operator of the trail). Upsert facility_programme (not pin_epoch). Statuses: ok | no_trail.';
COMMENT ON FUNCTION private.partner_offers_list_for_partner(text) IS
  '0059 (S6). edge_partner only; class A0 (operator of the trail). Full offer columns for every status on the trail.';
COMMENT ON FUNCTION private.partner_offer_upsert_for_partner(uuid, text, text, jsonb, text, uuid, numeric, integer, numeric, date, date) IS
  '0059 (S6). edge_partner only; class A3. Create or edit a draft offer. Statuses: ok | not_found | not_draft | bad_funder.';
COMMENT ON FUNCTION private.partner_offer_approve_for_partner(uuid) IS
  '0059 (S6). edge_partner only; class A3; ADMIN only. draft to live. Statuses: ok | not_found | not_draft.';
COMMENT ON FUNCTION private.partner_offer_end_for_partner(uuid) IS
  '0059 (S6). edge_partner only; class A3; operator of the trail or admin. live to ended. Statuses: ok | not_found | not_live.';
COMMENT ON FUNCTION private.partner_sponsorships_list_for_partner(text) IS
  '0059 (S6). edge_partner only; class A0 (operator of the trail). Sponsorships on the trail.';
COMMENT ON FUNCTION private.partner_sponsorship_upsert_for_partner(uuid, uuid, text, text, text, text, text, numeric, date, date) IS
  '0059 (S6). edge_partner only; class A3. Create or edit a draft sponsorship (sponsor_org kind=sponsor). Statuses: ok | not_found | not_draft | bad_sponsor.';
COMMENT ON FUNCTION private.partner_sponsorship_approve_for_partner(uuid) IS
  '0059 (S6, AT(20)). edge_partner only; class A3; operator of the sponsorship trail or admin. draft to live; stock_short when a holds_special_marker facility lacks on_hand >= 1. Statuses: ok | not_found | not_draft | stock_short.';
COMMENT ON FUNCTION private.partner_operator_rollup_for_partner(text) IS
  '0059 (S6). edge_partner only; class A0 (operator of the trail). operator_rollup rows.';
COMMENT ON FUNCTION private.partner_sponsor_rollup_for_partner(uuid) IS
  '0059 (S6). edge_partner only; class A0; scope is the sponsorship trail. sponsor_rollup rows.';
RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

-- ============================================================================
-- 4. Registries
-- ============================================================================
INSERT INTO private.function_inventory
  (schema_name, function_name, identity_args, expected_anon, expected_authenticated, expected_service_role, expected_edge_actor, expected_edge_system, expected_edge_partner, expected_edge_partner_minter, note)
VALUES
  ('private', 'partner_bound_operator_at_trail', 'p_trail_id text', false, false, false, false, false, false, false, '0059 (S6): policy predicate, a partner binding of an operator of the trail (or admin); EXECUTE for nobody but the owner'),
  ('private', 'partner_trail_programme_read_for_partner', 'p_trail_id text', false, false, false, false, false, true, false, '0059 (S6): edge_partner only; class A0; trail_programme read'),
  ('private', 'partner_facility_programme_list_for_partner', 'p_trail_id text', false, false, false, false, false, true, false, '0059 (S6): edge_partner only; class A0; facility_programme list'),
  ('private', 'partner_trail_programme_upsert_for_partner', 'p_trail_id text, p_status text, p_marker_source text, p_marker_requires_completion boolean, p_special_marker_funded_by text, p_special_marker_low_threshold integer, p_web_player_flow boolean, p_special_marker_sku text, p_special_marker_sponsorship_id uuid, p_fee_model text, p_fee_amount numeric, p_starts_on date, p_ends_on date', false, false, false, false, false, true, false, '0059 (S6): edge_partner only; class A3; trail_programme upsert'),
  ('private', 'partner_facility_programme_upsert_for_partner', 'p_trail_id text, p_facility_id text, p_participation text, p_stocks_markers boolean, p_holds_special_marker boolean, p_connectivity text, p_staff_network boolean, p_wifi_note text, p_qr_mode text', false, false, false, false, false, true, false, '0059 (S6): edge_partner only; class A3; facility_programme upsert'),
  ('private', 'partner_offers_list_for_partner', 'p_trail_id text', false, false, false, false, false, true, false, '0059 (S6): edge_partner only; class A0; full offer list for a trail'),
  ('private', 'partner_offer_upsert_for_partner', 'p_id uuid, p_trail_id text, p_facility_id text, p_eligibility jsonb, p_funder text, p_sponsorship_id uuid, p_budget_cap numeric, p_max_redemptions integer, p_face_value numeric, p_valid_from date, p_valid_to date', false, false, false, false, false, true, false, '0059 (S6): edge_partner only; class A3; draft offer upsert'),
  ('private', 'partner_offer_approve_for_partner', 'p_id uuid', false, false, false, false, false, true, false, '0059 (S6): edge_partner only; class A3; ADMIN only; draft to live'),
  ('private', 'partner_offer_end_for_partner', 'p_id uuid', false, false, false, false, false, true, false, '0059 (S6): edge_partner only; class A3; live to ended'),
  ('private', 'partner_sponsorships_list_for_partner', 'p_trail_id text', false, false, false, false, false, true, false, '0059 (S6): edge_partner only; class A0; sponsorship list'),
  ('private', 'partner_sponsorship_upsert_for_partner', 'p_id uuid, p_sponsor_org_id uuid, p_trail_id text, p_category text, p_scope text, p_attribution_name text, p_attribution_asset text, p_placement_fee numeric, p_starts_on date, p_ends_on date', false, false, false, false, false, true, false, '0059 (S6): edge_partner only; class A3; draft sponsorship upsert'),
  ('private', 'partner_sponsorship_approve_for_partner', 'p_id uuid', false, false, false, false, false, true, false, '0059 (S6, AT(20)): edge_partner only; class A3; sponsorship approve with stock check'),
  ('private', 'partner_operator_rollup_for_partner', 'p_trail_id text', false, false, false, false, false, true, false, '0059 (S6): edge_partner only; class A0; operator_rollup read'),
  ('private', 'partner_sponsor_rollup_for_partner', 'p_sponsorship_id uuid', false, false, false, false, false, true, false, '0059 (S6): edge_partner only; class A0; sponsor_rollup read');

GRANT INSERT, UPDATE ON private.definer_policy_allowlist TO CURRENT_USER;
CREATE POLICY current_user_seed_definer_policy_allowlist_0059 ON private.definer_policy_allowlist
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
INSERT INTO private.definer_policy_allowlist (schema_name, table_name, policy_name, command, scoped, note, role_name) VALUES
  ('app', 'trail_programme', 'pd_partner_programme_trail_select', 'SELECT', true, 'S6: trail_programme rows of a trail the bound partner member is operator of (or admin)', 'private_definer'),
  ('app', 'trail_programme', 'pd_partner_programme_trail_insert', 'INSERT', true, 'S6: insert trail_programme for a trail the bound member operates (or admin)', 'private_definer'),
  ('app', 'trail_programme', 'pd_partner_programme_trail_update', 'UPDATE', true, 'S6: update trail_programme for a trail the bound member operates (or admin)', 'private_definer'),
  ('app', 'facility_programme', 'pd_partner_programme_facility_insert', 'INSERT', true, 'S6: insert facility_programme for a trail the bound member operates (or admin); not pin_epoch', 'private_definer'),
  ('app', 'facility_programme', 'pd_partner_programme_facility_update', 'UPDATE', true, 'S6: update facility_programme programme columns (not pin_epoch) for a trail the bound member operates', 'private_definer'),
  ('app', 'offer', 'pd_partner_programme_offer_select', 'SELECT', true, 'S6: offers on a trail the bound member operates (full columns; draft/approved/live/ended)', 'private_definer'),
  ('app', 'offer', 'pd_partner_programme_offer_insert', 'INSERT', true, 'S6: insert an offer on a trail the bound member operates', 'private_definer'),
  ('app', 'offer', 'pd_partner_programme_offer_update', 'UPDATE', true, 'S6: update an offer on a trail the bound member operates (draft edit / approve / end)', 'private_definer'),
  ('app', 'sponsorship', 'pd_partner_programme_sponsorship_select', 'SELECT', true, 'S6: sponsorships on a trail the bound member operates (binding-keyed; pd_read_sponsorship USING(true) stays for actor helpers)', 'private_definer'),
  ('app', 'sponsorship', 'pd_partner_programme_sponsorship_insert', 'INSERT', true, 'S6: insert a sponsorship on a trail the bound member operates', 'private_definer'),
  ('app', 'sponsorship', 'pd_partner_programme_sponsorship_update', 'UPDATE', true, 'S6: update a sponsorship on a trail the bound member operates', 'private_definer'),
  ('app', 'operator_rollup', 'pd_partner_programme_operator_rollup_select', 'SELECT', true, 'S6: operator_rollup rows of a trail the bound member operates', 'private_definer'),
  ('app', 'sponsor_rollup', 'pd_partner_programme_sponsor_rollup_select', 'SELECT', true, 'S6: sponsor_rollup rows whose sponsorship is on a trail the bound member operates (or admin)', 'private_definer'),
  ('app', 'special_marker_stock', 'pd_partner_programme_stock_select', 'SELECT', true, 'S6: stock rows of a trail the bound member operates (AT(20) stock-everywhere check on sponsorship approve)', 'private_definer');
UPDATE private.definer_policy_allowlist al
SET using_expr = pg_get_expr(pol.polqual, pol.polrelid),
    with_check_expr = pg_get_expr(pol.polwithcheck, pol.polrelid)
FROM pg_policy pol
JOIN pg_class cl ON cl.oid = pol.polrelid
JOIN pg_namespace n ON n.oid = cl.relnamespace
WHERE n.nspname = al.schema_name AND cl.relname = al.table_name AND pol.polname = al.policy_name
  AND al.policy_name IN (
    'pd_partner_programme_trail_select', 'pd_partner_programme_trail_insert', 'pd_partner_programme_trail_update',
    'pd_partner_programme_facility_insert', 'pd_partner_programme_facility_update',
    'pd_partner_programme_offer_select', 'pd_partner_programme_offer_insert', 'pd_partner_programme_offer_update',
    'pd_partner_programme_sponsorship_select', 'pd_partner_programme_sponsorship_insert', 'pd_partner_programme_sponsorship_update',
    'pd_partner_programme_operator_rollup_select', 'pd_partner_programme_sponsor_rollup_select',
    'pd_partner_programme_stock_select');
DO $assert_0059_allowlist$
BEGIN
  IF (SELECT count(*) FROM private.definer_policy_allowlist WHERE policy_name IN (
    'pd_partner_programme_trail_select', 'pd_partner_programme_trail_insert', 'pd_partner_programme_trail_update',
    'pd_partner_programme_facility_insert', 'pd_partner_programme_facility_update',
    'pd_partner_programme_offer_select', 'pd_partner_programme_offer_insert', 'pd_partner_programme_offer_update',
    'pd_partner_programme_sponsorship_select', 'pd_partner_programme_sponsorship_insert', 'pd_partner_programme_sponsorship_update',
    'pd_partner_programme_operator_rollup_select', 'pd_partner_programme_sponsor_rollup_select',
    'pd_partner_programme_stock_select')
        AND (using_expr IS NOT NULL OR with_check_expr IS NOT NULL)) <> 14 THEN
    RAISE EXCEPTION '0059: an allowlist row names no live policy (its expressions were not derived)';
  END IF;
END
$assert_0059_allowlist$;
DROP POLICY current_user_seed_definer_policy_allowlist_0059 ON private.definer_policy_allowlist;
REVOKE INSERT, UPDATE ON private.definer_policy_allowlist FROM CURRENT_USER;
