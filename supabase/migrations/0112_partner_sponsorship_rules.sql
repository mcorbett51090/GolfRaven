-- 0112_partner_sponsorship_rules.sql
--
-- P5 section 143: what a sponsorship has to BE, not only whose it is, before it funds an offer or a trail's special marker (the product calls left open in design section 137.3,
-- decided by the owner on 2026-10-13: "recommend and go with the recommendation").
--
-- WHAT WAS WRONG (observed on the real database in section 137.1, left unchanged by 0109 on purpose). Once a sponsorship was of the right trail, anything else about it was ignored:
--   - an offer could be funded by a sponsorship that was still a draft, or ended, or whose scope is the special marker only (partner_offer_upsert_for_partner and
--     partner_offer_approve_for_partner read nothing about it); the admin's approve, the human gate, looked at the offer alone;
--   - a trail's special marker could name a sponsorship whose scope is offers only;
--   - a programme could say special_marker_funded_by = trail and still carry a sponsorship id (the two fields were not tied together).
--
-- WHAT THIS CHANGES (three functions, CREATE OR REPLACE; owner, ACL, search_path, volatility, signatures untouched; the 0059/0109 bodies verbatim plus the checks below)
--   1. partner_offer_upsert_for_partner: the sponsorship named by an offer must also have a scope of offers or both. Same refusal as every other funder mismatch (bad_funder, 422 on the
--      Edge, already mapped), so a foreign id, an unknown id and a sponsorship of the wrong scope are ONE answer.
--   2. partner_offer_approve_for_partner (the admin's approve): an offer whose funder is sponsor is approved only while its sponsorship is live, of the offer's trail and of scope offers or
--      both; otherwise 22023 (the Edge maps it to 422 invalid_request; the statuses of the function are unchanged, so the Edge needs no change). This is the check that matters most: a
--      sponsorship is edited while it is a draft, so a draft offer written against a good sponsorship can be left pointing at one that has since changed; the live status is final.
--   3. partner_trail_programme_upsert_for_partner: a special_marker_funded_by of trail with a sponsorship id is 22023; a sponsorship id must name a sponsorship whose scope is special_marker or
--      both (22023, after the 0109 check that it is one of this trail, so the scope answer is only ever given about the operator's own sponsorships). A programme that says sponsor
--      with NO id is still accepted (it may say so before the sponsorship exists).
--
-- DELIBERATELY NOT HERE: the sponsorship dates (starts_on / ends_on) are not compared with the offer's; a draft sponsorship is still a valid funder for a DRAFT offer; a programme whose funder is
-- NULL may still carry an id; the programme write has no later gate, so it is checked against the sponsorship as it is at the time of the write; existing rows are not repaired.
-- Nothing from 0001-0111 is edited.

-- ============================================================================
-- 1. Before any change: the three live functions are the 0059/0109 functions (drift aborts here, with nothing changed)
-- ============================================================================
DO $pre_0112$
DECLARE
  v_p pg_proc%ROWTYPE;
  v_sig text;
  v_hash text;
BEGIN
  FOR v_sig, v_hash IN
    VALUES
      ('private.partner_offer_approve_for_partner(uuid)', 'ecfd014b59378f2ec1e04b16bb318146'),
      ('private.partner_offer_upsert_for_partner(uuid, text, text, jsonb, text, uuid, numeric, integer, numeric, date, date)', '702be1ae01c8612a8658729a64cc6f01'),
      ('private.partner_trail_programme_upsert_for_partner(text, text, text, boolean, text, integer, boolean, text, uuid, text, numeric, date, date)', '6a1f069ee56a8d54c9891b30878ee973')
  LOOP
    SELECT * INTO v_p FROM pg_proc WHERE oid = v_sig::regprocedure;
    IF pg_catalog.md5(v_p.prosrc) <> v_hash THEN
      RAISE EXCEPTION '0112: % is not the expected definition (its source hashes to %)', v_sig, pg_catalog.md5(v_p.prosrc);
    END IF;
    IF pg_get_userbyid(v_p.proowner) <> 'private_definer' OR NOT v_p.prosecdef OR v_p.provolatile <> 'v' OR v_p.proconfig IS DISTINCT FROM ARRAY['search_path=""'] THEN
      RAISE EXCEPTION '0112: % owner / security / volatility / search_path drifted', v_sig;
    END IF;
    IF NOT has_function_privilege('edge_partner', v_p.oid, 'EXECUTE')
       OR has_function_privilege('authenticated', v_p.oid, 'EXECUTE')
       OR has_function_privilege('anon', v_p.oid, 'EXECUTE') THEN
      RAISE EXCEPTION '0112: % EXECUTE set drifted', v_sig;
    END IF;
  END LOOP;
END
$pre_0112$;
CREATE TEMP TABLE m0112_before AS
  SELECT oid::regprocedure::text AS sig, proacl::text AS acl, pg_get_function_arguments(oid) AS args, pg_get_userbyid(proowner) AS owner
  FROM pg_proc
  WHERE oid IN (
    'private.partner_offer_approve_for_partner(uuid)'::regprocedure,
    'private.partner_offer_upsert_for_partner(uuid, text, text, jsonb, text, uuid, numeric, integer, numeric, date, date)'::regprocedure,
    'private.partner_trail_programme_upsert_for_partner(text, text, text, boolean, text, integer, boolean, text, uuid, text, numeric, date, date)'::regprocedure
  );

-- ============================================================================
-- 2. The functions
-- ============================================================================
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

CREATE OR REPLACE FUNCTION private.partner_trail_programme_upsert_for_partner(
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
  -- 0112: a special marker the trail pays for names no sponsorship (sponsor with no id stays allowed: it may say so before the sponsorship exists).
  IF p_special_marker_funded_by = 'trail' AND p_special_marker_sponsorship_id IS NOT NULL THEN
    RAISE EXCEPTION 'partner_trail_programme_upsert_for_partner: a trail-funded special marker names no sponsorship' USING ERRCODE = '22023';
  END IF;
  -- 0109: the sponsorship named for the special marker is one of THIS trail (a foreign trail's sponsorship, or an id that names none, is 22023 like the other bad arguments;
  -- before 0109 the first was accepted and the second was a raw foreign-key error).
  IF p_special_marker_sponsorship_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM app.sponsorship s WHERE s.id = p_special_marker_sponsorship_id AND s.trail_id = p_trail_id
  ) THEN
    RAISE EXCEPTION 'partner_trail_programme_upsert_for_partner: the sponsorship must be one of this trail' USING ERRCODE = '22023';
  END IF;
  -- 0112: and it covers the special marker. Reached only for a sponsorship of this trail, so the answer says nothing about anyone else's ids.
  IF p_special_marker_sponsorship_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM app.sponsorship s WHERE s.id = p_special_marker_sponsorship_id AND s.scope IN ('special_marker', 'both')
  ) THEN
    RAISE EXCEPTION 'partner_trail_programme_upsert_for_partner: the sponsorship must cover the special marker' USING ERRCODE = '22023';
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

CREATE OR REPLACE FUNCTION private.partner_offer_upsert_for_partner(
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
  -- 0109: the sponsorship that funds an offer is one of THIS trail. Another trail's sponsorship, and an id that names no sponsorship at all, are the same refusal
  -- (so the answer is not a way to ask whether an id belongs to somebody else); before 0109 the first was accepted and the second was a raw foreign-key error.
  -- 0112: and its scope is offers or both (a sponsorship of the special marker alone does not fund an offer); the same refusal again.
  IF p_sponsorship_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM app.sponsorship s WHERE s.id = p_sponsorship_id AND s.trail_id = p_trail_id AND s.scope IN ('offers', 'both')
  ) THEN
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

CREATE OR REPLACE FUNCTION private.partner_offer_approve_for_partner(p_id uuid)
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
  SELECT o.status, o.trail_id, o.funder, o.sponsorship_id INTO v_row FROM app.offer o WHERE o.id = p_id;
  IF NOT FOUND THEN
    RETURN QUERY SELECT 'not_found'::text;
    RETURN;
  END IF;
  IF v_row.status <> 'draft' THEN
    RETURN QUERY SELECT 'not_draft'::text;
    RETURN;
  END IF;
  -- 0112: an offer funded by a sponsor goes live only while that sponsorship is live, is of the offer's trail and covers offers. A draft offer can be written against a sponsorship that is
  -- still a draft, and a draft sponsorship can be edited after that, so this is checked here, at the human gate, where the sponsorship's state is final.
  IF v_row.funder = 'sponsor' AND NOT EXISTS (
    SELECT 1 FROM app.sponsorship s
    WHERE s.id = v_row.sponsorship_id AND s.trail_id = v_row.trail_id AND s.status = 'live' AND s.scope IN ('offers', 'both')
  ) THEN
    RAISE EXCEPTION 'partner_offer_approve_for_partner: the sponsorship that funds an offer must be live and cover offers' USING ERRCODE = '22023';
  END IF;
  UPDATE app.offer SET status = 'live' WHERE id = p_id AND status = 'draft';
  PERFORM private.partner_audit_write('partner.offer_approve', 'app.offer', p_id::text,
    pg_catalog.jsonb_build_object('trail', v_row.trail_id));
  RETURN QUERY SELECT 'ok'::text;
END
$$;

COMMENT ON FUNCTION private.partner_trail_programme_upsert_for_partner(text, text, text, boolean, text, integer, boolean, text, uuid, text, numeric, date, date) IS
  '0059/0109/0112 (S6, sections 137, 143). edge_partner only; class A3 (operator of the trail). INSERT or UPDATE trail_programme. web_player_flow true is 22023; a special_marker_sponsorship_id that is not a sponsorship of this trail, or whose scope is not special_marker or both, is 22023; a trail-funded special marker with a sponsorship id is 22023. Statuses: ok | not_found.';
COMMENT ON FUNCTION private.partner_offer_upsert_for_partner(uuid, text, text, jsonb, text, uuid, numeric, integer, numeric, date, date) IS
  '0059/0109/0112 (S6, sections 137, 143). edge_partner only; class A3. Create or edit a draft offer; a sponsorship that is not one of this trail, or whose scope is not offers or both, is bad_funder. Statuses: ok | not_found | not_draft | bad_funder.';
COMMENT ON FUNCTION private.partner_offer_approve_for_partner(uuid) IS
  '0059/0112 (S6, section 143). edge_partner only; class A3; ADMIN only. Draft to live; a sponsor-funded offer needs a live sponsorship of its trail that covers offers (else 22023). Statuses: ok | not_found | not_draft.';

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

-- ============================================================================
-- 3. Inventory
-- ============================================================================
GRANT INSERT, UPDATE ON private.function_inventory TO CURRENT_USER;
CREATE POLICY current_user_edit_function_inventory_0112 ON private.function_inventory
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

UPDATE private.function_inventory
SET note = '0059/0109/0112 (S6, sections 137, 143): edge_partner only; class A3; trail_programme upsert; the special-marker sponsorship must be of this trail and cover the special marker, and a trail-funded marker names none (22023)'
WHERE schema_name = 'private'
  AND function_name = 'partner_trail_programme_upsert_for_partner';

UPDATE private.function_inventory
SET note = '0059/0109/0112 (S6, sections 137, 143): edge_partner only; class A3; draft offer upsert; the sponsorship must be of this trail and cover offers (bad_funder)'
WHERE schema_name = 'private'
  AND function_name = 'partner_offer_upsert_for_partner';

UPDATE private.function_inventory
SET note = '0059/0112 (S6, section 143): edge_partner only; class A3; ADMIN only; draft to live; a sponsor-funded offer needs a live sponsorship of its trail that covers offers (22023)'
WHERE schema_name = 'private'
  AND function_name = 'partner_offer_approve_for_partner';

DROP POLICY current_user_edit_function_inventory_0112 ON private.function_inventory;
REVOKE INSERT, UPDATE ON private.function_inventory FROM CURRENT_USER;

-- ============================================================================
-- 4. After: the new checks are there, and nothing else about the three functions moved
-- ============================================================================
DO $assert_0112$
DECLARE
  v_b m0112_before%ROWTYPE;
  v_p pg_proc%ROWTYPE;
  v_n integer := 0;
BEGIN
  FOR v_b IN SELECT * FROM m0112_before LOOP
    v_n := v_n + 1;
    SELECT * INTO v_p FROM pg_proc WHERE oid = v_b.sig::regprocedure;
    IF v_p.proacl::text IS DISTINCT FROM v_b.acl OR pg_get_function_arguments(v_p.oid) IS DISTINCT FROM v_b.args OR pg_get_userbyid(v_p.proowner) IS DISTINCT FROM v_b.owner
       OR NOT v_p.prosecdef OR v_p.provolatile <> 'v' OR v_p.proconfig IS DISTINCT FROM ARRAY['search_path=""'] THEN
      RAISE EXCEPTION '0112: the ACL, signature, owner, security, volatility or search_path of % changed', v_b.sig;
    END IF;
  END LOOP;
  IF v_n <> 3 THEN
    RAISE EXCEPTION '0112: expected three functions, found %', v_n;
  END IF;
  SELECT * INTO v_p FROM pg_proc WHERE oid = 'private.partner_offer_upsert_for_partner(uuid, text, text, jsonb, text, uuid, numeric, integer, numeric, date, date)'::regprocedure;
  IF v_p.prosrc NOT LIKE '%s.trail_id = p_trail_id AND s.scope IN (''offers'', ''both'')%' THEN
    RAISE EXCEPTION '0112: partner_offer_upsert_for_partner must check the sponsorship scope';
  END IF;
  SELECT * INTO v_p FROM pg_proc WHERE oid = 'private.partner_offer_approve_for_partner(uuid)'::regprocedure;
  IF v_p.prosrc NOT LIKE '%s.status = ''live'' AND s.scope IN (''offers'', ''both'')%' THEN
    RAISE EXCEPTION '0112: partner_offer_approve_for_partner must check the sponsorship is live and covers offers';
  END IF;
  SELECT * INTO v_p FROM pg_proc WHERE oid = 'private.partner_trail_programme_upsert_for_partner(text, text, text, boolean, text, integer, boolean, text, uuid, text, numeric, date, date)'::regprocedure;
  IF v_p.prosrc NOT LIKE '%s.scope IN (''special_marker'', ''both'')%' OR v_p.prosrc NOT LIKE '%p_special_marker_funded_by = ''trail'' AND p_special_marker_sponsorship_id IS NOT NULL%' THEN
    RAISE EXCEPTION '0112: partner_trail_programme_upsert_for_partner must check the sponsorship scope and the trail-funded marker';
  END IF;
END
$assert_0112$;
DROP TABLE m0112_before;
