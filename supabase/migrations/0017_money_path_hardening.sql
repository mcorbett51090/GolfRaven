-- 0017_money_path_hardening.sql
-- Money-path security review queue (post-S1, gate round 3 follow-up).
-- Six items, each addressed below in its own numbered section, each with
-- matching pgTAP coverage in supabase/tests/matrix/11_money_path.sql.
--
-- ⛔ ONE FLAGGED INTERPRETIVE CALL (item 3): the directive asked for a
-- `hard_signal text` column on app.play, but app.play (0003) ALREADY has
-- a `hard_signal boolean NOT NULL DEFAULT false` column — the literal
-- name collides with an existing column of a different type. Renaming or
-- retyping that existing column would be a breaking change to a column
-- every existing pgTAP fixture and RLS assumption already depends on, so
-- rather than guess which was intended, this migration ADDS a new,
-- differently-named column — `hard_signal_reason text` — that carries
-- what a `text`-typed "which hard signal fired" field would: a category
-- string (e.g. 'device_mismatch', 'geofence_fail'), independent of the
-- existing boolean flag. Flagged here and in the handback report; a
-- rename/retype is a one-line follow-up if a different design was meant.

-- ============================================================================
-- 1. play_evidence: UNIQUE(evidence_id) + play.user_id = evidence.user_id
-- ============================================================================
-- UNIQUE(evidence_id): a piece of evidence can back at most one play (the
-- PK is already (play_id, evidence_id), which only prevents the exact
-- same pair from repeating — it does NOT stop the same evidence_id being
-- attached to two DIFFERENT plays, which is the actual money-path risk
-- (one real evidence event backing two separate reward claims).
ALTER TABLE app.play_evidence ADD CONSTRAINT play_evidence_evidence_id_key UNIQUE (evidence_id);

-- Composite ownership check: play.user_id must equal evidence.user_id for
-- every (play_id, evidence_id) pair. A true composite FK would need a
-- UNIQUE(id, user_id) on both app.play and app.evidence AND
-- play_evidence to carry its own user_id column to FK against both —
-- carrying a THIRD, redundant user_id column onto play_evidence (whose
-- whole shape today is a clean two-column join table) is a bigger, more
-- invasive schema change than the directive's "or a trigger" alternative
-- calls for. A BEFORE INSERT OR UPDATE trigger enforces the same
-- invariant without reshaping the table.
CREATE OR REPLACE FUNCTION app.play_evidence_user_match() RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  v_play_user uuid;
  v_evidence_user uuid;
BEGIN
  SELECT user_id INTO v_play_user FROM app.play WHERE id = NEW.play_id;
  SELECT user_id INTO v_evidence_user FROM app.evidence WHERE id = NEW.evidence_id;
  IF v_play_user IS DISTINCT FROM v_evidence_user THEN
    RAISE EXCEPTION
      'play_evidence: play.user_id (%) does not match evidence.user_id (%) for play_id=%, evidence_id=%',
      v_play_user, v_evidence_user, NEW.play_id, NEW.evidence_id
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER play_evidence_user_match_trg
BEFORE INSERT OR UPDATE ON app.play_evidence
FOR EACH ROW EXECUTE FUNCTION app.play_evidence_user_match();

-- ============================================================================
-- 2. Attestation grade: typed column, not evidence.integrity jsonb
-- ============================================================================
-- app.attestation_grade already exists (0003:73: 'attested',
-- 'unattestable', 'failed'). evidence.integrity stays (it may still carry
-- other integrity signals the grade itself doesn't capture), but the
-- GRADE specifically now has its own typed, NOT NULL, indexed column —
-- a jsonb bucket lets an ingestion bug silently omit or mistype the grade
-- with nothing to catch it; a typed column can't.
ALTER TABLE app.evidence ADD COLUMN attestation_grade app.attestation_grade NOT NULL DEFAULT 'unattestable';
COMMENT ON COLUMN app.evidence.attestation_grade IS
  'Typed replacement for storing the attestation grade inside integrity jsonb (money-path security review). integrity jsonb may still carry other, non-grade integrity signals.';
CREATE INDEX evidence_attestation_grade_idx ON app.evidence (attestation_grade);

-- ============================================================================
-- 3. Scorer decision persisted on play; play_id/policy_version/basis on
--    offer_code and entitlement.
-- ============================================================================
-- play.hard_signal (boolean) and play.policy_version (text) already exist
-- (0003) — reused, not duplicated. New: money, held_review,
-- hard_signal_reason (see the flagged note at the top of this file),
-- input_digest (the scorer's own input-hash, for replay/audit — the same
-- "compute a ref before insert" discipline 0003's evidence.source_ref
-- comment already documents, applied to the scorer's own decision this
-- time).
ALTER TABLE app.play ADD COLUMN money boolean NOT NULL DEFAULT false;
ALTER TABLE app.play ADD COLUMN held_review boolean NOT NULL DEFAULT false;
ALTER TABLE app.play ADD COLUMN hard_signal_reason text;
ALTER TABLE app.play ADD COLUMN input_digest text;

-- offer_code: had none of the three. entitlement: already has `basis
-- jsonb` (0005) — only play_id/policy_version are new there.
--
-- ⛔ FIX (H1, post-P3a gate): the ADD COLUMN ... REFERENCES app.play (id)
-- form (no ON DELETE, not deferrable) defaults to NO ACTION,
-- non-deferrable — reproduced empirically: `private.delete_my_data`
-- deleting app.play for a user with a play_id-linked offer_code/
-- entitlement row failed at 0015:99 ("DELETE FROM app.%I WHERE %I = $1"
-- against app.play) with an FK violation, even though 0014's own
-- DEFERRABLE-INITIALLY-DEFERRED pass (§3) runs on every app-internal FK
-- that existed AT THAT TIME — these two didn't exist yet (0017 postdates
-- 0014). ON DELETE SET NULL closes the gap structurally (a deleted play
-- detaches, not blocks, the offer_code/entitlement it backed); DEFERRABLE
-- INITIALLY DEFERRED matches every other app-internal FK's contract so
-- delete_my_data's own multi-table deletes keep working in any statement
-- order, not just this one. delete_my_data also nulls both explicitly,
-- belt-and-suspenders (0015).
ALTER TABLE app.offer_code ADD COLUMN play_id uuid REFERENCES app.play (id)
  ON DELETE SET NULL DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE app.offer_code ADD COLUMN policy_version text;
ALTER TABLE app.offer_code ADD COLUMN basis jsonb NOT NULL DEFAULT '{}'::jsonb;
CREATE INDEX offer_code_play_idx ON app.offer_code (play_id);

ALTER TABLE app.entitlement ADD COLUMN play_id uuid REFERENCES app.play (id)
  ON DELETE SET NULL DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE app.entitlement ADD COLUMN policy_version text;
CREATE INDEX entitlement_play_idx ON app.entitlement (play_id);

-- ============================================================================
-- 4. Offer budgets: CHECK, max_redemptions enforcement, locked reserve fn.
-- ============================================================================
ALTER TABLE app.offer ADD CONSTRAINT offer_budget_within_cap
  CHECK (budget_used + budget_reserved <= budget_cap);

-- max_redemptions: a row-count check on offer_code, enforced at INSERT
-- time via trigger (a plain CHECK cannot reference another table's row
-- count). NULL max_redemptions means unlimited (matches the column's own
-- nullability, 0006).
CREATE OR REPLACE FUNCTION app.offer_code_enforce_max_redemptions() RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  v_max int;
  v_count int;
BEGIN
  SELECT max_redemptions INTO v_max FROM app.offer WHERE id = NEW.offer_id;
  IF v_max IS NOT NULL THEN
    SELECT count(*) INTO v_count FROM app.offer_code WHERE offer_id = NEW.offer_id;
    IF v_count >= v_max THEN
      RAISE EXCEPTION 'offer_code: offer % has reached its max_redemptions (%)', NEW.offer_id, v_max
        USING ERRCODE = '23514';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER offer_code_enforce_max_redemptions_trg
BEFORE INSERT ON app.offer_code
FOR EACH ROW EXECUTE FUNCTION app.offer_code_enforce_max_redemptions();

-- Reserve-budget function: locks the offer row (SELECT ... FOR UPDATE)
-- before reserving, so two concurrent reservations against the same
-- near-exhausted budget can't both read a stale budget_used/budget_reserved
-- and both succeed (the classic lost-update race a bare UPDATE ... WHERE
-- budget_used + budget_reserved + p_amount <= budget_cap would still be
-- exposed to under READ COMMITTED without the explicit row lock first).
-- Plain SQL/plpgsql, not SECURITY DEFINER: its caller (service_role, an
-- Edge Function) already has full DML + BYPASSRLS on app.offer, so no
-- elevation is needed the way private.* helpers need it for
-- anon/authenticated callers.
CREATE OR REPLACE FUNCTION app.reserve_offer_budget(p_offer_id uuid, p_amount numeric)
RETURNS boolean
LANGUAGE plpgsql
AS $$
DECLARE
  v_cap numeric;
  v_used numeric;
  v_reserved numeric;
BEGIN
  IF p_amount < 0 THEN
    RAISE EXCEPTION 'reserve_offer_budget: p_amount must be >= 0 (got %)', p_amount;
  END IF;
  SELECT budget_cap, budget_used, budget_reserved
    INTO v_cap, v_used, v_reserved
    FROM app.offer
    WHERE id = p_offer_id
    FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'reserve_offer_budget: no such offer %', p_offer_id;
  END IF;
  IF v_used + v_reserved + p_amount > v_cap THEN
    RETURN false;
  END IF;
  UPDATE app.offer SET budget_reserved = budget_reserved + p_amount WHERE id = p_offer_id;
  RETURN true;
END;
$$;

REVOKE EXECUTE ON FUNCTION app.reserve_offer_budget(uuid, numeric) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.reserve_offer_budget(uuid, numeric) TO service_role;

-- ============================================================================
-- 5. Receipt dedupe: partial unique index + serialized dedupe function.
-- ============================================================================
-- Partial unique index: two DIFFERENT receipts legitimately share a NULL
-- OCR number (OCR failed/not run), so the index only applies where the
-- OCR number is actually present.
CREATE UNIQUE INDEX receipt_fingerprint_ocr_facility_uniq
  ON app.receipt_fingerprint (receipt_number_ocr, facility_id)
  WHERE receipt_number_ocr IS NOT NULL;

-- phash is deliberately NOT made a bare UNIQUE constraint (a perceptual
-- hash is approximate by design — two independently legitimate receipts
-- CAN collide on phash without being the same receipt, so a hard UNIQUE
-- would produce false-positive rejections of honest submissions). Instead:
-- a serialized dedupe function, the directive's second option. It voids
-- the NEW purchase and writes a fraud_signal when an EXACT phash match
-- already exists for a DIFFERENT purchase; otherwise it records the new
-- fingerprint. pg_advisory_xact_lock serializes concurrent callers on the
-- SAME phash (released automatically at transaction end) so two
-- simultaneous submissions of the same receipt image can't both read "no
-- existing match" and both succeed.
CREATE OR REPLACE FUNCTION app.dedupe_receipt_fingerprint(
  p_purchase_evidence_id uuid,
  p_user_id uuid,
  p_phash text,
  p_facility_id text,
  p_local_date date,
  p_receipt_number_ocr text DEFAULT NULL
) RETURNS boolean
LANGUAGE plpgsql
AS $$
DECLARE
  v_dupe_id uuid;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtext(p_phash));

  SELECT id INTO v_dupe_id
  FROM app.receipt_fingerprint
  WHERE phash = p_phash
    AND (purchase_evidence_id IS DISTINCT FROM p_purchase_evidence_id)
  LIMIT 1;

  IF v_dupe_id IS NOT NULL THEN
    UPDATE app.purchase_evidence SET status = 'void' WHERE id = p_purchase_evidence_id;
    INSERT INTO app.fraud_signal (user_id, kind, detail)
    VALUES (
      p_user_id,
      'receipt_phash_duplicate',
      jsonb_build_object(
        'purchase_evidence_id', p_purchase_evidence_id,
        'duplicate_of_receipt_fingerprint_id', v_dupe_id,
        'phash', p_phash,
        'facility_id', p_facility_id,
        'local_date', p_local_date
      )
    );
    RETURN false;
  END IF;

  INSERT INTO app.receipt_fingerprint
    (purchase_evidence_id, user_id, phash, receipt_number_ocr, facility_id, local_date)
  VALUES
    (p_purchase_evidence_id, p_user_id, p_phash, p_receipt_number_ocr, p_facility_id, p_local_date);
  RETURN true;
END;
$$;

REVOKE EXECUTE ON FUNCTION app.dedupe_receipt_fingerprint(uuid, uuid, text, text, date, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.dedupe_receipt_fingerprint(uuid, uuid, text, text, date, text) TO service_role;

-- ============================================================================
-- 6. Nonce uniqueness: attestation.token_jti (already unique, 0004) —
--    checkin_challenge's nonce and used_at hardened here.
-- ============================================================================
-- checkin_challenge.nonce_hash is ALREADY a table-wide UNIQUE constraint
-- (0005) — plain UNIQUE, not UNIQUE(user_id, nonce_hash), so it was
-- already globally unique across users, not merely per-user; likewise
-- course_qr_token.nonce_hash is already its PRIMARY KEY (globally
-- unique). Both get pgTAP coverage proving this below (11_money_path.sql)
-- rather than a schema change, since nothing here needs one.
--
-- The real gap: nothing stopped `used_at` being set, then RESET or
-- overwritten — a challenge "unconsumed" and replayed, or consumed twice
-- with a different used_at. A BEFORE UPDATE trigger makes that transition
-- one-way: once used_at is non-NULL, it can never change again.
CREATE OR REPLACE FUNCTION app.checkin_challenge_used_at_once() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  -- Reject ANY further UPDATE once used_at is set, even one that would
  -- (re-)write the identical value: `now()` is stable for the whole
  -- transaction in Postgres, not per-statement, so "set it to now() a
  -- second time" can otherwise look like a no-op change and slip past an
  -- `IS DISTINCT FROM` check entirely (confirmed empirically this
  -- session). A consumed challenge must never be touched again, full
  -- stop -- that is the actual replay-protection contract, not merely
  -- "can't change to a different value".
  IF OLD.used_at IS NOT NULL THEN
    RAISE EXCEPTION 'checkin_challenge: used_at is already set (%) and cannot be changed (id=%)', OLD.used_at, OLD.id
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER checkin_challenge_used_at_once_trg
BEFORE UPDATE ON app.checkin_challenge
FOR EACH ROW EXECUTE FUNCTION app.checkin_challenge_used_at_once();

-- ============================================================================
-- S1 close-out follow-through: register the two new triggers' owning
-- functions + app.reserve_offer_budget/app.dedupe_receipt_fingerprint in
-- private.function_inventory (10_function_inventory.sql's own inventory
-- check derives from it and fails on anything missing) — none of these
-- are SECURITY DEFINER, so private_definer/0016's own inventory (owned-by
-- + allow-list checks) does not apply to them.
-- ============================================================================
-- private.function_inventory already has ENABLE+FORCE ROW LEVEL SECURITY
-- (0014) and only a SELECT grant (to service_role) -- no INSERT policy
-- for anyone, including its own owner. Under HARNESS_MODE=superuser this
-- migration runs as postgres (bypasses RLS regardless); under
-- HARNESS_MODE=restricted it runs as migration_owner, which OWNS this
-- table (it created it, via 0014, also as migration_owner) but is
-- NOBYPASSRLS -- owner + FORCE + NOBYPASSRLS means RLS genuinely applies
-- to it too (confirmed empirically this session: the INSERT below failed
-- with "new row violates row-level security policy" without this). As
-- the table's OWNER, migration_owner can grant/police itself directly
-- here, no bootstrap-as-superuser step needed (unlike storage.buckets in
-- supabase/tests/shim.sql, which is bootstrap-owned). Governance/manifest
-- data, not user data -- the same reasoning as storage.buckets' own
-- WITH CHECK (true).
GRANT INSERT ON private.function_inventory TO migration_owner;
CREATE POLICY migration_owner_seed_function_inventory ON private.function_inventory
  FOR INSERT TO migration_owner WITH CHECK (true);

INSERT INTO private.function_inventory
  (schema_name, function_name, identity_args, expected_anon, expected_authenticated, expected_service_role, note)
VALUES
  ('app', 'play_evidence_user_match', '', false, false, false, 'trigger function (app.play_evidence_user_match_trg) -- never EXECUTEd directly by any role'),
  ('app', 'offer_code_enforce_max_redemptions', '', false, false, false, 'trigger function (app.offer_code_enforce_max_redemptions_trg) -- never EXECUTEd directly by any role'),
  ('app', 'checkin_challenge_used_at_once', '', false, false, false, 'trigger function (app.checkin_challenge_used_at_once_trg) -- never EXECUTEd directly by any role'),
  ('app', 'reserve_offer_budget', 'p_offer_id uuid, p_amount numeric', false, false, true, 'locks + reserves offer budget; called by the (out-of-scope-this-stage) scorer/redemption Edge Function as service_role'),
  ('app', 'dedupe_receipt_fingerprint', 'p_purchase_evidence_id uuid, p_user_id uuid, p_phash text, p_facility_id text, p_local_date date, p_receipt_number_ocr text', false, false, true, 'serialized receipt-phash dedupe; called by the (out-of-scope-this-stage) receipt-ingestion Edge Function as service_role');
