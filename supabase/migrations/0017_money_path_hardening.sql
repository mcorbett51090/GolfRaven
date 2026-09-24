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

-- ⛔ FIX (M1, post-P3a gate): the original version used a BEFORE
-- INSERT/UPDATE plpgsql trigger doing two independent SELECTs, which was
-- bypassable two ways, both reproduced empirically: (1) deferred-FK
-- ordering — if play_id/evidence_id pointed at NOT-YET-COMMITTED or
-- deleted rows within the same deferred-FK transaction, the SELECT ...
-- INTO found nothing, v_play_user/v_evidence_user were both NULL, and
-- `NULL IS DISTINCT FROM NULL` is FALSE — the mismatch check silently
-- passed; (2) re-owning — the trigger only checked ownership AT LINK
-- TIME; nothing stopped play.user_id or evidence.user_id being changed
-- to a DIFFERENT user AFTERWARD, silently detaching the pair without
-- ever re-checking.
--
-- Replaced with the composite-FK design: app.play and app.evidence each
-- get `UNIQUE (id, user_id)` (a trivial derivation of their existing PK
-- plus one column), play_evidence gains its own `user_id` column, and
-- TWO composite foreign keys pin it to BOTH parents' (id, user_id) pairs
-- at once. This closes both bypasses structurally, not by a trigger that
-- can be out-raced or skipped: (1) a composite FK's NULL semantics only
-- exempt a referencING row with a NULL in one of ITS OWN key columns
-- (MATCH SIMPLE) — play_evidence.play_id/evidence_id/user_id are all NOT
-- NULL, so there is no NULL-lookup escape hatch at all, deferred or not;
-- (2) re-owning is blocked at the SOURCE: changing app.play.user_id or
-- app.evidence.user_id while a play_evidence row still references that
-- (id, user_id) pair is itself an FK violation (default ON UPDATE NO
-- ACTION) — Postgres refuses the re-own, it does not silently let the
-- child go stale.
ALTER TABLE app.play ADD CONSTRAINT play_id_user_id_key UNIQUE (id, user_id);
ALTER TABLE app.evidence ADD CONSTRAINT evidence_id_user_id_key UNIQUE (id, user_id);

ALTER TABLE app.play_evidence ADD COLUMN user_id uuid;
-- Backfill from app.play (an existing play_evidence row's play_id always
-- resolves to a real play; the play's own user_id is definitionally the
-- correct value here, since play_evidence's original intent — and the
-- FK we're about to add — is exactly "this evidence backs THIS user's
-- play").
UPDATE app.play_evidence pe SET user_id = p.user_id FROM app.play p WHERE p.id = pe.play_id;
ALTER TABLE app.play_evidence ALTER COLUMN user_id SET NOT NULL;

ALTER TABLE app.play_evidence
  ADD CONSTRAINT play_evidence_play_user_fk FOREIGN KEY (play_id, user_id)
    REFERENCES app.play (id, user_id) DEFERRABLE INITIALLY DEFERRED,
  ADD CONSTRAINT play_evidence_evidence_user_fk FOREIGN KEY (evidence_id, user_id)
    REFERENCES app.evidence (id, user_id) DEFERRABLE INITIALLY DEFERRED;
-- DEFERRABLE INITIALLY DEFERRED matches every other app-internal FK's
-- contract (0014 §3) so delete_my_data's multi-table deletes keep
-- working in any statement order — play_evidence rows are deleted
-- transitively (ON DELETE CASCADE from both play_id and evidence_id,
-- 0003), so by the time either FK is actually checked at commit the
-- referencing play_evidence row is already gone in the normal
-- delete_my_data path; deferring just removes any dependency on which
-- of play/evidence/play_evidence the generic loop happens to delete
-- first.

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
  'Typed replacement for storing the attestation grade inside integrity jsonb (money-path security review). integrity jsonb may still carry other, non-grade integrity signals. MUST be written from server-side verification only, never client-supplied. The enum has no explicit "pending/never graded" state distinct from unattestable -- see docs/security/p3-money-path-requirements.md addendum for why, and what to do when the P3 scoring Edge Function is built.';
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
-- ⛔ FIX (M2, post-P3a re-gate): the single-column `play_id REFERENCES
-- app.play (id)` form let three of the four confirmed bypasses through:
-- (c) UPDATE offer_code.user_id and (d) UPDATE play.user_id both left
-- play_id untouched, so neither ever re-checked ownership; the FK itself
-- says nothing about WHOSE row play_id points at, only that it exists.
-- A composite FK against app.play's `(id, user_id)` unique pair (0017
-- §1, `play_id_user_id_key`) closes both structurally, the same
-- mechanism M1 already uses for app.play_evidence: (c) is blocked
-- because changing JUST user_id would point this row at an (id,user_id)
-- pair that doesn't exist in app.play; (d) is blocked because changing
-- play.user_id while a composite FK still references its OLD (id,
-- user_id) pair is itself a violation (default ON UPDATE NO ACTION).
ALTER TABLE app.offer_code ADD COLUMN play_id uuid;
ALTER TABLE app.offer_code ADD COLUMN policy_version text;
ALTER TABLE app.offer_code ADD COLUMN basis jsonb NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE app.offer_code
  ADD CONSTRAINT offer_code_play_user_fk FOREIGN KEY (play_id, user_id)
    REFERENCES app.play (id, user_id) DEFERRABLE INITIALLY DEFERRED;
CREATE INDEX offer_code_play_idx ON app.offer_code (play_id);

ALTER TABLE app.entitlement ADD COLUMN play_id uuid;
ALTER TABLE app.entitlement ADD COLUMN policy_version text;
ALTER TABLE app.entitlement
  ADD CONSTRAINT entitlement_play_user_fk FOREIGN KEY (play_id, user_id)
    REFERENCES app.play (id, user_id) DEFERRABLE INITIALLY DEFERRED;
CREATE INDEX entitlement_play_idx ON app.entitlement (play_id);

-- H1's ON DELETE SET NULL is EXPRESSED HERE, not on the FK itself
-- (composite FKs support ON DELETE SET NULL fine, but a bare SET NULL on
-- a two-column FK nulls BOTH columns together, including user_id — never
-- what we want here; only play_id should null out when the play is
-- deleted). A trigger on app.play does the equivalent, narrowly: null
-- play_id only. delete_my_data's own explicit `UPDATE ... SET play_id =
-- NULL` (0015) stays as belt-and-suspenders, unchanged.
--
-- ⛔ FIX (post-P3a re-gate, found while regression-testing M2): this MUST
-- be a plain BEFORE DELETE trigger, not an AFTER ... DEFERRABLE
-- CONSTRAINT TRIGGER as first written. Reasoning, confirmed empirically
-- this session: Postgres fires same-timing AFTER ROW triggers on one
-- event in ALPHABETICAL trigger-name order, and queues deferred events in
-- that same order for whenever they're later checked (COMMIT or SET
-- CONSTRAINTS IMMEDIATE) — the composite FK's own auto-generated
-- delete-side enforcement trigger is named `RI_ConstraintTrigger_a_...`,
-- which sorts BEFORE any lowercase name (byte/ASCII comparison: 'R' <
-- 'p'). So an AFTER DEFERRABLE version of this trigger would always fire
-- AFTER the FK's own "is it still referenced" check — which finds it
-- STILL referenced (this trigger hasn't nulled anything out yet) and
-- raises, even though this trigger's own job is to make that check
-- unnecessary. This isn't a test-only ordering quirk: it would raise at
-- real COMMIT time too, for every real delete_my_data(user) call whose
-- user has a play with a live offer_code/entitlement still attached.
-- A plain BEFORE DELETE trigger sidesteps trigger-firing-order entirely:
-- it nulls play_id out of every referencing row BEFORE the DELETE of
-- app.play itself proceeds, so by the time the FK's own delete-side check
-- runs (immediately or deferred, doesn't matter), nothing references the
-- row being deleted any more. Non-deferrable and always-immediate is
-- correct here — this trigger enforces no external contract a caller
-- might need to defer past; it is pure bookkeeping tied to the DELETE
-- statement itself.
CREATE OR REPLACE FUNCTION app.play_deleted_detach_play_id() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  UPDATE app.offer_code SET play_id = NULL WHERE play_id = OLD.id;
  UPDATE app.entitlement SET play_id = NULL WHERE play_id = OLD.id;
  RETURN OLD;
END;
$$;

CREATE TRIGGER play_deleted_detach_play_id_trg
BEFORE DELETE ON app.play
FOR EACH ROW EXECUTE FUNCTION app.play_deleted_detach_play_id();

-- should-fix (post-P3a gate): "offer_code.play_id and entitlement.play_id
-- need an owner-match check. Add a DB guard so a play with
-- held_review=true cannot back a non-held code or entitlement." Both
-- state enums (app.offer_code_state / app.entitlement_state) already
-- have a `held_review` value (0005/0006) — the guard is that a
-- held_review PLAY can only be backing an offer_code/entitlement that is
-- ITSELF held_review, not something freely redeemable while the play
-- that justified it is still under fraud review.
--
-- ⛔ FIX (M2(a)/(b), post-P3a re-gate): bypass (a) — "the play is placed
-- on hold AFTER the code was issued" — is closed by the SEPARATE
-- app.play trigger below (this guard alone only ever fires when
-- offer_code/entitlement's OWN row changes, never when the PLAY changes
-- out from under it). Bypass (b) — "deferred insert ordering" — is
-- closed by making this a genuine DEFERRABLE INITIALLY DEFERRED
-- CONSTRAINT TRIGGER (AFTER, not BEFORE — Postgres constraint triggers
-- are always AFTER) instead of a plain BEFORE trigger: it now runs at
-- the SAME deferred-checking point as the composite FK above, so a
-- play_id that resolves to a row inserted LATER in the same transaction
-- is guaranteed to be visible by the time this fires, and NOT FOUND is
-- now a hard RAISE (fail-closed) rather than a silent pass-through — the
-- composite FK guarantees existence by commit time too, so this is
-- belt-and-suspenders against constraint-check ordering not being
-- guaranteed, not a live gap on its own anymore.
CREATE OR REPLACE FUNCTION app.offer_code_play_guard() RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  v_play_held boolean;
BEGIN
  IF NEW.play_id IS NULL THEN
    RETURN NEW;
  END IF;
  SELECT held_review INTO v_play_held FROM app.play WHERE id = NEW.play_id AND user_id = NEW.user_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'offer_code: play_id % (user_id %) was not found in app.play at constraint-check time', NEW.play_id, NEW.user_id
      USING ERRCODE = '23514';
  END IF;
  IF v_play_held AND NEW.state <> 'held_review' THEN
    RAISE EXCEPTION 'offer_code: play_id % is held_review, so this offer_code must be state=held_review too (got %)', NEW.play_id, NEW.state
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;

CREATE CONSTRAINT TRIGGER offer_code_play_guard_trg
AFTER INSERT OR UPDATE OF play_id, user_id, state ON app.offer_code
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION app.offer_code_play_guard();

CREATE OR REPLACE FUNCTION app.entitlement_play_guard() RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  v_play_held boolean;
BEGIN
  IF NEW.play_id IS NULL THEN
    RETURN NEW;
  END IF;
  SELECT held_review INTO v_play_held FROM app.play WHERE id = NEW.play_id AND user_id = NEW.user_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'entitlement: play_id % (user_id %) was not found in app.play at constraint-check time', NEW.play_id, NEW.user_id
      USING ERRCODE = '23514';
  END IF;
  IF v_play_held AND NEW.state <> 'held_review' THEN
    RAISE EXCEPTION 'entitlement: play_id % is held_review, so this entitlement must be state=held_review too (got %)', NEW.play_id, NEW.state
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;

CREATE CONSTRAINT TRIGGER entitlement_play_guard_trg
AFTER INSERT OR UPDATE OF play_id, user_id, state ON app.entitlement
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION app.entitlement_play_guard();

-- M2(a): bypass (a), "the play is placed on hold AFTER the code was
-- issued" — when app.play.held_review flips false->true, move every
-- backing offer_code/entitlement INTO the held_review state, so the
-- guard above (which only checks state AT THE TIME offer_code/
-- entitlement itself changes) can never be stale. Choice made here,
-- documented: move to 'held_review', not void — held_review is a REVIEW
-- state (money-path-security-requirements.md's own §3 vocabulary), not a
-- final denial, so the backing code/entitlement should freeze pending
-- review, not be destroyed; a human/process resolving the review can
-- still redeem or void it afterward. Terminal states (redeemed/void, and
-- offer_code's expired) are left alone — they are already resolved, and
-- moving a REDEEMED code backward into held_review would be wrong (the
-- money already moved).
CREATE OR REPLACE FUNCTION app.play_held_review_cascade() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.held_review AND NOT OLD.held_review THEN
    UPDATE app.offer_code SET state = 'held_review'
      WHERE play_id = NEW.id AND state NOT IN ('held_review', 'redeemed', 'void', 'expired');
    UPDATE app.entitlement SET state = 'held_review'
      WHERE play_id = NEW.id AND state NOT IN ('held_review', 'redeemed', 'void');
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER play_held_review_cascade_trg
AFTER UPDATE OF held_review ON app.play
FOR EACH ROW EXECUTE FUNCTION app.play_held_review_cascade();

-- ============================================================================
-- 4. Offer budgets: CHECK, max_redemptions enforcement, locked reserve fn.
-- ============================================================================
ALTER TABLE app.offer ADD CONSTRAINT offer_budget_within_cap
  CHECK (budget_used + budget_reserved <= budget_cap);
-- should-fix, post-P3a gate: a negative budget_used/budget_reserved
-- (e.g. a release_offer_budget bug, or a hand-run UPDATE) would otherwise
-- silently satisfy offer_budget_within_cap above while being nonsense —
-- the CAP check alone doesn't rule out negative numbers "canceling out".
ALTER TABLE app.offer ADD CONSTRAINT offer_budget_nonnegative
  CHECK (budget_used >= 0 AND budget_reserved >= 0);

-- max_redemptions: a row-count check on offer_code, enforced at INSERT
-- time via trigger (a plain CHECK cannot reference another table's row
-- count). NULL max_redemptions means unlimited (matches the column's own
-- nullability, 0006).
-- ⛔ FIX (H3, post-P3a gate): the original version read app.offer and
-- app.offer_code with plain SELECTs, no lock — reproduced empirically:
-- two concurrent sessions inserting against the SAME offer_id with
-- max_redemptions=1 could both read count=0 before either committed, and
-- both pass the check (classic TOCTOU race, the same class H3 names).
-- `SELECT ... FOR UPDATE` on the offer row serializes concurrent
-- redeemers of the SAME offer: the second session's FOR UPDATE blocks
-- until the first commits, then re-reads a count that already reflects
-- the first session's insert. Also now fires on `UPDATE OF offer_id`
-- (re-pointing an existing offer_code at a different, maybe-exhausted
-- offer was previously unchecked entirely).
CREATE OR REPLACE FUNCTION app.offer_code_enforce_max_redemptions() RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  v_max int;
  v_count int;
BEGIN
  SELECT max_redemptions INTO v_max FROM app.offer WHERE id = NEW.offer_id FOR UPDATE;
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
BEFORE INSERT OR UPDATE OF offer_id ON app.offer_code
FOR EACH ROW EXECUTE FUNCTION app.offer_code_enforce_max_redemptions();

-- Reserve/release/consume-budget functions: each locks the offer row
-- (SELECT ... FOR UPDATE) before touching it, so two concurrent callers
-- against the same near-exhausted budget can't both read a stale
-- budget_used/budget_reserved and both succeed (the classic lost-update
-- race a bare UPDATE ... WHERE budget_used + budget_reserved + p_amount
-- <= budget_cap would still be exposed to under READ COMMITTED without
-- the explicit row lock first). Plain SQL/plpgsql, not SECURITY DEFINER:
-- their caller (service_role, an Edge Function) already has full DML +
-- BYPASSRLS on app.offer, so no elevation is needed the way private.*
-- helpers need it for anon/authenticated callers.
--
-- ⛔ FIX (should-fix, post-P3a gate): reserve_offer_budget now also
-- checks the offer's own status ('live') and validity window
-- (valid_from/valid_to straddling current_date) — the original version
-- would happily reserve budget against a draft, paused, or expired
-- offer, since only the numeric cap was ever checked.
CREATE OR REPLACE FUNCTION app.reserve_offer_budget(p_offer_id uuid, p_amount numeric)
RETURNS boolean
LANGUAGE plpgsql
AS $$
DECLARE
  v_cap numeric;
  v_used numeric;
  v_reserved numeric;
  v_status app.offer_status;
  v_valid_from date;
  v_valid_to date;
BEGIN
  IF p_amount < 0 THEN
    RAISE EXCEPTION 'reserve_offer_budget: p_amount must be >= 0 (got %)', p_amount;
  END IF;
  SELECT budget_cap, budget_used, budget_reserved, status, valid_from, valid_to
    INTO v_cap, v_used, v_reserved, v_status, v_valid_from, v_valid_to
    FROM app.offer
    WHERE id = p_offer_id
    FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'reserve_offer_budget: no such offer %', p_offer_id;
  END IF;
  IF v_status <> 'live' OR current_date < v_valid_from OR current_date > v_valid_to THEN
    RETURN false;
  END IF;
  IF v_used + v_reserved + p_amount > v_cap THEN
    RETURN false;
  END IF;
  UPDATE app.offer SET budget_reserved = budget_reserved + p_amount WHERE id = p_offer_id;
  RETURN true;
END;
$$;

-- release_offer_budget: undoes an UNCONSUMED reservation (e.g. the
-- redemption it was held for was abandoned/declined) — moves the amount
-- OUT of budget_reserved without ever touching budget_used. Same lock
-- discipline; clamps at 0 rather than raising on a caller passing more
-- than is actually reserved, since "release everything that's left" is
-- the safe behaviour for a cleanup path.
CREATE OR REPLACE FUNCTION app.release_offer_budget(p_offer_id uuid, p_amount numeric)
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
  IF p_amount < 0 THEN
    RAISE EXCEPTION 'release_offer_budget: p_amount must be >= 0 (got %)', p_amount;
  END IF;
  PERFORM 1 FROM app.offer WHERE id = p_offer_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'release_offer_budget: no such offer %', p_offer_id;
  END IF;
  UPDATE app.offer SET budget_reserved = GREATEST(budget_reserved - p_amount, 0) WHERE id = p_offer_id;
END;
$$;

-- consume_offer_budget: converts a reservation into an actual spend —
-- moves the amount from budget_reserved into budget_used (the redemption
-- actually happened). Same lock discipline; clamps budget_reserved at 0
-- the same way release does, so a caller consuming slightly more than
-- was reserved (rounding) can't push it negative and trip
-- offer_budget_nonnegative.
CREATE OR REPLACE FUNCTION app.consume_offer_budget(p_offer_id uuid, p_amount numeric)
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
  IF p_amount < 0 THEN
    RAISE EXCEPTION 'consume_offer_budget: p_amount must be >= 0 (got %)', p_amount;
  END IF;
  PERFORM 1 FROM app.offer WHERE id = p_offer_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'consume_offer_budget: no such offer %', p_offer_id;
  END IF;
  UPDATE app.offer
  SET budget_reserved = GREATEST(budget_reserved - p_amount, 0),
      budget_used = budget_used + p_amount
  WHERE id = p_offer_id;
END;
$$;

REVOKE EXECUTE ON FUNCTION app.reserve_offer_budget(uuid, numeric) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.reserve_offer_budget(uuid, numeric) TO service_role;
REVOKE EXECUTE ON FUNCTION app.release_offer_budget(uuid, numeric) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.release_offer_budget(uuid, numeric) TO service_role;
REVOKE EXECUTE ON FUNCTION app.consume_offer_budget(uuid, numeric) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.consume_offer_budget(uuid, numeric) TO service_role;

-- ============================================================================
-- 5. Receipt dedupe: partial unique index + serialized dedupe function.
-- ============================================================================
-- Partial unique index: two DIFFERENT receipts legitimately share a NULL
-- OCR number (OCR failed/not run), so the index only applies where the
-- OCR number is actually present.
CREATE UNIQUE INDEX receipt_fingerprint_ocr_facility_uniq
  ON app.receipt_fingerprint (receipt_number_ocr, facility_id)
  WHERE receipt_number_ocr IS NOT NULL;

-- ⛔ FIX (M4, post-P3a gate) 2: UNIQUE(purchase_evidence_id) so a retry
-- (the same ingestion call replayed) is idempotent instead of minting a
-- second fingerprint row for the same purchase. Partial (WHERE NOT NULL)
-- for the same reason as the OCR index: the column is nullable (ON
-- DELETE SET NULL, 0003) once the purchase_evidence row it pointed at is
-- gone, and multiple already-detached rows legitimately share NULL.
CREATE UNIQUE INDEX receipt_fingerprint_purchase_evidence_uniq
  ON app.receipt_fingerprint (purchase_evidence_id)
  WHERE purchase_evidence_id IS NOT NULL;

-- ⛔ FIX (post-P3a re-gate, cross-user receipt griefing): dedupe_receipt_
-- fingerprint used to void the NEWER purchase on ANY phash match,
-- regardless of whose purchase the EXISTING fingerprint belonged to.
-- Across users that is a griefing vector: whoever uploads a photo of a
-- SHARED receipt (a real scenario — e.g. two people on the same trip
-- photographing the same paper receipt) first voids the rightful owner's
-- later, legitimate upload. Only a SAME-USER match (a genuine retry/
-- duplicate submission) is still auto-voided; a CROSS-USER match instead
-- opens a review_item + fraud_signal (kind=receipt_cross_user_match) and
-- leaves BOTH purchases pending, for a human to resolve.
--
-- void_reason distinguishes WHY a purchase_evidence row is void:
--   - 'duplicate' — this function's own same-user auto-void. Does not by
--     itself indicate fraud (an honest retry looks identical), so it
--     never itself becomes the reason a LATER unrelated submission gets
--     treated as suspicious.
--   - 'reviewer' — a human voided it directly (out of this stage's scope
--     — an ops/admin action). NULL on a void row means this: a void
--     written before this column existed, or by any path that doesn't
--     set it explicitly, is read as 'reviewer' (documented, not enforced
--     by a DEFAULT, so an intentionally-NULL 'reviewer' void and an
--     old/foreign void are indistinguishable on purpose — both mean
--     "not this function's own automatic duplicate logic").
--   - 'fraud' — voided as a confirmed fraud finding (out of this stage's
--     scope — a fraud-review action).
-- The (out-of-scope-this-stage) rules package tracks a matching
-- `voidReason` field and treats only 'reviewer'/'fraud' as "poisoning" a
-- fingerprint group (i.e. still treated as a live fraud signal for
-- future matching) — 'duplicate' does not, since it is just this
-- function's own bookkeeping, not an independent finding. This function
-- does not need special-case logic for that distinction itself: a
-- 'duplicate'-voided purchase never gets its OWN receipt_fingerprint row
-- (see below — the newer, voided submission's INSERT never runs), so
-- there is nothing on receipt_fingerprint for a 'duplicate' void to
-- "poison" in the first place; a 'reviewer'/'fraud' void's existing
-- fingerprint row is untouched by this function and so keeps matching
-- normally, which already is the desired "still poisons" behaviour.
CREATE TYPE app.purchase_void_reason AS ENUM ('duplicate', 'reviewer', 'fraud');
ALTER TABLE app.purchase_evidence ADD COLUMN void_reason app.purchase_void_reason;
COMMENT ON COLUMN app.purchase_evidence.void_reason IS
  'Only meaningful when status = void. NULL on a void row is read as ''reviewer'' (see this migration''s own note above). Set by dedupe_receipt_fingerprint (''duplicate'') or by an out-of-scope-this-stage reviewer/fraud action.';

-- app.purchase_evidence has NO relationship to app.play_evidence in this
-- schema — play_evidence links (play_id, evidence_id) -> app.evidence
-- (the self-report/device/staff-attestation evidence pathway), a
-- COMPLETELY SEPARATE table from app.purchase_evidence (the receipt-
-- purchase pathway); nothing ever links a purchase_evidence row to
-- play_evidence, directly or otherwise (confirmed by grep over every
-- migration this session). The one REAL "something was earned from this
-- purchase" link in the schema is app.marker_credit.purchase_evidence_id
-- (0005) — handled defensively below, same spirit as the instruction:
-- a same-user duplicate void must not leave a live, non-terminal credit
-- still pointing at a purchase now known to be a duplicate.

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
--
-- ⛔ FIX (M4, post-P3a gate):
--   1. Asserts transaction_isolation = 'read committed'. Under
--      REPEATABLE READ, the lock alone is not enough: the calling
--      transaction's snapshot is taken at its FIRST statement, before
--      this function's own pg_advisory_xact_lock even runs, so a phash
--      row committed by another session BETWEEN snapshot-start and lock-
--      acquisition is invisible to the SELECT below regardless of the
--      lock — the lock only serializes WRITERS against each other, it
--      does not make an already-fixed snapshot see a later commit. READ
--      COMMITTED re-takes its snapshot per-statement, so once the lock is
--      held, this function's own SELECT genuinely sees every row
--      committed before the lock was granted. Raising here, rather than
--      silently under-protecting, matches this codebase's fail-closed
--      convention (0015's own "classify it before this function can run"
--      posture).
--   3. An OCR-index collision (receipt_fingerprint_ocr_facility_uniq,
--      unique_violation) is now caught and treated exactly like a phash
--      duplicate — void + fraud_signal — instead of surfacing a raw
--      23505 to the caller (an Edge Function 500, not a handled fraud
--      case; every OTHER duplicate path here already resolves to a
--      handled outcome, not an exception).
--   4. p_user_id is checked against the purchase_evidence row's OWN
--      user_id before anything else — a caller passing a p_user_id that
--      does not match p_purchase_evidence_id's real owner would
--      otherwise silently attribute a fraud_signal (or a void) to the
--      wrong account.
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
  v_dupe_user_id uuid;
  v_dupe_purchase_evidence_id uuid;
  v_real_user_id uuid;
BEGIN
  IF current_setting('transaction_isolation') <> 'read committed' THEN
    RAISE EXCEPTION 'dedupe_receipt_fingerprint: requires transaction_isolation = read committed (got %) -- the advisory lock does not protect a REPEATABLE READ snapshot taken before it', current_setting('transaction_isolation');
  END IF;

  SELECT user_id INTO v_real_user_id FROM app.purchase_evidence WHERE id = p_purchase_evidence_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'dedupe_receipt_fingerprint: no such purchase_evidence %', p_purchase_evidence_id;
  END IF;
  IF v_real_user_id IS DISTINCT FROM p_user_id THEN
    RAISE EXCEPTION 'dedupe_receipt_fingerprint: p_user_id (%) does not match purchase_evidence.user_id (%) for purchase_evidence_id=%',
      p_user_id, v_real_user_id, p_purchase_evidence_id;
  END IF;

  PERFORM pg_advisory_xact_lock(hashtext(p_phash));

  SELECT id, user_id, purchase_evidence_id INTO v_dupe_id, v_dupe_user_id, v_dupe_purchase_evidence_id
  FROM app.receipt_fingerprint
  WHERE phash = p_phash
    AND (purchase_evidence_id IS DISTINCT FROM p_purchase_evidence_id)
  LIMIT 1;

  IF v_dupe_id IS NOT NULL AND v_dupe_user_id IS NOT DISTINCT FROM p_user_id THEN
    -- SAME USER: a genuine retry/duplicate submission — auto-void the
    -- NEWER (this) one, same as before, now tagged void_reason='duplicate'.
    UPDATE app.purchase_evidence SET status = 'void', void_reason = 'duplicate' WHERE id = p_purchase_evidence_id;
    -- Detach (never delete) any non-terminal marker_credit this purchase
    -- backed — see this section's own note above (no play_evidence link
    -- exists to detach; marker_credit is the real analog).
    UPDATE app.marker_credit SET purchase_evidence_id = NULL
      WHERE purchase_evidence_id = p_purchase_evidence_id AND status <> 'credited';
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
  ELSIF v_dupe_id IS NOT NULL THEN
    -- ⛔ FIX (post-P3a re-gate, cross-user griefing): a DIFFERENT user's
    -- fingerprint matches. Do NOT void either purchase -- neither
    -- submission is known-fraudulent from a phash match alone (a shared
    -- paper receipt legitimately produces this). Open a review_item +
    -- fraud_signal instead, and leave BOTH purchases pending (never
    -- reopen a purchase that is already terminally void, e.g. a prior
    -- reviewer/fraud void -- that verdict stands).
    UPDATE app.purchase_evidence SET status = 'pending' WHERE id = p_purchase_evidence_id AND status <> 'void';
    IF v_dupe_purchase_evidence_id IS NOT NULL THEN
      UPDATE app.purchase_evidence SET status = 'pending' WHERE id = v_dupe_purchase_evidence_id AND status <> 'void';
    END IF;
    INSERT INTO app.review_item (kind, subject_table, subject_id, detail)
    VALUES (
      'receipt_cross_user_match',
      'purchase_evidence',
      p_purchase_evidence_id,
      jsonb_build_object(
        'purchase_evidence_id', p_purchase_evidence_id,
        'user_id', p_user_id,
        'matched_purchase_evidence_id', v_dupe_purchase_evidence_id,
        'matched_user_id', v_dupe_user_id,
        'matched_receipt_fingerprint_id', v_dupe_id,
        'phash', p_phash,
        'facility_id', p_facility_id,
        'local_date', p_local_date
      )
    );
    INSERT INTO app.fraud_signal (user_id, kind, detail)
    VALUES (
      p_user_id,
      'receipt_cross_user_match',
      jsonb_build_object(
        'purchase_evidence_id', p_purchase_evidence_id,
        'matched_purchase_evidence_id', v_dupe_purchase_evidence_id,
        'matched_user_id', v_dupe_user_id,
        'phash', p_phash,
        'facility_id', p_facility_id,
        'local_date', p_local_date
      )
    );
    RETURN false;
  END IF;

  BEGIN
    INSERT INTO app.receipt_fingerprint
      (purchase_evidence_id, user_id, phash, receipt_number_ocr, facility_id, local_date)
    VALUES
      (p_purchase_evidence_id, p_user_id, p_phash, p_receipt_number_ocr, p_facility_id, p_local_date)
    ON CONFLICT (purchase_evidence_id) WHERE purchase_evidence_id IS NOT NULL DO NOTHING;
  EXCEPTION WHEN unique_violation THEN
    -- receipt_fingerprint_ocr_facility_uniq: a DIFFERENT receipt already
    -- claimed this (receipt_number_ocr, facility_id) pair. An OCR number
    -- is a real, near-unique printed identifier (not an approximate
    -- perceptual hash), so — unlike the phash path above — a collision
    -- here stays a same-user-shaped auto-void regardless of who the
    -- other purchase belongs to: two different people's receipts
    -- legitimately sharing the identical OCR'd receipt number at the
    -- identical facility/date is not a realistic "shared photo" scenario
    -- the way a phash collision is.
    UPDATE app.purchase_evidence SET status = 'void', void_reason = 'duplicate' WHERE id = p_purchase_evidence_id;
    UPDATE app.marker_credit SET purchase_evidence_id = NULL
      WHERE purchase_evidence_id = p_purchase_evidence_id AND status <> 'credited';
    INSERT INTO app.fraud_signal (user_id, kind, detail)
    VALUES (
      p_user_id,
      'receipt_ocr_duplicate',
      jsonb_build_object(
        'purchase_evidence_id', p_purchase_evidence_id,
        'receipt_number_ocr', p_receipt_number_ocr,
        'facility_id', p_facility_id,
        'local_date', p_local_date
      )
    );
    RETURN false;
  END;
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
-- should-fix (post-P3a gate): "Add a consumed-nonce tombstone ledger for
-- checkin_challenge.nonce_hash and attestation.token_jti, so DELETE then
-- re-INSERT can't replay." A plain table-level UNIQUE constraint (both
-- already have one) only stops a DUPLICATE while the original row still
-- exists — delete the row, then re-insert the identical nonce/jti, and
-- the UNIQUE constraint has nothing left to object to. A separate,
-- append-only ledger that nothing ever deletes from closes that: every
-- nonce/jti that was EVER inserted stays blocked forever, row or no row.
-- ============================================================================
CREATE TABLE private.consumed_nonce (
  nonce_hash text PRIMARY KEY,
  source text NOT NULL,
  consumed_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE private.consumed_nonce ENABLE ROW LEVEL SECURITY;
ALTER TABLE private.consumed_nonce FORCE ROW LEVEL SECURITY;
-- No client policy at all (nobody but the two trigger functions below
-- ever touches it) — service_role gets the table-level grants it needs
-- (it bypasses RLS entirely regardless, 0009/shim).
GRANT INSERT, SELECT ON private.consumed_nonce TO service_role;

CREATE OR REPLACE FUNCTION app.checkin_challenge_tombstone_nonce() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM private.consumed_nonce WHERE nonce_hash = NEW.nonce_hash) THEN
    RAISE EXCEPTION 'checkin_challenge: nonce_hash % was already consumed (tombstoned) and cannot be reused', NEW.nonce_hash
      USING ERRCODE = '23514';
  END IF;
  INSERT INTO private.consumed_nonce (nonce_hash, source) VALUES (NEW.nonce_hash, 'checkin_challenge');
  RETURN NEW;
END;
$$;

CREATE TRIGGER checkin_challenge_tombstone_nonce_trg
BEFORE INSERT ON app.checkin_challenge
FOR EACH ROW EXECUTE FUNCTION app.checkin_challenge_tombstone_nonce();

CREATE OR REPLACE FUNCTION app.attestation_tombstone_nonce() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM private.consumed_nonce WHERE nonce_hash = NEW.token_jti) THEN
    RAISE EXCEPTION 'attestation: token_jti % was already consumed (tombstoned) and cannot be reused', NEW.token_jti
      USING ERRCODE = '23514';
  END IF;
  INSERT INTO private.consumed_nonce (nonce_hash, source) VALUES (NEW.token_jti, 'attestation');
  RETURN NEW;
END;
$$;

CREATE TRIGGER attestation_tombstone_nonce_trg
BEFORE INSERT ON app.attestation
FOR EACH ROW EXECUTE FUNCTION app.attestation_tombstone_nonce();

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
-- for anyone, including its own owner. Whoever is RUNNING this migration
-- OWNS this table (created it, via 0014) but if NOBYPASSRLS, owner +
-- FORCE + NOBYPASSRLS means RLS genuinely applies to it too (confirmed
-- empirically this session: the INSERT below failed with "new row
-- violates row-level security policy" without this).
--
-- ⛔ FIX (H2, post-P3a gate): this used to name the harness-only role
-- `migration_owner` explicitly, the same defect as 0016:64 -- a real
-- deploy, run as its own migration role, has no role literally named
-- `migration_owner` and this GRANT/POLICY failed outright. `CURRENT_USER`
-- is self-referential and correct regardless of what the connecting role
-- is actually called (harness or real deploy) -- the table's OWNER can
-- grant/police itself directly, no bootstrap-as-superuser step needed
-- (unlike storage.buckets in supabase/tests/shim.sql, which is
-- bootstrap-owned, not owned by the migration role). Governance/manifest
-- data, not user data -- the same reasoning as storage.buckets' own
-- WITH CHECK (true).
GRANT INSERT ON private.function_inventory TO CURRENT_USER;
CREATE POLICY current_user_seed_function_inventory ON private.function_inventory
  FOR INSERT TO CURRENT_USER WITH CHECK (true);

INSERT INTO private.function_inventory
  (schema_name, function_name, identity_args, expected_anon, expected_authenticated, expected_service_role, note)
VALUES
  ('app', 'offer_code_enforce_max_redemptions', '', false, false, false, 'trigger function (app.offer_code_enforce_max_redemptions_trg) -- never EXECUTEd directly by any role'),
  ('app', 'offer_code_play_guard', '', false, false, false, 'trigger function (app.offer_code_play_guard_trg) -- never EXECUTEd directly by any role'),
  ('app', 'entitlement_play_guard', '', false, false, false, 'trigger function (app.entitlement_play_guard_trg) -- never EXECUTEd directly by any role'),
  ('app', 'play_deleted_detach_play_id', '', false, false, false, 'trigger function (app.play_deleted_detach_play_id_trg) -- never EXECUTEd directly by any role'),
  ('app', 'play_held_review_cascade', '', false, false, false, 'trigger function (app.play_held_review_cascade_trg) -- never EXECUTEd directly by any role'),
  ('app', 'checkin_challenge_used_at_once', '', false, false, false, 'trigger function (app.checkin_challenge_used_at_once_trg) -- never EXECUTEd directly by any role'),
  ('app', 'checkin_challenge_tombstone_nonce', '', false, false, false, 'trigger function (app.checkin_challenge_tombstone_nonce_trg) -- never EXECUTEd directly by any role'),
  ('app', 'attestation_tombstone_nonce', '', false, false, false, 'trigger function (app.attestation_tombstone_nonce_trg) -- never EXECUTEd directly by any role'),
  ('app', 'reserve_offer_budget', 'p_offer_id uuid, p_amount numeric', false, false, true, 'locks + reserves offer budget (checks status/validity window too); called by the (out-of-scope-this-stage) scorer/redemption Edge Function as service_role'),
  ('app', 'release_offer_budget', 'p_offer_id uuid, p_amount numeric', false, false, true, 'locks + releases an unconsumed reservation; service_role-only'),
  ('app', 'consume_offer_budget', 'p_offer_id uuid, p_amount numeric', false, false, true, 'locks + moves a reservation into budget_used; service_role-only'),
  ('app', 'dedupe_receipt_fingerprint', 'p_purchase_evidence_id uuid, p_user_id uuid, p_phash text, p_facility_id text, p_local_date date, p_receipt_number_ocr text', false, false, true, 'serialized receipt-phash dedupe; called by the (out-of-scope-this-stage) receipt-ingestion Edge Function as service_role');
