-- 0006_offers_booking_misc.sql
-- build plan §4.4 table, rows: offer / offer_code, offer_settlement (view),
-- connector_account, signin_provider_token, booking, review_item,
-- fraud_signal, webhook_event, audit_log, private.rate_limit_bucket
-- (docs/golf-trails/02-build-plan.md:853-860).

-- ---------------------------------------------------------------------------
-- offer / offer_code — build plan line 853.
-- ---------------------------------------------------------------------------
CREATE TYPE app.offer_funder AS ENUM ('course', 'operator', 'sponsor');
CREATE TYPE app.offer_status AS ENUM ('draft', 'approved', 'live', 'ended');
CREATE TYPE app.offer_code_state AS ENUM ('earned', 'held_review', 'issued', 'redeemed', 'expired', 'void');

CREATE TABLE app.offer (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  terms_id text, -- references the catalog OfferTerms artifact (§4.1); not a DB FK — catalog-owned id
  trail_id text NOT NULL REFERENCES app.catalog_trail (id),
  facility_id text NOT NULL REFERENCES app.catalog_facility (id),
  -- validated by the same closed-AST RuleExpr checker as the catalog
  -- (packages/rules — out of this stage's scope; TODO cite §4.1/§4.5 A2-05).
  eligibility jsonb NOT NULL,
  funder app.offer_funder NOT NULL,
  sponsorship_id uuid REFERENCES app.sponsorship (id),
  budget_cap numeric(10, 2) NOT NULL,
  budget_used numeric(10, 2) NOT NULL DEFAULT 0,
  budget_reserved numeric(10, 2) NOT NULL DEFAULT 0,
  max_redemptions int,
  valid_from date NOT NULL,
  valid_to date NOT NULL,
  status app.offer_status NOT NULL DEFAULT 'draft',
  -- funder = sponsor requires a sponsorship_id (O11, line 853).
  CHECK (funder <> 'sponsor' OR sponsorship_id IS NOT NULL)
);
CREATE INDEX offer_trail_idx ON app.offer (trail_id);
CREATE INDEX offer_facility_idx ON app.offer (facility_id);

CREATE TABLE app.offer_code (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  offer_id uuid NOT NULL REFERENCES app.offer (id),
  user_id uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
  facility_id text NOT NULL REFERENCES app.catalog_facility (id),
  code_hmac text, -- code-pool only
  pepper_kid text,
  state app.offer_code_state NOT NULL DEFAULT 'earned',
  earned_at timestamptz NOT NULL DEFAULT now(),
  activated_device_id uuid REFERENCES app.device (id),
  devicecheck_token_hash text,
  activated_at timestamptz,
  expires_at timestamptz,
  expiry_paused_at timestamptz,
  redeemed_at timestamptz,
  redeemed_by_staff uuid REFERENCES auth.users (id),
  redeemed_offline boolean NOT NULL DEFAULT false,
  UNIQUE (user_id, offer_id)
);
CREATE INDEX offer_code_user_idx ON app.offer_code (user_id);
CREATE INDEX offer_code_offer_idx ON app.offer_code (offer_id);

-- ---------------------------------------------------------------------------
-- connector_account / signin_provider_token — build plan lines 856-857.
-- ---------------------------------------------------------------------------
CREATE TABLE app.connector_account (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
  provider text NOT NULL,
  external_user_id text NOT NULL,
  -- envelope-encrypted (§4.8) — ciphertext + wrapped DEK only, never plaintext.
  refresh_token_ciphertext bytea NOT NULL,
  dek_wrapped bytea NOT NULL,
  kek_id text NOT NULL,
  scopes text[] NOT NULL DEFAULT '{}',
  status text NOT NULL DEFAULT 'active',
  created_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz,
  UNIQUE (user_id, provider, external_user_id)
);

-- signin_provider_token (O12) — build plan line 857.
CREATE TABLE app.signin_provider_token (
  user_id uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
  provider text NOT NULL CHECK (provider IN ('apple', 'google')),
  refresh_token_ciphertext bytea NOT NULL,
  dek_wrapped bytea NOT NULL,
  kek_id text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, provider)
);

-- ---------------------------------------------------------------------------
-- booking — build plan line 858 (P7 scope; table exists from P3 per §4.4).
-- ---------------------------------------------------------------------------
CREATE TABLE app.booking (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
  provider text NOT NULL,
  provider_ref text NOT NULL UNIQUE,
  facility_id text NOT NULL REFERENCES app.catalog_facility (id),
  tee_time timestamptz NOT NULL,
  status text NOT NULL DEFAULT 'confirmed'
);
CREATE INDEX booking_user_idx ON app.booking (user_id);

-- ---------------------------------------------------------------------------
-- review_item / fraud_signal / webhook_event / audit_log — build plan
-- line 859. Admin-only; no client policy anywhere (§4.7.7).
-- ---------------------------------------------------------------------------
CREATE TABLE app.review_item (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  kind text NOT NULL,
  subject_table text NOT NULL,
  subject_id uuid NOT NULL,
  status text NOT NULL DEFAULT 'open',
  detail jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  resolved_at timestamptz,
  resolved_by uuid REFERENCES auth.users (id)
);

CREATE TABLE app.fraud_signal (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid REFERENCES auth.users (id) ON DELETE SET NULL,
  kind text NOT NULL,
  detail jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  cleared_at timestamptz,
  cleared_by uuid REFERENCES auth.users (id)
);
CREATE INDEX fraud_signal_user_idx ON app.fraud_signal (user_id) WHERE cleared_at IS NULL;

CREATE TABLE app.webhook_event (
  provider text NOT NULL,
  event_id text NOT NULL,
  received_at timestamptz NOT NULL DEFAULT now(),
  payload jsonb,
  PRIMARY KEY (provider, event_id)
);

-- audit_log — "insert-only" (line 859). Enforced by RLS default-deny on
-- UPDATE/DELETE for every role incl. service_role's normal path staying
-- INSERT-only by convention; a hard guard is added as a trigger below so
-- "insert-only" is a DB invariant, not just a house rule.
CREATE TABLE app.audit_log (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  -- ON DELETE SET NULL (B3, gate round 2): lets private.delete_my_data
  -- redact the actor without deleting or blocking-on this insert-only
  -- audit row — see the trigger's narrow redaction exception below.
  actor_user_id uuid REFERENCES auth.users (id) ON DELETE SET NULL,
  action text NOT NULL,
  subject_table text,
  subject_id text,
  detail jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- ⛔ SECURITY/CORRECTNESS FIX (B3, gate round 2): the original trigger
-- blocked EVERY update or delete unconditionally — including the one
-- update account deletion legitimately needs (redacting `actor_user_id`
-- to NULL on the deleted user's own past audit rows, since app.audit_log
-- doesn't get a row deleted or its user_id nulled by the generic
-- FK-driven pass; it needs its OWN narrow carve-out because it must stay
-- insert-only for everything else). This version allows exactly one
-- shape of UPDATE — nulling `actor_user_id` and changing nothing else —
-- and still rejects every DELETE and every other UPDATE unconditionally.
CREATE OR REPLACE FUNCTION app.audit_log_no_mutation() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF TG_OP = 'UPDATE'
    AND NEW.actor_user_id IS NULL
    AND OLD.actor_user_id IS NOT NULL
    AND NEW.id = OLD.id
    AND NEW.action = OLD.action
    AND NEW.subject_table IS NOT DISTINCT FROM OLD.subject_table
    AND NEW.subject_id IS NOT DISTINCT FROM OLD.subject_id
    AND NEW.detail = OLD.detail
    AND NEW.created_at = OLD.created_at
  THEN
    -- The one allowed mutation: redacting the actor on account deletion.
    -- A PII-free tombstone — the row, action and detail survive; only the
    -- identity of who did it is removed.
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'app.audit_log is insert-only, except redacting actor_user_id to NULL (build plan line 859; §10 AT(6))';
END;
$$;

CREATE TRIGGER audit_log_no_update
  BEFORE UPDATE OR DELETE ON app.audit_log
  FOR EACH ROW EXECUTE FUNCTION app.audit_log_no_mutation();

-- ---------------------------------------------------------------------------
-- private.rate_limit_bucket — build plan line 860.
-- ---------------------------------------------------------------------------
CREATE TABLE private.rate_limit_bucket (
  bucket_key text NOT NULL,
  window_start timestamptz NOT NULL,
  count int NOT NULL DEFAULT 0,
  PRIMARY KEY (bucket_key, window_start)
);

-- ---------------------------------------------------------------------------
-- offer_settlement (view) — build plan line 854. Internal to `app`: read
-- only by the settlement-export Edge Function (service_role), never
-- exposed in `api` (no client role reads it directly; the export writes a
-- file to the private `exports` bucket instead, §4.4).
-- ---------------------------------------------------------------------------
CREATE VIEW app.offer_settlement AS
SELECT
  o.facility_id,
  date_trunc('month', oc.redeemed_at)::date AS month,
  o.funder,
  o.sponsorship_id,
  count(*) FILTER (WHERE oc.state = 'redeemed') AS redemptions,
  count(*) FILTER (WHERE oc.state = 'redeemed' AND oc.redeemed_offline) AS offline_redemptions,
  count(*) FILTER (
    WHERE oc.state = 'redeemed' AND oc.redeemed_by_staff IS NULL
  ) AS unconfirmed_redemptions
FROM app.offer_code oc
JOIN app.offer o ON o.id = oc.offer_id
WHERE oc.state = 'redeemed'
GROUP BY o.facility_id, date_trunc('month', oc.redeemed_at)::date, o.funder, o.sponsorship_id;
