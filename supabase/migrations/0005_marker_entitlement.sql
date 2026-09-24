-- 0005_marker_entitlement.sql
-- build plan §4.4 table, rows: device_reward_ledger, checkin_challenge,
-- course_qr_token, facility_qr, marker_code_batch, marker_code,
-- marker_credit, entitlement, special_marker_stock,
-- special_marker_stock_movement, special_marker_availability, sponsorship
-- (docs/golf-trails/02-build-plan.md:828-831, 845-853).

-- ---------------------------------------------------------------------------
-- device_reward_ledger — build plan line 828.
-- ---------------------------------------------------------------------------
CREATE TYPE app.reward_kind AS ENUM ('offer', 'special_marker');

CREATE TABLE app.device_reward_ledger (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id uuid NOT NULL REFERENCES app.device (id),
  devicecheck_token_hash text,
  user_id uuid NOT NULL REFERENCES auth.users (id),
  reward_kind app.reward_kind NOT NULL,
  reward_id uuid NOT NULL,
  at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX device_reward_ledger_device_idx ON app.device_reward_ledger (device_id);

-- checkin_challenge — build plan line 829.
CREATE TABLE app.checkin_challenge (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid REFERENCES auth.users (id),
  staff_user_id uuid REFERENCES auth.users (id),
  device_id uuid NOT NULL REFERENCES app.device (id),
  facility_id text REFERENCES app.catalog_facility (id),
  nonce_hash text NOT NULL UNIQUE,
  issued_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  used_at timestamptz,
  CHECK (
    (user_id IS NOT NULL AND staff_user_id IS NULL)
    OR (user_id IS NULL AND staff_user_id IS NOT NULL)
  )
);
CREATE INDEX checkin_challenge_device_idx ON app.checkin_challenge (device_id);

-- course_qr_token (O5) — build plan line 830. "one row per 'Marker sold'
-- tap; single-use; the QR carries the signed token, the table only its
-- hash".
CREATE TABLE app.course_qr_token (
  nonce_hash text PRIMARY KEY,
  facility_id text NOT NULL REFERENCES app.catalog_facility (id),
  issued_by_staff uuid NOT NULL REFERENCES auth.users (id),
  kid text NOT NULL,
  issued_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL, -- issued_at + 120s, enforced by the issuing function
  used_by_user uuid REFERENCES auth.users (id),
  used_at timestamptz
);
CREATE INDEX course_qr_token_facility_idx ON app.course_qr_token (facility_id, issued_at);

-- facility_qr (O5) — build plan line 831.
CREATE TABLE app.facility_qr (
  facility_id text PRIMARY KEY REFERENCES app.catalog_facility (id),
  qr_kid text NOT NULL,
  sig text NOT NULL,
  printed_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz
);

-- ---------------------------------------------------------------------------
-- sponsorship (O11) — build plan line 852.
-- ---------------------------------------------------------------------------
CREATE TYPE app.sponsorship_category AS ENUM ('equipment', 'apparel', 'tourism', 'other');
CREATE TYPE app.sponsorship_scope AS ENUM ('special_marker', 'offers', 'both');
CREATE TYPE app.sponsorship_status AS ENUM ('draft', 'approved', 'live', 'ended');

CREATE TABLE app.sponsorship (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  sponsor_org_id uuid NOT NULL REFERENCES app.partner_org (id),
  trail_id text NOT NULL REFERENCES app.catalog_trail (id),
  category app.sponsorship_category NOT NULL,
  scope app.sponsorship_scope NOT NULL,
  attribution_name text NOT NULL,
  attribution_asset text,
  placement_fee numeric(10, 2),
  marker_run_funded_at timestamptz,
  starts_on date,
  ends_on date,
  operator_approved_at timestamptz,
  status app.sponsorship_status NOT NULL DEFAULT 'draft'
);
CREATE INDEX sponsorship_trail_idx ON app.sponsorship (trail_id);

ALTER TABLE app.partner_scope
  ADD CONSTRAINT partner_scope_sponsorship_fk
  FOREIGN KEY (sponsorship_id) REFERENCES app.sponsorship (id);

ALTER TABLE app.trail_programme
  ADD CONSTRAINT trail_programme_sponsorship_fk
  FOREIGN KEY (special_marker_sponsorship_id) REFERENCES app.sponsorship (id);

-- sponsor_rollup_<metric> (O11) — build plan line 855. Literal reading:
-- `<metric>` names a family of one table per metric name, which the plan
-- never enumerates. We take the table's own column list ("sponsorship_id,
-- month, metric, value, cohort_n") as decisive over the name pattern and
-- implement ONE table with a `metric` column — see AMBIGUITIES in the
-- handback report (line 855).
CREATE TABLE app.sponsor_rollup (
  sponsorship_id uuid NOT NULL REFERENCES app.sponsorship (id),
  month date NOT NULL, -- first-of-month
  metric text NOT NULL,
  value numeric NOT NULL,
  cohort_n int NOT NULL,
  PRIMARY KEY (sponsorship_id, month, metric),
  -- k-anonymity: "no row is written when cohort_n < 10" (§4.7 item 3).
  CHECK (cohort_n >= 10)
);

-- operator_rollup_<metric> — build plan line 826. Same family-name reading
-- as sponsor_rollup above.
CREATE TABLE app.operator_rollup (
  trail_id text NOT NULL REFERENCES app.catalog_trail (id),
  month date NOT NULL,
  metric text NOT NULL,
  value numeric NOT NULL,
  cohort_n int NOT NULL,
  PRIMARY KEY (trail_id, month, metric),
  CHECK (cohort_n >= 10)
);

-- ---------------------------------------------------------------------------
-- marker_code_batch / marker_code (programme_marker only) — line 845-846.
-- ---------------------------------------------------------------------------
CREATE TABLE app.marker_code_batch (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  facility_id text NOT NULL REFERENCES app.catalog_facility (id),
  trail_id text NOT NULL REFERENCES app.catalog_trail (id),
  qty int NOT NULL CHECK (qty > 0),
  pepper_kid text NOT NULL,
  printed_at timestamptz,
  delivered_at timestamptz,
  voided_at timestamptz
);

CREATE TABLE app.marker_code (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  batch_id uuid NOT NULL REFERENCES app.marker_code_batch (id),
  code_hmac text NOT NULL UNIQUE,
  activated_at timestamptz,
  activated_by_staff uuid REFERENCES auth.users (id),
  redeemed_by uuid REFERENCES auth.users (id),
  redeemed_at timestamptz
);
CREATE INDEX marker_code_batch_idx ON app.marker_code (batch_id);

-- ---------------------------------------------------------------------------
-- marker_credit — build plan line 847.
-- ---------------------------------------------------------------------------
CREATE TYPE app.credit_status AS ENUM ('pending', 'held_review', 'credited', 'void');

CREATE TABLE app.marker_credit (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
  trail_id text NOT NULL REFERENCES app.catalog_trail (id),
  facility_id text NOT NULL REFERENCES app.catalog_facility (id),
  purchase_evidence_id uuid REFERENCES app.purchase_evidence (id),
  status app.credit_status NOT NULL DEFAULT 'pending',
  created_at timestamptz NOT NULL DEFAULT now()
);
-- "unique(user_id, trail_id, facility_id) where status='credited'"
CREATE UNIQUE INDEX marker_credit_one_credited
  ON app.marker_credit (user_id, trail_id, facility_id)
  WHERE status = 'credited';
CREATE INDEX marker_credit_user_idx ON app.marker_credit (user_id);

-- ---------------------------------------------------------------------------
-- entitlement — build plan line 848.
-- ---------------------------------------------------------------------------
CREATE TYPE app.entitlement_kind AS ENUM ('special_marker');
CREATE TYPE app.entitlement_state AS ENUM (
  'earned', 'held_review', 'redeemable', 'vouchered', 'redeemed', 'void'
);
CREATE TYPE app.redemption_method AS ENUM ('staff_scan', 'hand_over_token', 'offline_code');

CREATE TABLE app.entitlement (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
  kind app.entitlement_kind NOT NULL,
  trail_id text NOT NULL REFERENCES app.catalog_trail (id),
  roster_version int,
  sponsorship_id uuid REFERENCES app.sponsorship (id),
  basis jsonb NOT NULL DEFAULT '{}'::jsonb,
  state app.entitlement_state NOT NULL DEFAULT 'earned',
  activated_device_id uuid REFERENCES app.device (id),
  devicecheck_token_hash text,
  activated_at timestamptz,
  redeemed_at timestamptz,
  redeemed_facility_id text REFERENCES app.catalog_facility (id),
  redeemed_by_staff uuid REFERENCES auth.users (id),
  redemption_method app.redemption_method,
  redemption_jti text UNIQUE,
  redemption_cosignal_ok boolean,
  voucher_facility_id text REFERENCES app.catalog_facility (id),
  voucher_issued_at timestamptz,
  -- "one special marker per account per trail"
  UNIQUE (user_id, kind, trail_id)
  -- "redeemed and void are terminal; no address or shipping field exists"
  -- (O9/O10) — there is deliberately no address/shipping column above.
);
CREATE INDEX entitlement_user_idx ON app.entitlement (user_id);

-- ---------------------------------------------------------------------------
-- special_marker_stock / _stock_movement / _availability (O9/O10) — 849-851.
-- ---------------------------------------------------------------------------
CREATE TABLE app.special_marker_stock (
  trail_id text NOT NULL REFERENCES app.catalog_trail (id),
  facility_id text NOT NULL REFERENCES app.catalog_facility (id),
  on_hand int NOT NULL DEFAULT 0 CHECK (on_hand >= 0),
  low_threshold int NOT NULL DEFAULT 3,
  last_counted_at timestamptz,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (trail_id, facility_id)
);

CREATE TYPE app.stock_movement_kind AS ENUM (
  'delivered', 'redeemed', 'voucher_redeemed', 'transfer_out', 'transfer_in',
  'count_adjustment', 'damaged'
);

CREATE TABLE app.special_marker_stock_movement (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  trail_id text NOT NULL,
  facility_id text NOT NULL,
  kind app.stock_movement_kind NOT NULL,
  qty int NOT NULL,
  entitlement_id uuid REFERENCES app.entitlement (id),
  by_member uuid NOT NULL REFERENCES auth.users (id),
  note text,
  at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (trail_id, facility_id) REFERENCES app.special_marker_stock (trail_id, facility_id)
);
CREATE INDEX stock_movement_stock_idx ON app.special_marker_stock_movement (trail_id, facility_id, at);

CREATE TYPE app.availability_status AS ENUM ('in_stock', 'low', 'out');

CREATE TABLE app.special_marker_availability (
  trail_id text NOT NULL,
  facility_id text NOT NULL,
  status app.availability_status NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (trail_id, facility_id),
  FOREIGN KEY (trail_id, facility_id) REFERENCES app.special_marker_stock (trail_id, facility_id)
);
