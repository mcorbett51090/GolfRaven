-- 0004_partner_programme.sql
-- build plan §4.4 table, rows: partner_org / partner_member / partner_scope
-- / partner_invite, facility_programme, attestation, attestation_shift_log,
-- staff_activity, trail_programme
-- (docs/golf-trails/02-build-plan.md:839-844).

-- ---------------------------------------------------------------------------
-- partner_org / partner_member / partner_scope / partner_invite — line 839.
-- ---------------------------------------------------------------------------
CREATE TYPE app.partner_org_kind AS ENUM ('operator', 'facility', 'sponsor'); -- sponsor added v5, O11
CREATE TYPE app.partner_role AS ENUM ('staff', 'manager', 'operator', 'sponsor');

CREATE TABLE app.partner_org (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  kind app.partner_org_kind NOT NULL,
  name text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE app.partner_member (
  user_id uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
  org_id uuid NOT NULL REFERENCES app.partner_org (id) ON DELETE CASCADE,
  role app.partner_role NOT NULL,
  revoked_at timestamptz,
  invited_by uuid REFERENCES auth.users (id),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, org_id)
);
CREATE INDEX partner_member_org_idx ON app.partner_member (org_id) WHERE revoked_at IS NULL;

CREATE TABLE app.partner_scope (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id uuid NOT NULL REFERENCES app.partner_org (id) ON DELETE CASCADE,
  facility_id text REFERENCES app.catalog_facility (id),
  trail_id text REFERENCES app.catalog_trail (id),
  sponsorship_id uuid, -- FK added in 0005 after app.sponsorship exists
  CHECK (
    (facility_id IS NOT NULL)::int
    + (trail_id IS NOT NULL)::int
    + (sponsorship_id IS NOT NULL)::int
    >= 1
  )
);
CREATE INDEX partner_scope_org_idx ON app.partner_scope (org_id);
CREATE INDEX partner_scope_facility_idx ON app.partner_scope (facility_id);
CREATE INDEX partner_scope_trail_idx ON app.partner_scope (trail_id);

CREATE TABLE app.partner_invite (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id uuid NOT NULL REFERENCES app.partner_org (id) ON DELETE CASCADE,
  role app.partner_role NOT NULL,
  facility_id text REFERENCES app.catalog_facility (id),
  trail_id text REFERENCES app.catalog_trail (id),
  invited_by uuid NOT NULL REFERENCES auth.users (id),
  invitee_email text NOT NULL,
  token_hash text NOT NULL UNIQUE,
  expires_at timestamptz NOT NULL,
  accepted_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- trail_programme — build plan line 844 (defined before facility_programme
-- for FK order, though it is listed after in the plan's table).
-- ---------------------------------------------------------------------------
CREATE TYPE app.programme_status AS ENUM ('off', 'pilot', 'live');
CREATE TYPE app.marker_source AS ENUM ('any_purchase', 'programme_marker');
CREATE TYPE app.special_marker_funded_by AS ENUM ('trail', 'sponsor');
CREATE TYPE app.fee_model AS ENUM ('flat', 'per_redemption', 'none'); -- [unverified — training knowledge: §9.7 unit-economics fee shapes; exact enum not given verbatim in §4.4]

CREATE TABLE app.trail_programme (
  trail_id text PRIMARY KEY REFERENCES app.catalog_trail (id),
  status app.programme_status NOT NULL DEFAULT 'off',
  marker_source app.marker_source NOT NULL DEFAULT 'any_purchase',
  -- O19 DECIDED 2026-09-23 (build plan line 844): purchase at every
  -- marker-roster facility AND a qualifying play at every completion member.
  marker_requires_completion boolean NOT NULL DEFAULT true,
  special_marker_funded_by app.special_marker_funded_by,
  special_marker_low_threshold int NOT NULL DEFAULT 3,
  -- retired by O3/O5 (line 844): stays false on every trail; kept for audit.
  web_player_flow boolean NOT NULL DEFAULT false,
  special_marker_sku text,
  special_marker_sponsorship_id uuid, -- FK added in 0005
  fee_model app.fee_model,
  fee_amount numeric(10, 2),
  starts_on date,
  ends_on date,
  CHECK (web_player_flow = false)
);

-- ---------------------------------------------------------------------------
-- facility_programme — build plan line 840.
-- ---------------------------------------------------------------------------
CREATE TYPE app.programme_participation AS ENUM ('invited', 'accepted', 'declined', 'left');
CREATE TYPE app.connectivity AS ENUM ('ok', 'weak', 'none');
CREATE TYPE app.qr_mode AS ENUM ('rotating', 'static_pin', 'both');

CREATE TABLE app.facility_programme (
  trail_id text NOT NULL REFERENCES app.trail_programme (trail_id),
  facility_id text NOT NULL REFERENCES app.catalog_facility (id),
  participation app.programme_participation NOT NULL DEFAULT 'invited',
  stocks_markers boolean,
  holds_special_marker boolean,
  connectivity app.connectivity,
  staff_network boolean,
  wifi_note text,
  qr_mode app.qr_mode NOT NULL DEFAULT 'rotating',
  pin_epoch int NOT NULL DEFAULT 0,
  PRIMARY KEY (trail_id, facility_id)
);

-- ---------------------------------------------------------------------------
-- attestation / attestation_shift_log / staff_activity — build plan
-- lines 841-843.
-- ---------------------------------------------------------------------------
CREATE TYPE app.attestation_kind AS ENUM (
  'presence', 'marker_purchase', 'offer_redemption', 'special_marker_handover'
);

CREATE TABLE app.attestation (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  facility_id text NOT NULL REFERENCES app.catalog_facility (id),
  staff_user_id uuid NOT NULL REFERENCES auth.users (id),
  -- nulled on account deletion (private.delete_my_data, §10 AT(6)).
  player_user_id uuid REFERENCES auth.users (id) ON DELETE SET NULL,
  -- HMAC of user_id, kept for audit even after player_user_id is nulled.
  player_pseudonym text NOT NULL,
  kind app.attestation_kind NOT NULL,
  token_jti text NOT NULL UNIQUE,
  cosignal_ok boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  -- "A staff member can never attest their own player account" (§4.5) —
  -- enforced again here as a hard DB invariant, not just an Edge Function
  -- check (defence in depth for the 422 must-fail cells, §4.7.7).
  CHECK (player_user_id IS NULL OR player_user_id <> staff_user_id)
);
CREATE INDEX attestation_facility_idx ON app.attestation (facility_id, created_at);
CREATE INDEX attestation_player_idx ON app.attestation (player_user_id);

-- attestation_shift_log (projection, G3-06) — build plan line 842. "Rows
-- are kept 90 days." No FK to a player id at all — it is a snapshot.
CREATE TABLE app.attestation_shift_log (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  facility_id text NOT NULL REFERENCES app.catalog_facility (id),
  created_at timestamptz NOT NULL DEFAULT now(),
  kind app.attestation_kind NOT NULL,
  player_handle_snapshot text NOT NULL,
  -- B3 fix (gate round 2): a keyed HMAC of the player's user_id, same
  -- scheme as `attestation.player_pseudonym` (line 841) — NOT the user id
  -- itself (the table still holds "no user id" per the plan, line 842).
  -- Its only purpose is so `private.delete_my_data` can find "this
  -- player's" rows by a durable identifier instead of matching the
  -- CURRENT `handle` string, which breaks the moment a handle is reused
  -- by a different account after the original owner frees it, or simply
  -- changes. Nullable: the write path (an Edge Function, out of this
  -- stage's scope) populates it; a row written before that lands can't be
  -- redacted by user id and is redacted by handle as a fallback (see
  -- delete_my_data, 0014).
  player_pseudonym text,
  staff_handle text NOT NULL
);
CREATE INDEX attestation_shift_log_pseudonym_idx ON app.attestation_shift_log (player_pseudonym);
CREATE INDEX attestation_shift_log_facility_idx ON app.attestation_shift_log (facility_id, created_at);

-- staff_activity — build plan line 843. "counts and evidence ids only;
-- never a player id or handle".
CREATE TABLE app.staff_activity (
  staff_user_id uuid NOT NULL REFERENCES auth.users (id),
  facility_id text NOT NULL REFERENCES app.catalog_facility (id),
  day date NOT NULL,
  attests int NOT NULL DEFAULT 0,
  activations int NOT NULL DEFAULT 0,
  anomalies jsonb NOT NULL DEFAULT '[]'::jsonb,
  PRIMARY KEY (staff_user_id, facility_id, day)
);
CREATE INDEX staff_activity_facility_day_idx ON app.staff_activity (facility_id, day);
