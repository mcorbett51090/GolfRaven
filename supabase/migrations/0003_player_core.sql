-- 0003_player_core.sql
-- build plan §4.4 table, rows: profile, public_profile_projection, device,
-- push_token, evidence, purchase_evidence, receipt_fingerprint, play,
-- play_evidence, user_achievement
-- (docs/golf-trails/02-build-plan.md:824-825, 827, 832-838).
--
-- All FKs to a player point at auth.users(id) (build plan §3.6: "Player |
-- Supabase JWT ... RLS user_id = auth.uid()"). No RLS/GRANT here — every
-- table's RLS + grants live together in 0008_rls_policies.sql /
-- 0009_grants_revokes.sql, driven by the §4.4/§4.7 "client read" columns
-- (kept in one place so the policy set is auditable against the plan
-- table in one pass).

-- ---------------------------------------------------------------------------
-- profile — build plan line 824.
-- ---------------------------------------------------------------------------
CREATE TABLE app.profile (
  user_id uuid PRIMARY KEY REFERENCES auth.users (id) ON DELETE CASCADE,
  handle text UNIQUE NOT NULL CHECK (handle ~ '^[a-z0-9_]{3,20}$'),
  locale text,
  home_region text,
  birth_year_bucket text,
  leaderboard_opt_in boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- public_profile_projection — build plan line 825: "opted-in users only; no
-- user id, home_region or birth_year_bucket (A2-11)". Deliberately has no
-- FK to auth.users/profile — a projection carries no player identity.
CREATE TABLE app.public_profile_projection (
  handle text PRIMARY KEY,
  public_achievements jsonb NOT NULL DEFAULT '[]'::jsonb,
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- device — build plan line 827.
-- ---------------------------------------------------------------------------
CREATE TABLE app.device (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
  platform text NOT NULL CHECK (platform IN ('ios', 'android')),
  attest_key_id text,
  attest_counter bigint NOT NULL DEFAULT 0,
  devicecheck_token_hash text,
  integrity_last jsonb,
  first_seen timestamptz NOT NULL DEFAULT now(),
  last_seen timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX device_user_idx ON app.device (user_id);

-- push_token — build plan line 832: "replaced on reinstall, deleted by
-- DELETE /v1/me (G-P2-11)".
CREATE TABLE app.push_token (
  user_id uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
  device_id uuid NOT NULL REFERENCES app.device (id) ON DELETE CASCADE,
  expo_token text NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, device_id)
);

-- ---------------------------------------------------------------------------
-- evidence — build plan line 833 (play evidence only).
-- ---------------------------------------------------------------------------
CREATE TYPE app.evidence_source AS ENUM (
  'health_route', 'health_workout', 'foreground_checkin', 'foreground_dwell',
  'file_import', 'connect_iq', 'self_report', 'staff_presence',
  'receipt_green_fee', 'booking', 'ghin', 'arccos', 'garmin'
);
CREATE TYPE app.evidence_status AS ENUM (
  'accepted', 'queued_catalog', 'needs_attention', 'flagged', 'rejected'
);
CREATE TYPE app.attestation_grade AS ENUM ('attested', 'unattestable', 'failed');
CREATE TYPE app.course_disambiguated_by AS ENUM ('geometry', 'staff', 'user');

CREATE TABLE app.evidence (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
  device_id uuid REFERENCES app.device (id),
  source app.evidence_source NOT NULL,
  -- ⛔ SECURITY FIX (B4, gate round 2): NOT NULL, not merely present. A
  -- nullable source_ref made `unique(user_id, source, source_ref)`
  -- (line 833) NOT an idempotency key for any source with no natural ref
  -- (e.g. self_report) — Postgres's default NULLS DISTINCT semantics treat
  -- every NULL as unique, so a replayed self_report (or any submission
  -- whose caller omitted the field) inserted a fresh row every time,
  -- defeating "a replayed evidence payload yields one row" (§10 P3 AT(3)).
  -- The ingestion path (out of this stage's scope) must always compute a
  -- ref — a client-supplied id where one exists (health/device event id,
  -- staff scan token, receipt id), otherwise a server-side content hash of
  -- the normalized payload — before insert; the constraint is the backstop
  -- that makes skipping that step a hard failure, not a silent gap.
  source_ref text NOT NULL,
  source_bundle text,
  course_id text REFERENCES app.catalog_course (id),
  facility_id text REFERENCES app.catalog_facility (id),
  started_at timestamptz,
  ended_at timestamptz,
  -- incl. course_disambiguated_by, geometry_kind, local_date (§4.4 line 833)
  summary jsonb NOT NULL DEFAULT '{}'::jsonb,
  -- incl. the fix's attestation grade (§4.5)
  integrity jsonb NOT NULL DEFAULT '{}'::jsonb,
  cosignal jsonb NOT NULL DEFAULT '{}'::jsonb,
  matcher_version text,
  catalog_version int REFERENCES app.catalog_version (version),
  status app.evidence_status NOT NULL DEFAULT 'accepted',
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (user_id, source, source_ref)
);
CREATE INDEX evidence_user_idx ON app.evidence (user_id);
CREATE INDEX evidence_course_idx ON app.evidence (course_id);
CREATE INDEX evidence_facility_idx ON app.evidence (facility_id);

-- ---------------------------------------------------------------------------
-- purchase_evidence — build plan line 834 ("separate by rule SP4-7").
-- ---------------------------------------------------------------------------
CREATE TYPE app.purchase_method AS ENUM (
  'course_qr', 'staff_scan', 'receipt', 'code_card', 'pos_code', 'staff_scan_plus_receipt'
);
CREATE TYPE app.qr_variant AS ENUM ('rotating', 'static_pin');
CREATE TYPE app.no_cosignal_reason AS ENUM ('no_app', 'permission_denied', 'fix_timeout');
CREATE TYPE app.purchase_status AS ENUM ('pending', 'held_review', 'valid', 'void');

CREATE TABLE app.purchase_evidence (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
  facility_id text NOT NULL REFERENCES app.catalog_facility (id),
  trail_id text NOT NULL REFERENCES app.catalog_trail (id),
  method app.purchase_method NOT NULL,
  qr_variant app.qr_variant,
  ref_id text,
  offline boolean NOT NULL DEFAULT false,
  cosignal jsonb,
  no_cosignal_reason app.no_cosignal_reason,
  ip_region_match boolean,
  local_date date NOT NULL,
  status app.purchase_status NOT NULL DEFAULT 'pending',
  created_at timestamptz NOT NULL DEFAULT now(),
  -- §4.6(e) eligibility, G3-09: a staff_scan_plus_receipt row (path (e))
  -- must carry a reason; a course_qr row must carry a variant.
  CHECK (method <> 'staff_scan_plus_receipt' OR no_cosignal_reason IS NOT NULL),
  CHECK (method <> 'course_qr' OR qr_variant IS NOT NULL)
);
CREATE INDEX purchase_evidence_user_idx ON app.purchase_evidence (user_id);
CREATE INDEX purchase_evidence_facility_idx ON app.purchase_evidence (facility_id);

-- receipt_fingerprint — build plan line 835. "kept 24 months (no image)".
CREATE TABLE app.receipt_fingerprint (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  -- Nullable, ON DELETE SET NULL (not CASCADE): private.delete_my_data()
  -- deletes the player's app.purchase_evidence rows outright (§10 AT(6),
  -- "removes all personal rows"), but this row's own columns
  -- (phash/facility_id/local_date/receipt_number_ocr) already carry
  -- everything the 24-month cross-account fraud match (line 835) needs —
  -- a CASCADE here would silently defeat that retention the moment an
  -- account (honest or fraudulent) deletes itself.
  purchase_evidence_id uuid REFERENCES app.purchase_evidence (id) ON DELETE SET NULL,
  -- Nullable (not "NOT NULL"): private.delete_my_data() nulls this on
  -- account deletion rather than deleting the row, so the 24-month
  -- fraud-fingerprint retention (line 835) survives account deletion while
  -- the row stops being a "personal row" of the deleted account (§10 AT(6)).
  user_id uuid REFERENCES auth.users (id) ON DELETE SET NULL,
  phash text NOT NULL,
  receipt_number_ocr text,
  facility_id text NOT NULL REFERENCES app.catalog_facility (id),
  local_date date NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX receipt_fingerprint_phash_idx ON app.receipt_fingerprint (phash);

-- ---------------------------------------------------------------------------
-- play — build plan line 836.
-- ---------------------------------------------------------------------------
CREATE TYPE app.play_status AS ENUM ('provisional', 'confirmed', 'disputed', 'void');

CREATE TABLE app.play (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
  course_id text NOT NULL REFERENCES app.catalog_course (id),
  facility_id text NOT NULL REFERENCES app.catalog_facility (id),
  play_date date NOT NULL,
  course_disambiguated_by app.course_disambiguated_by,
  score_badge numeric(3, 2) NOT NULL DEFAULT 0 CHECK (score_badge BETWEEN 0 AND 0.99),
  score_monetary numeric(3, 2) NOT NULL DEFAULT 0 CHECK (score_monetary BETWEEN 0 AND 0.99),
  hard_signal boolean NOT NULL DEFAULT false,
  presence_signal boolean NOT NULL DEFAULT false,
  policy_version text NOT NULL,
  status app.play_status NOT NULL DEFAULT 'provisional',
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (user_id, course_id, play_date)
);
CREATE INDEX play_user_idx ON app.play (user_id);
CREATE INDEX play_facility_date_idx ON app.play (facility_id, play_date);

-- A2-01: "at most one user-picked course per (user, facility, play_date)".
-- Partial unique index (only enforceable when disambiguation was a user
-- pick — geometry/staff disambiguation is not limited this way).
CREATE UNIQUE INDEX play_user_pick_one_per_facility_date
  ON app.play (user_id, facility_id, play_date)
  WHERE course_disambiguated_by = 'user';

-- play_evidence — build plan line 837.
CREATE TABLE app.play_evidence (
  play_id uuid NOT NULL REFERENCES app.play (id) ON DELETE CASCADE,
  evidence_id uuid NOT NULL REFERENCES app.evidence (id) ON DELETE CASCADE,
  PRIMARY KEY (play_id, evidence_id)
);

-- ---------------------------------------------------------------------------
-- user_achievement — build plan line 838.
-- ---------------------------------------------------------------------------
CREATE TABLE app.user_achievement (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
  achievement_id text NOT NULL REFERENCES app.catalog_achievement_def (id),
  -- "v<N> for the completion family ... '' for every other achievement"
  award_key text NOT NULL DEFAULT '',
  awarded_at timestamptz NOT NULL DEFAULT now(),
  basis jsonb NOT NULL DEFAULT '{}'::jsonb,
  revoked_at timestamptz,
  revoke_reason text,
  UNIQUE (user_id, achievement_id, award_key)
);
CREATE INDEX user_achievement_user_idx ON app.user_achievement (user_id);
