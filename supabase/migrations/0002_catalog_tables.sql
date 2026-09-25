-- 0002_catalog_tables.sql
-- build plan §4.4 table, row "catalog_trail, catalog_facility, catalog_course
-- (stub courses included, G3-01), catalog_designer, catalog_hole,
-- catalog_roster_version(...), catalog_roster_member(...),
-- catalog_achievement_def" and the catalog_version / catalog_id_ledger rows
-- (docs/golf-trails/02-build-plan.md:821-823).
--
-- These tables mirror the catalog artifact whose FULL shape is the §4.1 Zod
-- schema (packages/catalog/src/schema.ts, build-plan lines 464-644) — that
-- package is out of this stage's scope (P3 is the player plane; the catalog
-- contract is P1/@golfraven/catalog). We implement the columns §4.4 names
-- explicitly, plus the minimum extra columns needed for referential
-- integrity and for the fields §4.4 calls out by name (`verification_status`,
-- facility `tz`, `course.closed`). Anything beyond that is intentionally
-- deferred.
-- TODO(build plan §4.1, lines 464-644): widen these tables to the full
-- catalog artifact shape when the import function (out of scope this stage,
-- §10 P3 "import-catalog" is listed as scope but its body is not P3-stage-a
-- work per this task's "out of scope" list) is built.

CREATE TYPE app.verification_status AS ENUM ('unverified', 'listed-verified', 'play-verified');
CREATE TYPE app.ledger_status AS ENUM ('stub', 'verified');
CREATE TYPE app.geometry_kind AS ENUM ('polygon', 'radius');

-- catalog_version — build plan line 821.
CREATE TABLE app.catalog_version (
  version int PRIMARY KEY,
  contract_version text NOT NULL,
  sha256 text NOT NULL,
  kid text NOT NULL,
  published_at timestamptz NOT NULL,
  imported_at timestamptz NOT NULL DEFAULT now()
);

-- catalog_id_ledger — build plan line 823. "the full ledger, so evidence is
-- validated against every ID ever minted, not the last import (FM-03)."
CREATE TABLE app.catalog_id_ledger (
  id text PRIMARY KEY,
  kind text NOT NULL, -- e.g. 'trail' | 'facility' | 'course' | 'hole'
  status app.ledger_status NOT NULL DEFAULT 'stub',
  verified_in_version int REFERENCES app.catalog_version (version),
  split_from text REFERENCES app.catalog_id_ledger (id),
  tombstoned_at timestamptz,
  merged_into text REFERENCES app.catalog_id_ledger (id),
  first_catalog_version int NOT NULL REFERENCES app.catalog_version (version),
  CHECK (id <> merged_into)
);

CREATE TABLE app.catalog_designer (
  id text PRIMARY KEY REFERENCES app.catalog_id_ledger (id),
  name text NOT NULL,
  catalog_version int NOT NULL REFERENCES app.catalog_version (version)
);

CREATE TABLE app.catalog_trail (
  id text PRIMARY KEY REFERENCES app.catalog_id_ledger (id),
  slug text NOT NULL UNIQUE,
  name text NOT NULL,
  catalog_version int NOT NULL REFERENCES app.catalog_version (version)
);

CREATE TABLE app.catalog_facility (
  id text PRIMARY KEY REFERENCES app.catalog_id_ledger (id),
  slug text NOT NULL UNIQUE,
  name text NOT NULL,
  region text NOT NULL,
  -- REQUIRED IANA zone (build plan line 465, G-P0-11).
  tz text NOT NULL,
  catalog_version int NOT NULL REFERENCES app.catalog_version (version)
);

CREATE TABLE app.catalog_course (
  id text PRIMARY KEY REFERENCES app.catalog_id_ledger (id),
  facility_id text NOT NULL REFERENCES app.catalog_facility (id),
  designer_id text REFERENCES app.catalog_designer (id),
  name text NOT NULL,
  -- "stub courses included" (G3-01): a course can exist before it is
  -- verified — see catalog_id_ledger.status for the stub/verified state.
  verification_status app.verification_status NOT NULL DEFAULT 'unverified',
  closed boolean NOT NULL DEFAULT false,
  geometry_kind app.geometry_kind,
  -- GEOMETRY, SRID 4326 (WGS84 lon/lat) [unverified — training knowledge:
  -- this is the standard SRID choice for lon/lat geodata; the plan does not
  -- state one]. NULL for a listed-verified course with no polygon
  -- (radius-fallback circle, §4.5).
  boundary geometry(Geometry, 4326),
  radius_center geometry(Point, 4326),
  radius_m numeric(10, 2),
  catalog_version int NOT NULL REFERENCES app.catalog_version (version)
);

-- GiST index on geometry (task instruction: "a GiST index on geometry if
-- the schema has it" — §4.2's polygon-match reads need this).
CREATE INDEX catalog_course_boundary_gix ON app.catalog_course USING gist (boundary);
CREATE INDEX catalog_course_radius_center_gix ON app.catalog_course USING gist (radius_center);
CREATE INDEX catalog_course_facility_idx ON app.catalog_course (facility_id);

CREATE TABLE app.catalog_hole (
  id text PRIMARY KEY REFERENCES app.catalog_id_ledger (id),
  course_id text NOT NULL REFERENCES app.catalog_course (id),
  number int NOT NULL CHECK (number BETWEEN 1 AND 36),
  catalog_version int NOT NULL REFERENCES app.catalog_version (version),
  UNIQUE (course_id, number)
);

-- catalog_roster_version — build plan line 822: "the rule parameters are
-- per version" (A2-02). completionRule is `all` by default (O15).
CREATE TYPE app.roster_unit AS ENUM ('course', 'facility', 'hole');
CREATE TYPE app.roster_rule_kind AS ENUM ('all', 'n_of_m');

CREATE TABLE app.catalog_roster_version (
  trail_id text NOT NULL REFERENCES app.catalog_trail (id),
  version int NOT NULL,
  completion_unit app.roster_unit NOT NULL,
  marker_unit app.roster_unit NOT NULL,
  completion_rule app.roster_rule_kind NOT NULL DEFAULT 'all',
  completion_rule_n int,
  completion_rule_source text, -- ruleSource, required when n_of_m (O15)
  marker_rule app.roster_rule_kind NOT NULL DEFAULT 'all',
  marker_rule_n int,
  marker_rule_source text,
  tracking_starts_on date,
  effective_from timestamptz NOT NULL,
  PRIMARY KEY (trail_id, version),
  CHECK (completion_rule <> 'n_of_m' OR completion_rule_source IS NOT NULL),
  CHECK (marker_rule <> 'n_of_m' OR marker_rule_source IS NOT NULL)
);

-- catalog_roster_member — build plan line 822.
CREATE TABLE app.catalog_roster_member (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  trail_id text NOT NULL,
  roster_version int NOT NULL,
  unit app.roster_unit NOT NULL,
  course_id text REFERENCES app.catalog_course (id),
  any_of_course_ids text[],
  facility_id text REFERENCES app.catalog_facility (id),
  hole_id text REFERENCES app.catalog_hole (id),
  stop_order int,
  -- derived by the import function (out of scope this stage), null while
  -- still a member of the latest version.
  removed_on date,
  FOREIGN KEY (trail_id, roster_version) REFERENCES app.catalog_roster_version (trail_id, version)
);

CREATE INDEX catalog_roster_member_trail_version_idx
  ON app.catalog_roster_member (trail_id, roster_version);

-- catalog_achievement_def — build plan line 822; §8.1 taxonomy (out of this
-- stage's scope in full, but the table + minConfidence column is needed by
-- the money-threshold / badge-threshold rules the scorer reads, §4.5).
CREATE TABLE app.catalog_achievement_def (
  id text PRIMARY KEY REFERENCES app.catalog_id_ledger (id),
  trail_id text REFERENCES app.catalog_trail (id),
  kind text NOT NULL,
  min_confidence numeric(3, 2) NOT NULL DEFAULT 0.50,
  catalog_version int NOT NULL REFERENCES app.catalog_version (version)
);
