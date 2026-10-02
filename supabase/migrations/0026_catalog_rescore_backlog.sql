-- 0026_catalog_rescore_backlog.sql
-- P3e round 3: AT 18 (stub -> verified promotion re-scores the affected
-- plays; a split's kept course counts once) + R3 (hole count).
--
-- 1. app.catalog_course.holes — the course's DECLARED hole count
--    (`Course.holes`, packages/catalog schema; 9 or 18 in practice). The
--    emitter publishes it but no column held it, so `courseHoleCount`
--    returned 0 for every imported course (it counted catalog_hole rows,
--    which exist only when the artifact carries `holesDetail`).
--    `Repo#catalog.courseHoleCount` now prefers the catalog_hole count and
--    falls back to this column; the dwell threshold treats anything other
--    than exactly 9 as 18 (the STRICTER threshold) — an unknown hole count
--    can never lower the bar.
ALTER TABLE app.catalog_course ADD COLUMN holes smallint CHECK (holes IS NULL OR holes > 0);
COMMENT ON COLUMN app.catalog_course.holes IS
  'Declared hole count (Course.holes) as published in the signed catalog artifact; NULL when the artifact omits it. catalog_hole rows (Course.holesDetail) take precedence in Repo#catalog.courseHoleCount.';

-- 2. The re-score backlog. The importer must not re-score every affected
--    play inside its own 12 s transaction (a large promotion could touch
--    thousands of plays), so the import only INSERTS one row per promoted
--    / newly-split course here (set-based, idempotent per (course, reason,
--    catalog version)); the drain pass (import-catalog/index.ts, after the
--    queued_catalog drain) then works the backlog a bounded batch at a
--    time with a keyset cursor over play ids, re-scoring each affected play
--    through the live scoring path inside that user's own `withOwnership`
--    transaction. Holds no user identifier: `cursor_play_id` is a play id,
--    deliberately NOT a foreign key (the play may since have been deleted).
CREATE TABLE app.catalog_rescore_backlog (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  course_id text NOT NULL REFERENCES app.catalog_id_ledger (id),
  reason text NOT NULL CHECK (reason IN ('promotion', 'split')),
  catalog_version int NOT NULL REFERENCES app.catalog_version (version),
  cursor_play_id uuid,
  created_at timestamptz NOT NULL DEFAULT now(),
  done_at timestamptz,
  UNIQUE (course_id, reason, catalog_version)
);
COMMENT ON TABLE app.catalog_rescore_backlog IS
  'AT 18 work queue: courses whose plays must be re-scored (stub->verified promotion) or re-labelled (split) after a catalog import. Bounded per drain pass via cursor_play_id. Server-only; no user data.';
CREATE INDEX catalog_rescore_backlog_open_idx ON app.catalog_rescore_backlog (id) WHERE done_at IS NULL;

ALTER TABLE app.catalog_rescore_backlog ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.catalog_rescore_backlog FORCE ROW LEVEL SECURITY;
-- No policy for any client role (service_role bypasses RLS). INSERT +
-- UPDATE (cursor/done_at) + SELECT; never DELETE — a finished row is the
-- idempotency record that stops a replayed import re-queuing the work.
GRANT SELECT, INSERT, UPDATE ON app.catalog_rescore_backlog TO service_role;
