-- 0013_realtime_disabled.sql
-- build plan §4.7 item 6 (docs/golf-trails/02-build-plan.md:1308-1311):
-- "Realtime is disabled (A2-21). CI asserts that the supabase_realtime
-- publication is empty and that no broadcast-channel authorization policy
-- exists [unverified — training knowledge on the object names; A67; the
-- P3 week-1 spike confirms them]."
--
-- No migration in this stage ever runs `ALTER PUBLICATION supabase_realtime
-- ADD TABLE ...`, so the publication stays empty by omission. This
-- migration makes that an enforced, idempotent invariant instead of an
-- absence: it drops any table a prior/future migration or manual change
-- may have added, so "empty" holds regardless of history.
DO $$
DECLARE
  t record;
BEGIN
  IF EXISTS (SELECT 1 FROM pg_publication WHERE pubname = 'supabase_realtime') THEN
    FOR t IN
      SELECT schemaname, tablename FROM pg_publication_tables WHERE pubname = 'supabase_realtime'
    LOOP
      EXECUTE format('ALTER PUBLICATION supabase_realtime DROP TABLE %I.%I', t.schemaname, t.tablename);
    END LOOP;
  END IF;
END
$$;

-- TODO(build plan line 1310-1311, A67): "no broadcast-channel authorization
-- policy exists" refers to Supabase Realtime's `realtime.messages`
-- broadcast-authorization RLS policies
-- [unverified — training knowledge on the exact object name; not
-- reproduced in supabase/tests/shim.sql, since the `realtime` extension
-- schema itself is Supabase-managed infrastructure, not something this
-- migration set creates]. The pgTAP check for this
-- (supabase/tests/matrix/09_realtime.sql) asserts the publication is
-- empty, which is the part reproducible in this local shim; it documents
-- the broadcast-policy half as a gap to re-check on staging (A67, "the P3
-- week-1 spike confirms them").
