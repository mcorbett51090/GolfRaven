-- 08_realtime.sql
-- build plan §4.7 item 6 (docs/golf-trails/02-build-plan.md:1308-1311):
-- "Realtime is disabled (A2-21). CI asserts that the supabase_realtime
-- publication is empty."

BEGIN;
SELECT plan(2);

SELECT ok(
  EXISTS (SELECT 1 FROM pg_publication WHERE pubname = 'supabase_realtime'),
  'the supabase_realtime publication exists (shimmed / provided by the real project)'
);

SELECT is(
  (SELECT count(*)::int FROM pg_publication_tables WHERE pubname = 'supabase_realtime'),
  0,
  'the supabase_realtime publication publishes zero tables (Realtime disabled, A2-21)'
);

SELECT * FROM finish();
ROLLBACK;

-- TODO(build plan line 1310-1311, A67): the "no broadcast-channel
-- authorization policy exists" half is not asserted here — it names
-- Supabase's `realtime.messages` broadcast-auth RLS policies
-- [unverified — training knowledge on the exact object name], which the
-- local shim does not reproduce (the `realtime` extension schema is
-- Supabase-managed infrastructure). Re-check on staging per the plan's own
-- "P3 week-1 spike confirms them."
