-- 07_rate_limit.sql
-- build plan §4.7 item 8 (docs/golf-trails/02-build-plan.md:1395-1418):
-- "private.hit_rate_limit(bucket_key, window, max) -> INSERT ... ON
-- CONFLICT ... DO UPDATE SET count = count + 1 RETURNING count" and "The
-- limits are tested in pgTAP under concurrency."

BEGIN;
SELECT plan(5);

-- S1 restricted-mode fix: private.hit_rate_limit is granted to
-- service_role only (0007) -- its real production caller. Under the
-- default harness this "worked" only because the connecting bootstrap
-- role is a superuser and bypasses the EXECUTE grant outright (the exact
-- false-pass S1 warns about); authenticate_as('service_role', ...) here
-- is the accurate caller identity.
SELECT tests.authenticate_as('service_role', '{}'::jsonb);

-- Under the max: succeeds and returns the running count.
SELECT is(
  private.hit_rate_limit('test:evidence:user-a', interval '1 hour', 60),
  1,
  'first hit in a fresh window returns count 1'
);
SELECT is(
  private.hit_rate_limit('test:evidence:user-a', interval '1 hour', 60),
  2,
  'second hit in the same window returns count 2'
);

-- At the max: the (max+1)th hit still INCREMENTS and returns the count
-- (P3c gate round 3, blocking MEDIUM 3, 0020_rate_limit_no_raise.sql) --
-- it no longer raises. A raise-on-overlimit design necessarily discards
-- the SAME statement's own increment when the transaction that call ran
-- in aborts, which is exactly how "80 rejected requests left the bucket
-- at 0" happened; the caller (privileged.ts#rateLimit.hit) now compares
-- the returned count to its own max instead of relying on the SQL layer
-- to fail the call.
SELECT is(
  private.hit_rate_limit('test:tight:user-a', interval '1 hour', 1),
  1,
  'first hit against a max=1 bucket returns count 1 (under/at the max)'
);
SELECT is(
  private.hit_rate_limit('test:tight:user-a', interval '1 hour', 1),
  2,
  'the (max+1)th hit still increments and returns count 2 -- never raises (P3c gate round 3)'
);

-- A different bucket_key is independent (per-user / per-endpoint
-- isolation, line 1401-1413's per-user/per-device/per-IP dimensions).
SELECT is(
  private.hit_rate_limit('test:evidence:user-b', interval '1 hour', 60),
  1,
  'a different bucket_key starts its own independent count'
);

SELECT * FROM finish();
ROLLBACK;
