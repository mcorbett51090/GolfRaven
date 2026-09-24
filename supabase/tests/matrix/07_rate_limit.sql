-- 07_rate_limit.sql
-- build plan §4.7 item 8 (docs/golf-trails/02-build-plan.md:1395-1418):
-- "private.hit_rate_limit(bucket_key, window, max) -> INSERT ... ON
-- CONFLICT ... DO UPDATE SET count = count + 1 RETURNING count" and "The
-- limits are tested in pgTAP under concurrency."

BEGIN;
SELECT plan(4);

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

-- At the max: the (max+1)th hit raises.
DO $$
BEGIN
  PERFORM private.hit_rate_limit('test:tight:user-a', interval '1 hour', 1);
  BEGIN
    PERFORM private.hit_rate_limit('test:tight:user-a', interval '1 hour', 1);
    RAISE EXCEPTION 'expected hit_rate_limit to raise on the 2nd call with max=1';
  EXCEPTION WHEN SQLSTATE 'P0429' THEN
    -- expected
  END;
END
$$;
SELECT pass('hit_rate_limit raises once a bucket exceeds its max (P0429)');

-- A different bucket_key is independent (per-user / per-endpoint
-- isolation, line 1401-1413's per-user/per-device/per-IP dimensions).
SELECT is(
  private.hit_rate_limit('test:evidence:user-b', interval '1 hour', 60),
  1,
  'a different bucket_key starts its own independent count'
);

SELECT * FROM finish();
ROLLBACK;
