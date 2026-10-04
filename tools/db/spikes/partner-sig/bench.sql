-- tools/db/spikes/partner-sig/bench.sql
--
-- The timing and correctness harness for partner_sig_spike.sql. Load the spike functions and the generated vectors first (run.sh does), then
--   psql -v runs=15 -f bench.sql
--
-- Every call's verdict is compared with the vector's `expect`; every call is timed with clock_timestamp() around the verify call alone (the whole
-- end-to-end verify: bytes -> integers, the structural checks, the arithmetic, the comparison). Run 0 of each vector is a warm-up and is reported
-- apart; statistics use runs 1..N. The pass criterion of the design (PA-0c, section 12, slice S0) is "verification under 200 ms and no extension",
-- judged here on the WORST single warm call (not the mean) over every vector a valid signature can produce, plus synthetic worst cases: ES256 with
-- both scalars all-ones (the most additions Shamir's trick can need) and RS256 at the 4096-bit ceiling the verifier accepts.

\if :{?runs}
\else
\set runs 15
\endif

SELECT set_config('spike.runs', :'runs', false) \gset

TRUNCATE spike_sig.timing;

CREATE OR REPLACE FUNCTION spike_sig.run_vector(v spike_sig.vector) RETURNS boolean
LANGUAGE sql STABLE AS $$
  SELECT CASE v.alg
    WHEN 'ES256' THEN spike_sig.es256_verify(v.k1, v.k2, v.msg, v.sig)
    WHEN 'RS256' THEN spike_sig.rs256_verify(v.k1, v.k2, v.msg, v.sig)
  END
$$;

DO $bench$
DECLARE
  v    spike_sig.vector;
  r    int;
  t0   timestamptz;
  t1   timestamptz;
  out  boolean;
  runs int := current_setting('spike.runs')::int;
BEGIN
  FOR v IN SELECT * FROM spike_sig.vector ORDER BY id LOOP
    FOR r IN 0 .. runs LOOP
      t0 := clock_timestamp();
      out := spike_sig.run_vector(v);
      t1 := clock_timestamp();
      INSERT INTO spike_sig.timing (vector_id, run, verdict, ms)
      VALUES (v.id, r, out, extract(epoch FROM (t1 - t0)) * 1000.0);
    END LOOP;
  END LOOP;
END
$bench$;

-- synthetic worst case for ES256: every bit of both scalars set, so every one of the 256 steps does a double AND an add of G+Q
CREATE TABLE spike_sig.worst (what text, run int, ms double precision);
DO $worst$
DECLARE
  q    spike_sig.vector;
  qx   numeric; qy numeric;
  t0   timestamptz; t1 timestamptz;
  all1 numeric := 2::numeric ^ 256 - 1;
  r    int;
  runs int := current_setting('spike.runs')::int;
  dummy spike_sig.jpoint;
BEGIN
  SELECT * INTO q FROM spike_sig.vector WHERE alg = 'ES256' AND expect AND label = 'valid' ORDER BY id LIMIT 1;
  qx := spike_sig.os2ip(q.k1);
  qy := spike_sig.os2ip(q.k2);
  FOR r IN 0 .. runs LOOP
    t0 := clock_timestamp();
    dummy := spike_sig.p256_shamir(all1, all1, qx, qy);
    t1 := clock_timestamp();
    INSERT INTO spike_sig.worst VALUES ('ES256 scalar mult, both scalars all-ones (256 doublings + 256 additions)', r, extract(epoch FROM (t1 - t0)) * 1000.0);
  END LOOP;
END
$worst$;

\echo
\echo '== environment'
SELECT version() AS postgres, current_setting('jit') AS jit, (SELECT count(*) FROM pg_extension WHERE extname <> 'plpgsql') AS extensions_installed,
       (SELECT count(*) FROM spike_sig.vector) AS vectors, :runs AS timed_runs_per_vector;

\echo
\echo '== correctness: every call agrees with its vector (a disagreement here invalidates the timings below)'
SELECT v.alg, count(DISTINCT v.id) AS vectors, count(*) AS calls, sum((t.verdict IS DISTINCT FROM v.expect)::int) AS wrong_verdicts
FROM spike_sig.vector v JOIN spike_sig.timing t ON t.vector_id = v.id
GROUP BY v.alg ORDER BY v.alg;

\echo
\echo '== per vector: expected verdict, observed, warm timing (ms)'
SELECT v.id, v.alg, left(v.label, 76) AS label, v.expect, bool_and(t.verdict = v.expect) AS agrees,
       round(min(t.ms) FILTER (WHERE t.run > 0)::numeric, 1) AS min_ms,
       round((percentile_cont(0.5) WITHIN GROUP (ORDER BY t.ms) FILTER (WHERE t.run > 0))::numeric, 1) AS median_ms,
       round(max(t.ms) FILTER (WHERE t.run > 0)::numeric, 1) AS max_ms
FROM spike_sig.vector v JOIN spike_sig.timing t ON t.vector_id = v.id
GROUP BY v.id, v.alg, v.label, v.expect ORDER BY v.id;

\echo
\echo '== cold: the very first call in this backend (function compilation included) and the first call of each algorithm'
SELECT v.alg, v.label, round(t.ms::numeric, 1) AS cold_ms
FROM spike_sig.timing t JOIN spike_sig.vector v ON v.id = t.vector_id
WHERE t.run = 0 AND v.id IN (SELECT min(id) FROM spike_sig.vector GROUP BY alg)
ORDER BY v.id;

\echo
\echo '== timing of the signatures that VERIFY (warm, ms) - what a legitimate sign-in costs'
SELECT v.alg, count(*) AS calls,
       round(min(t.ms)::numeric, 1) AS min_ms,
       round((percentile_cont(0.5) WITHIN GROUP (ORDER BY t.ms))::numeric, 1) AS median_ms,
       round((percentile_cont(0.95) WITHIN GROUP (ORDER BY t.ms))::numeric, 1) AS p95_ms,
       round(max(t.ms)::numeric, 1) AS max_ms
FROM spike_sig.vector v JOIN spike_sig.timing t ON t.vector_id = v.id
WHERE v.expect AND t.run > 0 AND v.label NOT LIKE '%4096%'
GROUP BY v.alg ORDER BY v.alg;

\echo
\echo '== timing of the signatures that are REFUSED after the arithmetic ran (warm, ms) - what a forged sign-in costs the database'
SELECT v.alg, count(*) AS calls, round(min(t.ms)::numeric, 1) AS min_ms,
       round((percentile_cont(0.5) WITHIN GROUP (ORDER BY t.ms))::numeric, 1) AS median_ms, round(max(t.ms)::numeric, 1) AS max_ms
FROM spike_sig.vector v JOIN spike_sig.timing t ON t.vector_id = v.id
WHERE NOT v.expect AND t.run > 0 AND v.label ~ '(bit flipped|another authenticator|SHA-384|4 garbage|0x00 byte inside|block type)'
GROUP BY v.alg ORDER BY v.alg;

\echo
\echo '== worst cases (warm, ms)'
SELECT what, count(*) AS calls, round(min(ms)::numeric, 1) AS min_ms, round((percentile_cont(0.5) WITHIN GROUP (ORDER BY ms))::numeric, 1) AS median_ms,
       round(max(ms)::numeric, 1) AS max_ms
FROM spike_sig.worst WHERE run > 0 GROUP BY what
UNION ALL
SELECT 'RS256 4096-bit modulus (valid signature)', count(*), round(min(t.ms)::numeric, 1), round((percentile_cont(0.5) WITHIN GROUP (ORDER BY t.ms))::numeric, 1), round(max(t.ms)::numeric, 1)
FROM spike_sig.vector v JOIN spike_sig.timing t ON t.vector_id = v.id WHERE v.label LIKE '%4096%' AND t.run > 0;

-- the verdict, one row per algorithm: PASS needs (1) every verdict correct, (2) the worst warm call of a signature that verifies under 200 ms,
-- (3) the synthetic worst case (ES256 all-ones scalars; RS256 4096-bit) under 200 ms, (4) no extension installed.
CREATE VIEW spike_sig.verdict AS
WITH ok AS (
  SELECT v.alg, bool_and(t.verdict = v.expect) AS verdicts_ok,
         max(t.ms) FILTER (WHERE v.expect AND t.run > 0 AND v.label NOT LIKE '%4096%') AS worst_valid_ms
  FROM spike_sig.vector v JOIN spike_sig.timing t ON t.vector_id = v.id GROUP BY v.alg
), worst AS (
  SELECT 'ES256' AS alg, max(ms) AS worst_ms FROM spike_sig.worst WHERE run > 0
  UNION ALL
  SELECT 'RS256', max(t.ms) FROM spike_sig.vector v JOIN spike_sig.timing t ON t.vector_id = v.id WHERE v.label LIKE '%4096%' AND t.run > 0
)
SELECT ok.alg, ok.verdicts_ok, round(ok.worst_valid_ms::numeric, 1) AS worst_valid_ms, round(worst.worst_ms::numeric, 1) AS worst_case_ms,
       (SELECT count(*) FROM pg_extension WHERE extname <> 'plpgsql') AS extensions,
       (ok.verdicts_ok AND ok.worst_valid_ms < 200 AND worst.worst_ms < 200 AND (SELECT count(*) FROM pg_extension WHERE extname <> 'plpgsql') = 0) AS pass
FROM ok JOIN worst USING (alg);

\echo
\echo '== VERDICT against the 200 ms criterion'
SELECT alg, CASE WHEN pass THEN 'PASS' ELSE 'FAIL' END AS result, verdicts_ok, worst_valid_ms, worst_case_ms, extensions FROM spike_sig.verdict ORDER BY alg;
