# X7 — PostGIS benchmark how-to

Covers plan §10 P0 check **X7**. Pass bar (verbatim, also in `docs/p0/X7.md`): "PostGIS available **and**
p95 < 100 ms." Runnable SQL: `docs/owner/x7-postgis-benchmark.sql`.

**Measurement is pre-registered (decision 0001, Addendum B, 2026-09-23, before any X7 run is treated as the
recorded result):** p95 is measured **in-database**, as server-side execution time via `clock_timestamp()`
inside the PL/pgSQL timing loop (equivalently, per-query `EXPLAIN ANALYZE` execution time) — not client round
trip and not end-to-end from the Edge Function region. The 1,000 query points are generated so that **roughly
half fall inside a polygon and half do not** (half via `st_pointonsurface` on a randomly chosen polygon, half
uniform-random over the bbox), and each point is bound once per iteration before timing starts, never
`random()` evaluated inside the predicate. The **hit rate is reported alongside p95**.

## Prerequisite

A Supabase project must exist first — either local (`supabase start`, fastest, no account needed) or the real
P0/staging project (see `docs/owner/accounts-and-domain-checklist.md`). This check can and should be run
**locally first** (free, immediate) and then re-run against the real chosen tier once that project exists,
since the pass bar is about the *chosen Supabase tier* specifically.

## Running it

### Locally (fastest first pass)

```shell
cd /home/user/RavenGolf/golfraven
supabase start
psql "$(supabase status -o env | grep DB_URL | cut -d= -f2)" -f docs/owner/x7-postgis-benchmark.sql
```

(Exact env-var extraction depends on your `supabase` CLI version — `supabase status` prints the local
Postgres connection string; use whichever form your installed CLI gives.)

### Against the real Supabase project

```shell
psql "postgresql://postgres:<password>@<project-ref>.supabase.co:5432/postgres" \
  -f docs/owner/x7-postgis-benchmark.sql
```

Get the connection string from the Supabase dashboard → Project Settings → Database → Connection string.

## Reading the output

The script prints several result sets in order:

1. `postgis_full_version()` — confirms the extension is present and its version. If `create extension`
   fails, PostGIS is not available on this tier and X7 kills the server-side spatial approach outright,
   independent of timing.
2. An `EXPLAIN (ANALYZE, BUFFERS)` plan for one sample point-in-polygon query, run against a **literal point
   bound once via `\gset`** (not `random()` inside the predicate — a volatile function there is re-evaluated
   per candidate row and defeats index usage). Because the point is drawn from inside a real polygon
   (`st_pointonsurface`), the expected plan is **`Index Scan using course_polygon_gix`**, and this is also a
   guaranteed hit.
3. The final summary row: `n_queries`, `n_hits`, `hit_rate_pct`, `min_ms`, `p50_ms`, `p95_ms`, `p99_ms`,
   `max_ms` — computed over 1,000 independent timed point-in-polygon queries via `percentile_cont`, over a
   point set that is roughly half inside a polygon and half not (§ above).

**The pass bar reads `p95_ms` against 100.** Record `postgis_full_version()`'s output, `hit_rate_pct`, and
`p95_ms` (plus `n_queries` to confirm all 1,000 ran) in `docs/p0/X7.md`'s MEASURED VALUE, and set VERDICT to
`pass` only if both the extension check succeeded **and** `p95_ms < 100`. A hit rate near 0% or near 100%
means the point generation did not work as intended and the run should not be recorded as the result.

## Alternative: pgbench custom script

If you prefer `pgbench` over the PL/pgSQL timing loop in the `.sql` file, an equivalent custom script is:

```sql
-- pip_query.sql (pgbench custom script)
\set lon random(-170, -52)
\set lat random(15, 72)
select id from x7_bench.course_polygon
where st_contains(geom, st_setsrid(st_makepoint(:lon, :lat), 4326))
limit 1;
```

```shell
pgbench -n -f pip_query.sql -T 30 --progress-timestamp -c 1 -j 1 "$DATABASE_URL"
```

Note `pgbench`'s built-in `random()` needs integer bounds, so this variant loses sub-degree precision
compared to the `.sql` file's `random()`-based floats — it's a coarser but still representative substitute.
`pgbench` reports latency **average**, not p95, directly; add `--log` and post-process the per-transaction
log for a true p95 if you use this path instead of the provided script.

## Local proxy run (not the Supabase tier) — 2026-09-23

Run against a local PostgreSQL 16.13 + PostGIS 3.4.2 instance (not Supabase, and not a substitute for the
real chosen tier — this is a proxy sanity check of the fixed script only) after the S1 fixes above:

```
postgis_full_version(): POSTGIS="3.4.2 c19ce56" [EXTENSION] PGSQL="160" GEOS="3.12.1-CAPI-1.18.1" ...

EXPLAIN (sample point, bound via \gset):
 Limit  (cost=0.14..20.66 rows=1 width=4) (actual time=0.180..0.181 rows=1 loops=1)
   ->  Index Scan using course_polygon_gix on course_polygon  (cost=0.14..20.66 rows=1 width=4)
         (actual time=0.180..0.180 rows=1 loops=1)
         Index Cond: (geom ~ '...'::geometry)
         Filter: st_contains(geom, '...'::geometry)
 Execution Time: 0.231 ms

 n_queries | n_hits | hit_rate_pct | min_ms | p50_ms | p95_ms | p99_ms | max_ms
-----------+--------+--------------+--------+--------+--------+--------+--------
      1000 |    500 |         50.0 |  0.006 |  0.021 |  0.032 |  0.058 |  0.195
```

The plan now shows `Index Scan using course_polygon_gix` as expected (previously a `Seq Scan`, per gate
review S1(b)), the hit rate is 50.0% (previously 0%, per S1(a)), and p95 = 0.032 ms, comfortably under the
100 ms bar. This is a local-hardware proxy result, not the P0/staging Supabase tier's number — re-run against
that tier once it exists, per the "Running it" section above, and record that run (not this one) in
`docs/p0/X7.md`'s MEASURED VALUE.

## Re-running / cleanup

The script is idempotent (`drop schema if exists x7_bench cascade` at the top), so it can be re-run freely.
The final `drop schema x7_bench cascade;` line is commented out by default so the benchmark data and timings
table stay inspectable after the run — uncomment it to clean up.
