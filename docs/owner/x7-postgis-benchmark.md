# X7 — PostGIS benchmark how-to

Covers plan §10 P0 check **X7**. Pass bar (verbatim, also in `docs/p0/X7.md`): "PostGIS available **and**
p95 < 100 ms." Runnable SQL: `docs/owner/x7-postgis-benchmark.sql`.

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
2. An `EXPLAIN (ANALYZE, BUFFERS)` plan for one sample point-in-polygon query — useful to confirm the GiST
   index (`course_polygon_gix`) is actually being used (look for `Index Scan using course_polygon_gix` rather
   than a full `Seq Scan`; a seq scan on only ~2k rows may still be fast, but would not represent behavior at
   the real eventual scale from X5's `N_osm`).
3. The final summary row: `n_queries`, `min_ms`, `p50_ms`, `p95_ms`, `p99_ms`, `max_ms` — computed over 1,000
   independent timed point-in-polygon queries via `percentile_cont`.

**The pass bar reads `p95_ms` against 100.** Record `postgis_full_version()`'s output and `p95_ms` (plus
`n_queries` to confirm all 1,000 ran) in `docs/p0/X7.md`'s MEASURED VALUE, and set VERDICT to `pass` only if
both the extension check succeeded **and** `p95_ms < 100`.

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

## Re-running / cleanup

The script is idempotent (`drop schema if exists x7_bench cascade` at the top), so it can be re-run freely.
The final `drop schema x7_bench cascade;` line is commented out by default so the benchmark data and timings
table stay inspectable after the run — uncomment it to clean up.
