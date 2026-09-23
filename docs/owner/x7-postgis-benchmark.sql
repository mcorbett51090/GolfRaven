-- x7-postgis-benchmark.sql
-- Covers plan §10 P0 check X7: "PostGIS on the chosen Supabase tier + a point-in-polygon query over ~2k
-- polygons." Pass bar (verbatim): "PostGIS available AND p95 < 100 ms."
--
-- Run against the P0 Supabase project (local `supabase start` for a first pass, then the real staging/prod
-- tier once created — see docs/owner/accounts-and-domain-checklist.md). Uses `psql` throughout.
--
-- Usage:
--   psql "$DATABASE_URL" -f docs/owner/x7-postgis-benchmark.sql
--
-- This script is idempotent: it drops and recreates its own benchmark schema each run, and touches nothing
-- outside `x7_bench.*`.

-- =====================================================================================
-- 1. Confirm PostGIS is available (first half of the pass bar)
-- =====================================================================================
create extension if not exists postgis;

select postgis_full_version();  -- record this in docs/p0/X7.md's MEASURED VALUE

-- =====================================================================================
-- 2. Synthetic ~2,000-polygon table, scattered across the US+CA bounding box
-- =====================================================================================
-- US+CA rough bounding box (lon/lat, WGS84): west -170 (western Alaska) .. east -52 (eastern Canada),
-- south 15 (southern tip of the pilot-relevant US mainland/Hawaii is out of scope here) .. north 72
-- (northern Canada). This is deliberately generous, not a tight fit -- it only needs to spread ~2k
-- synthetic "course" polygons at a density comparable to the real catalog, not model real coastlines.

drop schema if exists x7_bench cascade;
create schema x7_bench;

-- 2,000 random points across the bbox, each buffered ~150m (a plausible single-course footprint radius,
-- matching the plan's radius-fallback circle idea in §4.2) to make a polygon, mirroring
-- catalog_facility / catalog_course geometry at pilot-adjacent scale (X5 measures the real eventual count).
-- Uses the geography type for the buffer (accurate in meters at any latitude, including the northern
-- part of the bbox, where a fixed Web-Mercator-meter buffer would distort badly), then casts back to
-- geometry for the GiST index and st_contains query below.
create table x7_bench.course_polygon as
select
  gs as id,
  st_buffer(
    st_setsrid(
      st_makepoint(
        -170 + random() * (-52 - (-170)),   -- lon in [-170, -52]
        15   + random() * (72 - 15)          -- lat in [15, 72]
      ),
      4326
    )::geography,
    150                                      -- ~150m radius polygon, accurate in meters via geography
  )::geometry(polygon, 4326) as geom
from generate_series(1, 2000) as gs;

create index course_polygon_gix on x7_bench.course_polygon using gist (geom);

analyze x7_bench.course_polygon;

-- =====================================================================================
-- 3. Point-in-polygon query shape (what the app's evidence-scoring path actually runs:
--    "is this GPS fix inside a course polygon?" — cf. plan §7.4 insideRatio / §4.5 evidence scoring)
-- =====================================================================================
-- Single-query sanity check, returned as an example. The query point is materialized ONCE via \gset
-- into a literal WKT constant -- a volatile random() call embedded directly in the predicate is
-- re-evaluated per candidate row, which defeats GiST index usage and produces a Seq Scan on every
-- run (gate review S1(b)). With a bound literal point the planner can and does use the index.
select st_asewkt(st_pointonsurface(geom)) as sample_point_wkt
from x7_bench.course_polygon
order by id
limit 1 \gset

-- Expected plan: Index Scan using course_polygon_gix on course_polygon (the point is drawn from
-- inside the polygon's surface, so this is also a guaranteed hit).
explain (analyze, buffers, format text)
select id
from x7_bench.course_polygon
where st_contains(geom, :'sample_point_wkt'::geometry)
limit 1;

-- =====================================================================================
-- 4. Timed loop over 1,000 point-in-polygon queries, recording per-query latency and hit/miss
-- =====================================================================================
-- This uses a PL/pgSQL loop with clock_timestamp() (wall-clock, unaffected by transaction snapshotting)
-- to time 1,000 independent point-in-polygon lookups, and reports p50/p95/p99/max in milliseconds
-- plus the hit rate. This is the runnable alternative to a pgbench custom script -- use whichever is
-- easier in your environment; both measure the same thing.
--
-- Query points are generated so that roughly HALF fall inside a polygon and half do not (decision
-- 0001, Addendum B / gate review S1(a)): for even i, draw a point from the interior of a randomly
-- chosen polygon via st_pointonsurface (a real "near a course" fix); for odd i, draw a uniform random
-- point over the bbox (a real "nowhere near a course" fix). This measures both the index-scan-then-
-- exact-match path and the empty-probe path, instead of only the latter. In every iteration the point
-- is computed and bound to a plpgsql variable BEFORE clock_timestamp() starts -- the timed predicate
-- itself never evaluates random(), so it is a bound constant per query and can use the GiST index.

drop table if exists x7_bench.timings;
create table x7_bench.timings (run_id int, ms double precision, hit boolean);

do $$
declare
  i int;
  t0 timestamptz;
  t1 timestamptz;
  pt geometry;
  hit_id int;
  rand_poly_id int;
begin
  for i in 1..1000 loop
    if i % 2 = 0 then
      -- inside-polygon draw: pick a random polygon, take a point from its interior
      rand_poly_id := 1 + floor(random() * 2000)::int;
      select st_pointonsurface(geom) into pt
      from x7_bench.course_polygon
      where id = rand_poly_id;
    else
      -- outside/random draw: uniform random point over the full bbox
      pt := st_setsrid(
        st_makepoint(
          -170 + random() * (-52 - (-170)),
          15   + random() * (72 - 15)
        ),
        4326
      );
    end if;

    t0 := clock_timestamp();

    select id into hit_id
    from x7_bench.course_polygon
    where st_contains(geom, pt)
    limit 1;

    t1 := clock_timestamp();

    insert into x7_bench.timings (run_id, ms, hit)
    values (i, extract(epoch from (t1 - t0)) * 1000.0, hit_id is not null);
  end loop;
end $$;

-- =====================================================================================
-- 5. Read p50 / p95 / p99 / max and the hit rate — the pass bar is p95 < 100 ms
-- =====================================================================================
select
  count(*)                                                            as n_queries,
  sum(case when hit then 1 else 0 end)                                as n_hits,
  round(100.0 * sum(case when hit then 1 else 0 end) / count(*), 1)   as hit_rate_pct,
  round(min(ms)::numeric, 3)                                          as min_ms,
  round(percentile_cont(0.50) within group (order by ms)::numeric, 3) as p50_ms,
  round(percentile_cont(0.95) within group (order by ms)::numeric, 3) as p95_ms,
  round(percentile_cont(0.99) within group (order by ms)::numeric, 3) as p99_ms,
  round(max(ms)::numeric, 3)                                          as max_ms
from x7_bench.timings;

-- Record: postgis_full_version() output, n_queries (should be 1000), hit_rate_pct, and p95_ms
-- (measured IN-DATABASE, server-side execution time -- decision 0001 Addendum B) into
-- docs/p0/X7.md's MEASURED VALUE. VERDICT = pass iff PostGIS extension created successfully AND
-- p95_ms < 100.

-- =====================================================================================
-- 6. Cleanup (optional -- comment out to keep the benchmark schema for re-runs/inspection)
-- =====================================================================================
-- drop schema x7_bench cascade;
