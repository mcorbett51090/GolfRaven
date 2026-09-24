/**
 * Test-only synthetic geometry helpers. Not exported from `src/` — these
 * exist purely to build readable, controlled fixtures for the golden
 * fixtures in `fixtures.test.ts` and friends. `geo.test.ts` verifies the
 * package's own geo math independently of these helpers (using hand-
 * checked distances at the equator), so using a similar offset technique
 * here to construct fixtures is not circular for what these tests assert
 * (route-matching *outcomes*, not geo-primitive correctness).
 */
import type { LatLng, RouteFix } from "../src/index.js";

const EARTH_RADIUS_METERS = 6_371_000;

/** A plausible real-world origin (east Tennessee) so fixtures don't all
 * sit at (0, 0). */
export const ORIGIN: LatLng = { lat: 35.9, lon: -84.3 };

/** Offsets `origin` by `dxMeters` east and `dyMeters` north, using the
 * cos(lat) longitude correction so the offset is accurate regardless of
 * latitude. */
export function offset(
  origin: LatLng,
  dxMeters: number,
  dyMeters: number,
): LatLng {
  const lat0 = (origin.lat * Math.PI) / 180;
  const dLon =
    (dxMeters / (EARTH_RADIUS_METERS * Math.cos(lat0))) * (180 / Math.PI);
  const dLat = (dyMeters / EARTH_RADIUS_METERS) * (180 / Math.PI);
  return { lat: origin.lat + dLat, lon: origin.lon + dLon };
}

/** An axis-aligned rectangle centered at `origin`, `widthMeters` (east-west)
 * by `heightMeters` (north-south), as a 4-point outer ring. */
export function rectangle(
  origin: LatLng,
  widthMeters: number,
  heightMeters: number,
): LatLng[] {
  const hw = widthMeters / 2;
  const hh = heightMeters / 2;
  return [
    offset(origin, -hw, -hh),
    offset(origin, hw, -hh),
    offset(origin, hw, hh),
    offset(origin, -hw, hh),
  ];
}

/** Builds `count` fixes evenly spaced in time between `startMs` and
 * `endMs`, at the given points (points.length may differ from count —
 * points are sampled/repeated as needed by index). */
export function fixesAlong(
  points: readonly LatLng[],
  startMs: number,
  endMs: number,
): RouteFix[] {
  if (points.length === 1) {
    return [{ point: points[0]!, timestamp: startMs }];
  }
  return points.map((point, i) => ({
    point,
    timestamp: startMs + ((endMs - startMs) * i) / (points.length - 1),
  }));
}

/** Pushes `point` further away from `center`, along the center→point
 * direction, by `extraMeters`. Used to build a "drifted" fix that moves
 * consistently outward regardless of which side of a polygon it started
 * near (a fixed-axis offset would push a point on the near edge deeper
 * inside instead of further out). */
export function perturbOutward(
  center: LatLng,
  point: LatLng,
  extraMeters: number,
): LatLng {
  const lat0 = (center.lat * Math.PI) / 180;
  const dx =
    (point.lon - center.lon) *
    Math.cos(lat0) *
    (Math.PI / 180) *
    EARTH_RADIUS_METERS;
  const dy = (point.lat - center.lat) * (Math.PI / 180) * EARTH_RADIUS_METERS;
  const length = Math.hypot(dx, dy) || 1;
  const unitX = dx / length;
  const unitY = dy / length;
  return offset(point, unitX * extraMeters, unitY * extraMeters);
}

/** A closed loop of `n` points tracing the inside of `rect` (a rectangle
 * from `rectangle()`), inset by `insetMeters` so every point stays well
 * clear of the boundary — useful for a clean "route stayed inside" case. */
export function loopInsideRectangle(
  origin: LatLng,
  widthMeters: number,
  heightMeters: number,
  insetMeters: number,
  n: number,
): LatLng[] {
  const hw = widthMeters / 2 - insetMeters;
  const hh = heightMeters / 2 - insetMeters;
  const points: LatLng[] = [];
  for (let i = 0; i < n; i++) {
    const t = i / n;
    // Trace a simple rectangular perimeter path parameterized by t in [0,1).
    let x: number;
    let y: number;
    if (t < 0.25) {
      x = -hw + (t / 0.25) * (2 * hw);
      y = -hh;
    } else if (t < 0.5) {
      x = hw;
      y = -hh + ((t - 0.25) / 0.25) * (2 * hh);
    } else if (t < 0.75) {
      x = hw - ((t - 0.5) / 0.25) * (2 * hw);
      y = hh;
    } else {
      x = -hw;
      y = hh - ((t - 0.75) / 0.25) * (2 * hh);
    }
    points.push(offset(origin, x, y));
  }
  return points;
}
