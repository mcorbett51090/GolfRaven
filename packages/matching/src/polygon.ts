/**
 * Multipolygon-with-holes geometry, built once per candidate per match and
 * reused across every fix (build plan gate fix: "project each polygon
 * once per match" / bounding-box prefilter).
 *
 * `geo.ts` holds the single-ring primitives (kept stable — `probe2.mjs`
 * and `geo.test.ts` call `distanceToPolygonMeters` etc. directly with a
 * flat `LatLng[]`). This module builds on those primitives to support:
 *  - a polygon with holes (`PolygonWithHoles`) — a point inside a hole is
 *    outside the polygon;
 *  - a multipolygon (`MultiPolygon`) — several such polygons, e.g. a
 *    composite course whose two nines don't touch;
 *  - preparing a candidate's geometry once (project every ring to the
 *    local plane, compute a bounding box) so matching an 18,000-fix route
 *    against it doesn't re-derive a projector and re-project every ring
 *    vertex on every single fix.
 */
import {
  distancePointToSegment,
  distanceToRingBoundaryXY,
  makeProjector,
  pointInPolygonXY,
  roundTo,
  type XY,
} from "./geo.js";
import type {
  LatLng,
  MultiPolygon,
  PolygonInput,
  PolygonWithHoles,
  Ring,
} from "./types.js";

function isLatLng(value: unknown): value is LatLng {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as { lat?: unknown }).lat === "number" &&
    typeof (value as { lon?: unknown }).lon === "number"
  );
}

/**
 * Normalizes any of the three accepted `PolygonInput` shapes into the
 * canonical `MultiPolygon` (an array of polygons, each an outer ring
 * followed by its holes), by inspecting nesting depth at runtime:
 *  - `input[0]` is itself a `{lat, lon}` → `input` is a single outer ring
 *    (`LatLng[]`), wrapped as one polygon with no holes.
 *  - `input[0]` is an array whose own first element is a `{lat, lon}` →
 *    `input` is one polygon's rings (`Ring[]`, outer + holes).
 *  - otherwise → `input` is already a `MultiPolygon`.
 * An empty `input` normalizes to `[]` (no geometry).
 */
export function normalizePolygon(input: PolygonInput): MultiPolygon {
  if (input.length === 0) return [];
  const first = input[0] as unknown;
  if (isLatLng(first)) {
    return [[input as Ring]];
  }
  const firstArray = first as unknown[];
  if (firstArray.length === 0 || isLatLng(firstArray[0])) {
    return [input as PolygonWithHoles];
  }
  return input as MultiPolygon;
}

interface BBox {
  minX: number;
  maxX: number;
  minY: number;
  maxY: number;
}

function ringBBox(ring: readonly XY[]): BBox {
  let minX = Infinity;
  let maxX = -Infinity;
  let minY = Infinity;
  let maxY = -Infinity;
  for (const p of ring) {
    if (p.x < minX) minX = p.x;
    if (p.x > maxX) maxX = p.x;
    if (p.y < minY) minY = p.y;
    if (p.y > maxY) maxY = p.y;
  }
  return { minX, maxX, minY, maxY };
}

function unionBBox(a: BBox, b: BBox): BBox {
  return {
    minX: Math.min(a.minX, b.minX),
    maxX: Math.max(a.maxX, b.maxX),
    minY: Math.min(a.minY, b.minY),
    maxY: Math.max(a.maxY, b.maxY),
  };
}

export interface PreparedPolygonGeometry {
  kind: "polygon";
  /** Every polygon's rings, pre-projected once into the shared local
   * plane centered on `origin`. */
  multi: XY[][][];
  origin: LatLng;
  bbox: BBox;
}

/** Projects `multi` once into a single local plane (centered on the first
 * outer ring's first vertex — any stable, geometry-local point works,
 * since this projector is reused consistently for every point tested
 * against it) and computes its bounding box. */
export function preparePolygonGeometry(
  input: PolygonInput,
): PreparedPolygonGeometry | undefined {
  const multiLatLng = normalizePolygon(input);
  const firstRing = multiLatLng[0]?.[0];
  if (!firstRing || firstRing.length < 3) return undefined;
  const origin = firstRing[0]!;
  const projector = makeProjector(origin);
  const multi = multiLatLng.map((rings) =>
    rings.map((ring) => ring.map((p) => projector.toXY(p))),
  );
  let bbox: BBox | undefined;
  for (const rings of multi) {
    const outerBBox = ringBBox(rings[0]!);
    bbox = bbox ? unionBBox(bbox, outerBBox) : outerBBox;
  }
  if (!bbox) return undefined;
  return { kind: "polygon", multi, origin, bbox };
}

/** True if `point` is inside the polygon's outer ring and not inside any
 * of its holes, for at least one polygon in the multipolygon. */
function isInsidePreparedNoBuffer(
  pointXY: XY,
  prepared: PreparedPolygonGeometry,
): boolean {
  for (const rings of prepared.multi) {
    const outer = rings[0]!;
    if (!pointInPolygonXY(pointXY, outer)) continue;
    let inHole = false;
    for (let i = 1; i < rings.length; i++) {
      if (pointInPolygonXY(pointXY, rings[i]!)) {
        inHole = true;
        break;
      }
    }
    if (!inHole) return true;
  }
  return false;
}

function minDistanceToAnyRingXY(
  pointXY: XY,
  prepared: PreparedPolygonGeometry,
): number {
  let min = Infinity;
  for (const rings of prepared.multi) {
    for (const ring of rings) {
      const d = distanceToRingBoundaryXY(pointXY, ring);
      if (d < min) min = d;
      if (min === 0) return 0;
    }
  }
  return min;
}

/**
 * True if `point` is inside the prepared geometry, or within
 * `bufferMeters` of ANY ring's edge (outer boundary or hole boundary —
 * GPS noise near a hole's edge is symmetric, so the buffer forgives it
 * from either side; see `README.md` for this design choice). Uses the
 * bounding box (expanded by the buffer) to reject far-away points
 * cheaply, without walking every ring.
 */
export function isInsidePreparedWithBuffer(
  point: LatLng,
  prepared: PreparedPolygonGeometry,
  bufferMeters: number,
): boolean {
  const projector = makeProjector(prepared.origin);
  const pointXY = projector.toXY(point);
  const buffer = Math.max(0, bufferMeters);
  const { bbox } = prepared;
  if (
    pointXY.x < bbox.minX - buffer ||
    pointXY.x > bbox.maxX + buffer ||
    pointXY.y < bbox.minY - buffer ||
    pointXY.y > bbox.maxY + buffer
  ) {
    return false;
  }
  if (isInsidePreparedNoBuffer(pointXY, prepared)) return true;
  if (buffer === 0) return false;
  return (
    roundTo(minDistanceToAnyRingXY(pointXY, prepared), 2) <= roundTo(buffer, 2)
  );
}

function bboxDistanceXY(point: XY, bbox: BBox): number {
  const dx = Math.max(bbox.minX - point.x, 0, point.x - bbox.maxX);
  const dy = Math.max(bbox.minY - point.y, 0, point.y - bbox.maxY);
  return Math.hypot(dx, dy);
}

/**
 * True if `point` is inside the prepared geometry or within
 * `thresholdMeters` of it — the same test `distanceToPreparedMeters`
 * would answer, but bbox-prefiltered so a candidate whose geometry is
 * nowhere near `point` is rejected in O(1) without walking any ring
 * (build plan gate fix: bounding-box prefilter, for the 3 km candidate
 * search over many far-away candidates).
 */
export function isWithinDistanceOfPrepared(
  point: LatLng,
  prepared: PreparedPolygonGeometry,
  thresholdMeters: number,
): boolean {
  const projector = makeProjector(prepared.origin);
  const pointXY = projector.toXY(point);
  const threshold = Math.max(0, thresholdMeters);
  // The bbox distance is a lower bound on the true distance to the
  // polygon (the polygon is contained in its bbox), so if even the bbox
  // is farther than the threshold, the polygon certainly is too.
  if (bboxDistanceXY(pointXY, prepared.bbox) > threshold) return false;
  if (isInsidePreparedNoBuffer(pointXY, prepared)) return true;
  return (
    roundTo(minDistanceToAnyRingXY(pointXY, prepared), 2) <=
    roundTo(threshold, 2)
  );
}

/** Distance in meters from `point` to the prepared geometry: 0 if inside
 * (per `isInsidePreparedNoBuffer`), otherwise the distance to the nearest
 * ring edge across every polygon (used for the 3 km candidate search, not
 * for the buffered inside test). */
export function distanceToPreparedMeters(
  point: LatLng,
  prepared: PreparedPolygonGeometry,
): number {
  const projector = makeProjector(prepared.origin);
  const pointXY = projector.toXY(point);
  if (isInsidePreparedNoBuffer(pointXY, prepared)) return 0;
  return minDistanceToAnyRingXY(pointXY, prepared);
}
