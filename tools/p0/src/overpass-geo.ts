/**
 * Pure geometry helpers for `x5-overpass`'s match rule (`docs/p0/X5.md`
 * "Match rule", pre-registered before any query is run — implemented
 * literally, not reinterpreted).
 */

export interface LatLon {
  lat: number;
  lon: number;
}

const EARTH_RADIUS_METERS = 6371000;

/** Great-circle distance in meters (haversine). */
export function haversineMeters(a: LatLon, b: LatLon): number {
  const toRad = (deg: number) => (deg * Math.PI) / 180;
  const dLat = toRad(b.lat - a.lat);
  const dLon = toRad(b.lon - a.lon);
  const lat1 = toRad(a.lat);
  const lat2 = toRad(b.lat);
  const h =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(lat1) * Math.cos(lat2) * Math.sin(dLon / 2) ** 2;
  return 2 * EARTH_RADIUS_METERS * Math.asin(Math.min(1, Math.sqrt(h)));
}

/** Standard ray-casting point-in-polygon test. `ring` is treated as a
 * closed polygon (first/last point need not be identical). */
export function pointInPolygon(point: LatLon, ring: LatLon[]): boolean {
  let inside = false;
  for (let i = 0, j = ring.length - 1; i < ring.length; j = i++) {
    const pi = ring[i];
    const pj = ring[j];
    if (!pi || !pj) continue;
    const xi = pi.lon;
    const yi = pi.lat;
    const xj = pj.lon;
    const yj = pj.lat;
    const intersects =
      yi > point.lat !== yj > point.lat &&
      point.lon < ((xj - xi) * (point.lat - yi)) / (yj - yi) + xi;
    if (intersects) inside = !inside;
  }
  return inside;
}

/** Bounding box (south, west, north, east) around a center point, sized by
 * a radius in meters. This is only a *query-fetch* window — how wide a net
 * to cast for Overpass candidates — not itself a pass/fail parameter; the
 * pre-registered pass/fail parameter is the match rule applied to whatever
 * candidates come back (containment, or 500 m name-match). Default radius
 * is documented in `x5-overpass.ts` / README, not X5.md, since X5.md does
 * not pre-register a fetch-window size (only the 500 m name-match radius,
 * which is applied separately in `matchCourse`). */
export function boundingBox(
  center: LatLon,
  radiusMeters: number,
): { south: number; west: number; north: number; east: number } {
  const latDelta = radiusMeters / 111320;
  const lonDelta =
    radiusMeters / (111320 * Math.cos((center.lat * Math.PI) / 180));
  return {
    south: center.lat - latDelta,
    west: center.lon - lonDelta,
    north: center.lat + latDelta,
    east: center.lon + lonDelta,
  };
}

/** Centroid of a ring — kept only as a general-purpose helper (no longer
 * used by the name-match distance test as of decision 0001 Addendum F /
 * gate finding B-2, which measures distance to the polygon itself, not to
 * a centroid). Plain arithmetic mean. */
export function ringCentroid(ring: LatLon[]): LatLon {
  const sum = ring.reduce(
    (acc, p) => ({ lat: acc.lat + p.lat, lon: acc.lon + p.lon }),
    {
      lat: 0,
      lon: 0,
    },
  );
  return { lat: sum.lat / ring.length, lon: sum.lon / ring.length };
}

// ---------------------------------------------------------------------------
// Relation (multipolygon) outer-ring assembly — gate finding B-1
// ---------------------------------------------------------------------------

/** A relation member as Overpass `out geom` reports it: `way` members carry
 * their own `geometry`; `node` members (rare on a `leisure=golf_course`
 * relation) carry none and are ignored here. */
export interface OverpassMember {
  type: "way" | "node" | "relation";
  ref: number;
  role: string;
  geometry?: LatLon[];
}

const RING_JOIN_EPSILON_DEG = 1e-9;

function samePoint(a: LatLon, b: LatLon): boolean {
  return (
    Math.abs(a.lat - b.lat) < RING_JOIN_EPSILON_DEG &&
    Math.abs(a.lon - b.lon) < RING_JOIN_EPSILON_DEG
  );
}

/**
 * Joins a set of open/closed line segments (as Overpass returns them for
 * each `way` member of a multipolygon relation) end-to-end into closed
 * rings, matching shared endpoints. A `leisure=golf_course` relation's
 * outer boundary is very often split across more than one `way` member
 * (gate finding B-1's "split outer ring" case) — each member is just one
 * arc of the boundary, not a closed polygon on its own.
 *
 * Best-effort: a segment is reversed if that is what lets it extend the
 * ring being built. Segments that never close into a ring (a genuinely
 * incomplete/malformed relation) are still returned as open chains — the
 * caller's `pointInPolygon`/distance math treats any ring, closed or not,
 * as an implicitly-closed polygon (`pointInPolygon`'s own doc), so a
 * near-complete outer ring still works for containment/distance purposes.
 */
export function joinSegmentsIntoRings(segments: LatLon[][]): LatLon[][] {
  const remaining = segments.filter((s) => s.length >= 2).map((s) => [...s]);
  const rings: LatLon[][] = [];

  while (remaining.length > 0) {
    let ring = remaining.shift()!;
    let extended = true;
    while (extended && !samePoint(ring[0]!, ring[ring.length - 1]!)) {
      extended = false;
      for (let i = 0; i < remaining.length; i += 1) {
        const seg = remaining[i]!;
        const ringEnd = ring[ring.length - 1]!;
        if (samePoint(seg[0]!, ringEnd)) {
          ring = ring.concat(seg.slice(1));
        } else if (samePoint(seg[seg.length - 1]!, ringEnd)) {
          ring = ring.concat([...seg].reverse().slice(1));
        } else if (samePoint(seg[0]!, ring[0]!)) {
          ring = seg.slice(1).reverse().concat(ring);
        } else if (samePoint(seg[seg.length - 1]!, ring[0]!)) {
          ring = seg.slice(0, -1).concat(ring);
        } else {
          continue;
        }
        remaining.splice(i, 1);
        extended = true;
        break;
      }
    }
    rings.push(ring);
  }
  return rings;
}

/**
 * Resolves an Overpass element (way OR relation) to its **outer-ring**
 * polygon(s) only — decision 0001 Addendum F is explicit: "a
 * `leisure=golf_course` way or relation (outer-ring geometry)". Inner
 * (hole) rings are deliberately not subtracted; a point inside a relation's
 * outer boundary counts as inside, full stop, matching the addendum
 * literally rather than the gate report's broader "assemble inner rings
 * too" suggestion.
 *
 * A `way` element's own `geometry` is returned as a single ring. A
 * `relation` element's outer ring(s) are assembled from its `outer`-role
 * `way` members' geometries (gate finding B-1) — Overpass `out geom` puts a
 * relation's geometry under `members[].geometry`, never a top-level
 * `geometry`.
 */
export function resolveOuterRings(el: {
  type: "way" | "relation";
  geometry?: LatLon[];
  members?: OverpassMember[];
}): LatLon[][] {
  if (el.type === "way") {
    return el.geometry && el.geometry.length >= 3 ? [el.geometry] : [];
  }
  const members = el.members ?? [];
  let outerMembers = members.filter(
    (m) =>
      m.type === "way" &&
      m.role === "outer" &&
      m.geometry &&
      m.geometry.length >= 2,
  );
  // Gate finding F-N2: legacy multipolygon tagging sometimes leaves a
  // member's role blank instead of "outer". Only fall back to treating
  // blank-role way members as outer when there are NO explicit `outer`
  // members at all — a relation that already has explicit outer members
  // should never have an unrelated blank-role member (e.g. a stray
  // `inner` mistagged blank) silently folded into the boundary.
  if (outerMembers.length === 0) {
    const blankRoleMembers = members.filter(
      (m) =>
        m.type === "way" &&
        m.role === "" &&
        m.geometry &&
        m.geometry.length >= 2,
    );
    if (blankRoleMembers.length > 0) {
      console.warn(
        `overpass-geo: relation has no explicit "outer"-role way member(s) — treating ${blankRoleMembers.length} ` +
          "blank-role way member(s) as outer (gate finding F-N2, legacy multipolygon tagging).",
      );
      outerMembers = blankRoleMembers;
    }
  }
  const outerSegments = outerMembers.map((m) => m.geometry!);
  if (outerSegments.length === 0) return [];
  return joinSegmentsIntoRings(outerSegments).filter(
    (ring) => ring.length >= 3,
  );
}

/** True if `point` is inside ANY of the given rings (a relation may have
 * more than one disjoint outer ring — e.g. a course split by a road). */
export function pointInAnyRing(point: LatLon, rings: LatLon[][]): boolean {
  return rings.some((ring) => pointInPolygon(point, ring));
}

/**
 * Shortest distance in meters from `point` to a polygon assembled from
 * `rings` — **0 when the point is inside** any ring (decision 0001
 * Addendum F / gate finding B-2: "the shortest distance from the course's
 * point to the polygon ... where a point inside the polygon has distance
 * 0"), otherwise the minimum distance to any ring's edge. Uses a local
 * equirectangular projection (accurate at the sub-few-km scale this is
 * used at, and far simpler than true great-circle segment distance) to
 * compute point-to-segment distance, then converts back to meters via
 * `haversineMeters` scale.
 */
export function distanceToPolygonMeters(
  point: LatLon,
  rings: LatLon[][],
): number {
  if (pointInAnyRing(point, rings)) return 0;
  let best = Infinity;
  for (const ring of rings) {
    for (let i = 0, j = ring.length - 1; i < ring.length; j = i++) {
      const a = ring[j]!;
      const b = ring[i]!;
      const d = distancePointToSegmentMeters(point, a, b);
      if (d < best) best = d;
    }
  }
  return best;
}

// Gate finding F-N1: meters per degree of latitude derived from the SAME
// Earth radius `haversineMeters` uses (2π × 6,371,000m / 360°), not the
// WGS-84 surveying constant (111,320) — the two differ by ~0.1-0.3%, which
// at the 500m name-match boundary is up to ~2m in the kill direction.
const METERS_PER_DEGREE = (2 * Math.PI * EARTH_RADIUS_METERS) / 360;

/** Point-to-segment distance in meters, via a local equirectangular
 * projection centered on `point` (accurate at the sub-few-km scale golf
 * courses are measured at). */
function distancePointToSegmentMeters(
  point: LatLon,
  a: LatLon,
  b: LatLon,
): number {
  const toXY = (p: LatLon): { x: number; y: number } => {
    const latRad = (point.lat * Math.PI) / 180;
    return {
      x: (p.lon - point.lon) * Math.cos(latRad) * METERS_PER_DEGREE,
      y: (p.lat - point.lat) * METERS_PER_DEGREE,
    };
  };
  const p = { x: 0, y: 0 }; // point projects to the origin by construction
  const pa = toXY(a);
  const pb = toXY(b);
  const dx = pb.x - pa.x;
  const dy = pb.y - pa.y;
  const lenSq = dx * dx + dy * dy;
  let t = lenSq === 0 ? 0 : ((p.x - pa.x) * dx + (p.y - pa.y) * dy) / lenSq;
  t = Math.max(0, Math.min(1, t));
  const closest = { x: pa.x + t * dx, y: pa.y + t * dy };
  return Math.hypot(p.x - closest.x, p.y - closest.y);
}

// ---------------------------------------------------------------------------
// Name normalization (decision 0001 Addendum F — literal, no abbreviation
// list or fuzzy matching)
// ---------------------------------------------------------------------------

/**
 * Decision 0001 Addendum F, verbatim: "Unicode NFKD, diacritics removed,
 * lower-cased, every character that is not a letter or digit replaced by a
 * space, whitespace collapsed." No other normalisation, abbreviation list,
 * or fuzzy matching — e.g. "St." and "Saint" are deliberately NOT unified.
 */
export function normalizeName(raw: string): string {
  return (
    raw
      .normalize("NFKD")
      // Gate finding F-N4: strip EVERY Unicode combining-mark character
      // (`\p{M}`), not just the U+0300-036F "Combining Diacritical Marks"
      // block — a mark from another combining block (e.g. U+1AB0 range)
      // used to fall through to the next line's letter/digit strip, which
      // replaces it with a SPACE instead of deleting it (splitting one
      // accented character into two normalized tokens).
      .replace(/\p{M}/gu, "")
      .toLowerCase()
      .replace(/[^\p{L}\p{N}]+/gu, " ")
      .trim()
      .replace(/\s+/g, " ")
  );
}

/**
 * Decision 0001 Addendum F's name-match test: true when, after
 * `normalizeName`, the OSM name EQUALS the course name, or CONTAINS it as a
 * whole-word sequence (space-delimited substring match, since
 * `normalizeName` already collapsed everything to single spaces).
 */
export function namesMatch(osmName: string, courseName: string): boolean {
  const osm = normalizeName(osmName);
  const course = normalizeName(courseName);
  if (course === "") return false;
  if (osm === course) return true;
  return ` ${osm} `.includes(` ${course} `);
}
