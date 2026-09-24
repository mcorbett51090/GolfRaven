#!/usr/bin/env node
/**
 * The synthetic demo dataset — see `README.md` in this directory. Written
 * as a programmatic builder (not a hand-maintained JSON blob) so the
 * facility/trail records and their ID-ledger entries can never drift out
 * of sync (B4: "make the demo bundle pass verify-catalog"): the ledger is
 * DERIVED from the facility/trail lists below, not hand-typed.
 *
 * Every name, operator and URL here is FICTIONAL. `example.com`/
 * `example.org`/`example.ca` throughout.
 *
 * Plain `.mjs` (not `.ts`) deliberately: this module is imported both by
 * Vite/Astro (`derive.ts`) and by plain `node` scripts that cannot load
 * TypeScript without a loader (`scripts/emit-indexability.mjs`,
 * `scripts/verify-input.mjs`) — see those files' own docs.
 */

const source = (url, retrieved) => ({ url, retrieved });

// ---------------------------------------------------------------------
// Facilities
// ---------------------------------------------------------------------

const facilities = [
  {
    id: "fac_01M39X3D4XYCY6RVSY3D6YDRZT",
    slug: "ridge-overlook-golf-club",
    region: "US-TN",
    tz: "America/Chicago",
    name: "Ridge Overlook Golf Club",
    town: "Fictional Springs",
    lat: 36.1,
    lng: -86.7,
    approx: false,
    prov: {
      name: "operator",
      town: "operator",
      coord: "operator",
      blurb: "operator",
    },
    blurb:
      "A synthetic demo parkland course used to exercise GolfRaven's course-page template — fictional, not a real place.",
    access: "public",
    url: "https://ridge-overlook.example.com",
    verification: {
      status: "listed-verified",
      basis: "operator",
      verifiedAt: "2026-09-01",
      source: source("https://ridge-overlook.example.com", "2026-09-01"),
    },
    seed: { origin: "manual" },
    booking: [
      {
        provider: "course-native",
        url: "https://ridge-overlook.example.com/tee-times",
        source: source("https://ridge-overlook.example.com", "2026-09-01"),
        checkedAt: "2026-09-01",
      },
    ],
    courses: [
      {
        id: "crs_01M39X3D54EH17VDCQ3JKN8VYP",
        slug: "ridge-overlook-championship",
        name: "Ridge Overlook Championship",
        holes: 18,
        par: 72,
        prov: { name: "operator", holes: "operator", par: "operator" },
      },
    ],
  },
  {
    id: "fac_01M39X3D53Z2F3XGR6EK35TS29",
    slug: "blue-heron-links",
    region: "US-TN",
    tz: "America/Chicago",
    name: "Blue Heron Links",
    town: "Millbrook Junction",
    lat: 36.2,
    lng: -86.85,
    approx: false,
    prov: {
      name: "primary-source",
      town: "primary-source",
      coord: "primary-source",
    },
    access: "public",
    verification: {
      status: "listed-verified",
      basis: "primary-source",
      verifiedAt: "2026-09-02",
      source: source("https://example.org/blue-heron", "2026-09-02"),
    },
    seed: { origin: "manual" },
    booking: [],
    courses: [
      {
        id: "crs_01M39X3D54D8MBDYC2XE85WCY8",
        slug: "blue-heron-links-18",
        name: "Blue Heron Links",
        holes: 18,
        designers: ["dsg_01M39Y9Q74E0DZPY87SZ5J3S2B"],
        prov: {
          name: "primary-source",
          holes: "primary-source",
          designers: "primary-source",
        },
      },
    ],
  },
  {
    id: "fac_01M39X3D53T6SBSH7TTFD3NT1W",
    slug: "cedar-hollow-country-club",
    region: "US-TN",
    tz: "America/Chicago",
    name: "Cedar Hollow Country Club",
    town: "Cedar Hollow",
    lat: 36.05,
    lng: -86.6,
    approx: false,
    prov: { name: "operator", town: "operator", coord: "operator" },
    access: "private",
    verification: {
      status: "listed-verified",
      basis: "operator",
      verifiedAt: "2026-09-03",
      source: source("https://example.org/cedar-hollow", "2026-09-03"),
    },
    seed: { origin: "manual" },
    booking: [],
    courses: [
      {
        id: "crs_01M39X3D54JNRAD66XBVVQRGZ8",
        slug: "cedar-hollow-championship",
        name: "Cedar Hollow Championship",
        holes: 18,
        opened: 1985,
        prov: { name: "operator", holes: "operator", opened: "operator" },
      },
    ],
  },
  {
    // Unverified stub (§4.1, §4.2): no `name`/`town` — those stay unset
    // until an editor verifies it (never a reason to give it a `name`
    // that would then need its own `prov` stamp, PROV_MISSING_OR_OSM).
    // It DOES carry coordinates + a `prov.coord` stamp: `verify-catalog`'s
    // `tz` check (G-P0-11) fails closed on ANY facility with no
    // coordinates to check against, verified or not — `packages/catalog`'s
    // `loadCatalog()` has no `data/osm/` join implemented yet (out of
    // stage-1 scope), so a real un-joined stub has no other way to pass
    // this gate today. This coordinate is exactly what a re-seed would
    // record before an editor has looked at anything else.
    id: "fac_01M39X3D54QJ6XGVFM705SHC09",
    slug: "foggy-pines-golf-resort",
    region: "CA-BC",
    tz: "America/Vancouver",
    lat: 49.1,
    lng: -122.8,
    approx: false,
    prov: { coord: "primary-source" },
    verification: { status: "unverified" },
    seed: { origin: "manual" },
    booking: [],
    courses: [
      {
        id: "crs_01M39X3D54HAPAMSSAF9DSPJJX",
        slug: "foggy-pines-18",
      },
    ],
  },
  {
    id: "fac_01M39X3D54VM1YZ6PVEEQM7Q17",
    slug: "highland-meadows-golf-course",
    region: "CA-BC",
    tz: "America/Vancouver",
    name: "Highland Meadows Golf Course",
    town: "Port Aldergrove",
    lat: 49.25,
    lng: -123.0,
    approx: false,
    prov: { name: "operator", town: "operator", coord: "operator" },
    access: "public",
    url: "https://highland-meadows.example.ca",
    verification: {
      status: "listed-verified",
      basis: "operator",
      verifiedAt: "2026-09-04",
      source: source("https://highland-meadows.example.ca", "2026-09-04"),
    },
    seed: { origin: "manual" },
    booking: [
      {
        provider: "golfnow",
        url: "https://www.golfnow.com/example/highland-meadows",
        source: source("https://highland-meadows.example.ca", "2026-09-04"),
        checkedAt: "2026-09-04",
      },
    ],
    courses: [
      {
        id: "crs_01M39X3D55ZTPPKABZ95A0M78Y",
        slug: "highland-meadows-18",
        name: "Highland Meadows",
        holes: 18,
        tees: [
          {
            name: "Blue",
            yards: 6750,
            source: source(
              "https://highland-meadows.example.ca/tees",
              "2026-09-04",
            ),
            checkedAt: "2026-09-04",
          },
        ],
        prov: { name: "operator", holes: "operator" },
      },
    ],
  },
  {
    id: "fac_01M39X3D54R7ST7J3SQWD4A34V",
    slug: "stonebridge-municipal",
    region: "US-TN",
    tz: "America/Chicago",
    name: "Stonebridge Municipal",
    town: "Stonebridge",
    lat: 36.15,
    lng: -86.9,
    approx: false,
    prov: { name: "operator", town: "operator", coord: "operator" },
    access: "municipal",
    verification: {
      status: "listed-verified",
      basis: "operator",
      verifiedAt: "2026-09-05",
      source: source("https://example.org/stonebridge", "2026-09-05"),
    },
    seed: { origin: "manual" },
    booking: [],
    amenities: [
      {
        key: "driving-range",
        value: true,
        source: source("https://example.org/stonebridge", "2026-09-05"),
      },
    ],
    courses: [
      {
        id: "crs_01M39X3D55NEEY7JNXPSD8GMW4",
        slug: "stonebridge-18",
        name: "Stonebridge Municipal",
        holes: 18,
        prov: { name: "operator", holes: "operator" },
      },
    ],
  },
  {
    // Verified-but-THIN (B4/S4 fixture): gate-valid `listed-verified` —
    // name/town/lat/lng + course name/holes, all prov-stamped — but with
    // NO url, NO blurb, NO optional-research course fact and NO verified
    // amenity. R1 (`isIndexable`) must say `false`, while S4 says it still
    // gets a real page (just `noindex`) — this is the end-to-end proof
    // that "every verified facility gets a page" and "R1 decides only
    // whether it's indexed" are two different gates, both exercised by
    // `test/acceptance.test.ts`.
    id: "fac_01M39YVNQGP3SWPWF3KJXSY4WR",
    slug: "thinfield-muni",
    region: "US-TN",
    tz: "America/Chicago",
    name: "Thinfield Muni",
    town: "Thinfield",
    lat: 36.0,
    lng: -86.5,
    approx: false,
    prov: { name: "operator", town: "operator", coord: "operator" },
    access: "public",
    verification: {
      status: "listed-verified",
      basis: "operator",
      verifiedAt: "2026-09-06",
      source: source("https://example.org/thinfield-muni", "2026-09-06"),
    },
    seed: { origin: "manual" },
    booking: [],
    courses: [
      {
        id: "crs_01M39YVNQHZF2N462T9NJQK8CS",
        slug: "thinfield-muni-9",
        name: "Thinfield Muni",
        holes: 9,
        prov: { name: "operator", holes: "operator" },
      },
    ],
  },
];

// ---------------------------------------------------------------------
// Designers (referenced by Blue Heron Links, above)
// ---------------------------------------------------------------------

const designers = [
  {
    id: "dsg_01M39Y9Q74E0DZPY87SZ5J3S2B",
    name: "A. Fictional Designer",
    sources: [
      source(
        "https://example.org/designers/a-fictional-designer",
        "2026-09-02",
      ),
    ],
  },
];

// ---------------------------------------------------------------------
// Trails
// ---------------------------------------------------------------------

const trails = [
  {
    id: "trl_01M39X3D55H3JNDQ5ND6S4VZP3",
    slug: "fictional-ridge-golf-trail",
    name: "Fictional Ridge Golf Trail",
    countries: ["US"],
    regions: ["US-TN"],
    kind: "state-agency",
    status: "active",
    operator: {
      name: "Fictional State Parks",
      url: "https://example.org/fictional-state-parks",
      type: "state",
    },
    officialUrl: "https://example.org/fictional-ridge-golf-trail",
    rosterStatus: "verified",
    rosterVersions: [
      {
        version: 1,
        effectiveFrom: "2026-01-01",
        source: source(
          "https://example.org/fictional-ridge-golf-trail",
          "2026-09-01",
        ),
        verifiedAt: "2026-09-01",
        completionUnit: "course",
        markerUnit: "facility",
        completionRule: { kind: "all" },
        markerRule: { kind: "all" },
        members: [
          {
            unit: "course",
            courseId: "crs_01M39X3D54EH17VDCQ3JKN8VYP",
            stopOrder: 0,
          },
          {
            unit: "course",
            courseId: "crs_01M39X3D54D8MBDYC2XE85WCY8",
            stopOrder: 1,
          },
          {
            unit: "course",
            courseId: "crs_01M39X3D54JNRAD66XBVVQRGZ8",
            stopOrder: 2,
          },
        ],
      },
    ],
    blurb:
      "A synthetic demo trail linking three fictional Tennessee courses, one of them a private club playable only as a member's guest.",
    lastReviewed: "2026-09-24",
    sources: [
      source("https://example.org/fictional-ridge-golf-trail", "2026-09-01"),
    ],
  },
  {
    id: "trl_01M39X3D556JS2FS05AJDP25H2",
    slug: "somewhere-coastal-golf-trail",
    name: "Somewhere Coastal Golf Trail",
    countries: ["CA"],
    regions: ["CA-BC"],
    kind: "co-op",
    status: "active",
    operator: {
      name: "Somewhere Coastal Golf Co-op",
      url: "https://example.ca/somewhere-coastal",
      type: "co-op",
    },
    officialUrl: "https://example.ca/somewhere-coastal-golf-trail",
    rosterStatus: "conflicting",
    rosterVersions: [
      {
        version: 1,
        effectiveFrom: "2026-02-01",
        source: source(
          "https://example.ca/somewhere-coastal-golf-trail",
          "2026-09-04",
        ),
        verifiedAt: "2026-09-04",
        completionUnit: "facility",
        markerUnit: "facility",
        completionRule: { kind: "all" },
        markerRule: { kind: "all" },
        members: [
          {
            unit: "facility",
            facilityId: "fac_01M39X3D54QJ6XGVFM705SHC09",
            stopOrder: 0,
          },
          {
            unit: "facility",
            facilityId: "fac_01M39X3D54VM1YZ6PVEEQM7Q17",
            stopOrder: 1,
          },
          {
            unit: "facility",
            facilityId: "fac_01M39X3D54R7ST7J3SQWD4A34V",
            stopOrder: 2,
          },
        ],
      },
    ],
    blurb:
      "A synthetic demo trail spanning fictional British Columbia courses; two independent listings disagree on its exact roster, which is why this demo trail is flagged 'conflicting'.",
    lastReviewed: "2026-09-24",
    sources: [
      source("https://example.ca/somewhere-coastal-golf-trail", "2026-09-04"),
      source("https://example.ca/somewhere-coastal-alt-listing", "2026-08-20"),
    ],
  },
];

// ---------------------------------------------------------------------
// Regions (site-only — tools/catalog's bundle format has no `regions`)
// ---------------------------------------------------------------------

const regions = [
  {
    code: "US-TN",
    country: "US",
    slug: "tn",
    name: "Tennessee",
    polygonFile: "regions/us-tn.geojson",
  },
  {
    code: "CA-BC",
    country: "CA",
    slug: "bc",
    name: "British Columbia",
    polygonFile: "regions/ca-bc.geojson",
  },
];

// ---------------------------------------------------------------------
// ID ledger — DERIVED from facilities/trails/designers above, never
// hand-typed (B4: this is what keeps the demo bundle passing
// verify-catalog instead of drifting out of sync with it).
// ---------------------------------------------------------------------

function buildLedger() {
  const entries = {};
  const minted = (catalogVersion, date) => [
    { type: "minted", catalogVersion, date },
  ];
  const verified = (catalogVersion, date) => [
    { type: "minted", catalogVersion, date },
    { type: "verified", catalogVersion, date },
  ];

  for (const facility of facilities) {
    const isVerified = facility.verification.status !== "unverified";
    const date = facility.verification.verifiedAt ?? "2026-01-01";
    entries[facility.id] = {
      id: facility.id,
      kind: "fac",
      slug: facility.slug,
      status: isVerified ? "verified" : "stub",
      transitions: isVerified
        ? verified("demo-v1", date)
        : minted("demo-v1", date),
    };
    for (const course of facility.courses) {
      entries[course.id] = {
        id: course.id,
        kind: "crs",
        slug: course.slug,
        status: isVerified ? "verified" : "stub",
        transitions: isVerified
          ? verified("demo-v1", date)
          : minted("demo-v1", date),
        facilityId: facility.id,
      };
    }
  }
  for (const trail of trails) {
    entries[trail.id] = {
      id: trail.id,
      kind: "trl",
      slug: trail.slug,
      transitions: minted("demo-v1", trail.lastReviewed),
    };
  }
  for (const designer of designers) {
    entries[designer.id] = {
      id: designer.id,
      kind: "dsg",
      transitions: minted("demo-v1", "2026-09-02"),
    };
  }
  return { entries };
}

const idLedger = buildLedger();

/** The shape `@golfraven/catalog`'s `loadCatalogFromBundle` accepts
 * (`packages/catalog/src/load.ts`'s `CatalogBundleSchema`) — everything
 * the site needs to render, PLUS the same `idLedger` the verify payload
 * uses (see `demoBundleForVerify` below), so the two never disagree about
 * what the catalog actually contains. */
export function demoBundleForSite() {
  return { regions, facilities, trails, designers, idLedger };
}

/** The shape `@golfraven/catalog-tools`' `verifyCatalogRaw` accepts
 * (`tools/catalog/src/bundle.ts`'s `CatalogBundleSchema`) — same
 * facilities/trails/designers/idLedger, `regions` dropped (that bundle
 * format has no such field), `contractVersion` added. */
export function demoBundleForVerify() {
  return { contractVersion: 0, facilities, trails, designers, idLedger };
}
