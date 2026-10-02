/**
 * A tiny SYNTHETIC catalog for `__DEV__` builds with no catalog source
 * configured, so the screens can be seen without a server. It is clearly
 * labelled in the UI ("Demo data") and is injected as a read-only snapshot
 * — it never goes through, and never bypasses, the signature verifier; a
 * release build has no path to it. Ids are fabricated (`…01DEMO…`, not real ledger
 * ids), the names are fictional, and every URL is `example.com`.
 */
import type { Facility, Trail } from "@golfraven/catalog";
import type { CatalogSnapshot } from "../catalog/snapshot";

const SRC = { url: "https://example.com/source", retrieved: "2026-01-01" };

const facility = (id: string, slug: string, name: string, region: string, courseId: string, extra: Record<string, unknown> = {}): Facility =>
  ({
    id,
    slug,
    name,
    region,
    tz: region.startsWith("CA") ? "America/Toronto" : "America/Chicago",
    verification: { status: "unverified" },
    seed: { origin: "manual" },
    booking: [],
    courses: [{ id: courseId, slug: `${slug}-course`, holes: 18, par: 72 }],
    ...extra,
  }) as unknown as Facility;

const FACILITIES: Facility[] = [
  facility("fac_01DEMO0000000000000000001", "demo-hills-golf-club", "Demo Hills Golf Club", "US-TN", "crs_01DEMO0000000000000000001", {
    access: "public",
    booking: [{ provider: "course-native", url: "https://example.com/book/demo-hills", source: SRC, checkedAt: "2026-01-01" }],
  }),
  facility("fac_01DEMO0000000000000000002", "sample-creek-links", "Sample Creek Links", "US-TN", "crs_01DEMO0000000000000000002", { access: "municipal" }),
  facility("fac_01DEMO0000000000000000003", "exemple-du-lac", "Exemple du Lac", "CA-QC", "crs_01DEMO0000000000000000003", { nameFr: "Club de golf Exemple du Lac", access: "resort" }),
];

const TRAILS: Trail[] = [
  {
    id: "trl_01DEMO0000000000000000001",
    slug: "demo-state-trail",
    name: "Demo State Golf Trail",
    nameFr: "Circuit de démonstration",
    countries: ["US", "CA"],
    regions: ["US-TN", "CA-QC"],
    kind: "state-agency",
    status: "active",
    operator: { name: "Example Tourism Board", url: "https://example.com/operator", type: "state-agency" },
    officialUrl: "https://example.com/trail",
    rosterStatus: "verified",
    blurb: "A synthetic trail used to show the screens in development builds.",
    blurbFr: "Un circuit fictif servant à présenter les écrans dans les versions de développement.",
    rosterVersions: [
      {
        version: 1,
        effectiveFrom: "2026-01-01",
        source: SRC,
        verifiedAt: "2026-01-01",
        completionUnit: "course",
        markerUnit: "facility",
        completionRule: { kind: "all" },
        markerRule: { kind: "all" },
        members: [
          { unit: "course", courseId: "crs_01DEMO0000000000000000001", stopOrder: 1 },
          { unit: "course", courseId: "crs_01DEMO0000000000000000002", stopOrder: 2 },
          { unit: "course", courseId: "crs_01DEMO0000000000000000003", stopOrder: 3 },
        ],
      },
    ],
    lastReviewed: "2026-01-01",
    sources: [SRC],
  } as unknown as Trail,
];

export const DEMO_SNAPSHOT: CatalogSnapshot = {
  catalogVersion: "00000000-demo000",
  generatedAt: "2026-01-01T00:00:00.000Z",
  trails: TRAILS,
  facilities: FACILITIES,
};
