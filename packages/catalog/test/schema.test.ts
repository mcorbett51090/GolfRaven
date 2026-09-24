import { describe, expect, it } from "vitest";
import {
  CompletionOrMarkerRuleSchema,
  CourseSchema,
  FacilitySchema,
  OfferTermsSchema,
  RosterMemberSchema,
  RosterVersionSchema,
  SourceSchema,
  TrailSchema,
  CompositeSchema,
} from "../src/schema.js";

const source = { url: "https://example.com", retrieved: "2026-09-24" };

const stubCourse = {
  id: "crs_01ARZ3NDEKTSV4RRFFQ69G5FAV",
  slug: "stub-course",
  seed: { osmRef: "way/1" },
};

const stubFacility = {
  id: "fac_01ARZ3NDEKTSV4RRFFQ69G5FAV",
  slug: "stub-facility",
  region: "US-TN",
  tz: "America/Chicago",
  verification: { status: "unverified" },
  seed: { origin: "osm", osmRef: "way/1" },
  booking: [],
  courses: [stubCourse],
};

describe("SourceSchema", () => {
  it("accepts a valid source", () => {
    expect(SourceSchema.safeParse(source).success).toBe(true);
  });
  it("rejects a non-URL", () => {
    expect(
      SourceSchema.safeParse({ ...source, url: "not-a-url" }).success,
    ).toBe(false);
  });
});

describe("FacilitySchema", () => {
  it("accepts a minimal OSM-seeded stub facility (§4.1, §4.2)", () => {
    const result = FacilitySchema.safeParse(stubFacility);
    expect(result.success).toBe(true);
  });

  it("rejects a facility with an invalid tz", () => {
    const result = FacilitySchema.safeParse({
      ...stubFacility,
      tz: "Not/AZone",
    });
    expect(result.success).toBe(false);
  });

  it("rejects an unknown extra property (strict object)", () => {
    const result = FacilitySchema.safeParse({
      ...stubFacility,
      unexpectedField: true,
    });
    expect(result.success).toBe(false);
  });

  it("accepts a fully verified facility with prov on every content field", () => {
    const result = FacilitySchema.safeParse({
      ...stubFacility,
      name: "Pebble Hills Golf Club",
      town: "Nashville",
      lat: 36.16,
      lng: -86.78,
      approx: false,
      prov: { name: "operator", town: "operator", coord: "primary-source" },
      access: "public",
      verification: {
        status: "listed-verified",
        basis: "operator",
        verifiedAt: "2026-09-24",
        source,
      },
      courses: [
        {
          ...stubCourse,
          name: "Pebble Hills",
          holes: 18,
          prov: { name: "operator", holes: "operator" },
        },
      ],
    });
    expect(result.success).toBe(true);
  });
});

describe("CourseSchema", () => {
  it("rejects prov: 'osm' as a value (not one of the four allowed Prov values)", () => {
    const result = CourseSchema.safeParse({
      ...stubCourse,
      name: "Some Course",
      prov: { name: "osm" },
    });
    expect(result.success).toBe(false);
  });

  it("accepts a composite tuple of two course ids (G-P0-13)", () => {
    const result = CompositeSchema.safeParse([
      "crs_01ARZ3NDEKTSV4RRFFQ69G5FAV",
      "crs_01ARZ3NDEKTSV4RRFFQ69G5FAW",
    ]);
    expect(result.success).toBe(true);
  });

  it("rejects a composite of one course (must be a pair)", () => {
    const result = CompositeSchema.safeParse(["crs_01ARZ3NDEKTSV4RRFFQ69G5FAV"]);
    expect(result.success).toBe(false);
  });
});

describe("CompletionOrMarkerRuleSchema (discriminated union)", () => {
  it("accepts { kind: 'all' } with no other fields", () => {
    expect(CompletionOrMarkerRuleSchema.safeParse({ kind: "all" }).success).toBe(
      true,
    );
  });

  it("accepts n-of-m with n and ruleSource", () => {
    expect(
      CompletionOrMarkerRuleSchema.safeParse({
        kind: "n-of-m",
        n: 5,
        ruleSource: source,
      }).success,
    ).toBe(true);
  });

  it("rejects n-of-m with no ruleSource (O15) — the v6 AT(1) fixture case", () => {
    const result = CompletionOrMarkerRuleSchema.safeParse({
      kind: "n-of-m",
      n: 5,
    });
    expect(result.success).toBe(false);
  });
});

describe("RosterMemberSchema", () => {
  it("accepts a direct course member", () => {
    expect(
      RosterMemberSchema.safeParse({
        unit: "course",
        courseId: "crs_01ARZ3NDEKTSV4RRFFQ69G5FAV",
      }).success,
    ).toBe(true);
  });

  it("accepts an anyOf course member (A2-18)", () => {
    expect(
      RosterMemberSchema.safeParse({
        unit: "course",
        anyOf: [
          "crs_01ARZ3NDEKTSV4RRFFQ69G5FAV",
          "crs_01ARZ3NDEKTSV4RRFFQ69G5FAW",
        ],
      }).success,
    ).toBe(true);
  });

  it("accepts a facility member with stopOrder", () => {
    expect(
      RosterMemberSchema.safeParse({
        unit: "facility",
        facilityId: "fac_01ARZ3NDEKTSV4RRFFQ69G5FAV",
        stopOrder: 1,
      }).success,
    ).toBe(true);
  });

  it("rejects a member with an unknown unit", () => {
    expect(
      RosterMemberSchema.safeParse({
        unit: "region",
        regionId: "US-TN",
      }).success,
    ).toBe(false);
  });
});

describe("RosterVersionSchema", () => {
  const base = {
    version: 1,
    effectiveFrom: "2026-01-01",
    source,
    verifiedAt: "2026-01-01",
    completionUnit: "course",
    markerUnit: "facility",
    completionRule: { kind: "all" },
    markerRule: { kind: "all" },
    members: [{ unit: "course", courseId: "crs_01ARZ3NDEKTSV4RRFFQ69G5FAV" }],
  };

  it("accepts a well-formed roster version", () => {
    expect(RosterVersionSchema.safeParse(base).success).toBe(true);
  });

  it("rejects a roster version with no source (structurally required, §4.1)", () => {
    const { source: _drop, ...withoutSource } = base;
    expect(RosterVersionSchema.safeParse(withoutSource).success).toBe(false);
  });

  it("rejects an empty members array", () => {
    expect(
      RosterVersionSchema.safeParse({ ...base, members: [] }).success,
    ).toBe(false);
  });
});

describe("TrailSchema", () => {
  it("accepts a minimal single-version trail", () => {
    const trail = {
      id: "trl_01ARZ3NDEKTSV4RRFFQ69G5FAV",
      slug: "tennessee-golf-trail",
      name: "Tennessee Golf Trail",
      countries: ["US"],
      regions: ["US-TN"],
      kind: "state-agency",
      status: "active",
      operator: { name: "TN Dept. of Tourism", url: "https://example.com", type: "state-agency" },
      officialUrl: "https://example.com",
      rosterStatus: "verified",
      rosterVersions: [
        {
          version: 1,
          effectiveFrom: "2026-01-01",
          source,
          verifiedAt: "2026-01-01",
          completionUnit: "course",
          markerUnit: "facility",
          completionRule: { kind: "all" },
          markerRule: { kind: "all" },
          members: [
            { unit: "course", courseId: "crs_01ARZ3NDEKTSV4RRFFQ69G5FAV" },
          ],
        },
      ],
      lastReviewed: "2026-09-24",
      sources: [source],
    };
    expect(TrailSchema.safeParse(trail).success).toBe(true);
  });
});

describe("S2: FacilityProvSchema.nameFr (gate review post-e9b3ab0)", () => {
  it("accepts nameFr with a non-OSM prov stamp", () => {
    const result = FacilitySchema.safeParse({
      ...stubFacility,
      name: "Pebble Hills Golf Club",
      nameFr: "Club de golf Pebble Hills",
      town: "Nashville",
      lat: 36.16,
      lng: -86.78,
      prov: { name: "operator", nameFr: "operator", town: "operator", coord: "operator" },
      verification: {
        status: "listed-verified",
        basis: "operator",
        verifiedAt: "2026-09-24",
        source,
      },
    });
    expect(result.success).toBe(true);
  });
});

describe("S3: VerificationSchema requires basis/verifiedAt/source once verified (plan 677)", () => {
  it("rejects listed-verified with no basis/verifiedAt/source", () => {
    const result = FacilitySchema.safeParse({
      ...stubFacility,
      verification: { status: "listed-verified" },
    });
    expect(result.success).toBe(false);
  });

  it("accepts unverified with none of those fields", () => {
    const result = FacilitySchema.safeParse(stubFacility);
    expect(result.success).toBe(true);
  });
});

describe("S7: https-only URLs", () => {
  it("rejects a facility url that is not https:", () => {
    expect(FacilitySchema.shape.url.unwrap().safeParse("http://example.com").success).toBe(
      false,
    );
    expect(
      FacilitySchema.shape.url.unwrap().safeParse("javascript:alert(1)").success,
    ).toBe(false);
  });
  it("accepts an https facility url", () => {
    expect(FacilitySchema.shape.url.unwrap().safeParse("https://example.com").success).toBe(
      true,
    );
  });
});

describe("S6: OfferTermsSchema (no RuleExpr field — see schema.ts module doc)", () => {
  it("accepts a minimal OfferTerms record", () => {
    const result = OfferTermsSchema.safeParse({
      id: "oft_01ARZ3NDEKTSV4RRFFQ69G5FAV",
      trailId: "trl_01ARZ3NDEKTSV4RRFFQ69G5FAV",
      title: "Finish the Trail",
      terms: "Complete every stop to redeem.",
      mode: "portal-verify",
    });
    expect(result.success).toBe(true);
  });

  it("rejects an OfferTerms record with a RuleExpr-shaped extra field (strict object)", () => {
    const result = OfferTermsSchema.safeParse({
      id: "oft_01ARZ3NDEKTSV4RRFFQ69G5FAV",
      trailId: "trl_01ARZ3NDEKTSV4RRFFQ69G5FAV",
      title: "Finish the Trail",
      terms: "Complete every stop to redeem.",
      mode: "portal-verify",
      rule: { and: [] },
    });
    expect(result.success).toBe(false);
  });
});
