import { describe, expect, it } from "vitest";
import { mintId } from "../src/ids.js";
import {
  hasOwnUrl,
  hasSourcedBlurb,
  hasSourcedCourseFact,
  hasVerifiedAmenity,
  isIndexable,
  isThinStub,
  isVerified,
} from "../src/indexable.js";
import type { Facility } from "../src/schema.js";

const source = { url: "https://example.com", retrieved: "2026-09-24" };

function baseFacility(overrides: Partial<Facility> = {}): Facility {
  return {
    id: mintId("fac") as Facility["id"],
    slug: "bear-trace",
    region: "US-TN",
    tz: "America/Chicago",
    verification: { status: "unverified" },
    seed: { origin: "osm" },
    booking: [],
    courses: [{ id: mintId("crs") as Facility["courses"][number]["id"], slug: "bear-trace-18" }],
    ...overrides,
  } as Facility;
}

const verified = {
  status: "listed-verified" as const,
  basis: "operator" as const,
  verifiedAt: "2026-09-24",
  source,
};

describe("isVerified", () => {
  it("is false for 'unverified'", () => {
    expect(isVerified(baseFacility())).toBe(false);
  });
  it("is true for 'listed-verified'", () => {
    expect(isVerified(baseFacility({ verification: verified }))).toBe(true);
  });
  it("is true for 'play-verified' (verified or better)", () => {
    expect(
      isVerified(baseFacility({ verification: { ...verified, status: "play-verified" } })),
    ).toBe(true);
  });
});

describe("hasOwnUrl", () => {
  it("is false when url is absent", () => {
    expect(hasOwnUrl(baseFacility())).toBe(false);
  });
  it("is false for a whitespace-only url", () => {
    expect(hasOwnUrl(baseFacility({ url: "   " as Facility["url"] }))).toBe(false);
  });
  it("is true for a real url", () => {
    expect(hasOwnUrl(baseFacility({ url: "https://example.com" }))).toBe(true);
  });
});

describe("hasSourcedCourseFact", () => {
  it("is false when no course carries a prov stamp", () => {
    expect(hasSourcedCourseFact(baseFacility())).toBe(false);
  });
  it("is true when a course carries at least one prov-stamped field", () => {
    const f = baseFacility({
      courses: [
        {
          id: mintId("crs") as Facility["courses"][number]["id"],
          slug: "bear-trace-18",
          name: "Bear Trace",
          prov: { name: "operator" },
        },
      ],
    });
    expect(hasSourcedCourseFact(f)).toBe(true);
  });
});

describe("hasVerifiedAmenity", () => {
  it("is false with no amenities", () => {
    expect(hasVerifiedAmenity(baseFacility())).toBe(false);
  });
  it("is true with at least one (source-bearing) amenity", () => {
    const f = baseFacility({
      amenities: [{ key: "cart-rental", value: true, source }],
    });
    expect(hasVerifiedAmenity(f)).toBe(true);
  });
});

describe("hasSourcedBlurb", () => {
  it("is false when the facility carries no blurb field (the current schema)", () => {
    expect(hasSourcedBlurb(baseFacility())).toBe(false);
  });
  it("is false for a short duck-typed blurb", () => {
    const f = { ...baseFacility(), blurb: "Too short." };
    expect(hasSourcedBlurb(f as Facility)).toBe(false);
  });
  it("is true for a duck-typed blurb of 40+ characters", () => {
    const f = {
      ...baseFacility(),
      blurb: "A championship-length parkland course opened in 1998.",
    };
    expect(hasSourcedBlurb(f as Facility)).toBe(true);
  });
});

describe("isIndexable — the R1 predicate (§5.1)", () => {
  it("is false when unverified, even with a url (verification gates first)", () => {
    const f = baseFacility({ url: "https://example.com" });
    expect(isIndexable(f)).toBe(false);
    expect(isThinStub(f)).toBe(true);
  });

  it("is false when verified but with no url, course fact or amenity (thin-content guard)", () => {
    const f = baseFacility({ verification: verified });
    expect(isIndexable(f)).toBe(false);
    expect(isThinStub(f)).toBe(true);
  });

  it("is true when verified with an own url", () => {
    const f = baseFacility({ verification: verified, url: "https://example.com" });
    expect(isIndexable(f)).toBe(true);
    expect(isThinStub(f)).toBe(false);
  });

  it("is true when verified with a sourced course fact, even with no url", () => {
    const f = baseFacility({
      verification: verified,
      courses: [
        {
          id: mintId("crs") as Facility["courses"][number]["id"],
          slug: "bear-trace-18",
          holes: 18,
          prov: { holes: "operator" },
        },
      ],
    });
    expect(isIndexable(f)).toBe(true);
  });

  it("is true when verified with a verified amenity, even with no url", () => {
    const f = baseFacility({
      verification: verified,
      amenities: [{ key: "driving-range", value: true, source }],
    });
    expect(isIndexable(f)).toBe(true);
  });

  it("trail membership alone is never consulted (the predicate takes no trail input at all)", () => {
    // isIndexable's signature only accepts a Facility — there is no trail
    // parameter to pass, which is the literal enforcement of "trail
    // membership alone is not enough".
    expect(isIndexable.length).toBe(1);
  });
});
