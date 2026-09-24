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

/** A gate-valid minimal `listed-verified` facility: every field
 * `verify-catalog` requires present for `listed-verified` (name/town/
 * lat/lng, each `prov`-stamped; the one course's name/holes, `prov`-
 * stamped) and nothing else — the thin-content case R1 must still catch. */
function baseFacility(overrides: Partial<Facility> = {}): Facility {
  return {
    id: mintId("fac") as Facility["id"],
    slug: "bear-trace",
    region: "US-TN",
    tz: "America/Chicago",
    name: "Bear Trace",
    town: "Harrison Bay",
    lat: 35.1,
    lng: -85.0,
    approx: false,
    prov: { name: "operator", town: "operator", coord: "operator" },
    access: "public",
    verification: { status: "unverified" },
    seed: { origin: "manual" },
    booking: [],
    courses: [
      {
        id: mintId("crs") as Facility["courses"][number]["id"],
        slug: "bear-trace-18",
        name: "Bear Trace at Harrison Bay",
        holes: 18,
        prov: { name: "operator", holes: "operator" },
      },
    ],
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

describe("hasSourcedBlurb — the real Facility.blurb field", () => {
  it("is false when blurb is absent", () => {
    expect(hasSourcedBlurb(baseFacility())).toBe(false);
  });
  it("is false for a short blurb", () => {
    expect(hasSourcedBlurb(baseFacility({ blurb: "Too short." }))).toBe(false);
  });
  it("is true for a blurb of 40+ characters", () => {
    expect(
      hasSourcedBlurb(
        baseFacility({ blurb: "A championship-length parkland course opened in 1998." }),
      ),
    ).toBe(true);
  });
});

describe("hasSourcedCourseFact — excludes mandatory name/holes", () => {
  it("is false when the only prov-stamped fields are the mandatory name/holes", () => {
    // baseFacility()'s course carries ONLY name+holes (both mandatory,
    // both prov-stamped) — must NOT count, or R1 could never fire.
    expect(hasSourcedCourseFact(baseFacility())).toBe(false);
  });

  it("is true when a course carries a prov-stamped OPTIONAL field (par)", () => {
    const f = baseFacility({
      courses: [
        {
          id: mintId("crs") as Facility["courses"][number]["id"],
          slug: "bear-trace-18",
          name: "Bear Trace",
          holes: 18,
          par: 72,
          prov: { name: "operator", holes: "operator", par: "operator" },
        },
      ],
    });
    expect(hasSourcedCourseFact(f)).toBe(true);
  });

  it("is false when the optional field is present but not prov-stamped", () => {
    const f = baseFacility({
      courses: [
        {
          id: mintId("crs") as Facility["courses"][number]["id"],
          slug: "bear-trace-18",
          name: "Bear Trace",
          holes: 18,
          par: 72,
          prov: { name: "operator", holes: "operator" },
        },
      ],
    });
    expect(hasSourcedCourseFact(f)).toBe(false);
  });

  it("is true when a course carries a sourced tee (no prov needed — tees carry their own source)", () => {
    const f = baseFacility({
      courses: [
        {
          id: mintId("crs") as Facility["courses"][number]["id"],
          slug: "bear-trace-18",
          name: "Bear Trace",
          holes: 18,
          prov: { name: "operator", holes: "operator" },
          tees: [{ name: "Blue", yards: 6800, source, checkedAt: "2026-09-24" }],
        },
      ],
    });
    expect(hasSourcedCourseFact(f)).toBe(true);
  });
});

describe("hasVerifiedAmenity — only value: true counts", () => {
  it("is false with no amenities", () => {
    expect(hasVerifiedAmenity(baseFacility())).toBe(false);
  });
  it("is false when every amenity entry is a sourced-and-confirmed ABSENCE (value: false)", () => {
    const f = baseFacility({ amenities: [{ key: "cart-rental", value: false, source }] });
    expect(hasVerifiedAmenity(f)).toBe(false);
  });
  it("is true with at least one value:true amenity", () => {
    const f = baseFacility({ amenities: [{ key: "cart-rental", value: true, source }] });
    expect(hasVerifiedAmenity(f)).toBe(true);
  });
  it("is true when a false and a true entry are both present", () => {
    const f = baseFacility({
      amenities: [
        { key: "food-onsite", value: false, source },
        { key: "cart-rental", value: true, source },
      ],
    });
    expect(hasVerifiedAmenity(f)).toBe(true);
  });
});

describe("isIndexable — the R1 predicate (§5.1)", () => {
  it("is false when unverified, even with a url (verification gates first)", () => {
    const f = baseFacility({ url: "https://example.com" });
    expect(isIndexable(f)).toBe(false);
    expect(isThinStub(f)).toBe(true);
  });

  it("(B4 fixture) a GATE-VALID listed-verified facility with no url, no blurb, no optional course fact and no verified amenity is NOT indexable — the thin-content guard must bite", () => {
    const f = baseFacility({ verification: verified });
    expect(isIndexable(f)).toBe(false);
    expect(isThinStub(f)).toBe(true);
  });

  it("is true when verified with an own url", () => {
    const f = baseFacility({ verification: verified, url: "https://example.com" });
    expect(isIndexable(f)).toBe(true);
    expect(isThinStub(f)).toBe(false);
  });

  it("is true when verified with a sourced blurb", () => {
    const f = baseFacility({
      verification: verified,
      blurb: "A championship-length parkland course opened in 1998.",
    });
    expect(isIndexable(f)).toBe(true);
  });

  it("is true when verified with a sourced OPTIONAL course fact, even with no url", () => {
    const f = baseFacility({
      verification: verified,
      courses: [
        {
          id: mintId("crs") as Facility["courses"][number]["id"],
          slug: "bear-trace-18",
          name: "Bear Trace",
          holes: 18,
          designers: [],
          opened: 1998,
          prov: { name: "operator", holes: "operator", opened: "operator" },
        },
      ],
    });
    expect(isIndexable(f)).toBe(true);
  });

  it("is true when verified with a verified (value:true) amenity, even with no url", () => {
    const f = baseFacility({
      verification: verified,
      amenities: [{ key: "driving-range", value: true, source }],
    });
    expect(isIndexable(f)).toBe(true);
  });

  it("trail membership alone is never consulted (the predicate takes no trail input at all)", () => {
    expect(isIndexable.length).toBe(1);
  });
});
