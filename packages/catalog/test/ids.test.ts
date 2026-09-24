import { describe, expect, it } from "vitest";
import {
  CourseIdSchema,
  FacilityIdSchema,
  OsmRefIdSchema,
  generateUlid,
  mintId,
} from "../src/ids.js";

describe("generateUlid", () => {
  it("produces a 26-character Crockford-base32 string", () => {
    const ulid = generateUlid();
    expect(ulid).toMatch(/^[0-9A-HJKMNP-TV-Z]{26}$/);
  });

  it("never uses the excluded letters I, L, O, U", () => {
    for (let i = 0; i < 50; i += 1) {
      const ulid = generateUlid();
      expect(ulid).not.toMatch(/[ILOU]/);
    }
  });
});

describe("mintId", () => {
  it("mints an id matching its kind's branded schema", () => {
    const facilityId = mintId("fac");
    expect(FacilityIdSchema.safeParse(facilityId).success).toBe(true);
    const courseId = mintId("crs");
    expect(CourseIdSchema.safeParse(courseId).success).toBe(true);
  });

  it("mints ids that are opaque and immutable in shape (prefix_ULID)", () => {
    expect(mintId("fac")).toMatch(/^fac_[0-9A-HJKMNP-TV-Z]{26}$/);
  });
});

describe("OsmRefIdSchema", () => {
  it("accepts way/relation/node refs", () => {
    expect(OsmRefIdSchema.safeParse("way/123").success).toBe(true);
    expect(OsmRefIdSchema.safeParse("relation/456").success).toBe(true);
    expect(OsmRefIdSchema.safeParse("node/789").success).toBe(true);
  });

  it("rejects an inlined shape or unknown element kind", () => {
    expect(OsmRefIdSchema.safeParse("way123").success).toBe(false);
    expect(OsmRefIdSchema.safeParse("polygon/123").success).toBe(false);
  });
});
