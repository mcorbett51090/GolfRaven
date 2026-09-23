import { afterEach, describe, expect, it, vi } from "vitest";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import {
  computeX4Coverage,
  isLiveFacilityPage,
  runX4Verify,
  type X4CheckResult,
  type X4CourseMap,
  type X4SavedEnvelope,
} from "../src/x4-verify.js";

const OUT_DIR = mkdtempSync(path.join(tmpdir(), "golfraven-p0-x4-test-"));

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("x4-verify: isLiveFacilityPage (decision 0001 Addendum G's 'live page' definition, literal)", () => {
  it("live: HTTP 200, final URL matches the facility pattern, page text contains the course name", () => {
    const result = isLiveFacilityPage(
      200,
      "https://www.golfnow.com/tee-times/facility/2360-grand-national/search",
      "Welcome to Grand National tee times.",
      "Grand National",
    );
    expect(result.live).toBe(true);
  });

  it("not live: a redirect to a generic search page (no facility id in the final URL)", () => {
    const result = isLiveFacilityPage(
      200,
      "https://www.golfnow.com/tee-times/search?q=grand+national",
      "No results found for Grand National.",
      "Grand National",
    );
    expect(result.live).toBe(false);
    expect(result.reason).toContain("does not contain /tee-times/facility/<id>-");
  });

  it("not live: HTTP 200 but the course name is missing from the page text", () => {
    const result = isLiveFacilityPage(
      200,
      "https://www.golfnow.com/tee-times/facility/2360-grand-national/search",
      "This page does not mention the course by name.",
      "Grand National",
    );
    expect(result.live).toBe(false);
    expect(result.reason).toContain("was not found on the page text");
  });

  it("not live: a non-200 status", () => {
    const result = isLiveFacilityPage(
      404,
      "https://www.golfnow.com/tee-times/facility/2360-grand-national/search",
      "Grand National",
      "Grand National",
    );
    expect(result.live).toBe(false);
    expect(result.reason).toContain("HTTP 404");
  });

  it("name match applies Addendum F normalisation (case/punctuation-insensitive whole-word match)", () => {
    const result = isLiveFacilityPage(
      200,
      "https://www.golfnow.com/tee-times/facility/2361-cambrian-ridge/search",
      "BOOK YOUR TEE TIME AT CAMBRIAN RIDGE GOLF CLUB TODAY",
      "Cambrian Ridge",
    );
    expect(result.live).toBe(true);
  });
});

function course(trail: string, status: X4CheckResult["status"]): X4CheckResult {
  return {
    course: "x",
    trail,
    url: status === "no-url" ? null : "https://www.golfnow.com/x",
    status,
    reason: status,
    httpStatus: status === "live" || status === "not-live" ? 200 : null,
    finalUrl: null,
    blocked: false,
  };
}

describe("x4-verify: computeX4Coverage — per-trail 80% boundary (decision 0001 Addendum G)", () => {
  it("exactly 80% (4 of 5) PASSES", () => {
    const perCourse = [
      course("TN", "live"),
      course("TN", "live"),
      course("TN", "live"),
      course("TN", "live"),
      course("TN", "not-live"),
    ];
    const perTrail = computeX4Coverage(perCourse);
    expect(perTrail.TN?.pct).toBe(80);
    expect(perTrail.TN?.verdict).toBe("pass");
    expect(perTrail.TN?.consequence).toBeNull();
  });

  it("just under 80% (3 of 4 = 75%) KILLS, with the per-trail consequence", () => {
    const perCourse = [
      course("VI", "live"),
      course("VI", "live"),
      course("VI", "live"),
      course("VI", "not-live"),
    ];
    const perTrail = computeX4Coverage(perCourse);
    expect(perTrail.VI?.pct).toBe(75);
    expect(perTrail.VI?.verdict).toBe("kill");
    expect(perTrail.VI?.consequence).toContain("Course-native link becomes primary for VI");
  });

  it("a null URL counts as not covered, same as a non-live page", () => {
    const perCourse = [
      course("RTJ", "live"),
      course("RTJ", "live"),
      course("RTJ", "live"),
      course("RTJ", "live"),
      course("RTJ", "no-url"),
    ];
    const perTrail = computeX4Coverage(perCourse);
    expect(perTrail.RTJ?.pct).toBe(80);
    expect(perTrail.RTJ?.rosterSize).toBe(5);
  });

  it("computes per-trail figures independently — one trail's low coverage doesn't drag another's", () => {
    const perCourse = [
      course("TN", "live"),
      course("TN", "not-live"),
      course("VI", "live"),
      course("VI", "live"),
    ];
    const perTrail = computeX4Coverage(perCourse);
    expect(perTrail.TN?.verdict).toBe("kill");
    expect(perTrail.VI?.verdict).toBe("pass");
  });
});

describe("x4-verify: runX4Verify — live mode", () => {
  it("fetches each non-null URL, records live/not-live, and saves every live response for replay", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        const res = new Response("Grand National Golf Club tee times available now.", {
          status: 200,
          headers: { "content-type": "text/html" },
        });
        Object.defineProperty(res, "url", {
          value: "https://www.golfnow.com/tee-times/facility/2360-grand-national/search",
        });
        return res;
      }),
    );
    const courseMap: X4CourseMap = {
      "Grand National": {
        trail: "RTJ",
        golfnowFacilityUrl:
          "https://www.golfnow.com/tee-times/facility/2360-grand-national/search",
      },
      "No Page Course": { trail: "RTJ", golfnowFacilityUrl: null },
    };
    const outDir = path.join(OUT_DIR, "live-run");
    const result = await runX4Verify(courseMap, outDir);

    expect(result.perTrail.RTJ?.liveCount).toBe(1);
    expect(result.perTrail.RTJ?.rosterSize).toBe(2);

    const saved = JSON.parse(
      readFileSync(path.join(outDir, "responses.json"), "utf8"),
    ) as Record<string, X4SavedEnvelope>;
    expect(saved["Grand National"]?.response.status).toBe(200);
    expect(saved["Grand National"]?.response.finalUrl).toContain("2360-grand-national");
    expect(typeof saved["Grand National"]?.fetchedAt).toBe("string");
  });

  it("records a blocked fetch distinctly and does not treat it as not-live silently", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new Error("CONNECT tunnel failed, response 403");
      }),
    );
    const courseMap: X4CourseMap = {
      "Grand National": {
        trail: "RTJ",
        golfnowFacilityUrl: "https://www.golfnow.com/tee-times/facility/2360-grand-national/search",
      },
    };
    const result = await runX4Verify(courseMap, path.join(OUT_DIR, "blocked-run"));
    expect(result.perCourse[0]?.status).toBe("failed");
    expect(result.perCourse[0]?.blocked).toBe(true);
    expect(result.warnings[0]).toContain("BLOCKED — network policy");
  });

  it("refuses on an empty course map", async () => {
    await expect(
      runX4Verify({}, path.join(OUT_DIR, "empty-run")),
    ).rejects.toThrow(/Course map is empty/);
  });
});

describe("x4-verify: runX4Verify — replay mode", () => {
  it("round-trips a live run's saved responses through --responses with an identical result", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        const res = new Response("Oxmoor Valley Golf Club — tee times.", {
          status: 200,
          headers: { "content-type": "text/html" },
        });
        Object.defineProperty(res, "url", {
          value: "https://www.golfnow.com/tee-times/facility/2353-oxmoor-valley/search",
        });
        return res;
      }),
    );
    const courseMap: X4CourseMap = {
      "Oxmoor Valley": {
        trail: "RTJ",
        golfnowFacilityUrl:
          "https://www.golfnow.com/tee-times/facility/2353-oxmoor-valley/search",
      },
    };
    const livePrefix = path.join(OUT_DIR, "roundtrip-live");
    const liveResult = await runX4Verify(courseMap, livePrefix);

    vi.unstubAllGlobals();
    const responses = JSON.parse(
      readFileSync(path.join(livePrefix, "responses.json"), "utf8"),
    ) as Record<string, X4SavedEnvelope>;
    const replayPrefix = path.join(OUT_DIR, "roundtrip-replay");
    const replayResult = await runX4Verify(courseMap, replayPrefix, { responses });

    expect(replayResult.perTrail).toEqual(liveResult.perTrail);
    expect(replayResult.perCourse[0]?.status).toBe("live");
  });

  it("refuses (throws) when --responses is missing an entry for a course, rather than treating it as not-live", async () => {
    const courseMap: X4CourseMap = {
      "Missing Response Course": {
        trail: "TN",
        golfnowFacilityUrl: "https://www.golfnow.com/tee-times/facility/1-x/search",
      },
    };
    await expect(
      runX4Verify(courseMap, path.join(OUT_DIR, "missing-response-run"), {
        responses: {},
      }),
    ).rejects.toThrow(/No saved response/);
  });
});
