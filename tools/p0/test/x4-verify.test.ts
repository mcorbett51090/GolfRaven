import { afterEach, describe, expect, it, vi } from "vitest";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import {
  computeX4Coverage,
  isLiveFacilityPage,
  parseFacilityId,
  runX4Verify,
  type X4CheckResult,
  type X4CourseMap,
  type X4SavedEnvelope,
} from "../src/x4-verify.js";

const OUT_DIR = mkdtempSync(path.join(tmpdir(), "golfraven-p0-x4-test-"));

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("x4-verify: parseFacilityId (gate finding B2)", () => {
  it("parses the numeric id from a well-formed configured URL", () => {
    expect(
      parseFacilityId("https://www.golfnow.com/tee-times/facility/2360-grand-national/search"),
    ).toBe("2360");
  });

  it("refuses (throws) on http instead of https", () => {
    expect(() =>
      parseFacilityId("http://www.golfnow.com/tee-times/facility/2360-grand-national/search"),
    ).toThrow(/does not match/);
  });

  it("refuses (throws) on a foreign host", () => {
    expect(() =>
      parseFacilityId("https://evil.example/tee-times/facility/2360-grand-national/search"),
    ).toThrow(/does not match/);
  });

  it("refuses (throws) when the URL has no numeric id segment", () => {
    expect(() =>
      parseFacilityId("https://www.golfnow.com/tee-times/search"),
    ).toThrow(/does not match/);
  });
});

describe("x4-verify: isLiveFacilityPage (decision 0001 Addendum H's three-way outcome, literal)", () => {
  it("live: HTTP 200, final URL matches the SAME facility id, page text contains the course name", () => {
    const result = isLiveFacilityPage(
      200,
      "https://www.golfnow.com/tee-times/facility/2360-grand-national/search",
      "Welcome to Grand National tee times.",
      "Grand National",
      "2360",
    );
    expect(result.status).toBe("live");
  });

  it("not-live: HTTP 200 but a DIFFERENT facility id in the final URL (gate B2 probe P4a)", () => {
    const result = isLiveFacilityPage(
      200,
      "https://www.golfnow.com/tee-times/facility/9999-nearby-course/search",
      "Nearby Course tee times, also mentions Grand National nearby.",
      "Grand National",
      "2360",
    );
    expect(result.status).toBe("not-live");
    expect(result.reason).toContain("SAME id");
  });

  it("not-live: HTTP 200 but the requested id only appears in the QUERY STRING, not the path (gate B2 probe P4b)", () => {
    const result = isLiveFacilityPage(
      200,
      "https://www.golfnow.com/tee-times/search?ret=/tee-times/facility/2360-x",
      "No results found for Grand National.",
      "Grand National",
      "2360",
    );
    expect(result.status).toBe("not-live");
  });

  it("not-live: HTTP 200 but a FOREIGN HOST (gate B2 probe P4c)", () => {
    const result = isLiveFacilityPage(
      200,
      "https://evil.example/tee-times/facility/2360-grand-national/search",
      "Grand National tee times available.",
      "Grand National",
      "2360",
    );
    expect(result.status).toBe("not-live");
    expect(result.reason).toContain("not exactly");
  });

  it("not-live: HTTP 200 but the course name is missing from the page text", () => {
    const result = isLiveFacilityPage(
      200,
      "https://www.golfnow.com/tee-times/facility/2360-grand-national/search",
      "This page does not mention the course by name.",
      "Grand National",
      "2360",
    );
    expect(result.status).toBe("not-live");
    expect(result.reason).toContain("was not found on the page text");
  });

  it("not-live (definitive): HTTP 404", () => {
    const result = isLiveFacilityPage(404, "https://www.golfnow.com/x", "x", "Grand National", "2360");
    expect(result.status).toBe("not-live");
    expect(result.reason).toContain("HTTP 404");
  });

  it("not-live (definitive): HTTP 410", () => {
    const result = isLiveFacilityPage(410, "https://www.golfnow.com/x", "x", "Grand National", "2360");
    expect(result.status).toBe("not-live");
  });

  it("indeterminate (Addendum H, never 'not covered'): HTTP 403", () => {
    const result = isLiveFacilityPage(403, "https://www.golfnow.com/x", "x", "Grand National", "2360");
    expect(result.status).toBe("indeterminate");
  });

  it("indeterminate: HTTP 429", () => {
    const result = isLiveFacilityPage(429, "https://www.golfnow.com/x", "x", "Grand National", "2360");
    expect(result.status).toBe("indeterminate");
  });

  it("indeterminate: HTTP 503 (any 5xx)", () => {
    const result = isLiveFacilityPage(503, "https://www.golfnow.com/x", "x", "Grand National", "2360");
    expect(result.status).toBe("indeterminate");
  });

  it("indeterminate: an unlisted status (e.g. 400)", () => {
    const result = isLiveFacilityPage(400, "https://www.golfnow.com/x", "x", "Grand National", "2360");
    expect(result.status).toBe("indeterminate");
  });

  it("decision 0001 Addendum J(b): a same-id redirect to the NEW /courses/<id>- shape counts as live", () => {
    const result = isLiveFacilityPage(
      200,
      "https://www.golfnow.com/courses/2360-grand-national-details",
      "Grand National Golf Club course details and tee times.",
      "Grand National",
      "2360",
    );
    expect(result.status).toBe("live");
  });

  it("decision 0001 Addendum J(b): a DIFFERENT id in the /courses/ redirect is not covered", () => {
    const result = isLiveFacilityPage(
      200,
      "https://www.golfnow.com/courses/9999-nearby-course-details",
      "Nearby Course details, also mentions Grand National nearby.",
      "Grand National",
      "2360",
    );
    expect(result.status).toBe("not-live");
    expect(result.reason).toContain("SAME id");
  });

  it("decision 0001 Addendum J(b): a /courses/<id>- URL missing the course name is not covered", () => {
    const result = isLiveFacilityPage(
      200,
      "https://www.golfnow.com/courses/2360-grand-national-details",
      "This page does not mention the course by name.",
      "Grand National",
      "2360",
    );
    expect(result.status).toBe("not-live");
    expect(result.reason).toContain("was not found on the page text");
  });

  it("decision 0001 Addendum J(b): the OLD /tee-times/facility/<id>- shape still counts as live, unchanged", () => {
    const result = isLiveFacilityPage(
      200,
      "https://www.golfnow.com/tee-times/facility/2360-grand-national/search",
      "Grand National tee times available now.",
      "Grand National",
      "2360",
    );
    expect(result.status).toBe("live");
  });

  it("name match applies Addendum F normalisation (case/punctuation-insensitive whole-word match)", () => {
    const result = isLiveFacilityPage(
      200,
      "https://www.golfnow.com/tee-times/facility/2361-cambrian-ridge/search",
      "BOOK YOUR TEE TIME AT CAMBRIAN RIDGE GOLF CLUB TODAY",
      "Cambrian Ridge",
      "2361",
    );
    expect(result.status).toBe("live");
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

  it("decision 0001 Addendum H: ANY indeterminate course blocks that trail's whole verdict, regardless of the rest", () => {
    const perCourse = [
      course("TN", "live"),
      course("TN", "live"),
      course("TN", "live"),
      course("TN", "live"),
      course("TN", "indeterminate"),
    ];
    const perTrail = computeX4Coverage(perCourse);
    expect(perTrail.TN?.verdict).toBe("not-run");
    expect(perTrail.TN?.pct).toBeNull();
    expect(perTrail.TN?.indeterminateCount).toBe(1);
    expect(perTrail.TN?.consequence).toBeNull();
  });
});

describe("x4-verify: runX4Verify — live mode", () => {
  it("fetches each non-null URL, records live/not-live, and saves every live response for replay", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
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
    const result = await runX4Verify(courseMap, outDir, { slateTrails: ["RTJ"] });

    expect(result.perTrail.RTJ?.liveCount).toBe(1);
    expect(result.perTrail.RTJ?.rosterSize).toBe(2);
    expect(result.anyIndeterminate).toBe(false);

    const saved = JSON.parse(
      readFileSync(path.join(outDir, "responses.json"), "utf8"),
    ) as Record<string, X4SavedEnvelope>;
    expect(saved["Grand National"]?.response.status).toBe(200);
    expect(saved["Grand National"]?.response.finalUrl).toContain("2360-grand-national");
    expect(typeof saved["Grand National"]?.fetchedAt).toBe("string");
  });

  it("records a blocked fetch as indeterminate and does not treat it as not-live silently (gate B1)", async () => {
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
    const result = await runX4Verify(courseMap, path.join(OUT_DIR, "blocked-run"), {
      slateTrails: ["RTJ"],
    });
    expect(result.perCourse[0]?.status).toBe("indeterminate");
    expect(result.perCourse[0]?.blocked).toBe(true);
    expect(result.warnings[0]).toContain("BLOCKED — network policy");
    expect(result.anyIndeterminate).toBe(true);
    expect(result.perTrail.RTJ?.verdict).toBe("not-run");
  });

  it("gate B1: a timeout is indeterminate, never counted as not covered", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(
        () =>
          new Promise((_resolve, reject) => {
            setTimeout(() => reject(new Error("The operation was aborted")), 10);
          }),
      ),
    );
    const courseMap: X4CourseMap = {
      "Grand National": {
        trail: "RTJ",
        golfnowFacilityUrl: "https://www.golfnow.com/tee-times/facility/2360-grand-national/search",
      },
    };
    const result = await runX4Verify(courseMap, path.join(OUT_DIR, "timeout-run"), {
      slateTrails: ["RTJ"],
      timeoutMs: 5,
    });
    expect(result.perCourse[0]?.status).toBe("indeterminate");
    expect(result.perTrail.RTJ?.verdict).toBe("not-run");
  });

  it("gate B1: a site-side 403/429/5xx resolves to indeterminate, not not-live", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response("rate limited", { status: 429 })),
    );
    const courseMap: X4CourseMap = {
      "Grand National": {
        trail: "RTJ",
        golfnowFacilityUrl: "https://www.golfnow.com/tee-times/facility/2360-grand-national/search",
      },
    };
    const result = await runX4Verify(courseMap, path.join(OUT_DIR, "429-run"), {
      slateTrails: ["RTJ"],
    });
    expect(result.perCourse[0]?.status).toBe("indeterminate");
  });

  it("gate B1: a 404 is not-live (definitive not-covered), not indeterminate", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response("not found", { status: 404 })),
    );
    const courseMap: X4CourseMap = {
      "Grand National": {
        trail: "RTJ",
        golfnowFacilityUrl: "https://www.golfnow.com/tee-times/facility/2360-grand-national/search",
      },
    };
    const result = await runX4Verify(courseMap, path.join(OUT_DIR, "404-run"), {
      slateTrails: ["RTJ"],
    });
    expect(result.perCourse[0]?.status).toBe("not-live");
    expect(result.anyIndeterminate).toBe(false);
    expect(result.perTrail.RTJ?.verdict).toBe("kill");
  });

  it("refuses on an empty course map", async () => {
    await expect(
      runX4Verify({}, path.join(OUT_DIR, "empty-run")),
    ).rejects.toThrow(/Course map is empty/);
  });

  it("gate N7: refuses when a slate trail is entirely missing from the course map", async () => {
    const courseMap: X4CourseMap = {
      "Grand National": {
        trail: "RTJ",
        golfnowFacilityUrl: "https://www.golfnow.com/tee-times/facility/2360-grand-national/search",
      },
    };
    await expect(
      runX4Verify(courseMap, path.join(OUT_DIR, "missing-slate-run")),
    ).rejects.toThrow(/no entry for trail\(s\)/);
  });

  it("gate N7: an explicit slateTrails list overrides the default pilot slate", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        const res = new Response("Grand National tee times.", {
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
        golfnowFacilityUrl: "https://www.golfnow.com/tee-times/facility/2360-grand-national/search",
      },
    };
    const result = await runX4Verify(courseMap, path.join(OUT_DIR, "explicit-slate-run"), {
      slateTrails: ["RTJ"],
    });
    expect(result.perTrail.RTJ?.verdict).toBe("pass");
  });

  it("gate B2: refuses (throws) when a course map entry's configured URL is malformed", async () => {
    const courseMap: X4CourseMap = {
      "Grand National": { trail: "RTJ", golfnowFacilityUrl: "https://www.golfnow.com/tee-times/search" },
    };
    await expect(
      runX4Verify(courseMap, path.join(OUT_DIR, "bad-url-run"), { slateTrails: ["RTJ"] }),
    ).rejects.toThrow(/does not match/);
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
    const liveResult = await runX4Verify(courseMap, livePrefix, { slateTrails: ["RTJ"] });

    vi.unstubAllGlobals();
    const responses = JSON.parse(
      readFileSync(path.join(livePrefix, "responses.json"), "utf8"),
    ) as Record<string, X4SavedEnvelope>;
    const replayPrefix = path.join(OUT_DIR, "roundtrip-replay");
    const replayResult = await runX4Verify(courseMap, replayPrefix, {
      responses,
      slateTrails: ["RTJ"],
    });

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
        slateTrails: ["TN"],
      }),
    ).rejects.toThrow(/No saved response/);
  });

  it("gate N1: refuses (throws) a replay whose saved request URL no longer matches the course map's current URL", async () => {
    const courseMap: X4CourseMap = {
      "Some Course": {
        trail: "TN",
        golfnowFacilityUrl: "https://www.golfnow.com/tee-times/facility/2222-some-course/search",
      },
    };
    const responses: Record<string, X4SavedEnvelope> = {
      "Some Course": {
        request: { url: "https://www.golfnow.com/tee-times/facility/1111-some-course/search" },
        fetchedAt: new Date().toISOString(),
        response: {
          status: 200,
          finalUrl: "https://www.golfnow.com/tee-times/facility/1111-some-course/search",
          bodyText: "Some Course tee times.",
        },
      },
    };
    await expect(
      runX4Verify(courseMap, path.join(OUT_DIR, "stale-replay-run"), {
        responses,
        slateTrails: ["TN"],
      }),
    ).rejects.toThrow(/differs from the course map's current URL/);
  });
});
