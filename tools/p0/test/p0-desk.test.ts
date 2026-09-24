import { afterEach, describe, expect, it, vi } from "vitest";
import { mkdtempSync, writeFileSync, existsSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { runP0Desk, renderStatusBoard } from "../src/p0-desk.js";

const OUT_DIR = mkdtempSync(path.join(tmpdir(), "golfraven-p0-desk-test-"));

afterEach(() => {
  vi.unstubAllGlobals();
});

function writeX2Config(dir: string): string {
  const p = path.join(dir, "x2-sources.json");
  writeFileSync(
    p,
    JSON.stringify({
      TN: ["https://www.tnstateparks.com/golf"],
      VI: ["https://golfvancouverisland.ca/"],
      RTJ: ["https://www.rtjgolf.com/"],
    }),
    "utf8",
  );
  return p;
}

describe("p0-desk: BLOCKED reporting with a fake fetch that returns a 403 CONNECT error", () => {
  it("surfaces the proxy block as 'BLOCKED — network policy (<host>)' for both x5 n-osm and x2-fetch, and exits non-zero", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new Error("CONNECT tunnel failed, response 403");
      }),
    );
    const runDir = path.join(OUT_DIR, "all-blocked-run");
    const x2ConfigPath = writeX2Config(OUT_DIR);
    const result = await runP0Desk({
      runDir,
      x2ConfigPath,
      x4CoursesPath: path.join(OUT_DIR, "does-not-exist-course-map.json"),
    });

    const x5Row = result.rows.find((r) => r.name === "x5-overpass n-osm");
    const x2Row = result.rows.find((r) => r.name === "x2-fetch");
    const x4Row = result.rows.find((r) => r.name === "x4-verify");

    expect(x5Row?.state).toBe("blocked");
    expect(x5Row?.detail).toContain(
      "BLOCKED — network policy (overpass-api.de)",
    );

    expect(x2Row?.state).toBe("blocked");
    expect(x2Row?.detail).toMatch(
      /BLOCKED — network policy \(.*tnstateparks\.com.*\)/,
    );

    expect(x4Row?.state).toBe("skipped");

    expect(result.exitCode).toBe(1);

    const board = renderStatusBoard(result);
    expect(board).toContain("[BLOCKED] x5-overpass n-osm");
    expect(board).toContain("[BLOCKED] x2-fetch");
    expect(board).toContain("[SKIPPED] x4-verify");
    expect(board).toContain("Exiting non-zero");

    // Evidence dir + status.json still get written even though everything blocked.
    expect(existsSync(path.join(runDir, "status.json"))).toBe(true);
    expect(existsSync(path.join(runDir, "x2-evidence", "manifest.json"))).toBe(
      true,
    );
    const status = JSON.parse(
      readFileSync(path.join(runDir, "status.json"), "utf8"),
    );
    expect(status.exitCode).toBe(1);
  });
});

describe("p0-desk: a healthy run", () => {
  it("state 'ran' for x5 n-osm, 'needs-confirmation' for x2-fetch, 'skipped' for x4-verify (no course map) -> exit 0", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        if (url.includes("overpass-api.de")) {
          return new Response(
            JSON.stringify({
              elements: [{ type: "count", id: 0, tags: { total: "16212" } }],
            }),
            { status: 200 },
          );
        }
        return new Response("<h1>Some Trail Page</h1>", {
          status: 200,
          headers: { "content-type": "text/html" },
        });
      }),
    );
    const runDir = path.join(OUT_DIR, "healthy-run");
    const x2ConfigPath = writeX2Config(OUT_DIR);
    const result = await runP0Desk({
      runDir,
      x2ConfigPath,
      x4CoursesPath: path.join(OUT_DIR, "still-does-not-exist.json"),
    });

    const x5Row = result.rows.find((r) => r.name === "x5-overpass n-osm");
    const x2Row = result.rows.find((r) => r.name === "x2-fetch");
    const x4Row = result.rows.find((r) => r.name === "x4-verify");

    expect(x5Row?.state).toBe("ran");
    expect(x5Row?.detail).toContain("N_osm = 16212");
    expect(x2Row?.state).toBe("needs-confirmation");
    expect(x4Row?.state).toBe("skipped");
    expect(result.exitCode).toBe(0);
  });
});

describe("p0-desk: gate finding S5 — partial block/failure must not read as a clean exit-0 state", () => {
  it("x2-fetch: some URLs fetched, some failed -> state 'partial-blocked', exit non-zero", async () => {
    let call = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        if (url.includes("overpass-api.de")) {
          return new Response(
            JSON.stringify({
              elements: [{ type: "count", id: 0, tags: { total: "100" } }],
            }),
            { status: 200 },
          );
        }
        call += 1;
        if (call === 1) return new Response("not found", { status: 404 });
        return new Response("<h1>OK</h1>", {
          status: 200,
          headers: { "content-type": "text/html" },
        });
      }),
    );
    const runDir = path.join(OUT_DIR, "partial-x2-run");
    const x2ConfigPath = writeX2Config(OUT_DIR);
    const result = await runP0Desk({
      runDir,
      x2ConfigPath,
      x4CoursesPath: path.join(OUT_DIR, "no-course-map.json"),
    });
    const x2Row = result.rows.find((r) => r.name === "x2-fetch");
    expect(x2Row?.state).toBe("partial-blocked");
    expect(result.exitCode).toBe(1);
  });

  it("x4-verify: an indeterminate course (e.g. 429) -> state 'partial-blocked', exit non-zero, never a clean 'verdict'", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        if (url.includes("overpass-api.de")) {
          return new Response(
            JSON.stringify({
              elements: [{ type: "count", id: 0, tags: { total: "100" } }],
            }),
            { status: 200 },
          );
        }
        if (url.includes("golfnow.com")) {
          return new Response("rate limited", { status: 429 });
        }
        return new Response("<h1>Trail Page</h1>", {
          status: 200,
          headers: { "content-type": "text/html" },
        });
      }),
    );
    const runDir = path.join(OUT_DIR, "indeterminate-x4-run");
    const x2ConfigPath = writeX2Config(OUT_DIR);
    const x4CoursesPath = path.join(
      OUT_DIR,
      "x4-course-map-indeterminate.json",
    );
    writeFileSync(
      x4CoursesPath,
      JSON.stringify({
        "Grand National": {
          trail: "RTJ",
          golfnowFacilityUrl:
            "https://www.golfnow.com/tee-times/facility/2360-grand-national/search",
        },
      }),
      "utf8",
    );
    const result = await runP0Desk({ runDir, x2ConfigPath, x4CoursesPath });
    const x4Row = result.rows.find((r) => r.name === "x4-verify");
    expect(x4Row?.state).toBe("partial-blocked");
    expect(x4Row?.detail).toContain("not run — indeterminate");
    expect(result.exitCode).toBe(1);
  });
});

describe("p0-desk: x4-verify runs and reports a verdict when a course map file IS present", () => {
  it("state 'verdict' with per-trail pass/kill once a course-map file exists", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        if (url.includes("overpass-api.de")) {
          return new Response(
            JSON.stringify({
              elements: [{ type: "count", id: 0, tags: { total: "100" } }],
            }),
            { status: 200 },
          );
        }
        if (url.includes("golfnow.com")) {
          const res = new Response("Grand National Golf Club tee times.", {
            status: 200,
            headers: { "content-type": "text/html" },
          });
          Object.defineProperty(res, "url", {
            value:
              "https://www.golfnow.com/tee-times/facility/2360-grand-national/search",
          });
          return res;
        }
        return new Response("<h1>Trail Page</h1>", {
          status: 200,
          headers: { "content-type": "text/html" },
        });
      }),
    );
    const runDir = path.join(OUT_DIR, "with-x4-run");
    const x2ConfigPath = writeX2Config(OUT_DIR);
    const x4CoursesPath = path.join(OUT_DIR, "x4-course-map.json");
    writeFileSync(
      x4CoursesPath,
      JSON.stringify({
        "Grand National": {
          trail: "RTJ",
          golfnowFacilityUrl:
            "https://www.golfnow.com/tee-times/facility/2360-grand-national/search",
        },
      }),
      "utf8",
    );
    const result = await runP0Desk({ runDir, x2ConfigPath, x4CoursesPath });
    const x4Row = result.rows.find((r) => r.name === "x4-verify");
    expect(x4Row?.state).toBe("verdict");
    expect(x4Row?.detail).toContain("RTJ 1/1 (100.0%) PASS");
    expect(result.exitCode).toBe(0);
  });
});
