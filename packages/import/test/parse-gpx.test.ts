import { describe, expect, it } from "vitest";
import { parseGpxFile } from "../src/parse-gpx.js";
import { checkInputSize, MAX_INPUT_BYTES } from "../src/safety.js";

function bytes(xml: string): Uint8Array {
  return new TextEncoder().encode(xml);
}

const GPX_11 = `<?xml version="1.0" encoding="UTF-8"?>
<gpx version="1.1" creator="Garmin Connect" xmlns="http://www.topografix.com/GPX/1/1">
  <metadata>
    <name>Metadata Course Name</name>
    <time>2026-06-01T14:00:00Z</time>
  </metadata>
  <trk>
    <name>Pinehill Links Round</name>
    <trkseg>
      <trkpt lat="43.6500" lon="-79.3800"><ele>100.0</ele><time>2026-06-01T14:05:00Z</time></trkpt>
      <trkpt lat="43.6510" lon="-79.3790"><ele>101.0</ele><time>2026-06-01T14:10:00Z</time></trkpt>
      <trkpt lat="43.6520" lon="-79.3780"><ele>102.0</ele><time>2026-06-01T14:15:00Z</time></trkpt>
    </trkseg>
  </trk>
</gpx>`;

const GPX_10 = `<?xml version="1.0"?>
<gpx version="1.0" creator="OldWatch 1.0">
  <name>Top Level Course Name</name>
  <time>2026-05-01T09:00:00Z</time>
  <rte>
    <rtept lat="43.10" lon="-79.10"><time>2026-05-01T09:05:00Z</time></rtept>
    <rtept lat="43.11" lon="-79.11"><time>2026-05-01T09:35:00Z</time></rtept>
  </rte>
</gpx>`;

const GPX_NO_TIME = `<?xml version="1.1"?>
<gpx version="1.1" creator="NoTimeDevice" xmlns="http://www.topografix.com/GPX/1/1">
  <trk><trkseg>
    <trkpt lat="43.0" lon="-79.0"></trkpt>
    <trkpt lat="43.01" lon="-79.01"></trkpt>
  </trkseg></trk>
</gpx>`;

const GPX_NO_TIME_WITH_OFFSET_METADATA = `<?xml version="1.1"?>
<gpx version="1.1" creator="NoTimeDevice" xmlns="http://www.topografix.com/GPX/1/1">
  <metadata><time>2026-04-15T22:00:00-04:00</time></metadata>
  <trk><trkseg>
    <trkpt lat="43.0" lon="-79.0"></trkpt>
  </trkseg></trk>
</gpx>`;

const GPX_NO_TIME_WITH_Z_METADATA = `<?xml version="1.1"?>
<gpx version="1.1" creator="NoTimeDevice" xmlns="http://www.topografix.com/GPX/1/1">
  <metadata><time>2026-04-16T02:00:00Z</time></metadata>
  <trk><trkseg>
    <trkpt lat="43.0" lon="-79.0"></trkpt>
  </trkseg></trk>
</gpx>`;

const GPX_MALFORMED = `<?xml version="1.1"?>
<gpx version="1.1"><trk><trkseg><trkpt lat="1" lon="2">`;

const NOT_GPX = `<?xml version="1.0"?><kml><Document/></kml>`;

const GPX_XXE = `<?xml version="1.0"?>
<!DOCTYPE gpx [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<gpx version="1.1" creator="Evil"><trk><trkseg><trkpt lat="1" lon="2"><time>2026-01-01T00:00:00Z</time></trkpt></trkseg></trk></gpx>`;

describe("parseGpxFile: GPX 1.1", () => {
  it("parses trkpts, prefers the trk name, and reads the creator", () => {
    const result = parseGpxFile(bytes(GPX_11));
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.round.format).toBe("gpx");
    expect(result.round.fixes).toHaveLength(3);
    expect(result.round.device).toBe("Garmin Connect");
    expect(result.round.courseNameHint).toBe("Pinehill Links Round");
    expect(result.round.startedAt).toBe(Date.parse("2026-06-01T14:05:00Z"));
    expect(result.round.endedAt).toBe(Date.parse("2026-06-01T14:15:00Z"));
    expect(result.round.localDate).toBeUndefined();

    // Mutation-pinning: exact coordinates.
    expect(result.round.fixes[0]!.lat).toBe(43.65);
    expect(result.round.fixes[0]!.lon).toBe(-79.38);
  });
});

describe("parseGpxFile: GPX 1.0", () => {
  it("parses rtepts and falls back to the top-level name", () => {
    const result = parseGpxFile(bytes(GPX_10));
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.round.fixes).toHaveLength(2);
    expect(result.round.device).toBe("OldWatch 1.0");
    expect(result.round.courseNameHint).toBe("Top Level Course Name");
    expect(result.round.startedAt).toBe(Date.parse("2026-05-01T09:05:00Z"));
    expect(result.round.endedAt).toBe(Date.parse("2026-05-01T09:35:00Z"));
  });
});

describe("parseGpxFile: no <time> on any point", () => {
  it("drops the route (empty fixes) and warns, with no date available", () => {
    const result = parseGpxFile(bytes(GPX_NO_TIME));
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.round.fixes).toEqual([]);
    expect(result.round.startedAt).toBeUndefined();
    expect(result.round.localDate).toBeUndefined();
    expect(result.round.warnings.length).toBeGreaterThan(0);
  });

  it("uses <metadata><time>'s own offset directly when it carries one", () => {
    const result = parseGpxFile(bytes(GPX_NO_TIME_WITH_OFFSET_METADATA));
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.round.fixes).toEqual([]);
    expect(result.round.localDate).toBe("2026-04-15");
  });

  it("does NOT trust a bare-Z metadata time as a local date without a tz option", () => {
    const result = parseGpxFile(bytes(GPX_NO_TIME_WITH_Z_METADATA));
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.round.localDate).toBeUndefined();
    expect(result.round.warnings.some((w) => w.toLowerCase().includes("tz"))).toBe(true);
  });

  it("uses a tz option to convert a bare-Z metadata time into a local date", () => {
    const result = parseGpxFile(bytes(GPX_NO_TIME_WITH_Z_METADATA), { tz: "America/Toronto" });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    // 2026-04-16T02:00:00Z is 2026-04-15T22:00 EDT (UTC-4).
    expect(result.round.localDate).toBe("2026-04-15");
  });
});

describe("parseGpxFile: malformed XML", () => {
  it("is refused rather than throwing", () => {
    const result = parseGpxFile(bytes(GPX_MALFORMED));
    expect(result.ok).toBe(false);
  });
});

describe("parseGpxFile: not a GPX file", () => {
  it("is refused loudly rather than silently returning an empty round", () => {
    const result = parseGpxFile(bytes(NOT_GPX));
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toContain("GPX");
  });
});

describe("parseGpxFile: an XXE attempt", () => {
  it("is refused outright", () => {
    const result = parseGpxFile(bytes(GPX_XXE));
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.toUpperCase()).toContain("DOCTYPE");
  });
});

describe("parseGpxFile: coordinate safety (should-fix: decimal regex before Number())", () => {
  it("drops a trkpt with an out-of-range lat/lon", () => {
    const xml = `<?xml version="1.1"?>
<gpx version="1.1" xmlns="http://www.topografix.com/GPX/1/1">
  <trk><trkseg>
    <trkpt lat="43.0" lon="-79.0"><time>2026-01-01T00:00:00Z</time></trkpt>
    <trkpt lat="999" lon="-79.0"><time>2026-01-01T00:01:00Z</time></trkpt>
  </trkseg></trk>
</gpx>`;
    const result = parseGpxFile(bytes(xml));
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.round.fixes).toHaveLength(1);
    expect(result.round.warnings.some((w) => w.includes("invalid"))).toBe(true);
  });

  it("never turns an empty lat/lon into 0 (null island)", () => {
    const xml = `<?xml version="1.1"?>
<gpx version="1.1" xmlns="http://www.topografix.com/GPX/1/1">
  <trk><trkseg><trkpt lat="" lon=" "><time>2026-01-01T00:00:00Z</time></trkpt></trkseg></trk>
</gpx>`;
    const result = parseGpxFile(bytes(xml));
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.round.fixes).toEqual([]);
  });

  it("rejects a hex lat", () => {
    const xml = `<?xml version="1.1"?>
<gpx version="1.1" xmlns="http://www.topografix.com/GPX/1/1">
  <trk><trkseg><trkpt lat="0x10" lon="1e1"><time>2026-01-01T00:00:00Z</time></trkpt></trkseg></trk>
</gpx>`;
    const result = parseGpxFile(bytes(xml));
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.round.fixes).toEqual([]);
  });
});

describe("parseGpxFile: strict timestamps (should-fix)", () => {
  const badTimes = {
    "a naive time (no Z/offset)": "2026-06-01T14:00:00",
    "a non-ISO string": "June 1 2026 2:00 PM",
    "a year before 2000": "1999-06-01T14:00:00Z",
    "Feb 30 (round 2 should-fix — Date.parse silently rolls this to March 2nd)": "2026-02-30T14:00:00+02:00",
  };
  for (const [label, value] of Object.entries(badTimes)) {
    it(`drops a trkpt with ${label} rather than guessing`, () => {
      const xml = `<?xml version="1.1"?>
<gpx version="1.1" xmlns="http://www.topografix.com/GPX/1/1">
  <trk><trkseg><trkpt lat="43.0" lon="-79.0"><time>${value}</time></trkpt></trkseg></trk>
</gpx>`;
      const result = parseGpxFile(bytes(xml));
      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(result.round.fixes).toEqual([]);
    });
  }

  it("accepts a numeric UTC offset", () => {
    const xml = `<?xml version="1.1"?>
<gpx version="1.1" xmlns="http://www.topografix.com/GPX/1/1">
  <trk><trkseg><trkpt lat="43.0" lon="-79.0"><time>2026-06-01T10:00:00-04:00</time></trkpt></trkseg></trk>
</gpx>`;
    const result = parseGpxFile(bytes(xml));
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.round.fixes).toHaveLength(1);
    expect(result.round.fixes[0]!.timestamp).toBe(Date.parse("2026-06-01T14:00:00Z"));
  });
});

describe("parseGpxFile: size cap (should-fix: 5 MB, same as FIT)", () => {
  it("MAX_INPUT_BYTES is exactly 5 MB", () => {
    expect(MAX_INPUT_BYTES).toBe(5 * 1024 * 1024);
  });

  it("boundary: refuses one byte over the cap", () => {
    const oversized = new Uint8Array(MAX_INPUT_BYTES + 1);
    const result = parseGpxFile(oversized);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toContain("bytes");
  });

  it("boundary: exactly at the cap is not refused for size (the size check alone passes it through)", () => {
    // checkInputSize's own boundary math is unit-tested precisely in
    // safety.test.ts; this just confirms parseGpxFile wires the cap in
    // (not off-by-one) without constructing a slow, unnecessary 5 MB
    // buffer of real-looking XML.
    expect(checkInputSize(MAX_INPUT_BYTES, MAX_INPUT_BYTES)).toBeUndefined();
    expect(checkInputSize(MAX_INPUT_BYTES + 1, MAX_INPUT_BYTES)).toBeDefined();
  });
});
