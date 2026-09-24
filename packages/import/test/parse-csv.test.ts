import { describe, expect, it } from "vitest";
import { parseCsvFile } from "../src/parse-csv.js";
import { checkInputSize, MAX_INPUT_BYTES, MAX_WARNINGS } from "../src/safety.js";

function bytes(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

describe("parseCsvFile: fixes format", () => {
  it("parses timestamp,lat,lon,accuracy with strict ISO timestamps", () => {
    const csv =
      "timestamp,lat,lon,accuracy\n" +
      "2026-06-01T14:00:00Z,43.65,-79.38,5\n" +
      "2026-06-01T14:05:00Z,43.651,-79.379,6\n";
    const result = parseCsvFile(bytes(csv));
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.round.format).toBe("csv");
    expect(result.round.fixes).toHaveLength(2);
    // Mutation-pinning: exact values, not just "close enough".
    expect(result.round.fixes[0]!.lat).toBe(43.65);
    expect(result.round.fixes[0]!.lon).toBe(-79.38);
    expect(result.round.fixes[0]!.timestamp).toBe(Date.parse("2026-06-01T14:00:00Z"));
    expect(result.round.fixes[0]!.accuracyMeters).toBe(5);
    expect(result.round.startedAt).toBe(Date.parse("2026-06-01T14:00:00Z"));
    expect(result.round.endedAt).toBe(Date.parse("2026-06-01T14:05:00Z"));
  });

  it("accepts a numeric UTC offset in place of Z", () => {
    const csv = "timestamp,lat,lon\n2026-06-01T10:00:00-04:00,43.65,-79.38\n";
    const result = parseCsvFile(bytes(csv));
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.round.fixes[0]!.timestamp).toBe(Date.parse("2026-06-01T14:00:00Z"));
  });

  it("sorts out-of-order rows by timestamp", () => {
    const csv =
      "timestamp,lat,lon\n" +
      "2026-06-01T14:10:00Z,43.652,-79.377\n" +
      "2026-06-01T14:00:00Z,43.65,-79.38\n";
    const result = parseCsvFile(bytes(csv));
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.round.fixes[0]!.timestamp).toBeLessThan(result.round.fixes[1]!.timestamp);
  });

  it("drops an invalid row and warns, keeping the valid rows", () => {
    const csv =
      "timestamp,lat,lon\n" +
      "2026-06-01T14:00:00Z,43.65,-79.38\n" +
      "not-a-timestamp,43.65,-79.38\n" +
      "2026-06-01T14:05:00Z,999,-79.38\n";
    const result = parseCsvFile(bytes(csv));
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.round.fixes).toHaveLength(1);
    expect(result.round.warnings).toHaveLength(2);
  });

  describe("strict timestamp rejection (should-fix: require ISO-8601 + Z/offset)", () => {
    const badTimestamps = {
      "a bare epoch-millisecond number": "1780000000000",
      "a bare epoch-seconds number": "1780000000",
      "a naive time (no Z/offset)": "2026-06-01T14:00:00",
      "a US-style date": "06/01/2026 2:00 PM",
      "a date with no time": "2026-06-01",
      "a year before 2000": "1999-06-01T14:00:00Z",
    };
    for (const [label, value] of Object.entries(badTimestamps)) {
      it(`rejects ${label}`, () => {
        const csv = `timestamp,lat,lon\n${value},43.65,-79.38\n`;
        const result = parseCsvFile(bytes(csv));
        expect(result.ok).toBe(true);
        if (!result.ok) return;
        // The row is dropped (not the whole file — a header match is
        // still a fixes-shaped file), leaving zero fixes.
        expect(result.round.fixes).toEqual([]);
      });
    }
  });

  describe("coordinate safety (should-fix: decimal regex before Number())", () => {
    it("never turns an empty lat/lon into 0 (null island)", () => {
      const csv = "timestamp,lat,lon\n2026-06-01T14:00:00Z,,\n";
      const result = parseCsvFile(bytes(csv));
      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(result.round.fixes).toEqual([]);
    });

    it("rejects hex lat/lon", () => {
      const csv = "timestamp,lat,lon\n2026-06-01T14:00:00Z,0x10,-79.38\n";
      const result = parseCsvFile(bytes(csv));
      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(result.round.fixes).toEqual([]);
    });
  });

  describe("accuracy sanitization", () => {
    it("turns 0 or negative accuracy into undefined rather than keeping it", () => {
      const csv =
        "timestamp,lat,lon,accuracy\n" +
        "2026-06-01T14:00:00Z,43.65,-79.38,0\n" +
        "2026-06-01T14:01:00Z,43.65,-79.38,-5\n";
      const result = parseCsvFile(bytes(csv));
      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(result.round.fixes).toHaveLength(2);
      expect(result.round.fixes[0]!.accuracyMeters).toBeUndefined();
      expect(result.round.fixes[1]!.accuracyMeters).toBeUndefined();
    });
  });

  it("is routeless-only when every row is invalid: no startedAt/endedAt, warns", () => {
    const csv = "timestamp,lat,lon\nnot-a-timestamp,43.65,-79.38\n";
    const result = parseCsvFile(bytes(csv));
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.round.fixes).toEqual([]);
    expect(result.round.startedAt).toBeUndefined();
    expect(result.round.endedAt).toBeUndefined();
    expect(result.round.localDate).toBeUndefined();
    expect(result.round.warnings.length).toBeGreaterThan(0);
  });

  it("bounds warnings at MAX_WARNINGS plus one summary entry", () => {
    const rows = Array.from({ length: MAX_WARNINGS + 30 }, () => "not-a-timestamp,43.65,-79.38").join("\n");
    const csv = `timestamp,lat,lon\n${rows}\n`;
    const result = parseCsvFile(bytes(csv));
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.round.warnings.length).toBeLessThanOrEqual(MAX_WARNINGS + 1);
    expect(result.round.warnings[result.round.warnings.length - 1]).toContain("more");
  });
});

describe("parseCsvFile: scorecard format", () => {
  it("parses date,course,holes,score", () => {
    const csv = "date,course,holes,score\n2026-06-01,Pinehill Links,18,84\n";
    const result = parseCsvFile(bytes(csv));
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.round.fixes).toEqual([]);
    expect(result.round.localDate).toBe("2026-06-01");
    expect(result.round.courseNameHint).toBe("Pinehill Links");
    expect(result.round.holes).toBe(18);
    expect(result.round.totalScore).toBe(84);
    expect(result.round.startedAt).toBeUndefined();
  });

  it("supports a quoted course name containing a comma (RFC 4180)", () => {
    const csv = 'date,course,holes,score\n2026-06-01,"Pinehill Links, North Course",18,84\n';
    const result = parseCsvFile(bytes(csv));
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.round.courseNameHint).toBe("Pinehill Links, North Course");
  });

  it("supports an escaped-quote course name", () => {
    const csv = 'date,course,holes,score\n2026-06-01,"The ""Pines"" Club",18,84\n';
    const result = parseCsvFile(bytes(csv));
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.round.courseNameHint).toBe('The "Pines" Club');
  });

  it("rejects a non-calendar-shaped date", () => {
    const csv = "date,course,holes,score\n06/01/2026,Pinehill Links,18,84\n";
    const result = parseCsvFile(bytes(csv));
    expect(result.ok).toBe(false);
  });

  it("rejects a date that isn't a real calendar date (should-fix)", () => {
    const csv = "date,course,holes,score\n2026-13-45,Pinehill Links,18,84\n";
    const result = parseCsvFile(bytes(csv));
    expect(result.ok).toBe(false);
  });

  it("rejects Feb 30", () => {
    const csv = "date,course,holes,score\n2026-02-30,Pinehill Links,18,84\n";
    const result = parseCsvFile(bytes(csv));
    expect(result.ok).toBe(false);
  });

  it("rejects a full timestamp with Feb 30 in the fixes-format header too (round 2 should-fix)", () => {
    const csv = "timestamp,lat,lon\n2026-02-30T14:00:00+02:00,43.65,-79.38\n";
    const result = parseCsvFile(bytes(csv));
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.round.fixes).toEqual([]);
  });

  describe("holes (should-fix: 9, 18, or an integer up to 36)", () => {
    it("accepts 9", () => {
      const csv = "date,course,holes,score\n2026-06-01,X,9,40\n";
      const result = parseCsvFile(bytes(csv));
      expect(result.ok).toBe(true);
    });
    it("accepts 18", () => {
      const csv = "date,course,holes,score\n2026-06-01,X,18,84\n";
      const result = parseCsvFile(bytes(csv));
      expect(result.ok).toBe(true);
    });
    it("accepts 27 (a composite) since it's an integer under the 36 ceiling", () => {
      const csv = "date,course,holes,score\n2026-06-01,X,27,120\n";
      const result = parseCsvFile(bytes(csv));
      expect(result.ok).toBe(true);
    });
    it("rejects a non-integer (1e3)", () => {
      const csv = "date,course,holes,score\n2026-06-01,X,1e3,72\n";
      const result = parseCsvFile(bytes(csv));
      expect(result.ok).toBe(false);
    });
    it("rejects a fractional value", () => {
      const csv = "date,course,holes,score\n2026-06-01,X,18.5,72\n";
      const result = parseCsvFile(bytes(csv));
      expect(result.ok).toBe(false);
    });
    it("rejects over 36", () => {
      const csv = "date,course,holes,score\n2026-06-01,X,72,150\n";
      const result = parseCsvFile(bytes(csv));
      expect(result.ok).toBe(false);
    });
    it("rejects 0 or negative", () => {
      expect(parseCsvFile(bytes("date,course,holes,score\n2026-06-01,X,0,72\n")).ok).toBe(false);
      expect(parseCsvFile(bytes("date,course,holes,score\n2026-06-01,X,-9,72\n")).ok).toBe(false);
    });
  });

  describe("score (should-fix: positive integer)", () => {
    it("rejects a fractional score", () => {
      const csv = "date,course,holes,score\n2026-06-01,X,18,72.5\n";
      const result = parseCsvFile(bytes(csv));
      expect(result.ok).toBe(false);
    });
    it("rejects 0 or negative", () => {
      expect(parseCsvFile(bytes("date,course,holes,score\n2026-06-01,X,18,0\n")).ok).toBe(false);
      expect(parseCsvFile(bytes("date,course,holes,score\n2026-06-01,X,18,-1\n")).ok).toBe(false);
    });
  });

  it("uses only the first row and warns about extras", () => {
    const csv = "date,course,holes,score\n2026-06-01,Course A,18,84\n2026-06-02,Course B,18,90\n";
    const result = parseCsvFile(bytes(csv));
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.round.courseNameHint).toBe("Course A");
    expect(result.round.warnings.length).toBeGreaterThan(0);
  });
});

describe("parseCsvFile: ambiguous / unrecognized headers", () => {
  it("refuses a header matching neither known shape", () => {
    const csv = "time,latitude,longitude\n2026-06-01T14:00:00Z,43.65,-79.38\n";
    const result = parseCsvFile(bytes(csv));
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toContain("unrecognized");
  });

  it("refuses an empty file", () => {
    const result = parseCsvFile(bytes(""));
    expect(result.ok).toBe(false);
  });

  it("refuses a fixes-shaped header with the columns in the wrong order", () => {
    const csv = "lat,lon,timestamp\n43.65,-79.38,2026-06-01T14:00:00Z\n";
    const result = parseCsvFile(bytes(csv));
    expect(result.ok).toBe(false);
  });
});

describe("parseCsvFile: many valid rows still work", () => {
  it("parses 1000 valid fixes rows cleanly (well under the row cap)", () => {
    const rows = Array.from({ length: 1000 }, () => "2026-06-01T14:00:00Z,43.65,-79.38").join("\n");
    const csv = `timestamp,lat,lon\n${rows}\n`;
    const result = parseCsvFile(bytes(csv));
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.round.fixes).toHaveLength(1000);
  });
});

describe("parseCsvFile: size cap (should-fix: 5 MB, same as FIT)", () => {
  it("MAX_INPUT_BYTES is exactly 5 MB", () => {
    expect(MAX_INPUT_BYTES).toBe(5 * 1024 * 1024);
  });

  it("boundary: refuses one byte over the cap", () => {
    const oversized = new Uint8Array(MAX_INPUT_BYTES + 1);
    const result = parseCsvFile(oversized);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toContain("bytes");
  });

  it("boundary: exactly at the cap is not refused for size", () => {
    expect(checkInputSize(MAX_INPUT_BYTES, MAX_INPUT_BYTES)).toBeUndefined();
    expect(checkInputSize(MAX_INPUT_BYTES + 1, MAX_INPUT_BYTES)).toBeDefined();
  });
});
