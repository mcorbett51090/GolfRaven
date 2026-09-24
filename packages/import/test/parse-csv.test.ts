import { describe, expect, it } from "vitest";
import { parseCsvFile } from "../src/parse-csv.js";

function bytes(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

describe("parseCsvFile: fixes format", () => {
  it("parses timestamp,lat,lon,accuracy with ISO timestamps", () => {
    const csv =
      "timestamp,lat,lon,accuracy\n" +
      "2026-06-01T14:00:00Z,43.65,-79.38,5\n" +
      "2026-06-01T14:05:00Z,43.651,-79.379,6\n";
    const result = parseCsvFile(bytes(csv));
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.round.format).toBe("csv");
    expect(result.round.fixes).toHaveLength(2);
    expect(result.round.fixes[0]!.timestamp).toBe(Date.parse("2026-06-01T14:00:00Z"));
    expect(result.round.fixes[0]!.accuracyMeters).toBe(5);
    expect(result.round.startedAt).toBe(Date.parse("2026-06-01T14:00:00Z"));
    expect(result.round.endedAt).toBe(Date.parse("2026-06-01T14:05:00Z"));
  });

  it("parses timestamp,lat,lon with bare epoch-millisecond timestamps and no accuracy column", () => {
    const csv = "timestamp,lat,lon\n1780000000000,43.65,-79.38\n1780000300000,43.651,-79.379\n";
    const result = parseCsvFile(bytes(csv));
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.round.fixes).toHaveLength(2);
    expect(result.round.fixes[0]!.accuracyMeters).toBeUndefined();
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

  it("rejects a malformed date", () => {
    const csv = "date,course,holes,score\n06/01/2026,Pinehill Links,18,84\n";
    const result = parseCsvFile(bytes(csv));
    expect(result.ok).toBe(false);
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
