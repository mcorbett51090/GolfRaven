import { afterEach, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import {
  findLedgerEntry,
  loadLedger,
  normalizeUrlForFirstCapture,
  registerCapture,
  saveLedger,
  RECORDED_LEDGER_FILENAME,
  type RecordedLedger,
} from "../src/x2-recorded-ledger.js";

/** Gate finding 2c (re-gate): `defaultLedgerPath` was REMOVED — every
 * caller now builds an explicit ledger path. This is the one place tests
 * in this file do that, so the removal reads as one deliberate helper, not
 * as `path.join(dir, RECORDED_LEDGER_FILENAME)` repeated at every call
 * site. */
function ledgerPathFor(dir: string): string {
  return path.join(dir, RECORDED_LEDGER_FILENAME);
}

const OUT_DIR = mkdtempSync(path.join(tmpdir(), "golfraven-p0-ledger-test-"));

afterEach(() => {
  // best-effort cleanup between tests that write real files
});

describe("x2-recorded-ledger: normalizeUrlForFirstCapture (gate finding 2a)", () => {
  it("lowercases the host", () => {
    expect(normalizeUrlForFirstCapture("https://EXAMPLE.com/golf")).toBe(
      normalizeUrlForFirstCapture("https://example.com/golf"),
    );
  });

  it("drops a leading www.", () => {
    expect(normalizeUrlForFirstCapture("https://www.example.com/golf")).toBe(
      normalizeUrlForFirstCapture("https://example.com/golf"),
    );
  });

  it("drops the fragment", () => {
    expect(normalizeUrlForFirstCapture("https://example.com/golf#courses")).toBe(
      normalizeUrlForFirstCapture("https://example.com/golf"),
    );
  });

  it("drops the query string", () => {
    expect(normalizeUrlForFirstCapture("https://example.com/golf?utm_source=x")).toBe(
      normalizeUrlForFirstCapture("https://example.com/golf"),
    );
  });

  it("drops one trailing slash", () => {
    expect(normalizeUrlForFirstCapture("https://example.com/golf/")).toBe(
      normalizeUrlForFirstCapture("https://example.com/golf"),
    );
  });

  it("treats the bare root path as / , not empty", () => {
    expect(normalizeUrlForFirstCapture("https://example.com/")).toBe("example.com/");
    expect(normalizeUrlForFirstCapture("https://example.com")).toBe("example.com/");
  });

  it("all five bypass variants together normalize to the exact same key", () => {
    const canonical = normalizeUrlForFirstCapture("https://example.com/golf");
    const variants = [
      "https://WWW.EXAMPLE.COM/golf/",
      "https://www.example.com/golf#trail",
      "https://example.com/golf?ref=facebook",
      "https://EXAMPLE.com/golf/?ref=facebook#trail",
      "https://www.Example.com/golf/",
    ];
    for (const v of variants) {
      expect(normalizeUrlForFirstCapture(v)).toBe(canonical);
    }
  });

  it("a genuinely different path is NOT collapsed", () => {
    expect(normalizeUrlForFirstCapture("https://example.com/golf")).not.toBe(
      normalizeUrlForFirstCapture("https://example.com/golf/courses"),
    );
  });

  it("a genuinely different host is NOT collapsed", () => {
    expect(normalizeUrlForFirstCapture("https://example.com/golf")).not.toBe(
      normalizeUrlForFirstCapture("https://other-example.com/golf"),
    );
  });

  it("gate finding 2a (re-gate): decodes UNRESERVED percent-encoding (%67 -> g)", () => {
    expect(normalizeUrlForFirstCapture("https://example.com/%67olf")).toBe(
      normalizeUrlForFirstCapture("https://example.com/golf"),
    );
  });

  it("gate finding 2a (re-gate): does NOT decode a RESERVED percent-encoding (%2F, which encodes '/')", () => {
    // %2F decoded would turn one path segment into two — decoding it
    // would CHANGE the URL's structure, not just its spelling, so it must
    // be left exactly as written and therefore NOT match the two-segment
    // form.
    expect(normalizeUrlForFirstCapture("https://example.com/golf%2Fcourses")).not.toBe(
      normalizeUrlForFirstCapture("https://example.com/golf/courses"),
    );
  });

  it("gate finding 2a (re-gate): collapses a doubled path slash", () => {
    expect(normalizeUrlForFirstCapture("https://example.com//golf")).toBe(
      normalizeUrlForFirstCapture("https://example.com/golf"),
    );
  });

  it("gate finding 2a (re-gate): drops a ;param path segment parameter", () => {
    expect(normalizeUrlForFirstCapture("https://example.com/golf;x=1")).toBe(
      normalizeUrlForFirstCapture("https://example.com/golf"),
    );
  });

  it("gate finding 2a (re-gate): a ;param on a NON-final segment is stripped too", () => {
    expect(normalizeUrlForFirstCapture("https://example.com/golf;x/courses")).toBe(
      normalizeUrlForFirstCapture("https://example.com/golf/courses"),
    );
  });

  it("gate finding 2a (re-gate): the DEFAULT https port (:443, explicit) normalizes the same as no port", () => {
    expect(normalizeUrlForFirstCapture("https://example.com:443/golf")).toBe(
      normalizeUrlForFirstCapture("https://example.com/golf"),
    );
  });

  it("gate finding 2a (re-gate): a NON-default port is KEPT — a different port is a genuinely different resource", () => {
    expect(normalizeUrlForFirstCapture("https://example.com:8443/golf")).not.toBe(
      normalizeUrlForFirstCapture("https://example.com/golf"),
    );
  });

  it("gate finding 2a (re-gate): path CASE is left untouched — /GOLF and /golf are genuinely different resources", () => {
    expect(normalizeUrlForFirstCapture("https://example.com/GOLF")).not.toBe(
      normalizeUrlForFirstCapture("https://example.com/golf"),
    );
  });

  it("gate finding 2a (re-gate): a trailing dot on the hostname is NOT stripped — a different (if DNS-equivalent) hostname string is not silently collapsed", () => {
    expect(normalizeUrlForFirstCapture("https://example.com./golf")).not.toBe(
      normalizeUrlForFirstCapture("https://example.com/golf"),
    );
  });

  it("gate finding 2a (re-gate): all the re-gate bypass variants together normalize to the exact same key as the first-round ones", () => {
    const canonical = normalizeUrlForFirstCapture("https://example.com/golf");
    const variants = [
      "https://example.com/%67olf",
      "https://example.com//golf",
      "https://example.com/golf;x=1",
      "https://example.com:443/golf",
      "https://WWW.example.com:443//%67olf;p",
    ];
    for (const v of variants) {
      expect(normalizeUrlForFirstCapture(v)).toBe(canonical);
    }
  });
});

describe("x2-recorded-ledger: loadLedger / saveLedger", () => {
  it("loadLedger returns an empty ledger when the file does not exist yet", async () => {
    const p = path.join(OUT_DIR, "missing", RECORDED_LEDGER_FILENAME);
    const ledger = await loadLedger(p);
    expect(ledger).toEqual({ entries: [] });
  });

  it("loadLedger refuses (throws) a malformed JSON file rather than treating it as empty", async () => {
    const dir = mkdtempSync(path.join(OUT_DIR, "malformed-"));
    const p = path.join(dir, RECORDED_LEDGER_FILENAME);
    const { writeFile } = await import("node:fs/promises");
    await writeFile(p, "{ not valid json", "utf8");
    await expect(loadLedger(p)).rejects.toThrow(/not valid JSON/);
  });

  it("loadLedger refuses a well-formed JSON file with the wrong shape", async () => {
    const dir = mkdtempSync(path.join(OUT_DIR, "wrongshape-"));
    const p = path.join(dir, RECORDED_LEDGER_FILENAME);
    const { writeFile } = await import("node:fs/promises");
    await writeFile(p, JSON.stringify({ notEntries: [] }), "utf8");
    await expect(loadLedger(p)).rejects.toThrow(/expected \{ entries: \[\.\.\.\] \} shape/);
  });

  it("saveLedger then loadLedger round-trips exactly, creating parent dirs as needed", async () => {
    const p = path.join(OUT_DIR, "nested", "dir", RECORDED_LEDGER_FILENAME);
    const ledger: RecordedLedger = {
      entries: [
        {
          method: "direct",
          normalizedUrl: "example.com/golf",
          url: "https://example.com/golf",
          sha256: "a".repeat(64),
          recordedAt: "2026-09-24T00:00:00.000Z",
        },
      ],
    };
    await saveLedger(p, ledger);
    const loaded = await loadLedger(p);
    expect(loaded).toEqual(ledger);
  });

  it("gate finding 2c (re-gate): there is no automatic per-directory default ledger path any more — RECORDED_LEDGER_FILENAME is only a naming constant a caller opts into explicitly", () => {
    expect(RECORDED_LEDGER_FILENAME).toBe("recorded-ledger.json");
    // (No `defaultLedgerPath` function exists to test here any more — its
    // removal IS the point of this test's title.)
  });
});

describe("x2-recorded-ledger: findLedgerEntry", () => {
  it("finds an entry by method + normalized URL, matching a differently-shaped variant of the same URL", () => {
    const ledger: RecordedLedger = {
      entries: [
        {
          method: "direct",
          normalizedUrl: "example.com/golf",
          url: "https://www.example.com/golf/",
          sha256: "b".repeat(64),
          recordedAt: "2026-09-24T00:00:00.000Z",
        },
      ],
    };
    const found = findLedgerEntry(ledger, "direct", "https://EXAMPLE.com/golf?ref=x#y");
    expect(found?.sha256).toBe("b".repeat(64));
  });

  it("does not find an entry under a different method for the same URL", () => {
    const ledger: RecordedLedger = {
      entries: [
        {
          method: "direct",
          normalizedUrl: "example.com/golf",
          url: "https://example.com/golf",
          sha256: "c".repeat(64),
          recordedAt: "2026-09-24T00:00:00.000Z",
        },
      ],
    };
    expect(findLedgerEntry(ledger, "owner-saved", "https://example.com/golf")).toBeUndefined();
  });
});

describe("x2-recorded-ledger: registerCapture (gate finding 2c)", () => {
  it("the first capture of a URL+method is recorded: true and persisted to the ledger file", async () => {
    const dir = mkdtempSync(path.join(OUT_DIR, "reg1-"));
    const ledgerPath = ledgerPathFor(dir);
    const result = await registerCapture(ledgerPath, {
      method: "direct",
      url: "https://example.com/golf",
      sha256: "d".repeat(64),
    });
    expect(result.recorded).toBe(true);
    const onDisk = await loadLedger(ledgerPath);
    expect(onDisk.entries).toHaveLength(1);
    expect(onDisk.entries[0]?.sha256).toBe("d".repeat(64));
  });

  it("a second capture of the SAME normalized URL+method, allowAdditional=false (default), THROWS — never silently drops the first", async () => {
    const dir = mkdtempSync(path.join(OUT_DIR, "reg2-"));
    const ledgerPath = ledgerPathFor(dir);
    await registerCapture(ledgerPath, {
      method: "direct",
      url: "https://example.com/golf",
      sha256: "e".repeat(64),
    });
    await expect(
      registerCapture(ledgerPath, {
        method: "direct",
        url: "https://www.example.com/golf/", // a URL-variant of the same page
        sha256: "f".repeat(64),
      }),
    ).rejects.toThrow(/already exists in the ledger/);
    // The first entry must be untouched.
    const onDisk = await loadLedger(ledgerPath);
    expect(onDisk.entries).toHaveLength(1);
    expect(onDisk.entries[0]?.sha256).toBe("e".repeat(64));
  });

  it("a second capture of the SAME normalized URL+method, allowAdditional=true, returns recorded:false and does NOT modify the ledger", async () => {
    const dir = mkdtempSync(path.join(OUT_DIR, "reg3-"));
    const ledgerPath = ledgerPathFor(dir);
    await registerCapture(ledgerPath, {
      method: "owner-saved",
      url: "https://example.com/golf",
      sha256: "1".repeat(64),
    });
    const second = await registerCapture(
      ledgerPath,
      {
        method: "owner-saved",
        url: "https://example.com/golf?utm=abc", // query-variant of the same page
        sha256: "2".repeat(64),
      },
      { allowAdditional: true },
    );
    expect(second.recorded).toBe(false);
    const onDisk = await loadLedger(ledgerPath);
    expect(onDisk.entries).toHaveLength(1);
    expect(onDisk.entries[0]?.sha256).toBe("1".repeat(64));
  });

  it("captures of the same URL under DIFFERENT methods (direct vs rendered vs owner-saved) are independent — each gets its own recorded:true", async () => {
    const dir = mkdtempSync(path.join(OUT_DIR, "reg4-"));
    const ledgerPath = ledgerPathFor(dir);
    const direct = await registerCapture(ledgerPath, {
      method: "direct",
      url: "https://example.com/golf",
      sha256: "3".repeat(64),
    });
    const rendered = await registerCapture(ledgerPath, {
      method: "rendered",
      url: "https://example.com/golf",
      sha256: "4".repeat(64),
    });
    const ownerSaved = await registerCapture(ledgerPath, {
      method: "owner-saved",
      url: "https://example.com/golf",
      sha256: "5".repeat(64),
    });
    expect(direct.recorded).toBe(true);
    expect(rendered.recorded).toBe(true);
    expect(ownerSaved.recorded).toBe(true);
    const onDisk = await loadLedger(ledgerPath);
    expect(onDisk.entries).toHaveLength(3);
  });

  it("a SHARED ledger path across two different logical out-dirs correctly refuses a second capture — the whole point of gate finding 2c", async () => {
    const sharedLedgerPath = path.join(
      mkdtempSync(path.join(OUT_DIR, "shared-ledger-")),
      RECORDED_LEDGER_FILENAME,
    );
    // Simulates run 1, writing into out-dir A.
    await registerCapture(sharedLedgerPath, {
      method: "direct",
      url: "https://example.com/golf",
      sha256: "6".repeat(64),
    });
    // Simulates a LATER, separate run writing into a DIFFERENT out-dir B,
    // but sharing the same ledger path — must see run 1's capture.
    await expect(
      registerCapture(sharedLedgerPath, {
        method: "direct",
        url: "https://example.com/golf",
        sha256: "7".repeat(64),
      }),
    ).rejects.toThrow(/already exists in the ledger/);
  });
});
