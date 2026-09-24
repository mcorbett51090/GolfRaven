import { afterEach, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import {
  defaultLedgerPath,
  findLedgerEntry,
  loadLedger,
  normalizeUrlForFirstCapture,
  registerCapture,
  saveLedger,
  RECORDED_LEDGER_FILENAME,
  type RecordedLedger,
} from "../src/x2-recorded-ledger.js";

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

  it("defaultLedgerPath joins the out dir with the standard filename", () => {
    expect(defaultLedgerPath("/tmp/x2-evidence")).toBe(
      path.join("/tmp/x2-evidence", RECORDED_LEDGER_FILENAME),
    );
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
    const ledgerPath = defaultLedgerPath(dir);
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
    const ledgerPath = defaultLedgerPath(dir);
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
    const ledgerPath = defaultLedgerPath(dir);
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
    const ledgerPath = defaultLedgerPath(dir);
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
