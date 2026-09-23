import { describe, expect, it } from "vitest";
import {
  extractRows,
  parseDay0FromK2Doc,
  parseExcludedAddressEntriesFromK2Doc,
  parseExcludedAddressesFromK2Doc,
  isShallowRepository,
} from "../scripts/k2-count.mjs";
// Reads docs/p0/K2.md's ACTUAL content at test-transform time (Vite/Vitest's
// `?raw` suffix — see vite-raw.d.ts) — this IS the real file, not a copy of
// its text, so the test can never silently drift from what the CLI reads.
import realMarkdown from "../../../docs/p0/K2.md?raw";

describe("parseDay0FromK2Doc", () => {
  it("returns null for the still-blank placeholder section", () => {
    const markdown = `## Day 0

_(blank — Matt sets this ...)_

## Excluded addresses (pre-Day-0 list)

_(blank — ...)_
`;
    expect(parseDay0FromK2Doc(markdown)).toBeNull();
  });

  it("parses a bare YYYY-MM-DD date once the owner fills it in", () => {
    const markdown = `## Day 0

2026-10-05

## Excluded addresses (pre-Day-0 list)

_(blank)_
`;
    expect(parseDay0FromK2Doc(markdown)).toBe("2026-10-05");
  });

  it("tolerates surrounding prose around the bare date", () => {
    const markdown = `## Day 0

Day 0 is 2026-10-05, logged before any promotion.

## Excluded addresses (pre-Day-0 list)
`;
    expect(parseDay0FromK2Doc(markdown)).toBe("2026-10-05");
  });

  it("refuses a date-time WITH an explicit Z offset — must be a bare date", () => {
    const markdown = `## Day 0

2026-10-05T00:00:00Z

## Excluded addresses (pre-Day-0 list)
`;
    expect(() => parseDay0FromK2Doc(markdown)).toThrow(
      /must be a bare YYYY-MM-DD date/,
    );
  });

  it("refuses a date-time with NO explicit UTC offset (ambiguous local time)", () => {
    const markdown = `## Day 0

2026-10-10T09:30

## Excluded addresses (pre-Day-0 list)
`;
    expect(() => parseDay0FromK2Doc(markdown)).toThrow(/ambiguous local time/);
  });

  it("refuses more than one date in the section", () => {
    const markdown = `## Day 0

logged 2026-10-12: day 0 is 2026-10-10

## Excluded addresses (pre-Day-0 list)
`;
    expect(() => parseDay0FromK2Doc(markdown)).toThrow(/more than one date/);
  });

  it("refuses a date that doesn't exist on the calendar", () => {
    const markdown = `## Day 0

2026-02-30

## Excluded addresses (pre-Day-0 list)
`;
    expect(() => parseDay0FromK2Doc(markdown)).toThrow(
      /not a valid calendar date/,
    );
  });

  it("throws when the '## Day 0' heading is missing entirely", () => {
    const markdown = `## Excluded addresses (pre-Day-0 list)

_(blank)_
`;
    expect(() => parseDay0FromK2Doc(markdown)).toThrow(
      /missing its "## Day 0" heading/,
    );
  });
});

describe("parseExcludedAddressesFromK2Doc", () => {
  it("returns [] for the still-blank placeholder section (heading present, body blank)", () => {
    const markdown = `## Excluded addresses (pre-Day-0 list)

_(blank — any owner/test email addresses to exclude ...)_

## OWNER
`;
    expect(parseExcludedAddressesFromK2Doc(markdown)).toEqual([]);
  });

  it("finds the list under the REAL heading, which has a suffix the old exact-match code missed (F1)", () => {
    const markdown = `## Excluded addresses (pre-Day-0 list)

- matt@golfraven.example
- test+k2@golfraven.example

## OWNER
`;
    expect(parseExcludedAddressesFromK2Doc(markdown)).toEqual([
      "matt@golfraven.example",
      "test+k2@golfraven.example",
    ]);
  });

  it("matches the heading case-insensitively with any suffix", () => {
    const markdown = `## EXCLUDED ADDRESSES — whatever suffix

- owner@golfraven.example

## OWNER
`;
    expect(parseExcludedAddressesFromK2Doc(markdown)).toEqual([
      "owner@golfraven.example",
    ]);
  });

  it("throws (never silently returns []) when no 'Excluded addresses...' heading exists at all", () => {
    const markdown = `## Day 0

2026-10-05

## OWNER
`;
    expect(() => parseExcludedAddressesFromK2Doc(markdown)).toThrow(
      /missing an "Excluded addresses" heading/,
    );
  });

  describe("decoration forms (F8)", () => {
    it("strips backticks", () => {
      const markdown =
        "## Excluded addresses (pre-Day-0 list)\n\n- `a@b.com`\n";
      expect(parseExcludedAddressesFromK2Doc(markdown)).toEqual(["a@b.com"]);
    });

    it("strips a markdown link, without concatenating the text and target into one bad token", () => {
      const markdown =
        "## Excluded addresses (pre-Day-0 list)\n\n- [a@b.com](mailto:a@b.com)\n";
      expect(parseExcludedAddressesFromK2Doc(markdown)).toEqual(["a@b.com"]);
    });

    it("strips a bare mailto: prefix", () => {
      const markdown =
        "## Excluded addresses (pre-Day-0 list)\n\n- mailto:a@b.com\n";
      expect(parseExcludedAddressesFromK2Doc(markdown)).toEqual(["a@b.com"]);
    });

    it("strips trailing sentence punctuation", () => {
      const markdown =
        "## Excluded addresses (pre-Day-0 list)\n\nOwner test address is a@b.com.\n";
      expect(parseExcludedAddressesFromK2Doc(markdown)).toEqual(["a@b.com"]);
    });

    it("strips angle brackets", () => {
      const markdown =
        "## Excluded addresses (pre-Day-0 list)\n\n- <a@b.com>\n";
      expect(parseExcludedAddressesFromK2Doc(markdown)).toEqual(["a@b.com"]);
    });

    it("lower-cases mixed-case addresses", () => {
      const markdown =
        "## Excluded addresses (pre-Day-0 list)\n\n- Matt@GolfRaven.example\n";
      expect(parseExcludedAddressesFromK2Doc(markdown)).toEqual([
        "matt@golfraven.example",
      ]);
    });

    it("F8 residual: strips paired underscore emphasis without dropping the address", () => {
      const markdown =
        "## Excluded addresses (pre-Day-0 list)\n\n- _x@y.com_\n";
      expect(parseExcludedAddressesFromK2Doc(markdown)).toEqual(["x@y.com"]);
    });

    it("A-8: strips underscore emphasis wrapped TIGHTLY around the address even with trailing prose on the line", () => {
      // Round-3 gate repro: "- _a2@x.com_ (owner)" used to extract the
      // WRONG address, "_a2@x.com" (leading underscore included, since the
      // whole-line strip above only fires when the marker is at the very
      // end of the trimmed line too).
      const markdown =
        "## Excluded addresses (pre-Day-0 list)\n\n- _a2@x.com_ (owner)\n";
      expect(parseExcludedAddressesFromK2Doc(markdown)).toEqual(["a2@x.com"]);
    });

    it("A-8: strips asterisk emphasis wrapped tightly around the address with trailing prose", () => {
      const markdown =
        "## Excluded addresses (pre-Day-0 list)\n\n- *a2@x.com* (owner)\n";
      expect(parseExcludedAddressesFromK2Doc(markdown)).toEqual(["a2@x.com"]);
    });

    it("A-8: a genuine underscore that is part of the local part (not a pair) is left alone", () => {
      const markdown =
        "## Excluded addresses (pre-Day-0 list)\n\n- test_user@golfraven.example\n";
      expect(parseExcludedAddressesFromK2Doc(markdown)).toEqual([
        "test_user@golfraven.example",
      ]);
    });

    it("F8 residual: strips paired asterisk emphasis", () => {
      const markdown =
        "## Excluded addresses (pre-Day-0 list)\n\n- *x@y.com*\n";
      expect(parseExcludedAddressesFromK2Doc(markdown)).toEqual(["x@y.com"]);
    });

    it("F8 residual: accepts a unicode local part instead of matching only its ASCII suffix", () => {
      const markdown =
        "## Excluded addresses (pre-Day-0 list)\n\n- ünï13@x.com\n";
      expect(parseExcludedAddressesFromK2Doc(markdown)).toEqual([
        "ünï13@x.com",
      ]);
    });

    it("strips a trailing comma in prose", () => {
      const markdown =
        "## Excluded addresses (pre-Day-0 list)\n\nOwner test address is a@b.com, for now.\n";
      expect(parseExcludedAddressesFromK2Doc(markdown)).toEqual(["a@b.com"]);
    });

    it("F8 residual (3): a bullet with no valid TLD is a hard refusal, not a silent drop", () => {
      const markdown =
        "## Excluded addresses (pre-Day-0 list)\n\n- test10@localhost\n";
      expect(() => parseExcludedAddressesFromK2Doc(markdown)).toThrow(
        /does not contain exactly one/,
      );
    });

    it("F8 residual (3): a spelled-out, unparseable bullet is a hard refusal", () => {
      const markdown =
        "## Excluded addresses (pre-Day-0 list)\n\n- matt at golfraven dot com\n";
      expect(() => parseExcludedAddressesFromK2Doc(markdown)).toThrow(
        /does not contain exactly one/,
      );
    });
  });
});

describe("parseExcludedAddressEntriesFromK2Doc (F7/F8 residual — line numbers for git blame)", () => {
  it("reports the 1-indexed absolute line number of each address's first occurrence", () => {
    const markdown = [
      "## Excluded addresses (pre-Day-0 list)",
      "",
      "- matt@golfraven.example",
      "- test@golfraven.example",
      "",
    ].join("\n");
    expect(parseExcludedAddressEntriesFromK2Doc(markdown)).toEqual([
      { address: "matt@golfraven.example", line: 3 },
      { address: "test@golfraven.example", line: 4 },
    ]);
  });
});

describe("isShallowRepository (decision 0001 Addendum F / gate findings A-5, A-6)", () => {
  it("returns a boolean against the real checkout (this repo may itself be shallow in a CI/web-session clone)", () => {
    expect(typeof isShallowRepository()).toBe("boolean");
  });
});

describe("parses the REAL docs/p0/K2.md (F1 — this is exactly what hid the bug)", () => {
  it("day 0 is still unset (blank), as expected pre-launch — and this does NOT throw", () => {
    expect(parseDay0FromK2Doc(realMarkdown)).toBeNull();
  });

  it("finds the real 'Excluded addresses (pre-Day-0 list)' heading and returns [] for its still-blank body, without throwing", () => {
    expect(parseExcludedAddressesFromK2Doc(realMarkdown)).toEqual([]);
  });

  it("would find real addresses if the owner filled the section in, matching the real heading's exact text", () => {
    const filledIn = realMarkdown.replace(
      "_(blank — any owner/test email addresses to exclude from the K2 count go here. Decision 0001 Addendum F\n" +
        '("K2 exclusion dating"): an address is excluded only if it **first appeared** in this file\'s git history\n' +
        "in a commit **committed and pushed to GitHub before Day 0 00:00 UTC**. A later reformat or deletion of the\n" +
        "line does not change that. List and commit+push the address here BEFORE running any end-to-end test that\n" +
        "uses it, and before logging Day 0 above — see `apps/signup-worker/README.md`'s deploy runbook step 9.)_",
      "- matt@golfraven.example\n- `test1@golfraven.example`\n- [test2@golfraven.example](mailto:test2@golfraven.example)",
    );
    expect(filledIn).not.toBe(realMarkdown); // sanity: the replace actually matched
    expect(parseExcludedAddressesFromK2Doc(filledIn)).toEqual([
      "matt@golfraven.example",
      "test1@golfraven.example",
      "test2@golfraven.example",
    ]);
  });
});

describe("extractRows", () => {
  it("accepts a plain row array", () => {
    const rows = [
      { email_lc: "a@example.com", confirmed_at: "2026-10-06T00:00:00.000Z" },
    ];
    expect(extractRows(rows)).toBe(rows);
  });

  it("unwraps a `wrangler d1 execute --json` result array", () => {
    const wranglerShape = [
      {
        results: [
          {
            email_lc: "a@example.com",
            confirmed_at: "2026-10-06T00:00:00.000Z",
          },
        ],
        success: true,
        meta: {},
      },
    ];
    expect(extractRows(wranglerShape)).toEqual(wranglerShape[0]!.results);
  });

  it("throws on an unrecognized shape", () => {
    expect(() => extractRows({ not: "an array" })).toThrow();
  });
});
