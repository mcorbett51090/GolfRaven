import { describe, expect, it } from "vitest";
import { z } from "zod";
import {
  IsoDateTimeSchema,
  KidSchema,
  VersionEntrySchema,
  appendVersion,
  assertVersionsAppendOnly,
  canonicalStringify,
  compareCatalogVersions,
  compareCodePoints,
  parseCatalogVersion,
  parseStrictJson,
  sha256Hex,
  sortById,
  strictParseAndValidate,
  type VersionEntry,
} from "../src/manifest.js";

describe("compareCodePoints", () => {
  it("orders ASCII the same way plain < does", () => {
    expect(compareCodePoints("a", "b")).toBeLessThan(0);
    expect(compareCodePoints("b", "a")).toBeGreaterThan(0);
    expect(compareCodePoints("a", "a")).toBe(0);
  });

  it("orders by true code point across a surrogate-pair boundary", () => {
    // U+FFFF (BMP, encoded as one UTF-16 code unit 0xFFFF) vs U+10000
    // (astral, encoded as the surrogate pair 0xD800 0xDC00). Code-point
    // order: U+FFFF < U+10000. UTF-16-code-UNIT order (`<`'s default,
    // comparing the first code unit) would instead see 0xD800 < 0xFFFF
    // and get this backwards.
    const bmp = "￿";
    const astral = "\u{10000}";
    expect(compareCodePoints(bmp, astral)).toBeLessThan(0);
    expect(compareCodePoints(astral, bmp)).toBeGreaterThan(0);
  });
});

describe("canonicalStringify", () => {
  it("sorts object keys recursively, by code point", () => {
    const a = canonicalStringify({ b: 1, a: { d: 2, c: 3 } });
    const b = canonicalStringify({ a: { c: 3, d: 2 }, b: 1 });
    expect(a).toBe(b);
  });

  it("leaves array element order exactly as given", () => {
    const s = canonicalStringify({ list: [{ z: 1 }, { a: 1 }] });
    const parsed = JSON.parse(s) as { list: unknown[] };
    expect(Object.keys(parsed.list[0] as object)).toEqual(["z"]);
    expect(Object.keys(parsed.list[1] as object)).toEqual(["a"]);
  });

  it("ends with a trailing newline", () => {
    expect(canonicalStringify({ a: 1 }).endsWith("\n")).toBe(true);
  });

  it("rejects -0", () => {
    expect(() => canonicalStringify({ a: -0 })).toThrow(/-0/);
  });

  it("rejects NaN and Infinity", () => {
    expect(() => canonicalStringify({ a: NaN })).toThrow(/non-finite/);
    expect(() => canonicalStringify({ a: Infinity })).toThrow(/non-finite/);
    expect(() => canonicalStringify({ a: -Infinity })).toThrow(/non-finite/);
  });

  it("accepts ordinary 0", () => {
    expect(() => canonicalStringify({ a: 0 })).not.toThrow();
  });
});

describe("sha256Hex", () => {
  it("is a known, stable digest for a known input", () => {
    expect(sha256Hex(Buffer.from(""))).toBe(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
  });
});

describe("sortById", () => {
  it("sorts by id (code-point order) without mutating the input array", () => {
    const input = [{ id: "b" }, { id: "a" }, { id: "c" }];
    const sorted = sortById(input);
    expect(sorted.map((x) => x.id)).toEqual(["a", "b", "c"]);
    expect(input.map((x) => x.id)).toEqual(["b", "a", "c"]);
  });
});

describe("parseStrictJson", () => {
  it("parses ordinary JSON the same as JSON.parse would", () => {
    const text = '{"a":1,"b":[1,2,"x"],"c":null,"d":true,"e":false}';
    expect(parseStrictJson(text)).toEqual(JSON.parse(text));
  });

  it("PROBE: rejects a duplicate key (e.g. a duplicate minAppVersion)", () => {
    const text = '{"minAppVersion":"1.0.0","kid":"k1","minAppVersion":"9.9.9"}';
    expect(() => parseStrictJson(text)).toThrow(
      /duplicate object key "minAppVersion"/,
    );
  });

  it("PROBE: rejects an injected __proto__ key", () => {
    expect(() => parseStrictJson('{"__proto__":{"polluted":true}}')).toThrow(
      /forbidden object key "__proto__"/,
    );
  });

  it("rejects constructor and prototype keys too", () => {
    expect(() => parseStrictJson('{"constructor":1}')).toThrow(
      /forbidden object key "constructor"/,
    );
    expect(() => parseStrictJson('{"prototype":1}')).toThrow(
      /forbidden object key "prototype"/,
    );
  });

  it("built objects have no inherited prototype (Object.create(null))", () => {
    const value = parseStrictJson('{"a":1}') as Record<string, unknown>;
    expect(Object.getPrototypeOf(value)).toBeNull();
  });

  it("PROBE: rejects -0.0e0 (and other spellings of negative zero)", () => {
    for (const literal of ["-0", "-0.0", "-0.0e0", "-0e0", "-0E0"]) {
      expect(() => parseStrictJson(`{"a":${literal}}`), literal).toThrow(
        /negative zero/,
      );
    }
  });

  it("accepts ordinary 0 and negative non-zero numbers", () => {
    expect(parseStrictJson("0")).toBe(0);
    expect(parseStrictJson("-1")).toBe(-1);
    expect(parseStrictJson("-1.5e2")).toBe(-150);
  });

  it("rejects trailing content after the value", () => {
    expect(() => parseStrictJson("{}garbage")).toThrow(/trailing content/);
  });

  it("rejects malformed JSON", () => {
    expect(() => parseStrictJson("{not json")).toThrow();
  });
});

describe("strictParseAndValidate", () => {
  const Schema = z.strictObject({ a: z.number() });

  it("returns ok:true with the validated value on success", () => {
    const result = strictParseAndValidate(
      Buffer.from('{"a":1}'),
      Schema,
      "test",
    );
    expect(result).toEqual({ ok: true, value: { a: 1 } });
  });

  it("returns ok:false with issues (never throws) on a strict-parse failure", () => {
    const result = strictParseAndValidate(
      Buffer.from('{"a":1,"a":2}'),
      Schema,
      "test",
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.issues[0]).toContain("test:");
      expect(result.issues[0]).toContain("duplicate object key");
    }
  });

  it("returns ok:false with issues (never throws) on a schema-validation failure", () => {
    const result = strictParseAndValidate(
      Buffer.from('{"a":"not a number"}'),
      Schema,
      "test",
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.issues[0]).toContain("test: a:");
    }
  });
});

describe("compareCatalogVersions", () => {
  it("orders by date first", () => {
    expect(
      compareCatalogVersions("20260101-abc0001", "20260102-abc0001"),
    ).toBeLessThan(0);
    expect(
      compareCatalogVersions("20260102-abc0001", "20260101-abc0001"),
    ).toBeGreaterThan(0);
  });

  it("falls back to the sha suffix within the same date", () => {
    expect(
      compareCatalogVersions("20260101-aaa0000", "20260101-bbb0000"),
    ).toBeLessThan(0);
  });

  it("is 0 for an identical version", () => {
    expect(compareCatalogVersions("20260101-abc0001", "20260101-abc0001")).toBe(
      0,
    );
  });
});

describe("parseCatalogVersion", () => {
  it("parses a well-formed version", () => {
    expect(parseCatalogVersion("20260101-abc0001")).toEqual({
      date: "20260101",
      sha: "abc0001",
    });
  });

  it("returns undefined for a malformed version", () => {
    expect(parseCatalogVersion("not-a-version")).toBeUndefined();
  });
});

function version(overrides: Partial<VersionEntry> = {}): VersionEntry {
  return {
    version: "20260101-abc0001",
    publishedAt: "2026-01-01T00:00:00.000Z",
    kid: "test-kid-1",
    sha256: "a".repeat(64),
    ...overrides,
  };
}

describe("VersionEntrySchema", () => {
  it("accepts a well-formed entry", () => {
    expect(VersionEntrySchema.safeParse(version()).success).toBe(true);
  });

  it("rejects a catalogVersion-shaped field that doesn't match yyyymmdd-gitsha7", () => {
    expect(
      VersionEntrySchema.safeParse(version({ version: "not-a-version" }))
        .success,
    ).toBe(false);
  });
});

describe("assertVersionsAppendOnly", () => {
  it("passes when next is previous plus new entries at the end", () => {
    const previous = [version()];
    const next = [version(), version({ version: "20260102-abc0002" })];
    expect(() => assertVersionsAppendOnly(previous, next)).not.toThrow();
  });

  it("throws when an earlier entry is dropped", () => {
    const previous = [version(), version({ version: "20260102-abc0002" })];
    const next = [version({ version: "20260102-abc0002" })];
    expect(() => assertVersionsAppendOnly(previous, next)).toThrow(
      /append-only violation/,
    );
  });

  it("throws when an earlier entry's content is changed", () => {
    const previous = [version()];
    const next = [version({ sha256: "b".repeat(64) })];
    expect(() => assertVersionsAppendOnly(previous, next)).toThrow(
      /append-only violation/,
    );
  });

  it("throws when an earlier entry is reordered", () => {
    const previous = [
      version({ version: "20260101-aaa0001" }),
      version({ version: "20260102-aaa0002" }),
    ];
    const next = [
      version({ version: "20260102-aaa0002" }),
      version({ version: "20260101-aaa0001" }),
    ];
    expect(() => assertVersionsAppendOnly(previous, next)).toThrow(
      /append-only violation/,
    );
  });
});

describe("appendVersion", () => {
  it("appends a genuinely new, strictly-later version", () => {
    const previous = [version()];
    const next = appendVersion(
      previous,
      version({
        version: "20260102-abc0002",
        publishedAt: "2026-01-02T00:00:00.000Z",
      }),
    );
    expect(next.map((v) => v.version)).toEqual([
      "20260101-abc0001",
      "20260102-abc0002",
    ]);
  });

  it("is idempotent for an identical republish of the CURRENT LAST version", () => {
    const previous = [version()];
    const next = appendVersion(previous, version());
    expect(next).toEqual(previous);
  });

  it("refuses a republish of the last version under different content", () => {
    const previous = [version()];
    expect(() =>
      appendVersion(previous, version({ sha256: "c".repeat(64) })),
    ).toThrow(/already published with different content/);
  });

  it("refuses a version string equal to an EARLIER (non-last) entry", () => {
    const previous = [
      version({ version: "20260101-aaa0001" }),
      version({ version: "20260102-aaa0002" }),
    ];
    expect(() =>
      appendVersion(previous, version({ version: "20260101-aaa0001" })),
    ).toThrow(/not as the last entry/);
  });

  it("PROBE (finding #5): refuses a new version that is not strictly greater than the last", () => {
    const previous = [version({ version: "20260102-aaa0002" })];
    expect(() =>
      appendVersion(
        previous,
        version({
          version: "20260101-aaa0001",
          publishedAt: "2026-01-03T00:00:00.000Z",
        }),
      ),
    ).toThrow(/must be strictly greater/);
  });

  it("PROBE (finding #5): refuses a new entry whose publishedAt does not strictly increase", () => {
    const previous = [version({ publishedAt: "2026-01-05T00:00:00.000Z" })];
    expect(() =>
      appendVersion(
        previous,
        version({
          version: "20260102-abc0002",
          publishedAt: "2026-01-01T00:00:00.000Z",
        }),
      ),
    ).toThrow(/must be strictly after/);
  });
});

describe("finding #2: strict formats for signed strings", () => {
  describe("KidSchema", () => {
    it.each(["a", "k1", "pre-p3-key-1", "a".repeat(64)])(
      "accepts %s",
      (kid) => {
        expect(KidSchema.safeParse(kid).success).toBe(true);
      },
    );

    it.each([
      ["", "empty"],
      ["A", "upper-case"],
      ["k_1", "underscore"],
      ["kid with spaces", "spaces"],
      ["a".repeat(65), "over 64 chars"],
      ["kid\n", "trailing newline"],
      ["kïd", "non-ASCII"],
    ])("rejects %s (%s)", (kid) => {
      expect(KidSchema.safeParse(kid).success).toBe(false);
    });
  });

  describe("IsoDateTimeSchema", () => {
    it("accepts exactly what Date#toISOString() produces", () => {
      expect(
        IsoDateTimeSchema.safeParse(
          new Date("2026-01-01T00:00:00.000Z").toISOString(),
        ).success,
      ).toBe(true);
    });

    it("PROBE: rejects an extended-year datetime (year outside 0000-9999)", () => {
      const extended = new Date("+010000-01-01T00:00:00Z").toISOString();
      expect(extended.startsWith("+")).toBe(true); // sanity: Date really does produce this
      expect(IsoDateTimeSchema.safeParse(extended).success).toBe(false);
    });

    it("rejects a form with a timezone OFFSET instead of Z", () => {
      expect(
        IsoDateTimeSchema.safeParse("2026-01-01T00:00:00.000+05:00").success,
      ).toBe(false);
    });

    it("rejects a form missing the Z suffix (local time)", () => {
      expect(
        IsoDateTimeSchema.safeParse("2026-01-01T00:00:00.000").success,
      ).toBe(false);
    });

    it("rejects a form with the wrong fractional-second precision", () => {
      expect(IsoDateTimeSchema.safeParse("2026-01-01T00:00:00Z").success).toBe(
        false,
      ); // no ms
      expect(
        IsoDateTimeSchema.safeParse("2026-01-01T00:00:00.00Z").success,
      ).toBe(false); // 2 digits
    });
  });

  describe("parseStrictJson: lone surrogates and control characters", () => {
    it("PROBE: rejects a lone (unpaired) high surrogate", () => {
      expect(() => parseStrictJson('"\\ud800"')).toThrow(
        /lone \(unpaired\) high surrogate/,
      );
    });

    it("PROBE: rejects a lone (unpaired) low surrogate", () => {
      expect(() => parseStrictJson('"\\udc00"')).toThrow(
        /lone \(unpaired\) low surrogate/,
      );
    });

    it("accepts a properly paired surrogate (a real astral character)", () => {
      // U+1F600 GRINNING FACE, as its UTF-16 surrogate pair.
      expect(parseStrictJson('"\\ud83d\\ude00"')).toBe("\u{1f600}");
    });

    it("PROBE: rejects an escaped control character (\\u0000)", () => {
      expect(() => parseStrictJson('"\\u0000"')).toThrow(/control character/);
    });

    it("PROBE: rejects an escaped DEL (\\u007f)", () => {
      expect(() => parseStrictJson('"\\u007f"')).toThrow(/control character/);
    });

    it("still rejects a raw (unescaped) control character", () => {
      expect(() => parseStrictJson('"a\tb"')).toThrow(/control character/);
    });

    // Every actual field in manifest.json/manifest.sig.json/versions.json/
    // versions.sig.json (kid, catalogVersion, generatedAt/publishedAt,
    // sha256, sig, ...) is a short technical token that never legitimately
    // contains whitespace controls — so rejecting even the NAMED escapes
    // (\n, \t, \r) here, not just raw literal control bytes, costs nothing
    // for this parser's actual scope (these 4 small metadata files) while
    // closing off one more place a signed string's meaning could be bent.
    it("PROBE: rejects the named whitespace escapes (\\n, \\t, \\r) too, not just raw control bytes", () => {
      expect(() => parseStrictJson('"a\\nb"')).toThrow(/control character/);
      expect(() => parseStrictJson('"a\\tb"')).toThrow(/control character/);
      expect(() => parseStrictJson('"a\\rb"')).toThrow(/control character/);
    });

    it("accepts ordinary printable text with no control characters", () => {
      expect(parseStrictJson('"hello world 123-abc"')).toBe(
        "hello world 123-abc",
      );
    });
  });
});
