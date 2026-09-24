/**
 * Manifest and `versions.json` shape, canonical-JSON, strict parsing, and
 * append-only helpers for the catalog artifact (build plan §3.3 "A
 * signed, append-only `catalog/v1/versions.json`", §3.5 "App lifecycle
 * fields in the signed manifest", §10 P1 AT(2)).
 *
 * **Rewritten after the Opus security gate (commit 7692919, 4 blocking
 * findings).** The load-bearing correction: canonical JSON is signed and
 * verified as EXACT BYTES on both ends — never re-derived from a parsed
 * object at verify time (`sign.ts`'s `verifyArtifact` reads the file's raw
 * bytes and hashes those; it never calls `canonicalStringify` on a parsed
 * manifest and checks a signature against that). `canonicalStringify` here
 * is used only (a) by the emitter, to produce the bytes that get written
 * and hashed in the first place, and (b) as a self-check inside the
 * emitter (`raw === canonicalStringify(parseStrictJson(raw))`) — a check
 * on the WRITER's own serializer, not part of what a verifier trusts.
 *
 * This module still adds no dependency beyond `zod`, which
 * `@golfraven/catalog-tools` already depends on (`package.json`) — using
 * it here is not a new dependency.
 */
import { createHash } from "node:crypto";
import { z } from "zod";

/* ------------------------------------------------------------------ */
/* Code-point string ordering (finding: "code-point ordering, not        */
/* engine or localeCompare order")                                      */
/* ------------------------------------------------------------------ */

/** Compares two strings by Unicode code point (not UTF-16 code unit,
 * which is what `<`/`.sort()`'s default comparator and `.localeCompare`
 * both use, and which can disagree with true code-point order across a
 * surrogate-pair boundary). Used everywhere this module or its callers
 * need a stable, engine-independent, locale-independent order: object key
 * sort, shard-list sort, `revokedKids[]` sort, `sortById`. */
export function compareCodePoints(a: string, b: string): number {
  if (a === b) return 0;
  const ai = Array.from(a);
  const bi = Array.from(b);
  const len = Math.min(ai.length, bi.length);
  for (let i = 0; i < len; i += 1) {
    const ca = ai[i]!.codePointAt(0)!;
    const cb = bi[i]!.codePointAt(0)!;
    if (ca !== cb) return ca < cb ? -1 : 1;
  }
  return ai.length - bi.length;
}

/** Sorts an array of `{id: string}`-shaped records by `id` (code-point
 * order), without mutating the input. */
export function sortById<T extends { id: string }>(items: readonly T[]): T[] {
  return [...items].sort((a, b) => compareCodePoints(a.id, b.id));
}

/* ------------------------------------------------------------------ */
/* Canonical JSON                                                       */
/* ------------------------------------------------------------------ */

function sortAndValidate(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(sortAndValidate);
  }
  if (value !== null && typeof value === "object") {
    const input = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(input).sort(compareCodePoints)) {
      out[key] = sortAndValidate(input[key]);
    }
    return out;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new Error(`canonicalStringify: refusing a non-finite number (${value})`);
    }
    if (Object.is(value, -0)) {
      throw new Error("canonicalStringify: refusing -0 (negative zero)");
    }
  }
  return value;
}

/**
 * Deterministic JSON: object keys sorted by code point recursively (array
 * element order is left exactly as the caller built it — array element
 * ordering is the caller's job, e.g. `sortById`). Rejects any non-finite
 * number or `-0` anywhere in the value tree. Two-space indent, trailing
 * newline, so two emits with the same logical content are byte-identical.
 */
export function canonicalStringify(value: unknown): string {
  return `${JSON.stringify(sortAndValidate(value), null, 2)}\n`;
}

export function sha256Hex(data: Buffer | string): string {
  return createHash("sha256").update(data).digest("hex");
}

/* ------------------------------------------------------------------ */
/* Strict JSON parsing (finding: reject duplicate keys, __proto__/       */
/* constructor/prototype keys, and -0, at PARSE time — `JSON.parse`      */
/* cannot detect duplicate keys once they've collapsed to "last wins")  */
/* ------------------------------------------------------------------ */

const FORBIDDEN_KEYS = new Set(["__proto__", "constructor", "prototype"]);

/**
 * Rejects a decoded JSON string that contains a raw or `\u`-escaped C0/DEL
 * control character, or a lone (unpaired) UTF-16 surrogate — checked on
 * the FULLY DECODED string, so `\u0000` (an escaped control char) is
 * caught exactly like a literal one, and `\ud800` (a lone high surrogate
 * with no following low surrogate) is caught whether it came from one
 * `\u` escape or a raw code unit. Every signed string in this artifact
 * (`kid`, `catalogVersion`, `generatedAt`/`publishedAt`, ...) is already
 * format-constrained by its own Zod regex, but this runs earlier, at
 * PARSE time, over every string `parseStrictJson` ever builds — including
 * ones a looser schema might one day forget to constrain.
 */
function assertNoLoneSurrogatesOrControls(s: string, fail: (msg: string) => never): void {
  for (let idx = 0; idx < s.length; idx += 1) {
    const code = s.charCodeAt(idx);
    if (code < 0x20 || code === 0x7f) {
      fail(`string contains a control character (U+${code.toString(16).padStart(4, "0")})`);
    }
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = s.charCodeAt(idx + 1);
      if (Number.isNaN(next) || next < 0xdc00 || next > 0xdfff) {
        fail(`string contains a lone (unpaired) high surrogate U+${code.toString(16)}`);
      } else {
        idx += 1; // consumed as a valid surrogate pair
      }
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      fail(`string contains a lone (unpaired) low surrogate U+${code.toString(16)}`);
    }
  }
}

/**
 * A minimal, strict, recursive-descent JSON parser (full grammar; no
 * extensions). Differs from `JSON.parse` in exactly the ways that matter
 * for trusting an artifact someone else produced:
 *  - an object with a **duplicate key** throws (`JSON.parse` silently
 *    keeps the last one — a duplicate `minAppVersion` key would otherwise
 *    parse without a trace of the ambiguity, which is exactly the shape
 *    of a canonicalization-confusion attack);
 *  - an object key of `__proto__`, `constructor` or `prototype` throws;
 *  - a number literal that evaluates to `-0` (`-0`, `-0.0`, `-0.0e0`, ...)
 *    throws — JSON's own grammar already makes `NaN`/`Infinity` literals
 *    unparseable, so nothing extra is needed for those.
 * Objects are built with `Object.create(null)` (no inherited prototype at
 * all), so even a permitted-looking key can never reach `Object.prototype`.
 */
export function parseStrictJson(text: string): unknown {
  let i = 0;
  const n = text.length;

  function fail(msg: string): never {
    throw new Error(`strict JSON parse error at offset ${i}: ${msg}`);
  }
  function skipWs(): void {
    while (i < n) {
      const c = text[i];
      if (c === " " || c === "\t" || c === "\n" || c === "\r") i += 1;
      else break;
    }
  }
  function parseValue(): unknown {
    skipWs();
    if (i >= n) fail("unexpected end of input");
    const c = text[i];
    if (c === "{") return parseObject();
    if (c === "[") return parseArray();
    if (c === '"') return parseString();
    if (c === "t") return parseLiteral("true", true);
    if (c === "f") return parseLiteral("false", false);
    if (c === "n") return parseLiteral("null", null);
    if (c === "-" || (c !== undefined && c >= "0" && c <= "9")) return parseNumber();
    fail(`unexpected character ${JSON.stringify(c)}`);
  }
  function parseLiteral(lit: string, val: unknown): unknown {
    if (text.slice(i, i + lit.length) !== lit) fail(`expected literal "${lit}"`);
    i += lit.length;
    return val;
  }
  function parseObject(): Record<string, unknown> {
    i += 1; // "{"
    const obj: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
    const seen = new Set<string>();
    skipWs();
    if (text[i] === "}") {
      i += 1;
      return obj;
    }
    for (;;) {
      skipWs();
      if (text[i] !== '"') fail("expected a string key");
      const key = parseString();
      if (FORBIDDEN_KEYS.has(key)) fail(`forbidden object key "${key}"`);
      if (seen.has(key)) fail(`duplicate object key "${key}"`);
      seen.add(key);
      skipWs();
      if (text[i] !== ":") fail('expected ":"');
      i += 1;
      obj[key] = parseValue();
      skipWs();
      if (text[i] === ",") {
        i += 1;
        continue;
      }
      if (text[i] === "}") {
        i += 1;
        break;
      }
      fail('expected "," or "}"');
    }
    return obj;
  }
  function parseArray(): unknown[] {
    i += 1; // "["
    const arr: unknown[] = [];
    skipWs();
    if (text[i] === "]") {
      i += 1;
      return arr;
    }
    for (;;) {
      arr.push(parseValue());
      skipWs();
      if (text[i] === ",") {
        i += 1;
        continue;
      }
      if (text[i] === "]") {
        i += 1;
        break;
      }
      fail('expected "," or "]"');
    }
    return arr;
  }
  function parseString(): string {
    i += 1; // opening quote
    let out = "";
    for (;;) {
      if (i >= n) fail("unterminated string");
      const c = text[i];
      if (c === '"') {
        i += 1;
        break;
      }
      if (c === "\\") {
        i += 1;
        const esc = text[i];
        switch (esc) {
          case '"':
            out += '"';
            break;
          case "\\":
            out += "\\";
            break;
          case "/":
            out += "/";
            break;
          case "b":
            out += "\b";
            break;
          case "f":
            out += "\f";
            break;
          case "n":
            out += "\n";
            break;
          case "r":
            out += "\r";
            break;
          case "t":
            out += "\t";
            break;
          case "u": {
            const hex = text.slice(i + 1, i + 5);
            if (!/^[0-9a-fA-F]{4}$/.test(hex)) fail("invalid \\u escape");
            out += String.fromCharCode(parseInt(hex, 16));
            i += 4;
            break;
          }
          default:
            fail(`invalid escape "\\${String(esc)}"`);
        }
        i += 1;
      } else if (c !== undefined) {
        const code = c.charCodeAt(0);
        if (code < 0x20) fail("unescaped control character in string");
        out += c;
        i += 1;
      } else {
        fail("unterminated string");
      }
    }
    assertNoLoneSurrogatesOrControls(out, fail);
    return out;
  }
  function parseNumber(): number {
    const start = i;
    if (text[i] === "-") i += 1;
    const d0 = text[i];
    if (d0 === "0") {
      i += 1;
    } else if (d0 !== undefined && d0 >= "1" && d0 <= "9") {
      i += 1;
      while (i < n && text[i]! >= "0" && text[i]! <= "9") i += 1;
    } else {
      fail("invalid number");
    }
    if (text[i] === ".") {
      i += 1;
      if (!(i < n && text[i]! >= "0" && text[i]! <= "9")) fail("invalid number (fraction)");
      while (i < n && text[i]! >= "0" && text[i]! <= "9") i += 1;
    }
    if (text[i] === "e" || text[i] === "E") {
      i += 1;
      const sign = text[i];
      if (sign === "+" || sign === "-") i += 1;
      if (!(i < n && text[i]! >= "0" && text[i]! <= "9")) fail("invalid number (exponent)");
      while (i < n && text[i]! >= "0" && text[i]! <= "9") i += 1;
    }
    const literal = text.slice(start, i);
    const value = Number(literal);
    if (!Number.isFinite(value)) fail("non-finite number");
    if (Object.is(value, -0)) fail("negative zero is not allowed");
    return value;
  }

  const value = parseValue();
  skipWs();
  if (i !== n) fail("trailing content after the JSON value");
  return value;
}

/* ------------------------------------------------------------------ */
/* Schemas                                                              */
/* ------------------------------------------------------------------ */

export const Sha256HexSchema = z.string().regex(/^[0-9a-f]{64}$/, "must be a lowercase hex sha256");

/** `yyyymmdd-gitsha7` (§3.5). */
export const CatalogVersionSchema = z
  .string()
  .regex(/^\d{8}-[0-9a-f]{7}$/, 'must be "yyyymmdd-gitsha7"');

export const SemverSchema = z
  .string()
  .regex(
    /^\d+\.\d+\.\d+(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/,
    "must be a semver string",
  );

/** A key id: lower-case letters, digits and hyphens only, 1–64 chars. */
export const KidSchema = z.string().regex(/^[a-z0-9-]{1,64}$/, "must match ^[a-z0-9-]{1,64}$");

/**
 * A strict, UTC-only ISO-8601 datetime with millisecond precision —
 * exactly what `Date#toISOString()` produces
 * (`YYYY-MM-DDTHH:mm:ss.sssZ`). Rejects an offset (`+05:00`), a local
 * (no-`Z`) form, and — because the underlying regex's year component is a
 * plain `\d{4}`, not an open-ended digit run — an "extended year" string
 * like `+010000-01-01T00:00:00Z` (which `new Date(...)` will happily
 * parse and `.toISOString()` will happily echo back, but which breaks the
 * plain string comparison `appendVersion` uses for "publishedAt strictly
 * increases").
 */
export const IsoDateTimeSchema = z.iso.datetime({ precision: 3 });

/**
 * Shard paths, relative to `catalog/v1/`. Lower-case only (a security-gate
 * requirement, not a style choice — see `emit-catalog.ts`'s module doc for
 * why region-code shard filenames are lower-cased even though the
 * `Region`/`Facility.region` VALUE inside the file stays the real,
 * upper-case ISO 3166-2 code). No `..` segment, never absolute.
 */
export const ShardPathSchema = z
  .string()
  .min(1)
  .regex(/^[a-z0-9][a-z0-9/_.-]*\.(json|txt)$/, "invalid shard path")
  .refine((p) => !p.split("/").includes(".."), { message: "shard path must not contain .." })
  .refine((p) => !p.startsWith("/"), { message: "shard path must not be absolute" });

export const ShardEntrySchema = z.strictObject({
  path: ShardPathSchema,
  sha256: Sha256HexSchema,
  bytes: z.int().nonnegative(),
  license: z.literal("ODbL-1.0").optional(),
});
export type ShardEntry = z.infer<typeof ShardEntrySchema>;

export const CatalogManifestSchema = z.strictObject({
  contractVersion: z.int().nonnegative(),
  catalogVersion: CatalogVersionSchema,
  minAppVersion: SemverSchema,
  kid: KidSchema,
  revokedKids: z.array(KidSchema),
  generatedAt: IsoDateTimeSchema,
  shards: z.array(ShardEntrySchema),
});
export type CatalogManifest = z.infer<typeof CatalogManifestSchema>;

/** The domain-separated statement that actually gets signed (§3.3(ii)):
 * `"golfraven/catalog/v1/manifest\n" + canonicalStringify(ManifestStatement)`.
 * `manifestSha` is the sha256 of `manifest.json`'s raw bytes — the
 * statement commits to the manifest's exact content through that hash,
 * without the statement itself needing to embed the (potentially large)
 * manifest body. */
export const ManifestStatementSchema = z.strictObject({
  catalogVersion: CatalogVersionSchema,
  contractVersion: z.int().nonnegative(),
  kid: KidSchema,
  manifestSha: Sha256HexSchema,
});
export type ManifestStatement = z.infer<typeof ManifestStatementSchema>;

/** `manifest.sig.json`: the statement's fields plus the signature. */
export const ManifestSignatureSchema = ManifestStatementSchema.extend({
  sig: z.string().min(1),
});
export type ManifestSignature = z.infer<typeof ManifestSignatureSchema>;

export const MANIFEST_DOMAIN = "golfraven/catalog/v1/manifest\n";
export const VERSIONS_DOMAIN = "golfraven/catalog/v1/versions\n";

export function manifestStatementBytes(statement: ManifestStatement): Buffer {
  return Buffer.from(MANIFEST_DOMAIN + canonicalStringify(statement), "utf8");
}

/** One entry in the append-only `catalog/v1/versions.json`. */
export const VersionEntrySchema = z.strictObject({
  version: CatalogVersionSchema,
  publishedAt: IsoDateTimeSchema,
  kid: KidSchema,
  sha256: Sha256HexSchema,
});
export type VersionEntry = z.infer<typeof VersionEntrySchema>;

export const VersionsArraySchema = z.array(VersionEntrySchema);

/** `versions.sig.json`: signs `versions.json`'s raw bytes, domain-separated
 * from the manifest signature so one can never be replayed as the other. */
export const VersionsStatementSchema = z.strictObject({
  kid: KidSchema,
  versionsSha: Sha256HexSchema,
});
export type VersionsStatement = z.infer<typeof VersionsStatementSchema>;

export const VersionsSignatureSchema = VersionsStatementSchema.extend({
  sig: z.string().min(1),
});
export type VersionsSignature = z.infer<typeof VersionsSignatureSchema>;

export function versionsStatementBytes(statement: VersionsStatement): Buffer {
  return Buffer.from(VERSIONS_DOMAIN + canonicalStringify(statement), "utf8");
}

/* ------------------------------------------------------------------ */
/* Strict-parse + schema-validate, in one call, returning issues rather */
/* than throwing (finding: "Zod-validate ... returning issues rather    */
/* than throwing a TypeError")                                          */
/* ------------------------------------------------------------------ */

export type StrictParseResult<T> = { ok: true; value: T } | { ok: false; issues: string[] };

export function strictParseAndValidate<T>(
  raw: Buffer,
  schema: z.ZodType<T>,
  label: string,
): StrictParseResult<T> {
  let parsed: unknown;
  try {
    parsed = parseStrictJson(raw.toString("utf8"));
  } catch (err) {
    return { ok: false, issues: [`${label}: ${err instanceof Error ? err.message : String(err)}`] };
  }
  const result = schema.safeParse(parsed);
  if (!result.success) {
    return {
      ok: false,
      issues: result.error.issues.map((i) => `${label}: ${formatZodPath(i.path)}: ${i.message}`),
    };
  }
  return { ok: true, value: result.data };
}

function formatZodPath(path: readonly PropertyKey[]): string {
  if (path.length === 0) return "<root>";
  return path.map(String).join(".");
}

/* ------------------------------------------------------------------ */
/* catalogVersion ordering (for append-only strict-increase + rollback  */
/* refusal)                                                             */
/* ------------------------------------------------------------------ */

export function parseCatalogVersion(v: string): { date: string; sha: string } | undefined {
  const m = /^(\d{8})-([0-9a-f]{7})$/.exec(v);
  if (!m) return undefined;
  return { date: m[1]!, sha: m[2]! };
}

/** Orders `yyyymmdd-gitsha7` strings primarily by date, falling back to a
 * code-point comparison of the sha suffix only to make the ordering total
 * (two versions cut on the same day have no other meaningful order). Not
 * cryptographically or chronologically meaningful beyond the date — it
 * exists only to detect "not older" / "not the same instant published
 * twice", not to reconstruct true publish order within a day. */
export function compareCatalogVersions(a: string, b: string): number {
  const pa = parseCatalogVersion(a);
  const pb = parseCatalogVersion(b);
  if (!pa || !pb) return compareCodePoints(a, b);
  if (pa.date !== pb.date) return pa.date < pb.date ? -1 : 1;
  return compareCodePoints(pa.sha, pb.sha);
}

/* ------------------------------------------------------------------ */
/* versions.json append-only                                           */
/* ------------------------------------------------------------------ */

/**
 * Enforces `versions.json`'s append-only discipline (§3.3): every entry in
 * `previous` must appear, unchanged, at the same position, in `next` —
 * `next` may only add entries after `previous`'s. Throws with a message
 * naming the exact violation; never silently drops or rewrites data.
 */
export function assertVersionsAppendOnly(
  previous: readonly VersionEntry[],
  next: readonly VersionEntry[],
): void {
  if (next.length < previous.length) {
    throw new Error(
      `versions.json append-only violation: ${previous.length} previous entries, only ${next.length} in the new list`,
    );
  }
  for (let i = 0; i < previous.length; i += 1) {
    const before = previous[i];
    const after = next[i];
    if (!before || !after || before.version !== after.version) {
      throw new Error(
        `versions.json append-only violation: entry ${i} was version "${before?.version ?? "<missing>"}", now "${after?.version ?? "<missing>"}"`,
      );
    }
    if (
      before.publishedAt !== after.publishedAt ||
      before.kid !== after.kid ||
      before.sha256 !== after.sha256
    ) {
      throw new Error(
        `versions.json append-only violation: version "${before.version}" changed (was publishedAt=${before.publishedAt} kid=${before.kid} sha256=${before.sha256}, now publishedAt=${after.publishedAt} kid=${after.kid} sha256=${after.sha256})`,
      );
    }
  }
}

/**
 * Appends `entry` to `previous`. A genuinely new entry must strictly
 * increase both `version` (by `compareCatalogVersions`) and `publishedAt`
 * (by plain string comparison — safe because every `publishedAt` this
 * module writes is a fixed-format `Date#toISOString()` UTC timestamp) past
 * the current last entry, or the append is refused. A duplicate `version`
 * is legal ONLY as an idempotent republish of the CURRENT last entry with
 * IDENTICAL content (a retried emit of the same version); a duplicate of
 * any earlier version, or a same-version republish with different
 * content, is refused outright.
 */
export function appendVersion(
  previous: readonly VersionEntry[],
  entry: VersionEntry,
): VersionEntry[] {
  const existingIndex = previous.findIndex((v) => v.version === entry.version);
  if (existingIndex !== -1) {
    if (existingIndex !== previous.length - 1) {
      throw new Error(
        `versions.json append-only violation: version "${entry.version}" already exists earlier in the list, not as the last entry — refusing to rewrite history`,
      );
    }
    const existing = previous[existingIndex];
    if (
      !existing ||
      existing.publishedAt !== entry.publishedAt ||
      existing.kid !== entry.kid ||
      existing.sha256 !== entry.sha256
    ) {
      throw new Error(
        `versions.json append-only violation: version "${entry.version}" was already published with different content`,
      );
    }
    return [...previous];
  }
  const last = previous[previous.length - 1];
  if (last) {
    if (compareCatalogVersions(entry.version, last.version) <= 0) {
      throw new Error(
        `versions.json append-only violation: new version "${entry.version}" must be strictly greater than the last published version "${last.version}"`,
      );
    }
    if (!(entry.publishedAt > last.publishedAt)) {
      throw new Error(
        `versions.json append-only violation: new publishedAt "${entry.publishedAt}" must be strictly after the last published "${last.publishedAt}"`,
      );
    }
  }
  const next = [...previous, entry];
  assertVersionsAppendOnly(previous, next);
  return next;
}
