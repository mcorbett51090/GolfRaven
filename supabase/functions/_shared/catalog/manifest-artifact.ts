// supabase/functions/_shared/catalog/manifest-artifact.ts
//
// Hand-rolled (no zod, no `node:crypto` — this file has to run under
// Deno's Edge Runtime, and per this repo's own convention
// (evidence/request-shape.ts's own header), a second, version-mismatched
// zod dependency is avoided where a small hand-rolled parser suffices)
// parsing of the catalog artifact's manifest/versions shape, build plan
// §3.3/§3.5. This module CANNOT `import` `tools/catalog/src/manifest.ts`
// directly — that package is Node-only (`node:crypto`) and lives outside
// `supabase/functions/**`, which `tools/service-role-lint` treats as a
// closed tree (only a relative import that resolves INSIDE
// `supabase/functions`, or a bare specifier pinned in
// `tools/service-role-lint/pinned-import-targets.json`, is legitimate —
// see that tool's own header). The same "reimplemented here since this
// file cannot import that package" pattern privileged.ts's own
// `resolveLedgerId` already uses for `packages/catalog`'s
// `resolveMergedId`.
//
// What's reimplemented, and why it must be BYTE-IDENTICAL to
// `tools/catalog/src/manifest.ts`'s own algorithm: `canonicalStringify`
// (object keys sorted by Unicode code point, 2-space indent, trailing
// newline) is what the SIGNING side (tools/catalog/src/sign.ts) hashes —
// a verifier that canonicalizes differently would compute different
// signed bytes and every real signature would fail to verify, even a
// genuine one. `compareCodePoints`/`sortAndValidate`/`canonicalStringify`
// below are a direct, unmodified port of manifest.ts's own functions.
// `MANIFEST_DOMAIN`/`VERSIONS_DOMAIN` are copied verbatim (the exact
// strings, including their trailing "\n") — a domain-tag typo here would
// silently make every real signature fail, and there is no test that
// could catch a "both sides agree on the wrong string" bug except
// comparing byte-for-byte against the signing side's own source, which
// this header does.

/** Verbatim port of manifest.ts#compareCodePoints. */
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

/** Verbatim port of manifest.ts#canonicalStringify — MUST stay byte-for-byte
 * identical to the signing side's own algorithm (see this module's header). */
export function canonicalStringify(value: unknown): string {
  return `${JSON.stringify(sortAndValidate(value), null, 2)}\n`;
}

export const MANIFEST_DOMAIN = "golfraven/catalog/v1/manifest\n";
export const VERSIONS_DOMAIN = "golfraven/catalog/v1/versions\n";

export interface ManifestStatement {
  catalogVersion: string;
  contractVersion: number;
  kid: string;
  manifestSha: string;
}

export function manifestStatementBytes(statement: ManifestStatement): Uint8Array {
  return new TextEncoder().encode(MANIFEST_DOMAIN + canonicalStringify(statement));
}

export interface VersionsStatement {
  kid: string;
  versionsSha: string;
}

export function versionsStatementBytes(statement: VersionsStatement): Uint8Array {
  return new TextEncoder().encode(VERSIONS_DOMAIN + canonicalStringify(statement));
}

/* ------------------------------------------------------------------ */
/* Strict shape checks — deliberately narrower than manifest.ts's zod   */
/* schemas (no regex-exact format checks beyond what this importer      */
/* itself needs to trust the fields it actually reads); every REJECTED  */
/* shape here is also rejected by the real schema, so nothing this      */
/* module accepts that the real emitter wouldn't produce, but a field   */
/* this module doesn't itself use (e.g. shard `license`) is passed      */
/* through loosely rather than re-validated byte-for-byte.               */
/* ------------------------------------------------------------------ */

const SHA256_HEX_RE = /^[0-9a-f]{64}$/;
const CATALOG_VERSION_RE = /^\d{8}-[0-9a-f]{7}$/;
const KID_RE = /^[a-z0-9-]{1,64}$/;
const SEMVER_RE = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;
// Strict UTC ISO-8601 with millisecond precision — Date#toISOString()'s
// exact shape (manifest.ts's own IsoDateTimeSchema constraint).
const ISO_DATETIME_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

export type ParseResult<T> = { ok: true; value: T } | { ok: false; issue: string };

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

export interface ShardEntry {
  path: string;
  sha256: string;
  bytes: number;
}

export interface CatalogManifest {
  contractVersion: number;
  catalogVersion: string;
  minAppVersion: string;
  kid: string;
  revokedKids: string[];
  generatedAt: string;
  shards: ShardEntry[];
}

export function parseCatalogManifest(raw: unknown): ParseResult<CatalogManifest> {
  if (!isPlainObject(raw)) return { ok: false, issue: "manifest.json: not an object" };
  if (!Number.isInteger(raw.contractVersion) || (raw.contractVersion as number) < 0) {
    return { ok: false, issue: "manifest.json: contractVersion must be a non-negative integer" };
  }
  if (typeof raw.catalogVersion !== "string" || !CATALOG_VERSION_RE.test(raw.catalogVersion)) {
    return { ok: false, issue: "manifest.json: catalogVersion must be yyyymmdd-gitsha7" };
  }
  if (typeof raw.minAppVersion !== "string" || !SEMVER_RE.test(raw.minAppVersion)) {
    return { ok: false, issue: "manifest.json: minAppVersion must be a semver string" };
  }
  if (typeof raw.kid !== "string" || !KID_RE.test(raw.kid)) {
    return { ok: false, issue: "manifest.json: kid must match ^[a-z0-9-]{1,64}$" };
  }
  if (!Array.isArray(raw.revokedKids) || !raw.revokedKids.every((k) => typeof k === "string" && KID_RE.test(k))) {
    return { ok: false, issue: "manifest.json: revokedKids must be an array of kid strings" };
  }
  if (typeof raw.generatedAt !== "string" || !ISO_DATETIME_RE.test(raw.generatedAt)) {
    return { ok: false, issue: "manifest.json: generatedAt must be a strict UTC ISO-8601 datetime" };
  }
  if (!Array.isArray(raw.shards)) return { ok: false, issue: "manifest.json: shards must be an array" };
  const shards: ShardEntry[] = [];
  for (const s of raw.shards) {
    if (!isPlainObject(s) || typeof s.path !== "string" || typeof s.sha256 !== "string" || !SHA256_HEX_RE.test(s.sha256) || !Number.isInteger(s.bytes) || (s.bytes as number) < 0) {
      return { ok: false, issue: "manifest.json: each shard entry must be {path: string, sha256: hex64, bytes: nonneg int}" };
    }
    if (s.path.includes("..") || s.path.startsWith("/")) {
      return { ok: false, issue: `manifest.json: shard path "${s.path}" must be relative with no ".." segment` };
    }
    shards.push({ path: s.path, sha256: s.sha256, bytes: s.bytes as number });
  }
  return {
    ok: true,
    value: {
      contractVersion: raw.contractVersion as number,
      catalogVersion: raw.catalogVersion,
      minAppVersion: raw.minAppVersion,
      kid: raw.kid,
      revokedKids: raw.revokedKids as string[],
      generatedAt: raw.generatedAt,
      shards,
    },
  };
}

export interface ManifestSignature {
  catalogVersion: string;
  contractVersion: number;
  kid: string;
  manifestSha: string;
  sig: string;
}

export function parseManifestSignature(raw: unknown): ParseResult<ManifestSignature> {
  if (!isPlainObject(raw)) return { ok: false, issue: "manifest.sig.json: not an object" };
  if (typeof raw.catalogVersion !== "string" || !CATALOG_VERSION_RE.test(raw.catalogVersion)) {
    return { ok: false, issue: "manifest.sig.json: catalogVersion must be yyyymmdd-gitsha7" };
  }
  if (!Number.isInteger(raw.contractVersion) || (raw.contractVersion as number) < 0) {
    return { ok: false, issue: "manifest.sig.json: contractVersion must be a non-negative integer" };
  }
  if (typeof raw.kid !== "string" || !KID_RE.test(raw.kid)) {
    return { ok: false, issue: "manifest.sig.json: kid must match ^[a-z0-9-]{1,64}$" };
  }
  if (typeof raw.manifestSha !== "string" || !SHA256_HEX_RE.test(raw.manifestSha)) {
    return { ok: false, issue: "manifest.sig.json: manifestSha must be a lowercase hex sha256" };
  }
  if (typeof raw.sig !== "string" || raw.sig.length === 0) {
    return { ok: false, issue: "manifest.sig.json: sig must be a non-empty string" };
  }
  return {
    ok: true,
    value: { catalogVersion: raw.catalogVersion, contractVersion: raw.contractVersion as number, kid: raw.kid, manifestSha: raw.manifestSha, sig: raw.sig },
  };
}

export interface VersionEntry {
  version: string;
  publishedAt: string;
  kid: string;
  sha256: string;
}

export function parseVersionsArray(raw: unknown): ParseResult<VersionEntry[]> {
  if (!Array.isArray(raw)) return { ok: false, issue: "versions.json: not an array" };
  const out: VersionEntry[] = [];
  for (let i = 0; i < raw.length; i++) {
    const e = raw[i];
    if (!isPlainObject(e)) return { ok: false, issue: `versions.json[${i}]: not an object` };
    if (typeof e.version !== "string" || !CATALOG_VERSION_RE.test(e.version)) {
      return { ok: false, issue: `versions.json[${i}]: version must be yyyymmdd-gitsha7` };
    }
    if (typeof e.publishedAt !== "string" || !ISO_DATETIME_RE.test(e.publishedAt)) {
      return { ok: false, issue: `versions.json[${i}]: publishedAt must be a strict UTC ISO-8601 datetime` };
    }
    if (typeof e.kid !== "string" || !KID_RE.test(e.kid)) {
      return { ok: false, issue: `versions.json[${i}]: kid must match ^[a-z0-9-]{1,64}$` };
    }
    if (typeof e.sha256 !== "string" || !SHA256_HEX_RE.test(e.sha256)) {
      return { ok: false, issue: `versions.json[${i}]: sha256 must be a lowercase hex sha256` };
    }
    out.push({ version: e.version, publishedAt: e.publishedAt, kid: e.kid, sha256: e.sha256 });
  }
  return { ok: true, value: out };
}

export interface VersionsSignature {
  kid: string;
  versionsSha: string;
  sig: string;
}

export function parseVersionsSignature(raw: unknown): ParseResult<VersionsSignature> {
  if (!isPlainObject(raw)) return { ok: false, issue: "versions.sig.json: not an object" };
  if (typeof raw.kid !== "string" || !KID_RE.test(raw.kid)) {
    return { ok: false, issue: "versions.sig.json: kid must match ^[a-z0-9-]{1,64}$" };
  }
  if (typeof raw.versionsSha !== "string" || !SHA256_HEX_RE.test(raw.versionsSha)) {
    return { ok: false, issue: "versions.sig.json: versionsSha must be a lowercase hex sha256" };
  }
  if (typeof raw.sig !== "string" || raw.sig.length === 0) {
    return { ok: false, issue: "versions.sig.json: sig must be a non-empty string" };
  }
  return { ok: true, value: { kid: raw.kid, versionsSha: raw.versionsSha, sig: raw.sig } };
}

/** yyyymmdd-gitsha7 ordering — a direct port of manifest.ts#compareCatalogVersions
 * (date-primary, sha-suffix as a total-order tiebreak only). */
export function compareCatalogVersions(a: string, b: string): number {
  const ma = /^(\d{8})-([0-9a-f]{7})$/.exec(a);
  const mb = /^(\d{8})-([0-9a-f]{7})$/.exec(b);
  if (!ma || !mb) return compareCodePoints(a, b);
  if (ma[1] !== mb[1]) return ma[1]! < mb[1]! ? -1 : 1;
  return compareCodePoints(ma[2]!, mb[2]!);
}

/* ------------------------------------------------------------------ */
/* parseStrictJson — a VERBATIM port of tools/catalog/src/manifest.ts's  */
/* own (P3e round 2 gate, LOW: "use P1's parseStrictJson instead of      */
/* JSON.parse"). Same reasoning as canonicalStringify's own port above:  */
/* this module cannot import the Node-only tools/catalog package, so the */
/* algorithm is copied byte-for-byte rather than re-derived. Differs     */
/* from JSON.parse exactly where it matters for trusting a third party's */
/* artifact: a duplicate object key, a __proto__/constructor/prototype   */
/* key, or a -0 number all throw instead of silently "last write wins"-  */
/* ing or parsing into something later code cannot distinguish from a    */
/* legitimate value.                                                     */
/* ------------------------------------------------------------------ */

const FORBIDDEN_KEYS = new Set(["__proto__", "constructor", "prototype"]);

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
