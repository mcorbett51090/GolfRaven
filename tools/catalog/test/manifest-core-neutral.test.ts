/**
 * `manifest-core.ts` is shared with the mobile app (apps/mobile), which is
 * bundled by Metro and runs on Hermes: it must stay free of `node:*`
 * imports and of `Buffer`. This is the guard for that contract, plus a
 * check that the Node-side wrappers in `manifest.ts` encode exactly the
 * strings the core produces (so the split cannot drift the signed bytes).
 */
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  MANIFEST_DOMAIN,
  VERSIONS_DOMAIN,
  manifestStatementText,
  strictParseAndValidateText,
  versionsStatementText,
  CatalogManifestSchema,
} from "../src/manifest-core.js";
import {
  manifestStatementBytes,
  strictParseAndValidate,
  versionsStatementBytes,
} from "../src/manifest.js";

const KID = "k-test-1";
const SHA = "a".repeat(64);

describe("manifest-core is platform-neutral", () => {
  it("has no node:* import and no Buffer in code", async () => {
    const src = await readFile(fileURLToPath(new URL("../src/manifest-core.ts", import.meta.url)), "utf8");
    const code = src
      .split("\n")
      .filter((line) => !/^\s*(\*|\/\/|\/\*)/.test(line))
      .join("\n");
    expect(code).not.toMatch(/from\s+["']node:/);
    expect(code).not.toMatch(/require\(/);
    expect(code).not.toMatch(/\bBuffer\b/);
    expect(code).not.toMatch(/\bprocess\b/);
  });
});

describe("manifest.ts wrappers encode exactly the core's text", () => {
  it("manifestStatementBytes === utf8(manifestStatementText)", () => {
    const stmt = { catalogVersion: "20260101-abcdef0", contractVersion: 0, kid: KID, manifestSha: SHA };
    expect(manifestStatementText(stmt).startsWith(MANIFEST_DOMAIN)).toBe(true);
    expect(manifestStatementBytes(stmt).equals(Buffer.from(manifestStatementText(stmt), "utf8"))).toBe(true);
  });

  it("versionsStatementBytes === utf8(versionsStatementText)", () => {
    const stmt = { kid: KID, versionsSha: SHA };
    expect(versionsStatementText(stmt).startsWith(VERSIONS_DOMAIN)).toBe(true);
    expect(versionsStatementBytes(stmt).equals(Buffer.from(versionsStatementText(stmt), "utf8"))).toBe(true);
  });

  it("strictParseAndValidate(Buffer) agrees with strictParseAndValidateText(string)", () => {
    const text = '{"a": 1, "a": 2}';
    const viaBuffer = strictParseAndValidate(Buffer.from(text), CatalogManifestSchema, "x");
    const viaText = strictParseAndValidateText(text, CatalogManifestSchema, "x");
    expect(viaBuffer).toEqual(viaText);
    expect(viaText.ok).toBe(false);
  });
});
