// supabase/tests/unit/wycheproof-vendored-pin.test.ts
//
// S1.1b (gate N-1): the vendored Wycheproof corpora are the evidence behind the ES256 / RS256 verifier cells, and NOTICE.md says their sha256 values "pin the content". A pin
// nothing checks is prose: an edited, truncated or re-vendored file would keep every cell that reads it green while proving something different. This test re-hashes each
// vendored file and compares it with the value NOTICE.md records for it, and requires NOTICE.md to name exactly the files that exist (no unpinned corpus, no orphan pin).
import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const DIR = join(import.meta.dirname, "..", "fixtures", "partner-sig", "wycheproof");
const notice = readFileSync(join(DIR, "NOTICE.md"), "utf8");

/** `| \`file.json\` | ... | <sha256> |` table rows of NOTICE.md -> file -> pinned sha256. */
function pins(): Map<string, string> {
  const out = new Map<string, string>();
  for (const line of notice.split("\n")) {
    const m = /^\|\s*`([^`]+\.json)`\s*\|.*\|\s*`([0-9a-f]{64})`\s*\|\s*$/.exec(line);
    if (m) out.set(m[1]!, m[2]!);
  }
  return out;
}

describe("vendored Wycheproof corpora match the sha256 pins in NOTICE.md", () => {
  const pinned = pins();
  const files = readdirSync(DIR).filter((f) => f.endsWith(".json")).sort();

  it("NOTICE.md pins every vendored corpus and nothing else", () => {
    expect(files.length).toBeGreaterThan(0);
    expect([...pinned.keys()].sort()).toEqual(files);
  });

  it.each(files)("%s hashes to its pin", (file) => {
    const actual = createHash("sha256").update(readFileSync(join(DIR, file))).digest("hex");
    expect(actual).toBe(pinned.get(file));
  });
});
