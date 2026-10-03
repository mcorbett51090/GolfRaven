/**
 * P4.2b-1 release safety: nothing the evidence lane adds to the app can carry a mock or a test string into a release bundle, and the dev-only
 * pieces stay dev-only. (The built-bundle grep is run by hand and recorded in the PR notes; this is the source-level half, in CI.)
 */
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const root = fileURLToPath(new URL("..", import.meta.url));
function files(dir: string): string[] {
  if (!existsSync(dir)) return [];
  return readdirSync(dir).flatMap((n) => {
    const p = join(dir, n);
    return statSync(p).isDirectory() ? files(p) : /\.(ts|tsx)$/.test(n) ? [p] : [];
  });
}
const strip = (s: string): string => s.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");
const text = (f: string): string => readFileSync(f, "utf8");
const rel = (f: string): string => relative(root, f);

describe("the evidence lane ships no mock or test strings", () => {
  const lane = ["attest", "challenges", "evidence", "offline-code", "rewards"].flatMap((d) => files(join(root, "src", d)));
  const wiring = ["src/api/http-client.ts", "src/api/evidence-answer.ts", "src/api/retry-after.ts", "src/api/unconfigured.ts", "src/outbox/runner.ts", "src/runtime/services.ts", "src/runtime/backend.ts"].map((p) => join(root, p));

  it("the scan is not vacuous", () => {
    expect(lane.length).toBeGreaterThanOrEqual(12);
    expect(lane.map(rel)).toContain("src/evidence/send.ts");
  });

  it("no lane or wiring file mentions a mock, a test framework, a fixture, or the demo values", () => {
    for (const f of [...lane, ...wiring]) {
      const code = strip(text(f));
      expect(code, rel(f)).not.toMatch(/createMock|MockApi|mock-auth|api\/mock|MOCK_|vitest|\bfixtures?\b|demo[-_]challenge|demo[-_]jti|mock-user-|mock-access-token|demo-authorization-code/i);
      expect(code, rel(f)).not.toMatch(/from\s*["'][^"']*\/test\//);
    }
  });

  it("the fake challenge / token values exist only in the dev-only mock module", () => {
    const hits = files(join(root, "src"))
      .filter((f) => /demo[-_]challenge|demo[-_]jti|demo_nonce/.test(text(f)))
      .map(rel);
    expect(hits).toEqual(["src/api/mock.ts"]);
  });

  it("the DevPanel is still __DEV__-only: it is required only under __DEV__ and imports no evidence internals", () => {
    const me = text(join(root, "app/(tabs)/me.tsx"));
    expect(me).toMatch(/const DevPanel = __DEV__ \? \(require\("..\/..\/src\/screens\/DevPanel"\)/);
    expect(files(join(root, "src")).concat(files(join(root, "app"))).filter((f) => /screens\/DevPanel/.test(strip(text(f)))).map(rel)).toEqual(["app/(tabs)/me.tsx"]);
    expect(strip(text(join(root, "src/screens/DevPanel.tsx")))).not.toMatch(/evidence\/|challenges\/|attest\//);
  });

  it("the mock still has no static path into the app (the existing guarantee, re-asserted for the new members)", () => {
    for (const f of [...lane, ...wiring]) expect(strip(text(f)), rel(f)).not.toMatch(/from\s*["'][^"']*\/mock["']/);
  });
});
