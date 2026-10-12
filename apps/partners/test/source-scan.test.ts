/**
 * The SOURCE under src/: the rules the CSP and the storage design impose, checked where they are written (the build-output scan checks what ships).
 * Comments are stripped first, so a doc comment may name a forbidden API to say it is forbidden.
 */
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const SRC = new URL("../src/", import.meta.url).pathname;

function listTs(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? listTs(join(dir, e.name)) : e.name.endsWith(".ts") ? [join(dir, e.name)] : []));
}
const strip = (s: string) => s.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|\s)\/\/.*$/gm, "$1");
const sources = listTs(SRC).map((p) => ({ path: p.slice(SRC.length), code: strip(readFileSync(p, "utf8")) }));

const FORBIDDEN: Array<[string, RegExp]> = [
  ["console", /\bconsole\s*\./],
  ["localStorage", /\blocalStorage\b/],
  ["sessionStorage", /\bsessionStorage\b/],
  ["indexedDB", /\bindexedDB\b/],
  ["Cache Storage", /\bcaches\b/],
  ["cookie", /\bcookie/i],
  ["service worker", /\bserviceWorker\b/],
  ["innerHTML", /\binnerHTML\b/],
  ["outerHTML", /\bouterHTML\b/],
  ["insertAdjacentHTML", /\binsertAdjacentHTML\b/],
  ["document.write", /\bdocument\s*\.\s*write/],
  ["eval", /\beval\s*\(/],
  ["Function constructor", /\bnew\s+Function\b|(^|[^.\w$])Function\s*\(/],
  ["string timer", /\b(?:setTimeout|setInterval)\s*\(\s*["'`]/],
  ["XMLHttpRequest", /\bXMLHttpRequest\b/],
  ["WebSocket", /\bWebSocket\b/],
  ["sendBeacon", /\bsendBeacon\b/],
  ["credentials include", /credentials\s*:\s*["'`](?:include|same-origin)["'`]/],
  ["the data API", /postgrest|\/rest\/v1|supabase\.co/i],
  ["window global", /\bwindow\s*\.\s*\w+\s*=/],
];

describe("source rules", () => {
  it("finds the source files (a control: an empty list would pass every rule)", () => {
    expect(sources.length).toBeGreaterThan(10);
  });

  it.each(FORBIDDEN)("no %s anywhere in src/", (_name, re) => {
    const hits = sources.filter((s) => re.test(s.code)).map((s) => s.path);
    expect(hits).toEqual([]);
  });

  // A first-line check only: this regex cannot see a side-effect `import "pkg"`, a dynamic `import("pkg")` or a `require`. The authoritative one is
  // test/bundle-inputs.test.ts (esbuild's metafile, which build.mjs also enforces on every build).
  it("every import is relative: no runtime dependency, no third-party code in the bundle", () => {
    for (const s of sources) {
      for (const m of s.code.matchAll(/(?:^|\n)\s*(?:import|export)\b[^;]*?\bfrom\s+["']([^"']+)["']/g)) expect(m[1], `${s.path}: ${m[0]}`).toMatch(/^\.\.?\//);
    }
    const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as Record<string, unknown>;
    expect(pkg["dependencies"]).toBeUndefined();
  });

  it("fetch is called in exactly one place: the API client", () => {
    expect(sources.filter((s) => /\bfetch\s*\(|\)\s*\(\s*`\$\{base\}/.test(s.code) || /\bfetch\b/.test(s.code.replace(/config\.fetch/g, ""))).map((s) => s.path).sort()).toEqual(["api/client.ts"]);
  });

  it("every element is built with textContent / text nodes: dom.ts appends text nodes and nothing sets markup", () => {
    const dom = sources.find((s) => s.path === "ui/dom.ts")!.code;
    expect(dom).toContain("document.createTextNode");
    expect(dom).toContain("addEventListener");
    expect(dom).not.toMatch(/\.on[a-z]+\s*=/);
  });

  it("the token lives in api/client.ts only: no other module names a bearer or the token prefix", () => {
    const others = sources.filter((s) => s.path !== "api/client.ts" && /Bearer|gr_ps_|authorization/i.test(s.code)).map((s) => s.path);
    expect(others).toEqual([]);
  });

  it("the PIN derivation has ONE entry point: only auth/pin.ts imports the shared contract and deny-list, and nothing else in src/ touches Web Crypto", () => {
    const importers = sources.filter((s) => /pin-contract|pin-deny-list/.test(s.code)).map((s) => s.path);
    expect(importers).toEqual(["auth/pin.ts"]);
    expect(sources.filter((s) => /crypto\s*\.\s*(subtle|getRandomValues)|\bSubtleCrypto\b/.test(s.code)).map((s) => s.path)).toEqual([]);
  });

  it("the only files outside src/ that the bundle may read are the three shared PIN-contract files, imported by exact relative path", () => {
    const outside = sources.flatMap((s) => [...s.code.matchAll(/from\s+["'](\.\.\/[^"']*supabase[^"']*)["']/g)].map((m) => `${s.path}: ${m[1]}`));
    expect(outside.map((l) => l.replace(/^.*: /, "").split("/").pop()).sort()).toEqual(["pin-contract.ts", "pin-deny-list.ts", "token.ts"]);
  });

  it("the scan regexes do match what they are meant to (a control)", () => {
    expect(FORBIDDEN.find(([n]) => n === "localStorage")![1].test("localStorage.setItem(1)")).toBe(true);
    expect(FORBIDDEN.find(([n]) => n === "Function constructor")![1].test("x = new Function('a')")).toBe(true);
    expect(strip("a; // localStorage\n/* sessionStorage */ b")).not.toMatch(/Storage/);
  });
});
