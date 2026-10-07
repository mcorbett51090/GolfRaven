/**
 * The BUILT bundle (not the source): a real build into a scratch directory, scanned for inline script, eval, `new Function`, storage APIs and
 * third-party origins; plus must-fail fixtures proving the scanner catches each of those (a scanner that cannot fail proves nothing).
 */
import { mkdir, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { buildPartners } from "../scripts/build.mjs";
import { buildCsp } from "../scripts/lib/csp.mjs";
import { scanDist } from "../scripts/lib/scan-output.mjs";

const API_BASE = "https://abc123.example.org/functions/v1";
const API_ORIGIN = "https://abc123.example.org";
let scratch: string;
let dist: string;

async function files(dir: string, prefix = ""): Promise<string[]> {
  const out: string[] = [];
  for (const e of await readdir(dir, { withFileTypes: true })) {
    if (e.isDirectory()) out.push(...(await files(join(dir, e.name), `${prefix}${e.name}/`)));
    else out.push(`${prefix}${e.name}`);
  }
  return out.sort();
}

beforeAll(async () => {
  scratch = await mkdtemp(join(tmpdir(), "gr-partners-build-"));
  dist = join(scratch, "dist");
  await buildPartners({ dist, env: { GOLFRAVEN_PARTNERS_API_BASE: API_BASE } });
});
afterAll(async () => {
  await rm(scratch, { recursive: true, force: true });
});

describe("a real production-shaped build", () => {
  it("emits exactly the static bundle: index.html, one hashed script, one hashed stylesheet, the manifest, the icon and _headers", async () => {
    const names = await files(dist);
    expect(names.filter((n) => !n.startsWith("assets/"))).toEqual(["_headers", "favicon.svg", "index.html", "manifest.webmanifest"]);
    expect(names.filter((n) => n.startsWith("assets/")).map((n) => n.replace(/-[A-Z0-9]+\./, "-HASH."))).toEqual(["assets/app-HASH.js", "assets/styles-HASH.css"]);
  });

  it("passes its own output scan with no findings", async () => {
    expect(await scanDist(dist, { apiOrigin: API_ORIGIN })).toEqual([]);
  });

  it("index.html has exactly one script, a same-origin external module, and no inline script, style or handler", async () => {
    const html = await readFile(join(dist, "index.html"), "utf8");
    const scripts = [...html.matchAll(/<script\b[^>]*>[\s\S]*?<\/script>/gi)].map((m) => m[0]);
    expect(scripts).toHaveLength(1);
    expect(scripts[0]).toMatch(/^<script type="module" src="\.\/assets\/app-[A-Z0-9]+\.js"><\/script>$/);
    expect(html).not.toMatch(/<style\b|\sstyle\s*=|\son[a-z]+\s*=|javascript:/i);
    expect((html.match(/<link rel="stylesheet" href="\.\/assets\/styles-[A-Z0-9]+\.css"/g) ?? []).length).toBe(1);
  });

  it("the page's meta CSP and the _headers CSP are the same policy (the meta one without frame-ancestors)", async () => {
    const html = await readFile(join(dist, "index.html"), "utf8");
    const meta = /http-equiv="Content-Security-Policy" content="([^"]+)"/.exec(html)?.[1];
    expect(meta).toBe(buildCsp(API_BASE, { meta: true }));
    const headers = await readFile(join(dist, "_headers"), "utf8");
    expect(headers).toContain(`Content-Security-Policy: ${buildCsp(API_BASE)}`);
  });

  it("bakes the API base into the bundle and names no other origin anywhere", async () => {
    const js = await readFile(join(dist, "assets", (await files(join(dist, "assets"))).find((n) => n.endsWith(".js"))!), "utf8");
    expect(js).toContain(API_BASE);
    const origins = new Set<string>();
    for (const n of await files(dist)) {
      if (!/\.(html|js|css|webmanifest)$/.test(n) && n !== "_headers") continue;
      for (const m of (await readFile(join(dist, n), "utf8")).matchAll(/https?:\/\/[A-Za-z0-9.:-]+/g)) origins.add(m[0]);
    }
    expect([...origins]).toEqual([API_ORIGIN]);
  });

  it("ships no source map, no service worker and no test harness", async () => {
    for (const n of await files(dist)) {
      expect(n).not.toMatch(/\.map$/);
      expect(n).not.toMatch(/(^|\/)(sw|service-worker|workbox)/i);
      expect(n).not.toMatch(/harness/i);
    }
    expect(await readFile(join(dist, "index.html"), "utf8")).not.toMatch(/serviceWorker/);
  });

  it("the bundle references no storage API, no eval, no Function constructor and no console", async () => {
    const js = await readFile(join(dist, "assets", (await files(join(dist, "assets"))).find((n) => n.endsWith(".js"))!), "utf8");
    for (const re of [/localStorage/, /sessionStorage/, /indexedDB/, /\bcaches\b/, /\bcookie/i, /serviceWorker/, /\beval\s*\(/, /new\s+Function/, /\bFunction\s*\(/, /console\./, /innerHTML/, /credentials:"(include|same-origin)"/]) {
      expect(js, String(re)).not.toMatch(re);
    }
    expect(js).toMatch(/credentials:"omit"/);
  });

  it("a production build refuses the placeholder API host", async () => {
    await expect(buildPartners({ dist: join(scratch, "prod"), env: { GOLFRAVEN_ENV: "production" } })).rejects.toThrow(/placeholder/);
  });

  it("the default (placeholder) build still scans clean and names the placeholder origin", async () => {
    const d = join(scratch, "default");
    const r = await buildPartners({ dist: d, env: {} });
    expect(r.apiOrigin).toBe("https://partners-api.golfraven.example");
    expect(await scanDist(d, { apiOrigin: r.apiOrigin })).toEqual([]);
  });
});

describe("the e2e build (harness) is separate from production", () => {
  it("builds the harness page only with GOLFRAVEN_PARTNERS_E2E=1, and accepts a loopback API only then", async () => {
    const d = join(scratch, "e2e");
    await buildPartners({ dist: d, env: { GOLFRAVEN_PARTNERS_E2E: "1", GOLFRAVEN_PARTNERS_API_BASE: "http://localhost:4999/functions/v1" } });
    expect((await files(d)).filter((n) => /harness/.test(n)).sort()).toEqual(["assets/harness-" + (await files(join(d, "assets"))).find((n) => n.startsWith("harness-"))!.slice("harness-".length), "harness.html"].sort());
    // without the flag a loopback API is refused outright
    await expect(buildPartners({ dist: join(scratch, "e2e-no"), env: { GOLFRAVEN_PARTNERS_API_BASE: "http://localhost:4999/functions/v1" } })).rejects.toThrow(/https/);
    // and a production scan of an e2e build reports the harness
    const findings = await scanDist(d, { apiOrigin: "http://localhost:4999" });
    expect(findings.some((f) => f.rule === "harness")).toBe(true);
  });

  it("GOLFRAVEN_PARTNERS_E2E=1 together with GOLFRAVEN_ENV=production is REFUSED, whatever the API base, and builds nothing (LOW-1)", async () => {
    for (const base of ["http://localhost:4999/functions/v1", "https://abc123.supabase.co/functions/v1", undefined]) {
      const d = join(scratch, `e2e-prod-${String(base).length}`);
      const env: Record<string, string> = { GOLFRAVEN_PARTNERS_E2E: "1", GOLFRAVEN_ENV: "production" };
      if (base !== undefined) env["GOLFRAVEN_PARTNERS_API_BASE"] = base;
      await expect(buildPartners({ dist: d, env }), String(base)).rejects.toThrow(/GOLFRAVEN_PARTNERS_E2E=1 is refused/);
      await expect(readdir(d), "nothing was written").rejects.toThrow();
    }
    // control: the same build without production goes through
    await buildPartners({ dist: join(scratch, "e2e-ok"), env: { GOLFRAVEN_PARTNERS_E2E: "1", GOLFRAVEN_PARTNERS_API_BASE: "http://localhost:4999/functions/v1" } });
  });

  it("a production build of a real API host works and is not the e2e build", async () => {
    const d = join(scratch, "prod-ok");
    const r = await buildPartners({ dist: d, env: { GOLFRAVEN_ENV: "production", GOLFRAVEN_PARTNERS_API_BASE: "https://abc123.supabase.co/functions/v1" } });
    expect(r.apiOrigin).toBe("https://abc123.supabase.co");
    expect((await files(d)).some((n) => /harness/.test(n))).toBe(false);
  });
});

describe("the scanner catches each thing it exists to catch (must-fail fixtures)", () => {
  const GOOD_HTML = `<!doctype html><html><head><meta http-equiv="Content-Security-Policy" content="default-src 'none'"><link rel="stylesheet" href="./a.css"><script type="module" src="./a.js"></script></head><body><div id="app"></div></body></html>`;

  async function fixture(over: Record<string, string | null>): Promise<string> {
    const d = await mkdtemp(join(scratch, "fx-"));
    const base: Record<string, string> = { "index.html": GOOD_HTML, "_headers": "/*\n  X: y\n", "a.js": "export const x = 1;", "a.css": "body{margin:0}" };
    for (const [name, content] of Object.entries({ ...base, ...over })) {
      if (content === null) continue;
      await mkdir(join(d, name, ".."), { recursive: true });
      await writeFile(join(d, name), content);
    }
    return d;
  }
  const rules = async (over: Record<string, string | null>) => (await scanDist(await fixture(over), { apiOrigin: API_ORIGIN })).map((f) => f.rule);

  it("control: the known-good fixture has no findings", async () => {
    expect(await rules({})).toEqual([]);
  });

  const html = (body: string) => GOOD_HTML.replace('<div id="app"></div>', body);
  const cases: Array<[string, Record<string, string | null>, string]> = [
    ["an inline script", { "index.html": html("<script>alert(1)</script>") }, "inline script"],
    ["a script with a body and a src", { "index.html": html('<script src="./a.js" type="module">x()</script>') }, "inline script"],
    ["a classic (non-module) script", { "index.html": html('<script src="./a.js"></script>') }, "classic script"],
    ["an event-handler attribute", { "index.html": html('<button onclick="x()">b</button>') }, "event handler attribute"],
    ["a javascript: URL", { "index.html": html('<a href="javascript:x()">b</a>') }, "javascript: URL"],
    ["an inline <style>", { "index.html": html("<style>body{}</style>") }, "inline style"],
    ["a style attribute", { "index.html": html('<p style="color:red">b</p>') }, "inline style"],
    ["an iframe", { "index.html": html('<iframe src="./a.html"></iframe>') }, "forbidden element"],
    ["a third-party script", { "index.html": html('<script type="module" src="https://cdn.evil.test/x.js"></script>') }, "third-party origin"],
    ["a protocol-relative third-party script", { "index.html": html('<script type="module" src="//cdn.evil.test/x.js"></script>') }, "third-party origin"],
    ["eval", { "a.js": "const r = eval('1+1');" }, "eval"],
    ["new Function", { "a.js": "const f = new Function('return 1');" }, "new Function"],
    ["a bare Function() call", { "a.js": "const f = Function('return 1');" }, "Function("],
    ["a string timer", { "a.js": "setTimeout('x()', 1);" }, "string timer"],
    ["document.write", { "a.js": "document.write('x');" }, "document.write"],
    ["innerHTML", { "a.js": "el.innerHTML = s;" }, "innerHTML"],
    ["insertAdjacentHTML", { "a.js": "el.insertAdjacentHTML('beforeend', s);" }, "insertAdjacentHTML"],
    ["localStorage", { "a.js": "localStorage.setItem('k','v');" }, "localStorage"],
    ["sessionStorage", { "a.js": "sessionStorage.setItem('k','v');" }, "sessionStorage"],
    ["indexedDB", { "a.js": "indexedDB.open('d');" }, "indexedDB"],
    ["Cache Storage", { "a.js": "caches.open('c');" }, "Cache Storage"],
    ["a cookie", { "a.js": "document.cookie = 'a=b';" }, "document.cookie"],
    ["a service worker registration", { "a.js": "navigator.serviceWorker.register('/sw.js');" }, "service worker"],
    ["a Worker", { "a.js": "new Worker('w.js');" }, "Worker"],
    ["a console call", { "a.js": "console.log(1);" }, "console"],
    ["credentials: include", { "a.js": "fetch(u,{credentials:'include'});" }, "credentials include"],
    ["credentials: same-origin", { "a.js": 'fetch(u,{credentials:"same-origin"});' }, "credentials include"],
    ["XMLHttpRequest", { "a.js": "new XMLHttpRequest();" }, "XMLHttpRequest"],
    ["a WebSocket", { "a.js": "new WebSocket('wss://x');" }, "WebSocket"],
    ["a beacon", { "a.js": "navigator.sendBeacon('/x');" }, "sendBeacon"],
    ["a third-party URL in the bundle", { "a.js": "const u='https://tracker.evil.test/p';" }, "third-party origin"],
    ["a CSS @import", { "a.css": "@import url(x.css);" }, "css import"],
    ["a remote CSS url()", { "a.css": "a{background:url(https://evil.test/x.png)}" }, "css remote url"],
    ["a source map", { "a.js.map": "{}" }, "source map"],
    ["a service worker file", { "sw.js": "self.skipWaiting();" }, "service worker"],
    ["the test harness in a production build", { "harness.html": "<p>h</p>" }, "harness"],
    ["a missing _headers", { "_headers": null }, "missing"],
    ["a missing index.html", { "index.html": null }, "missing"],
  ];
  it.each(cases)("%s", async (_name, over, rule) => {
    expect(await rules(over)).toContain(rule);
  });

  it("the namespace URL of an SVG is not a network origin, and the allowed API origin is not a finding", async () => {
    expect(await rules({ "a.js": 'const ns="http://www.w3.org/2000/svg"; const api="https://abc123.example.org/functions/v1";' })).toEqual([]);
  });
});
