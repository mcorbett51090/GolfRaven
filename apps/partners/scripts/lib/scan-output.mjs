// @ts-check
/**
 * The build-output scan: reads every text file in a built `dist/` and reports anything the page's CSP and storage rules forbid. `scripts/build.mjs`
 * runs it as the last step (a violation fails the build), and `test/build-output.test.ts` runs it against a real build and against must-fail fixtures.
 *
 * Source scan vs output scan: `test/source-scan.test.ts` reads `src/`; this reads what ships. Both exist because a bundler can introduce what the
 * source does not contain (a polyfill with `new Function`, an inlined script), and the output is what the browser actually executes.
 */
import { readdir, readFile } from "node:fs/promises";
import { join, relative } from "node:path";

/** @typedef {{ file: string, rule: string, detail: string }} Finding */

/** Patterns in shipped JavaScript. Each is a thing the strict CSP, the Trusted Types rule or the "no storage" rule forbids. */
const JS_RULES = /** @type {Array<[string, RegExp]>} */ ([
  ["eval", /\beval\s*\(/],
  ["new Function", /\bnew\s+Function\b/],
  ["Function(", /(^|[^.\w$])Function\s*\(/],
  ["string timer", /\b(?:setTimeout|setInterval)\s*\(\s*["'`]/],
  ["document.write", /\bdocument\s*\.\s*write(?:ln)?\b/],
  ["innerHTML", /\binnerHTML\b/],
  ["outerHTML", /\bouterHTML\b/],
  ["insertAdjacentHTML", /\binsertAdjacentHTML\b/],
  ["srcdoc", /\bsrcdoc\b/],
  ["importScripts", /\bimportScripts\b/],
  ["Worker", /\b(?:Shared)?Worker\b/],
  ["service worker", /\bserviceWorker\b/],
  ["localStorage", /\blocalStorage\b/],
  ["sessionStorage", /\bsessionStorage\b/],
  ["indexedDB", /\bindexedDB\b/],
  ["Cache Storage", /\bcaches\b/],
  ["document.cookie", /\bcookie\b/],
  ["cookieStore", /\bcookieStore\b/],
  ["XMLHttpRequest", /\bXMLHttpRequest\b/],
  ["WebSocket", /\bWebSocket\b/],
  ["EventSource", /\bEventSource\b/],
  ["sendBeacon", /\bsendBeacon\b/],
  ["console", /\bconsole\s*\./],
  ["credentials include", /credentials\s*:\s*["'`](?:include|same-origin)["'`]/],
]);

const URL_RE = /(?:https?:)?\/\/[A-Za-z0-9.-]+(?::\d+)?/g;
/** Namespace identifiers that are not network origins. */
const NON_NETWORK = new Set(["http://www.w3.org"]);

/**
 * @param {string} dist
 * @param {{ apiOrigin: string, harness?: boolean }} opts
 * @returns {Promise<Finding[]>}
 */
export async function scanDist(dist, opts) {
  /** @type {Finding[]} */
  const findings = [];
  const add = (/** @type {string} */ file, /** @type {string} */ rule, /** @type {string} */ detail) => findings.push({ file, rule, detail });

  /** @type {string[]} */
  const files = [];
  /** @param {string} dir */
  async function walk(dir) {
    for (const e of await readdir(dir, { withFileTypes: true })) {
      const p = join(dir, e.name);
      if (e.isDirectory()) await walk(p);
      else files.push(p);
    }
  }
  await walk(dist);

  const names = files.map((f) => relative(dist, f).split("\\").join("/"));
  if (!names.includes("index.html")) add("index.html", "missing", "no index.html");
  if (!names.includes("_headers")) add("_headers", "missing", "no _headers file");
  for (const n of names) {
    if (n.endsWith(".map")) add(n, "source map", "a source map ships");
    if (/(^|\/)(sw|service-worker|workbox)[^/]*\.js$/i.test(n)) add(n, "service worker", "a service worker file ships");
    if (!opts.harness && /harness/i.test(n)) add(n, "harness", "the test harness is in a production build");
  }

  const allowedOrigins = new Set([opts.apiOrigin]);
  for (const f of files) {
    const name = relative(dist, f).split("\\").join("/");
    if (!/\.(html|js|css|webmanifest|json)$/.test(name) && name !== "_headers") continue;
    const text = await readFile(f, "utf8");

    if (name.endsWith(".html")) {
      for (const m of text.matchAll(/<script\b([^>]*)>/gi)) {
        const attrs = m[1] ?? "";
        if (!/\bsrc\s*=/.test(attrs)) add(name, "inline script", m[0]);
        else if (!/\btype\s*=\s*["']module["']/.test(attrs)) add(name, "classic script", m[0]);
      }
      if (/<script\b[^>]*>(?!\s*<\/script>)[^<]/i.test(text)) add(name, "inline script", "a script element has a body");
      if (/\son[a-z]+\s*=/i.test(text.replace(/<meta\b[^>]*>/gi, ""))) add(name, "event handler attribute", "an on*= attribute");
      if (/javascript\s*:/i.test(text)) add(name, "javascript: URL", "javascript:");
      if (/<style\b/i.test(text)) add(name, "inline style", "a <style> element");
      if (/\sstyle\s*=/i.test(text)) add(name, "inline style", "a style= attribute");
      if (/<(?:iframe|object|embed|base|form|frame)\b/i.test(text)) add(name, "forbidden element", "iframe/object/embed/base/form");
    }
    if (name.endsWith(".js") && !name.endsWith(".webmanifest")) {
      for (const [rule, re] of JS_RULES) if (re.test(text)) add(name, rule, String(re));
    }
    if (name.endsWith(".css")) {
      if (/@import\b/i.test(text)) add(name, "css import", "@import");
      if (/\burl\(\s*["']?(?:https?:)?\/\//i.test(text)) add(name, "css remote url", "url(//...)");
    }
    if (name !== "_headers") {
      for (const m of text.matchAll(URL_RE)) {
        const u = m[0];
        const origin = u.startsWith("//") ? `https:${u}` : u;
        if (NON_NETWORK.has(origin)) continue;
        if (!allowedOrigins.has(origin)) add(name, "third-party origin", u);
      }
    }
  }
  return findings;
}
