/**
 * serve-with-headers.mjs — a tiny static file server that applies the
 * generated `<dist>/_headers` file's rules with REAL Cloudflare Pages
 * semantics (confirmed against
 * https://developers.cloudflare.com/pages/configuration/headers/ and
 * cloudflare-docs PR #32995, re-gate correction):
 *
 *   - Rules apply in FILE ORDER; every block whose path pattern matches
 *     the request applies, not just the most specific one.
 *   - A header name repeated across matching blocks is JOINED with
 *     `", "` (comma-space) — NEVER overridden by a later block.
 *   - `! Header-Name` (a "detach") REMOVES that header from the
 *     accumulated set built so far; it only removes what EARLIER rules
 *     (in file order, including earlier lines in the SAME block) added —
 *     a `set` for the same name later in file order re-adds it fresh.
 *
 * Used ONLY by the Playwright runtime-CSP e2e test
 * (`apps/site/test/e2e/map-csp-check.mjs`) and its own unit tests
 * (`apps/site/test/serve-with-headers.test.ts`) — this is what makes the
 * e2e test a genuine "serve the built site with the generated `_headers`
 * CSP" check, not just a build-time text assertion on the file's
 * contents.
 */
import { createServer } from "node:http";
import { existsSync } from "node:fs";
import { readFile, stat } from "node:fs/promises";
import { extname, join } from "node:path";

const MIME = {
  ".html": "text/html",
  ".css": "text/css",
  ".js": "text/javascript",
  ".json": "application/json",
  ".geojson": "application/json",
  ".png": "image/png",
  ".svg": "image/svg+xml",
  ".webmanifest": "application/manifest+json",
  ".xml": "application/xml",
};

/**
 * @param {string} text
 * @returns {{path: string, ops: ({type: "set", name: string, value: string} | {type: "detach", name: string})[]}[]}
 */
export function parseHeadersFile(text) {
  const blocks = [];
  let current = null;
  for (const raw of text.split("\n")) {
    const line = raw.replace(/\r$/, "");
    if (!line.trim() || line.trim().startsWith("#")) continue;
    if (!/^\s/.test(line)) {
      current = { path: line.trim(), ops: [] };
      blocks.push(current);
    } else if (current) {
      const trimmed = line.trim();
      if (trimmed.startsWith("!")) {
        const name = trimmed.slice(1).trim();
        if (name) current.ops.push({ type: "detach", name });
      } else {
        const idx = trimmed.indexOf(":");
        if (idx === -1) continue;
        const name = trimmed.slice(0, idx).trim();
        const value = trimmed.slice(idx + 1).trim();
        if (name) current.ops.push({ type: "set", name, value });
      }
    }
  }
  return blocks;
}

/** Cloudflare Pages `_headers` path matching: `/*` = everything,
 * `/prefix/*` = prefix match, anything else = exact match. */
function matchPath(pattern, pathname) {
  if (pattern === "/*") return true;
  if (pattern.endsWith("/*")) return pathname.startsWith(pattern.slice(0, -1));
  return pathname === pattern;
}

/**
 * Applies every block whose `path` matches `pathname`, IN FILE ORDER,
 * replaying each block's `ops` in order — a `set` for a name already
 * accumulated joins with `", "`; a `detach` removes that name outright
 * (only what came before it; a `set` later still re-adds it). Returns a
 * plain `{ "Header-Name": "value" }` object, preserving each header's
 * first-seen casing.
 *
 * @param {ReturnType<typeof parseHeadersFile>} blocks
 * @param {string} pathname
 */
export function resolveHeaders(blocks, pathname) {
  /** @type {Map<string, {name: string, value: string}>} */
  const acc = new Map();
  for (const block of blocks) {
    if (!matchPath(block.path, pathname)) continue;
    for (const op of block.ops) {
      const key = op.name.toLowerCase();
      if (op.type === "detach") {
        acc.delete(key);
        continue;
      }
      const existing = acc.get(key);
      if (existing) {
        acc.set(key, {
          name: existing.name,
          value: `${existing.value}, ${op.value}`,
        });
      } else {
        acc.set(key, { name: op.name, value: op.value });
      }
    }
  }
  /** @type {Record<string, string>} */
  const out = {};
  for (const { name, value } of acc.values()) out[name] = value;
  return out;
}

export async function serveDistWithHeaders(distDir, port) {
  const headersPath = join(distDir, "_headers");
  const blocks = existsSync(headersPath)
    ? parseHeadersFile(await readFile(headersPath, "utf8"))
    : [];

  const server = createServer(async (req, res) => {
    try {
      const url = new URL(req.url, "http://127.0.0.1");
      let pathname = decodeURIComponent(url.pathname);
      if (pathname.endsWith("/")) pathname += "index.html";
      const full = join(distDir, pathname);
      const s = await stat(full).catch(() => null);
      const target = s?.isDirectory() ? join(full, "index.html") : full;
      const body = await readFile(target);

      const applied = resolveHeaders(blocks, url.pathname);
      res.writeHead(200, {
        "Content-Type": MIME[extname(target)] ?? "application/octet-stream",
        ...applied,
      });
      res.end(body);
    } catch {
      res.writeHead(404);
      res.end("not found");
    }
  });
  return new Promise((resolve) =>
    server.listen(port, "127.0.0.1", () => resolve(server)),
  );
}
