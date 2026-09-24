/**
 * serve-with-headers.mjs — a tiny static file server that also applies
 * the generated `<dist>/_headers` file's rules (Cloudflare Pages'
 * `_headers` format: an unindented path line, followed by indented
 * `Header-Name: value` lines, repeated per block) to matching responses.
 * Used ONLY by the Playwright runtime-CSP e2e test
 * (`apps/site/test/e2e/map-csp-check.mjs`) — this is what makes that test
 * a genuine "serve the built site with the generated `_headers` CSP"
 * check, not just a build-time text assertion on the file's contents.
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

/** @param {string} text @returns {{path: string, headers: Record<string,string>}[]} */
export function parseHeadersFile(text) {
  const blocks = [];
  let current = null;
  for (const raw of text.split("\n")) {
    const line = raw.replace(/\r$/, "");
    if (!line.trim() || line.trim().startsWith("#")) continue;
    if (!/^\s/.test(line)) {
      current = { path: line.trim(), headers: {} };
      blocks.push(current);
    } else if (current) {
      const idx = line.indexOf(":");
      if (idx === -1) continue;
      current.headers[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();
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

export async function serveDistWithHeaders(distDir, port) {
  const headersPath = join(distDir, "_headers");
  const blocks = existsSync(headersPath) ? parseHeadersFile(await readFile(headersPath, "utf8")) : [];

  const server = createServer(async (req, res) => {
    try {
      const url = new URL(req.url, "http://127.0.0.1");
      let pathname = decodeURIComponent(url.pathname);
      if (pathname.endsWith("/")) pathname += "index.html";
      const full = join(distDir, pathname);
      const s = await stat(full).catch(() => null);
      const target = s?.isDirectory() ? join(full, "index.html") : full;
      const body = await readFile(target);

      // Apply every matching block, in file order — later blocks win on a
      // shared header name, matching how `/*` (site-wide) then a more
      // specific `/pagefind/*` block are intended to layer.
      const applied = {};
      for (const block of blocks) {
        if (matchPath(block.path, url.pathname)) Object.assign(applied, block.headers);
      }
      res.writeHead(200, { "Content-Type": MIME[extname(target)] ?? "application/octet-stream", ...applied });
      res.end(body);
    } catch {
      res.writeHead(404);
      res.end("not found");
    }
  });
  return new Promise((resolve) => server.listen(port, "127.0.0.1", () => resolve(server)));
}
