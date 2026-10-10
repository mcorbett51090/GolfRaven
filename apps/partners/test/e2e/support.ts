/**
 * Plumbing for the Playwright suite: a static file server that applies the build's generated `_headers` (so the page is really served under its CSP),
 * the Chromium launch with the repo's skip policy, the virtual-authenticator setup over CDP, and a V8 heap search used to prove the token left memory.
 */
import { readFile, stat } from "node:fs/promises";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { extname, join } from "node:path";
import { chromium, type Browser, type CDPSession, type Page } from "@playwright/test";
import type { SoftCredential } from "../support/soft-authenticator";

const MIME: Record<string, string> = { ".html": "text/html", ".css": "text/css", ".js": "text/javascript", ".json": "application/json", ".svg": "image/svg+xml", ".webmanifest": "application/manifest+json" };

interface Block {
  readonly path: string;
  readonly headers: Array<[string, string]>;
}

/** Cloudflare Pages `_headers` semantics for the subset this build emits: every block whose pattern matches applies, in file order; a repeated name is joined with ", ". */
export function parseHeaders(text: string): Block[] {
  const blocks: Block[] = [];
  for (const raw of text.split("\n")) {
    if (raw.trim() === "" || raw.trim().startsWith("#")) continue;
    if (!/^\s/.test(raw)) blocks.push({ path: raw.trim(), headers: [] });
    else {
      const t = raw.trim();
      const i = t.indexOf(":");
      if (i > 0) blocks[blocks.length - 1]!.headers.push([t.slice(0, i).trim(), t.slice(i + 1).trim()]);
    }
  }
  return blocks;
}

export function headersFor(blocks: Block[], pathname: string): Record<string, string> {
  const out = new Map<string, [string, string]>();
  for (const b of blocks) {
    const hit = b.path === "/*" || (b.path.endsWith("/*") ? pathname.startsWith(b.path.slice(0, -1)) : pathname === b.path);
    if (!hit) continue;
    for (const [name, value] of b.headers) {
      const k = name.toLowerCase();
      const prev = out.get(k);
      out.set(k, [name, prev ? `${prev[1]}, ${value}` : value]);
    }
  }
  return Object.fromEntries([...out.values()]);
}

export interface Listening {
  readonly server: Server;
  readonly port: number;
  close(): Promise<void>;
}

export async function listen(server: Server): Promise<Listening> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return {
    server,
    port: (server.address() as AddressInfo).port,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

export interface StaticOptions {
  /** pathname -> a file of `dist` served in its place (e.g. a second URL for the same page), under the headers that match the ALIAS pathname */
  readonly alias?: Record<string, string>;
  /** pathname -> headers added on top (a header listed here replaces the generated one of the same name) */
  readonly extraHeaders?: Record<string, Record<string, string>>;
}

/** A static server for `dist()`, resolved on every request (the port must be known before the bundle is built, because the API origin is baked into it). */
export function staticServer(dist: () => string | null, extra: Record<string, string> = {}, opts: StaticOptions = {}): Server {
  return createServer((req, res) => {
    void (async () => {
      try {
        const root = dist();
        if (root === null) throw new Error("not built");
        const url = new URL(req.url ?? "/", "http://localhost");
        const probe = extra[url.pathname];
        if (probe !== undefined) {
          // test-only files (the CSP probe page) are served under the SAME generated headers as the bundle
          const blocks = parseHeaders(await readFile(join(root, "_headers"), "utf8"));
          res.writeHead(200, { "Content-Type": MIME[extname(probe)] ?? "application/octet-stream", ...headersFor(blocks, url.pathname) });
          res.end(await readFile(probe));
          return;
        }
        let pathname = decodeURIComponent(url.pathname);
        pathname = opts.alias?.[pathname] ?? pathname;
        if (pathname.endsWith("/")) pathname += "index.html";
        if (pathname.includes("..")) throw new Error("bad path");
        const file = join(root, pathname);
        if (!(await stat(file)).isFile()) throw new Error("not a file");
        const body = await readFile(file);
        const blocks = parseHeaders(await readFile(join(root, "_headers"), "utf8"));
        const generated = headersFor(blocks, url.pathname);
        const over = opts.extraHeaders?.[url.pathname] ?? {};
        const merged = Object.fromEntries([...Object.entries(generated).filter(([k]) => !Object.keys(over).some((o) => o.toLowerCase() === k.toLowerCase())), ...Object.entries(over)]);
        res.writeHead(200, { "Content-Type": MIME[extname(file)] ?? "application/octet-stream", ...merged });
        res.end(body);
      } catch {
        res.writeHead(404);
        res.end("not found");
      }
    })();
  });
}

/**
 * Chromium with the back/forward cache ENABLED. Two things stand between Playwright's default launch and a bfcache restore, and both hide exactly the bug the
 * MEDIUM-1 cells are about:
 *   - Playwright passes `--disable-back-forward-cache` (so `goBack()` is predictable): `ignoreDefaultArgs` removes that one switch;
 *   - `headless: true` runs the chromium-headless-shell build, which reports `BackForwardCacheDisabledForDelegate` (observed, Playwright 1.56.1 / chromium-1194):
 *     `channel: "chromium"` runs the full Chromium in its new headless mode, where the cache works.
 */
export async function launchWithBackForwardCache(): Promise<Browser> {
  return await chromium.launch({ ...browserChoice({ channel: "chromium" }), args: ["--no-sandbox"], ignoreDefaultArgs: ["--disable-back-forward-cache"] });
}

/**
 * Which browser to launch: Playwright's pinned Chromium (PLAYWRIGHT_BROWSERS_PATH) by default, or the executable named by `GOLFRAVEN_E2E_CHROME` (a machine that has a
 * Chrome but not the pinned build; the suite then runs against that browser, which is the only difference). CI never sets it.
 */
function browserChoice(pinned: { channel?: "chromium"; headless?: boolean }): { channel?: "chromium"; headless?: boolean; executablePath?: string } {
  const exe = process.env["GOLFRAVEN_E2E_CHROME"];
  return exe === undefined || exe === "" ? pinned : { headless: true, executablePath: exe };
}

/** Launches Chromium, or explains why it could not. Under CI a launch failure is a failure; elsewhere it is a skip (the repo's rule, apps/site/scripts/run-e2e.mjs). */
export async function launchOrSkip(): Promise<{ browser: Browser | null; reason: string | null }> {
  if (process.env["GOLFRAVEN_E2E_SKIP"] === "1") return { browser: null, reason: "GOLFRAVEN_E2E_SKIP=1" };
  const inCi = process.env["CI"] === "true" || process.env["CI"] === "1";
  try {
    return { browser: await chromium.launch({ ...browserChoice({ headless: true }), args: ["--no-sandbox"] }), reason: null };
  } catch (e) {
    const reason = e instanceof Error ? (e.message.split("\n")[0] ?? "launch failed") : String(e);
    if (inCi) throw new Error(`Chromium could not be launched under CI (${reason}); CI installs the pinned browser, so this is a failure. Set GOLFRAVEN_E2E_SKIP=1 to opt out deliberately.`);
    return { browser: null, reason };
  }
}

export interface VirtualAuthenticator {
  readonly cdp: CDPSession;
  readonly authenticatorId: string;
  credentials(): Promise<Array<{ signCount: number }>>;
  setUserVerified(v: boolean): Promise<void>;
}

/** A CTAP2 platform authenticator with resident keys and user verification, preloaded with the test credential (the same key the fake server trusts). */
export async function addVirtualAuthenticator(page: Page, credential: SoftCredential, rpId: string): Promise<VirtualAuthenticator> {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: { protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
  });
  await cdp.send("WebAuthn.addCredential", {
    authenticatorId,
    credential: {
      credentialId: Buffer.from(credential.credentialId).toString("base64"),
      isResidentCredential: true,
      rpId,
      privateKey: credential.privateKeyPkcs8Base64,
      userHandle: Buffer.from(credential.userHandle).toString("base64"),
      signCount: 0,
    },
  });
  return {
    cdp,
    authenticatorId,
    credentials: async () => (await cdp.send("WebAuthn.getCredentials", { authenticatorId })).credentials,
    setUserVerified: async (isUserVerified: boolean) => {
      await cdp.send("WebAuthn.setUserVerified", { authenticatorId, isUserVerified });
    },
  };
}

/** Forces a GC, takes a V8 heap snapshot of the page and reports whether `needle` occurs in it as a string. A positive control (the token while signed in) shows the method can see it. */
export async function heapContains(page: Page, needle: string): Promise<boolean> {
  const cdp = await page.context().newCDPSession(page);
  const chunks: string[] = [];
  cdp.on("HeapProfiler.addHeapSnapshotChunk", (ev: { chunk: string }) => {
    chunks.push(ev.chunk);
  });
  await cdp.send("HeapProfiler.enable");
  await cdp.send("HeapProfiler.collectGarbage");
  await cdp.send("HeapProfiler.collectGarbage");
  await cdp.send("HeapProfiler.takeHeapSnapshot", { reportProgress: false });
  await cdp.detach();
  return chunks.join("").includes(needle);
}
