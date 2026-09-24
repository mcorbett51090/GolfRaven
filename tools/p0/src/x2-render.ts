/**
 * Headless-Chromium rendering for X2 evidence (decision 0001 Addendum J(a)
 * (i), 2026-09-24, written AFTER the first X2 run showed VI's static HTML
 * is a JavaScript single-page app with no body text for a direct fetch to
 * read — see `docs/decisions/0001-owner-decisions-and-p0-thresholds.md`).
 *
 * `x2-fetch.ts --render` uses this module in place of a direct `fetch()`
 * for each configured URL. It stores the SAME evidence Addendum G already
 * requires (raw bytes — here, `page.content()`'s rendered HTML — final URL,
 * HTTP status, retrieval time UTC, SHA-256, extracted text), with `method:
 * "rendered"`. It keeps the tool's own bot-identifying User-Agent
 * (`buildX2UserAgent()`, never a browser UA — a site's WAF block is not
 * something this tool evades by pretending to be a browser) and the same
 * https-only rule (gate N6) `x2-fetch.ts`'s direct-fetch path already
 * enforces. The "host allow-list" Addendum J(a) refers to is simply this:
 * render mode only ever renders a URL that is already present in that
 * trail's own `config/x2-sources.json` entry, exactly like the direct-fetch
 * path — it never navigates anywhere else.
 *
 * Chromium is launched from the pinned revision this environment already
 * has at `PLAYWRIGHT_BROWSERS_PATH=/opt/pw-browsers` (matching
 * `apps/site`'s `@playwright/test@1.56.1` pin, chromium revision 1194) —
 * `DEFAULT_CHROMIUM_EXECUTABLE_PATH` below, never a fresh `playwright
 * install` download. The browser launcher is injectable (`opts.launch`)
 * against a minimal `BrowserLike`/`PageLike` surface so tests can supply a
 * fake without actually starting a browser — the same dependency-injection
 * principle `x2-fetch.test.ts` already uses for `global.fetch`.
 */
import { hostFromUrl } from "./net.js";

export const DEFAULT_CHROMIUM_EXECUTABLE_PATH = "/opt/pw-browsers/chromium";
export const X2_RENDER_DEFAULT_TIMEOUT_MS = 30_000;

export interface RenderedPage {
  status: number;
  finalUrl: string;
  /** The rendered document's HTML, from `page.content()` — this becomes the
   * evidence's raw bytes (UTF-8 encoded), per Addendum J(a)(i). */
  html: string;
}

/** The minimal Playwright surface this module needs — enough to render a
 * page and read its post-JS HTML back out, and nothing else, so a test can
 * supply a small fake instead of a real browser. */
export interface PageLike {
  setExtraHTTPHeaders(headers: Record<string, string>): Promise<void>;
  goto(
    url: string,
    opts: {
      waitUntil?: "load" | "domcontentloaded" | "networkidle";
      timeout?: number;
    },
  ): Promise<ResponseLike | null>;
  content(): Promise<string>;
  close(): Promise<void>;
}
export interface ResponseLike {
  status(): number;
  url(): string;
}
export interface BrowserLike {
  newPage(): Promise<PageLike>;
  close(): Promise<void>;
}
export type ChromiumLauncher = (opts: {
  executablePath: string;
  headless: boolean;
  args?: string[];
}) => Promise<BrowserLike>;

let cachedLauncher: ChromiumLauncher | null = null;

/** Lazily imports `playwright-core`'s `chromium.launch`, so a run that never
 * passes `--render` never needs the dependency resolvable, and so tests can
 * inject a fake launcher (`opts.launch`) instead of ever reaching this. */
async function defaultLauncher(): Promise<ChromiumLauncher> {
  if (cachedLauncher) return cachedLauncher;
  const { chromium } = await import("playwright-core");
  cachedLauncher = (opts) => chromium.launch(opts);
  return cachedLauncher;
}

/**
 * Renders `url` in headless Chromium and returns its final HTTP status,
 * final URL (after any client-side or server-side redirect Playwright
 * followed) and rendered HTML. Refuses (throws) a non-`https:` URL before
 * ever launching a browser (gate N6, same rule the direct-fetch path
 * enforces) and a navigation that produced no response at all (a fully
 * failed load, e.g. DNS failure or a blocked connection — never silently
 * returned as empty evidence).
 */
export async function renderUrl(
  url: string,
  opts: {
    userAgent: string;
    timeoutMs?: number;
    executablePath?: string;
    launch?: ChromiumLauncher;
    /** Extra Chromium command-line arguments, passed straight through to
     * the launcher. This is a generic escape hatch — e.g. for an
     * environment whose outbound network re-terminates TLS behind a proxy
     * with its own CA (this session's own agent proxy, `/root/.ccr/
     * README.md`), where the fix is `--ignore-certificate-errors-spki-list=
     * <that proxy's own known CA SPKI hashes>` — a scoped pin of specific,
     * already-known certificates, never a blanket `--ignore-certificate-
     * errors` that would also swallow a genuine TLS problem with the
     * destination site itself. Nothing proxy-specific is hard-coded here;
     * the CLI reads it from `X2_RENDER_CHROMIUM_ARGS` (see `x2-fetch.ts`). */
    extraArgs?: string[];
  },
): Promise<RenderedPage> {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`not a valid URL: "${url}" (gate N6)`);
  }
  if (parsed.protocol !== "https:") {
    throw new Error(
      `refusing to render non-https URL "${url}" (scheme "${parsed.protocol}") — gate N6`,
    );
  }

  const launch = opts.launch ?? (await defaultLauncher());
  const browser = await launch({
    executablePath: opts.executablePath ?? DEFAULT_CHROMIUM_EXECUTABLE_PATH,
    headless: true,
    ...(opts.extraArgs && opts.extraArgs.length > 0
      ? { args: opts.extraArgs }
      : {}),
  });
  try {
    const page = await browser.newPage();
    try {
      await page.setExtraHTTPHeaders({ "User-Agent": opts.userAgent });
      const response = await page.goto(url, {
        waitUntil: "networkidle",
        timeout: opts.timeoutMs ?? X2_RENDER_DEFAULT_TIMEOUT_MS,
      });
      if (!response) {
        throw new Error(
          `render navigation to "${url}" (host ${hostFromUrl(url)}) produced no response — a fully failed ` +
            "load is never silently recorded as empty evidence",
        );
      }
      const html = await page.content();
      return { status: response.status(), finalUrl: response.url(), html };
    } finally {
      await page.close();
    }
  } finally {
    await browser.close();
  }
}
