/**
 * Headless-Chromium rendering for X2 evidence (decision 0001 Addendum J(a)
 * (i), 2026-09-24, written AFTER the first X2 run showed VI's static HTML
 * carrying its data inside a `data-page="…JSON…"` attribute that the tag-
 * stripping text extractor never reads — see the Addendum J correction,
 * 2026-09-24, in `docs/decisions/0001-owner-decisions-and-p0-thresholds.md`
 * for why the original "no body text" framing was wrong, and this module's
 * own doc below for what a gate review then found wrong with rendering
 * ITSELF).
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
 * path — it never navigates anywhere else BY REQUEST; what follows is about
 * a rendered page's own outbound requests once it starts running.
 *
 * Chromium is launched from the pinned revision this environment already
 * has at `PLAYWRIGHT_BROWSERS_PATH=/opt/pw-browsers` (matching
 * `apps/site`'s `@playwright/test@1.56.1` pin, chromium revision 1194) —
 * `DEFAULT_CHROMIUM_EXECUTABLE_PATH` below, never a fresh `playwright
 * install` download. The browser launcher is injectable (`opts.launch`)
 * against a minimal `BrowserLike`/`PageLike` surface so tests can supply a
 * fake without actually starting a browser — the same dependency-injection
 * principle `x2-fetch.test.ts` already uses for `global.fetch`.
 *
 * **Gate findings fixed here (2026-09-24, after Addendum J's correction):**
 *
 * - **Chromium-arg allowlist.** `extraArgs` used to be an unrestricted
 *   escape hatch — any Chromium flag at all. `validateRenderExtraArgs`
 *   now allows EXACTLY one shape: a single
 *   `--ignore-certificate-errors-spki-list=<base64 sha256[,…]>` argument,
 *   and refuses everything else, including a second arg. The args actually
 *   used are recorded on the returned `RenderedPage` (`argsUsed`) so
 *   `x2-fetch.ts` can stamp them into the manifest entry.
 * - **Main-frame navigation control.** `finalUrl` is read from `page.url()`
 *   AFTER the page has settled, not `response.url()` — `response.url()`
 *   only reflects the response `page.goto()` itself waited for, and misses
 *   a client-side (JavaScript) navigation that happens after `goto()`
 *   resolves (the gate's own `/jsnav` probe: a `<script>` that calls
 *   `location.replace(...)` to an off-host page once loaded). A
 *   `page.route()` handler inspects every main-frame navigation request —
 *   including every hop of a redirect chain, not just the last one — and
 *   `route.abort()`s any that is not `https:` or not on the SAME host the
 *   render was asked to fetch; the capture also fails outright
 *   (`renderUrl` throws) if `page.url()`'s own host still ends up off-host
 *   despite that (defense in depth, not trusting the abort alone).
 * - **Third-party injected text.** The PRIMARY fix (per the gate's own
 *   preference order) is used: every SUBRESOURCE request (script, XHR,
 *   fetch, stylesheet, image, font, …) whose host differs from the page's
 *   own host is aborted outright, the same `page.route()` handler. This
 *   was tested against VI's real pages in Step C and did not break its
 *   rendering (VI's roster/completionUnit/season facts live in the initial
 *   document's own `data-page` attribute, not in any subresource) — see
 *   the Step C report for the live confirmation; the fallback "record
 *   every first-party response body and require rendered quotes to also
 *   appear in it" was NOT needed and is not implemented here.
 * - **Explicit timeouts and a subresource byte cap.** Chromium's LAUNCH
 *   itself now has an explicit timeout (`launchTimeoutMs`, previously left
 *   to Playwright's own default), `page.content()` is now wrapped in its
 *   own explicit timeout (`contentTimeoutMs` — the DOM serialization call
 *   itself has no timeout option in Playwright's API, so this is a manual
 *   `Promise.race`), and a `subresourceByteCapBytes` bounds the total
 *   `content-length` seen across every response during the render (a
 *   BEST-EFFORT cap — unlike `net.ts`'s direct-fetch cap, which is
 *   enforced while literally streaming bytes, this one reads the
 *   `content-length` RESPONSE HEADER as each response arrives, so a server
 *   that omits it, or lies about it, is not caught by this cap; it stops a
 *   page that is honest about its own size from ballooning the render).
 */
import { hostFromUrl } from "./net.js";

export const DEFAULT_CHROMIUM_EXECUTABLE_PATH = "/opt/pw-browsers/chromium";
export const X2_RENDER_DEFAULT_TIMEOUT_MS = 30_000;
export const DEFAULT_RENDER_LAUNCH_TIMEOUT_MS = 30_000;
export const DEFAULT_RENDER_CONTENT_TIMEOUT_MS = 15_000;
export const DEFAULT_RENDER_SUBRESOURCE_BYTE_CAP = 10 * 1024 * 1024; // 10 MB

/** Gate finding: `X2_RENDER_CHROMIUM_ARGS` used to accept ANY Chromium
 * flag. The only shape now allowed is a single SPKI-pin flag — a scoped
 * trust of specific, already-known certificates (this session's own agent
 * proxy CA, see `x2-fetch.ts`'s doc), never a blanket certificate-error
 * bypass and never any other Chromium switch. A base64-encoded SHA-256
 * digest is exactly 44 characters ending in `=` (32 bytes -> 44 base64
 * chars with one padding character). */
const SPKI_ARGS_RE =
  /^--ignore-certificate-errors-spki-list=[A-Za-z0-9+/]{43}=(?:,[A-Za-z0-9+/]{43}=)*$/;

/** Refuses (throws) unless `args` is empty or is EXACTLY one
 * `--ignore-certificate-errors-spki-list=<base64 sha256[,…]>` argument.
 * Called from `renderUrl` itself (not only the CLI) so every caller gets
 * the same protection regardless of entry point. */
export function validateRenderExtraArgs(args: readonly string[]): void {
  if (args.length === 0) return;
  if (args.length > 1) {
    throw new Error(
      `X2_RENDER_CHROMIUM_ARGS must be exactly one --ignore-certificate-errors-spki-list=<…> flag — got ` +
        `${args.length} args ("${args.join(" ")}"). No other Chromium flag, and no second flag, is permitted.`,
    );
  }
  const [arg] = args;
  if (!arg || !SPKI_ARGS_RE.test(arg)) {
    throw new Error(
      `X2_RENDER_CHROMIUM_ARGS must match --ignore-certificate-errors-spki-list=<base64 sha256[,…]> exactly ` +
        `— refusing "${arg}". This is the ONLY Chromium flag this tool will ever pass through.`,
    );
  }
}

export interface RenderedPage {
  status: number;
  /** Read from `page.url()` after the page has settled — reflects a
   * client-side (JavaScript) navigation too, not just the response
   * `page.goto()` itself waited for. */
  finalUrl: string;
  /** The rendered document's HTML, from `page.content()` — this becomes the
   * evidence's raw bytes (UTF-8 encoded), per Addendum J(a)(i). This is
   * the DOM's post-JavaScript serialization, NOT the network response
   * bytes any server actually sent (see the Addendum J correction). */
  html: string;
  /** The Chromium args actually used for this render (validated by
   * `validateRenderExtraArgs`) — echoed back so a caller can stamp them
   * into a manifest entry without having to re-derive them. */
  argsUsed: string[];
}

/** The minimal Playwright surface this module needs — enough to render a
 * page, control its outbound requests, and read its post-JS HTML back out,
 * so a test can supply a small fake instead of a real browser. */
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
  url(): string;
  mainFrame(): unknown;
  route(
    pattern: string,
    handler: (route: RouteLike, request: RequestLike) => void | Promise<void>,
  ): Promise<void>;
  on(event: "response", handler: (response: ResponseLike) => void): void;
}
export interface ResponseLike {
  status(): number;
  url(): string;
  headers(): Record<string, string>;
}
export interface RouteLike {
  abort(): Promise<void>;
  continue(): Promise<void>;
}
export interface RequestLike {
  url(): string;
  isNavigationRequest(): boolean;
  /** Throws for some early navigation requests, per Playwright's own docs
   * — callers must guard this with try/catch (this module does). */
  frame(): unknown;
}
export interface BrowserLike {
  newPage(): Promise<PageLike>;
  close(): Promise<void>;
}
export type ChromiumLauncher = (opts: {
  executablePath: string;
  headless: boolean;
  args?: string[];
  timeout?: number;
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

/** Manual timeout wrapper for a call with no timeout option of its own
 * (`page.content()`) — never left to hang indefinitely. */
async function withTimeout<T>(promise: Promise<T>, ms: number, label: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout>;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms);
  });
  try {
    return await Promise.race([promise, timeout]);
  } finally {
    clearTimeout(timer!);
  }
}

/**
 * Renders `url` in headless Chromium and returns its final HTTP status,
 * final URL (from `page.url()` — reflects a client-side navigation too,
 * not just what `page.goto()` itself waited for) and rendered HTML.
 * Refuses (throws) a non-`https:` URL before ever launching a browser
 * (gate N6, same rule the direct-fetch path enforces), an invalid
 * `extraArgs` shape (`validateRenderExtraArgs`), a navigation that
 * produced no response at all, a main-frame navigation that goes off-host
 * or downgrades to non-https at ANY hop of a redirect chain (blocked live,
 * via `page.route()`, and re-checked against the settled `page.url()`
 * afterwards), and a render whose total response bytes exceed
 * `subresourceByteCapBytes`.
 */
export async function renderUrl(
  url: string,
  opts: {
    userAgent: string;
    timeoutMs?: number;
    launchTimeoutMs?: number;
    contentTimeoutMs?: number;
    subresourceByteCapBytes?: number;
    executablePath?: string;
    launch?: ChromiumLauncher;
    /** Extra Chromium command-line arguments — validated by
     * `validateRenderExtraArgs` before anything else runs. See that
     * function's doc for the one shape this accepts. */
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
  const requestedHost = parsed.hostname;

  const extraArgs = opts.extraArgs ?? [];
  validateRenderExtraArgs(extraArgs);

  const launch = opts.launch ?? (await defaultLauncher());
  const browser = await launch({
    executablePath: opts.executablePath ?? DEFAULT_CHROMIUM_EXECUTABLE_PATH,
    headless: true,
    timeout: opts.launchTimeoutMs ?? DEFAULT_RENDER_LAUNCH_TIMEOUT_MS,
    ...(extraArgs.length > 0 ? { args: extraArgs } : {}),
  });
  try {
    const page = await browser.newPage();
    try {
      await page.setExtraHTTPHeaders({ "User-Agent": opts.userAgent });

      const byteCap = opts.subresourceByteCapBytes ?? DEFAULT_RENDER_SUBRESOURCE_BYTE_CAP;
      let totalBytes = 0;
      let capExceeded = false;
      let offHostNavigation: string | null = null;
      let insecureHop: string | null = null;

      page.on("response", (response) => {
        const len = response.headers()["content-length"];
        const n = len ? Number.parseInt(len, 10) : 0;
        if (Number.isFinite(n) && n > 0) totalBytes += n;
        if (totalBytes > byteCap) capExceeded = true;
      });

      await page.route("**/*", async (route, request) => {
        if (capExceeded) {
          await route.abort();
          return;
        }
        let reqUrl: URL;
        try {
          reqUrl = new URL(request.url());
        } catch {
          await route.abort();
          return;
        }
        let isMainFrameNav = false;
        if (request.isNavigationRequest()) {
          try {
            isMainFrameNav = request.frame() === page.mainFrame();
          } catch {
            // Per Playwright's own docs: `frame()` throws when the
            // navigation request is issued before its frame exists — this
            // happens especially for the page's OWN first navigation,
            // which IS the main frame's navigation.
            isMainFrameNav = true;
          }
        }
        if (isMainFrameNav) {
          if (reqUrl.protocol !== "https:") {
            insecureHop = request.url();
            await route.abort();
            return;
          }
          if (reqUrl.hostname !== requestedHost) {
            offHostNavigation = request.url();
            await route.abort();
            return;
          }
          await route.continue();
          return;
        }
        // Gate finding: third-party injected text. Primary fix — abort
        // every off-host SUBRESOURCE request outright, so nothing a
        // different host serves can end up in this page's rendered text.
        if (reqUrl.hostname !== requestedHost) {
          await route.abort();
          return;
        }
        await route.continue();
      });

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

      const finalUrl = page.url();
      if (insecureHop) {
        throw new Error(
          `render of "${url}" blocked a main-frame navigation hop that downgraded to non-https: "${insecureHop}"`,
        );
      }
      if (offHostNavigation) {
        throw new Error(
          `render of "${url}" blocked a main-frame navigation to an off-host target: "${offHostNavigation}" ` +
            `(requested host "${requestedHost}")`,
        );
      }
      let finalHost: string;
      try {
        finalHost = new URL(finalUrl).hostname;
      } catch {
        throw new Error(`render of "${url}" ended on an unparseable final URL "${finalUrl}"`);
      }
      if (finalHost !== requestedHost) {
        throw new Error(
          `render of "${url}" ended off-host: final URL "${finalUrl}" (host "${finalHost}") is not the ` +
            `requested host "${requestedHost}" — failing the capture rather than storing off-host evidence`,
        );
      }
      if (capExceeded) {
        throw new Error(
          `render of "${url}" exceeded the ${byteCap}-byte subresource cap (best-effort, from response ` +
            "content-length headers) — failing the capture rather than storing a partial/runaway render",
        );
      }

      const html = await withTimeout(
        page.content(),
        opts.contentTimeoutMs ?? DEFAULT_RENDER_CONTENT_TIMEOUT_MS,
        `page.content() for "${url}"`,
      );
      return { status: response.status(), finalUrl, html, argsUsed: extraArgs };
    } finally {
      await page.close();
    }
  } finally {
    await browser.close();
  }
}
