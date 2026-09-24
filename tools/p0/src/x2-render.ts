/**
 * Headless-Chromium rendering for X2 evidence (decision 0001 Addendum J(a)
 * (i)). `x2-fetch.ts --render` uses this module in place of a direct
 * `fetch()` for each configured URL. It stores the SAME evidence Addendum G
 * already requires (raw bytes — here, `page.content()`'s rendered HTML —
 * final URL, HTTP status, retrieval time UTC, SHA-256, extracted text),
 * with `method: "rendered"`. It keeps the tool's own bot-identifying User-
 * Agent (never a browser UA — a site's WAF block is not something this
 * tool evades by pretending to be a browser) and the same https-only rule
 * (gate N6) `x2-fetch.ts`'s direct-fetch path already enforces. The "host
 * allow-list" Addendum J(a) refers to is simply this: render mode only
 * ever renders a URL that is already present in that trail's own
 * `config/x2-sources.json` entry, exactly like the direct-fetch path — it
 * never navigates anywhere else BY REQUEST; what follows is about a
 * rendered page's own outbound activity once it starts running.
 *
 * Chromium is launched from the pinned revision this environment already
 * has at `PLAYWRIGHT_BROWSERS_PATH=/opt/pw-browsers` (matching
 * `apps/site`'s `@playwright/test@1.56.1` pin, chromium revision 1194) —
 * `DEFAULT_CHROMIUM_EXECUTABLE_PATH` below, never a fresh `playwright
 * install` download. The launcher/browser/context/page surface is all
 * injectable (`opts.launch`) against a minimal *Like interface so tests can
 * supply a fake without actually starting a browser — the same dependency-
 * injection principle `x2-fetch.test.ts` already uses for `global.fetch`.
 *
 * **Gate findings fixed here, in two passes (2026-09-24):**
 *
 * Pass 1 — Chromium-arg allowlist, main-frame navigation control (every
 * hop of a redirect chain, `page.url()` not `response.url()`), off-host
 * SUBRESOURCE blocking (the primary fix against third-party-injected
 * text), explicit launch/content timeouts, a best-effort subresource byte
 * cap. All of that stays in place below, now applied at the BROWSER
 * CONTEXT level (see pass 2's reasoning) rather than the page level.
 *
 * Pass 2 — **browser isolation bypasses a `page`-scoped fix cannot see,
 * confirmed live in real Chromium**, none of which are stopped by a plain
 * HTTP request interception at all:
 *
 * - **A WebSocket to another host** can exchange data with a page's script
 *   without ever going through the HTTP request pipeline `route()`
 *   intercepts — `context.routeWebSocket()` (added in this pass) inspects
 *   every websocket URL and `close()`s it immediately when its host
 *   differs from the page's own, before any message can be exchanged.
 * - **`window.open()` of another host, plus `postMessage` back to the
 *   opener**, creates a SEPARATE `Page` that a page-scoped `route()` /
 *   response listener never sees at all. Two independent defenses: the
 *   route/response listeners now live on the `BrowserContext`, not the
 *   `Page` — a popup opened via `window.open()` from a page in that same
 *   context is (per Playwright's default behavior) itself a page IN THAT
 *   CONTEXT, so its own main-frame navigation to the third-party URL is
 *   ALSO subject to the same off-host block; and `context.on("page", …)`
 *   closes any popup the instant it appears and marks the capture as
 *   failed — a popup opening at all is treated as a capture-level failure,
 *   not something to quietly tolerate having blocked.
 * - **A same-host Service Worker proxying a third-party `fetch()`** runs
 *   in its own execution context that a page's own network interception
 *   does not reliably cover across Playwright/Chromium versions. Fixed at
 *   the root instead of by interception: `browser.newContext({
 *   serviceWorkers: "block" })` disables Service Worker registration for
 *   the whole context, so `navigator.serviceWorker.register(...)` itself
 *   never succeeds.
 * - **All three also leaked the real `HeadlessChrome` User-Agent** —
 *   `page.setExtraHTTPHeaders` only overrides the HTTP header on requests
 *   THAT page's HTTP pipeline sends; it does not change the JS-visible
 *   `navigator.userAgent`, User-Agent Client Hints (`sec-ch-ua*`), or a
 *   WebSocket upgrade's own headers. Fixed by moving the User-Agent to
 *   `browser.newContext({ userAgent: … })`, which Chromium applies
 *   consistently across all of those surfaces for every page/popup in
 *   that context.
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
 * `--ignore-certificate-errors-spki-list=<base64 sha256[,…]>` argument —
 * a SINGLE array element; a caller who joined two flags into one string
 * with a space, or passed a second array element, is refused just the
 * same (gate probe: `["…spki-list=X --no-sandbox"]` as one element is
 * refused because the value after `=` isn't a valid base64/comma list —
 * the space breaks the regex — and `["…spki-list=X", "--no-sandbox"]` as
 * two elements is refused by the length check below). Called from
 * `renderUrl` itself (not only the CLI) so every caller gets the same
 * protection regardless of entry point. */
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
   * client-side (JavaScript or meta-refresh) navigation too, not just the
   * response `page.goto()` itself waited for. */
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
  /** Gate finding 1 (re-gate), defense in depth: modern Chromium sends
   * `Sec-Fetch-Dest: worker`/`sharedworker` on the request that fetches a
   * (shared) Worker's OWN script (Fetch Metadata Request Headers spec) —
   * checked to abort a worker-script load outright, alongside (never
   * instead of) failing the whole capture the moment `page.on("worker")`
   * fires (below), since a worker's OWN network activity is not reliably
   * covered by this context's `route()`/`routeWebSocket()` at all. */
  headers(): Record<string, string>;
}
export interface WebSocketRouteLike {
  url(): string;
  close(options?: { code?: number; reason?: string }): Promise<void> | void;
  /** Gate finding, should-fix (re-gate): a routed WebSocket does NOT
   * connect to the real server by default (Playwright mocks it entirely
   * unless this is called) — a same-host WebSocket that is merely left
   * "unhandled" never receives real server messages at all, breaking any
   * real trail-site functionality that depends on one. Calling this for
   * the same-host case is what makes a same-host WebSocket behave like a
   * normal, unrouted one (messages auto-forward both directions once
   * connected, since neither side ever calls `onMessage`). */
  connectToServer(): unknown;
}
/** Gate finding 1 (re-gate): the minimal Playwright `Worker` surface this
 * module needs — a dedicated Worker's own `url()`, for the error message
 * when one is detected. */
export interface WorkerLike {
  url(): string;
}

/** The minimal Playwright `Page` surface this module needs. Deliberately
 * thin — routing, popup handling and the response listener all now live
 * on the CONTEXT (see module doc, pass 2), not the page. */
export interface PageLike {
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
  /** Gate finding 1 (re-gate): a dedicated Worker created by this page —
   * Playwright's own `Page.on("worker", …)` event. There is NO equivalent
   * `BrowserContext`-level event for workers (checked against the pinned
   * `playwright-core@1.56.1` type definitions — `on(event: 'worker', …)`
   * exists only on `Page`, never on `BrowserContext`), unlike `"page"`
   * (popups), which IS a context-level event — this is why worker
   * detection has to be wired per-page, not once at the context level. */
  on(event: "worker", handler: (worker: WorkerLike) => void): void;
}

/** The minimal Playwright `BrowserContext` surface this module needs. */
export interface ContextLike {
  newPage(): Promise<PageLike>;
  route(
    pattern: string,
    handler: (route: RouteLike, request: RequestLike) => void | Promise<void>,
  ): Promise<void>;
  routeWebSocket(
    matcher: (url: URL) => boolean,
    handler: (ws: WebSocketRouteLike) => void | Promise<void>,
  ): Promise<void>;
  on(event: "page", handler: (page: PageLike) => void): void;
  on(event: "response", handler: (response: ResponseLike) => void): void;
  /** Gate finding 1 (re-re-gate): an init script installed in EVERY frame
   * (main + any iframe) of every page this context ever creates, BEFORE
   * any page script runs. Used to delete/neutralise `window.SharedWorker`
   * and `navigator.serviceWorker.register` at the JS-API level — a
   * SECOND, independent layer against SharedWorker/ServiceWorker (the
   * CDP-level target watch below is the first), since a script that never
   * gets a working `SharedWorker` constructor at all can't create one no
   * matter what CDP does or doesn't see. */
  addInitScript(script: () => void): Promise<void>;
  close(): Promise<void>;
}

/** Gate finding 1 (re-re-gate): the minimal Chrome DevTools Protocol
 * session surface this module needs — a raw `send`/`on`, not a typed
 * wrapper, since this module only ever calls two `Target.*` methods and
 * listens for one event. */
export interface CDPSessionLike {
  on(event: string, handler: (payload: unknown) => void): void;
  send(method: string, params?: Record<string, unknown>): Promise<unknown>;
  detach(): Promise<void>;
}

export interface BrowserLike {
  newContext(opts: {
    userAgent: string;
    serviceWorkers?: "allow" | "block";
  }): Promise<ContextLike>;
  /** Gate finding 1 (re-re-gate): a BROWSER-level (not context/page-level)
   * CDP session — `page.on("worker")` only ever fires for a DEDICATED
   * Worker created by that one page; it does not fire for a SharedWorker
   * (a target shared across same-origin pages, not owned by any one
   * page) or a ServiceWorker, which is exactly the bypass a gate review
   * found live (`/blobshared`, `/netshared` — a SharedWorker's own
   * WebSocket/`fetch()` reached the page's rendered content, and neither
   * page-level worker detection nor `route()` ever saw it). CDP's own
   * `Target.targetCreated` event, watched at the browser level via
   * `Target.setDiscoverTargets`/`Target.setAutoAttach`, sees EVERY
   * target Chromium creates — `shared_worker`, `service_worker` and
   * `worker` alike — regardless of which page (if any) "owns" it. */
  newBrowserCDPSession(): Promise<CDPSessionLike>;
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
 * Renders `url` in headless Chromium — inside a fresh `BrowserContext`
 * configured with the tool's own User-Agent and Service Workers blocked —
 * and returns its final HTTP status, final URL (from `page.url()` —
 * reflects a client-side navigation too) and rendered HTML. Refuses
 * (throws) a non-`https:` URL before ever launching a browser (gate N6),
 * an invalid `extraArgs` shape, a navigation that produced no response at
 * all, a main-frame navigation that goes off-host or downgrades to
 * non-https at ANY hop of a redirect chain, a POPUP opening at all (closed
 * immediately, and still a failure — never silently tolerated), a total
 * response-byte count over `subresourceByteCapBytes`, and — via
 * `context.routeWebSocket` and `serviceWorkers: "block"` — never lets an
 * off-host WebSocket or a Service-Worker-proxied fetch reach the page's
 * own script at all.
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
    // Gate finding 1 (re-re-gate): a BROWSER-level CDP watch for ANY
    // worker-shaped target — `page.on("worker")` only ever fires for a
    // DEDICATED Worker owned by that one page; it never fires for a
    // SharedWorker or ServiceWorker, which a gate review found live
    // (`/blobshared`, `/netshared`) still let a WebSocket/`fetch()`
    // reach the rendered page. `Target.targetCreated`, watched here, sees
    // every target Chromium creates regardless of which page (if any)
    // "owns" it. Set up BEFORE the context/page exist, so nothing can
    // race ahead of this watch.
    let disallowedTarget: string | null = null;
    const cdpSession = await browser.newBrowserCDPSession();
    try {
      cdpSession.on("Target.targetCreated", (payload) => {
        const info = (payload as { targetInfo?: { type?: string; url?: string } } | undefined)
          ?.targetInfo;
        const type = info?.type;
        if (type === "shared_worker" || type === "service_worker" || type === "worker") {
          disallowedTarget = `${type}${info?.url ? ` (${info.url})` : ""}`;
        }
      });
      await cdpSession.send("Target.setDiscoverTargets", { discover: true });
      await cdpSession.send("Target.setAutoAttach", {
        autoAttach: true,
        waitForDebuggerOnStart: false,
        flatten: true,
      });

      // Gate finding, pass 2: a fresh CONTEXT, not just a page — the User-
      // Agent and Service-Worker block apply to every page/popup this
      // context ever creates, and routing/response-listening at this level
      // (below) covers a popup automatically too.
      const context = await browser.newContext({
        userAgent: opts.userAgent,
        serviceWorkers: "block",
      });
      try {
        // Gate finding 1 (re-re-gate), second independent layer: an init
        // script, installed in every frame BEFORE any page script runs,
        // that neutralises `SharedWorker` and `ServiceWorker.register` at
        // the JS-API level itself — a script that never gets a working
        // `SharedWorker` constructor can't create one no matter what CDP
        // does or doesn't see. Written against `globalThis` (never
        // `window`/`navigator` as bare identifiers) so this file compiles
        // under this package's own `lib: ["ES2022"]` (no DOM lib) — the
        // function is serialised and evaluated IN THE BROWSER, where
        // those globals exist regardless of what this file's own compile
        // target believes.
        await context.addInitScript(() => {
          const g = globalThis as unknown as {
            SharedWorker?: unknown;
            navigator?: { serviceWorker?: { register?: (...args: unknown[]) => unknown } };
          };
          try {
            g.SharedWorker = undefined;
          } catch {
            // Best-effort — the CDP watch above and the request-level abort
            // below are independent layers, not relying on this alone.
          }
          try {
            if (g.navigator?.serviceWorker) {
              g.navigator.serviceWorker.register = () =>
                Promise.reject(new Error("ServiceWorker registration disabled for evidence capture"));
            }
          } catch {
            // Same — best-effort, not the only layer.
          }
        });

        const byteCap = opts.subresourceByteCapBytes ?? DEFAULT_RENDER_SUBRESOURCE_BYTE_CAP;
        let totalBytes = 0;
        let capExceeded = false;
        let offHostNavigation: string | null = null;
        let insecureHop: string | null = null;
        let popupOpened: string | null = null;
        let workerOpened: string | null = null;
        let mainPage: PageLike | null = null;

        context.on("response", (response) => {
          const len = response.headers()["content-length"];
          const n = len ? Number.parseInt(len, 10) : 0;
          if (Number.isFinite(n) && n > 0) totalBytes += n;
          if (totalBytes > byteCap) capExceeded = true;
        });

          // Gate finding: off-host WebSockets never reach the page's script
          // at all — closed before any message exchange. Gate finding,
          // should-fix (re-gate, corrected comment at what was line 321): a
          // same-host WebSocket must call `connectToServer()` to actually
          // reach the real server — a ROUTED WebSocket is, by Playwright's
          // own default, NOT connected to anything at all ("you can mock
          // entire WebSocket communication") until this is called; merely
          // leaving it "unhandled" does NOT connect it, it silently mocks it
          // into a dead end, breaking any real site functionality that
          // depends on it. This is the fix — not a no-op.
          await context.routeWebSocket(
            () => true,
            (ws) => {
              let wsHost: string | null = null;
              try {
                wsHost = new URL(ws.url()).hostname;
              } catch {
                wsHost = null;
              }
              if (wsHost !== requestedHost) {
                void ws.close();
                return;
              }
              ws.connectToServer();
            },
          );

          await context.route("**/*", async (route, request) => {
            if (capExceeded || popupOpened || workerOpened) {
              await route.abort();
              return;
            }
            // Gate finding 1 (re-gate), defense in depth: abort a request for
            // a (shared) Worker's OWN script outright, via the Fetch Metadata
            // `Sec-Fetch-Dest` header Chromium sends for it — belt-and-
            // suspenders alongside (never instead of) failing the whole
            // capture the moment `page.on("worker")` fires below, since a
            // worker's OWN subsequent network activity (e.g. a WebSocket it
            // opens) is not reliably covered by this context's own
            // `route()`/`routeWebSocket()` at all — the root-cause fix is
            // "no worker gets to run in the first place," not interception.
            let destHeader: string | undefined;
            try {
              destHeader = request.headers()["sec-fetch-dest"];
            } catch {
              destHeader = undefined;
            }
            if (destHeader === "worker" || destHeader === "sharedworker") {
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
                isMainFrameNav = mainPage !== null && request.frame() === mainPage.mainFrame();
              } catch {
                // Per Playwright's own docs: `frame()` throws when the
                // navigation request is issued before its frame exists — this
                // happens especially for the page's OWN first navigation,
                // which IS the main frame's navigation. A popup's own first
                // navigation can throw the same way, but `mainPage` is only
                // set once OUR page has been created, so treating this as
                // "main frame" before that point is still correct: it can
                // only be our own page's first request.
                isMainFrameNav = mainPage === null;
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
            // Gate finding: third-party injected text (subresources, and a
            // popup's or iframe's OWN navigation, which is not the main
            // frame). Primary fix — abort every off-host request outright.
            if (reqUrl.hostname !== requestedHost) {
              await route.abort();
              return;
            }
            await route.continue();
          });

          const page = await context.newPage();
          mainPage = page;
          // Gate finding: registered AFTER our own page exists — `context.
          // newPage()` itself fires this SAME "page" event internally (for
          // its own about:blank -> navigating transition), racing any
          // identity check against a `mainPage` variable assigned only once
          // `newPage()` resolves back to us. Registering the listener only
          // once we already have our own page sidesteps the race entirely:
          // by construction, every "page" event this listener ever sees from
          // here on is a genuine popup (`window.open()` from in-page script),
          // never our own page's creation.
          context.on("page", (popup) => {
            popupOpened = popup.url();
            popup.close().catch(() => {
              // Already closed/closing — nothing further to do.
            });
          });
          // Gate finding 1 (re-gate): a dedicated Worker is per-PAGE, not
          // per-context (see `PageLike.on`'s own doc for why) — registered on
          // OUR page, immediately after it exists, same timing reasoning as
          // the popup listener above. There is nothing to "close" a Worker
          // with (Playwright's `Worker` object has no `close()`); a Worker's
          // own network activity is not reliably interceptable at all (the
          // very bypass this finding is about), so the only sound fix is
          // failing the WHOLE capture the instant one is created — never
          // trying to let it run and hoping the request-routing catches
          // everything it does.
          page.on("worker", (worker) => {
            workerOpened = worker.url();
          });
          try {
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
            if (popupOpened) {
              throw new Error(
                `render of "${url}" opened a popup ("${popupOpened}") — closed immediately, but a popup opening ` +
                  "at all fails the capture rather than being silently tolerated.",
              );
            }
            if (workerOpened) {
              throw new Error(
                `render of "${url}" created a dedicated Worker ("${workerOpened}") — a Worker's own network ` +
                  "activity (e.g. a WebSocket it opens) is not reliably interceptable by this context's " +
                  "route()/routeWebSocket() at all (gate finding 1, re-gate), so a Worker being created at all " +
                  "fails the capture; a plain page renders fine without one.",
              );
            }
            if (insecureHop) {
              throw new Error(
                `render of "${url}" blocked a main-frame navigation hop that downgraded to non-https: ` +
                  `"${insecureHop}"`,
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

            // Should-fix (re-gate): re-check immediately before reading
            // content — `waitUntil: "networkidle"` resolving is not a hard
            // barrier against a popup/worker created by a script that kept
            // running (a `setTimeout`, a delayed event handler) after
            // `goto()` returned but before `page.content()` actually runs;
            // the checks above only caught one taken right after `goto()`.
            if (popupOpened || workerOpened) {
              throw new Error(
                `render of "${url}" opened a ${popupOpened ? `popup ("${popupOpened}")` : `Worker ("${workerOpened}")`} ` +
                  "just before content() was read — caught by the late re-check, not the earlier one.",
              );
            }

            const html = await withTimeout(
              page.content(),
              opts.contentTimeoutMs ?? DEFAULT_RENDER_CONTENT_TIMEOUT_MS,
              `page.content() for "${url}"`,
            );

            // Should-fix (re-gate): AND right after content() resolves too —
            // content() itself can take time (DEFAULT_RENDER_CONTENT_TIMEOUT_MS
            // worth), long enough for a delayed popup/worker to appear WHILE
            // it was running; a check only before it would miss that window.
            if (popupOpened || workerOpened) {
              throw new Error(
                `render of "${url}" opened a ${popupOpened ? `popup ("${popupOpened}")` : `Worker ("${workerOpened}")`} ` +
                  "while content() was being read — caught by the late re-check.",
              );
            }
            return { status: response.status(), finalUrl, html, argsUsed: extraArgs };
          } finally {
            await page.close();
          }
        } finally {
          await context.close();
        }
      } finally {
        await cdpSession.detach().catch(() => {
          // Already detached, or the browser is already closing — nothing
          // further to do.
        });
      }
    } finally {
      await browser.close();
    }
  }
}

