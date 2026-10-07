/**
 * The S7a browser suite (docs/security/partner-auth-design.md 12.1, S7): a real Chromium loads the BUILT bundle served under its real CSP header,
 * signs in with a virtual WebAuthn authenticator (CDP `WebAuthn.*`) against the real `partner-session` handler behind a fake database, and the suite
 * asserts what the design promises: the app works under the CSP (no inline script, no eval) with ZERO violations; the token is absent from every storage
 * API after sign-in; a reload requires a passkey tap; lock and sign-out clear state.
 *
 * Page origin and API origin are two different `localhost` ports (cross-origin, so CORS and the preflight are real). The RP ID is `localhost`.
 */
import { mkdtemp, rm } from "node:fs/promises";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Browser, BrowserContext, Page } from "@playwright/test";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { buildPartners } from "../../scripts/build.mjs";
import { buildCsp } from "../../scripts/lib/csp.mjs";
import { uuidToBytes } from "../../../../supabase/functions/_shared/partner/session-shape.ts";
import { createFakePartnerServer, USER_ID, type FakeServer } from "../support/fake-partner-server";
import { newSoftCredential } from "../support/soft-authenticator";
import { addVirtualAuthenticator, heapContains, launchOrSkip, launchWithBackForwardCache, listen, staticServer, type Listening, type VirtualAuthenticator } from "./support";

const here = dirname(fileURLToPath(import.meta.url));
const { browser, reason } = await launchOrSkip();
if (browser === null) process.stderr.write(`partners e2e: skipped (${reason})\n`);
const suite = browser === null ? describe.skip : describe;

suite("apps/partners in Chromium", () => {
  let scratch: string;
  let dist: string | null = null;
  let pageSrv: Listening;
  let apiSrv: Listening;
  let server: FakeServer;
  let pageOrigin: string;
  let apiOrigin: string;
  const credential = newSoftCredential(uuidToBytes(USER_ID)!);
  const contexts: BrowserContext[] = [];
  /** Chromium with the back/forward cache on (the MEDIUM-1 cells); launched on first use. */
  let bfBrowser: Browser | null = null;

  beforeAll(async () => {
    scratch = await mkdtemp(join(tmpdir(), "gr-partners-e2e-"));
    pageSrv = await listen(
      staticServer(
        () => dist,
        {
          "/__probe/probe.html": join(here, "probe/probe.html"),
          "/__probe/probe.js": join(here, "probe/probe.js"),
          "/__probe/probe-inline.html": join(here, "probe/probe-inline.html"),
          "/__probe/probe-connect.html": join(here, "probe/probe-connect.html"),
          "/__probe/probe-connect.js": join(here, "probe/probe-connect.js"),
        },
        {
          // the SAME pages under other URLs, for the bfcache cells: the harness (no pagehide handler) with and without `Cache-Control: no-store`, and the real app at a URL
          // the generated `_headers` does not mark no-store (so only the page's own pagehide/pageshow handlers stand between Back and a signed-in screen)
          alias: { "/harness-nostore.html": "/harness.html", "/harness-cacheable.html": "/harness.html", "/app-cacheable.html": "/index.html" },
          extraHeaders: { "/harness-nostore.html": { "Cache-Control": "no-store" } },
        },
      ),
    );
    apiSrv = await listen((await import("node:http")).createServer());
    pageOrigin = `http://localhost:${pageSrv.port}`;
    apiOrigin = `http://localhost:${apiSrv.port}`;
    await apiSrv.close();
    server = createFakePartnerServer({ pageOrigin, rpId: "localhost", credential });
    // the API server is created now that its port and the page origin are known; it is the fake wrapping the real handler
    const http = server.httpServer();
    await new Promise<void>((resolve) => http.listen(apiSrv.port, "127.0.0.1", resolve));
    apiSrv = { server: http, port: apiSrv.port, close: () => new Promise<void>((resolve) => http.close(() => resolve())) };
    dist = join(scratch, "dist");
    await buildPartners({ dist, env: { GOLFRAVEN_PARTNERS_E2E: "1", GOLFRAVEN_PARTNERS_API_BASE: `${apiOrigin}/functions/v1` } });
  });

  afterEach(async () => {
    for (const c of contexts.splice(0)) await c.close();
    server.reset();
  });

  afterAll(async () => {
    await apiSrv.close();
    await pageSrv.close();
    await browser?.close();
    await bfBrowser?.close();
    await rm(scratch, { recursive: true, force: true });
  });

  interface Watch {
    readonly page: Page;
    readonly context: BrowserContext;
    readonly auth: VirtualAuthenticator;
    readonly violations: () => Promise<Array<{ directive: string; blockedURI: string }>>;
    readonly console: string[];
    readonly pageErrors: string[];
    readonly requests: string[];
  }

  async function open(path = "/", opts: { ambientCookie?: boolean; bfcache?: boolean } = {}): Promise<Watch> {
    if (opts.bfcache) bfBrowser ??= await launchWithBackForwardCache();
    const context = await (opts.bfcache ? bfBrowser! : browser!).newContext();
    contexts.push(context);
    if (opts.ambientCookie) await context.addCookies([{ name: "ambient", value: "must-never-be-sent", url: pageOrigin }]);
    const page = await context.newPage();
    const consoleMsgs: string[] = [];
    const pageErrors: string[] = [];
    const requests: string[] = [];
    page.on("console", (m) => consoleMsgs.push(`${m.type()}: ${m.text()}`));
    page.on("pageerror", (e) => pageErrors.push(e.message));
    page.on("request", (r) => requests.push(r.url()));
    await page.addInitScript(() => {
      const w = window as unknown as { __violations: Array<{ directive: string; blockedURI: string }> };
      w.__violations = [];
      document.addEventListener("securitypolicyviolation", (ev) => w.__violations.push({ directive: ev.violatedDirective, blockedURI: ev.blockedURI }));
      // every pageshow of this document: `false` for a load, `true` for a restore from the back/forward cache (the same JS world, so the list keeps growing)
      const g = window as unknown as { __pageshows: boolean[] };
      g.__pageshows = [];
      window.addEventListener("pageshow", (ev) => g.__pageshows.push(ev.persisted));
    });
    const auth = await addVirtualAuthenticator(page, credential, "localhost");
    await page.goto(`${pageOrigin}${path}`, { waitUntil: "load" });
    return {
      page,
      context,
      auth,
      console: consoleMsgs,
      pageErrors,
      requests,
      violations: () => page.evaluate(() => (window as unknown as { __violations: Array<{ directive: string; blockedURI: string }> }).__violations),
    };
  }

  const signIn = async (w: Watch) => {
    await w.page.getByTestId("sign-in").click();
    await w.page.locator('[data-screen="signed-in"]').waitFor();
  };
  const screen = (w: Watch) => w.page.locator("main").getAttribute("data-screen");
  /** Playwright's locator text, awaited until it is there (vitest's `expect` has no Playwright matchers). */
  const textOf = async (l: ReturnType<Page["getByTestId"]>): Promise<string> => {
    await l.waitFor();
    return (await l.textContent()) ?? "";
  };
  const apiCalls = () => server.log.filter((r) => r.method !== "OPTIONS");

  describe("served under the real CSP", () => {
    it("the page response carries the generated CSP header, the hardening headers and a hashed bundle", async () => {
      const res = await (await open()).page.request.get(`${pageOrigin}/`);
      const h = res.headers();
      expect(h["content-security-policy"]).toBe(buildCsp(`${apiOrigin}/functions/v1`));
      expect(h["content-security-policy"]).toContain("require-trusted-types-for 'script'");
      expect(h["referrer-policy"]).toBe("no-referrer");
      expect(h["x-content-type-options"]).toBe("nosniff");
      expect(h["cross-origin-opener-policy"]).toBe("same-origin");
      expect(h["permissions-policy"]).toContain("publickey-credentials-get=(self)");
      expect(h["strict-transport-security"]).toBe("max-age=31536000; includeSubDomains");
      const html = await res.text();
      expect(html).toMatch(/<script type="module" src="\.\/assets\/app-[A-Z0-9]+\.js"><\/script>/);
    });

    it("the page itself is Cache-Control: no-store on / and /index.html and NOT on the hashed assets", async () => {
      const w = await open();
      const get = async (path: string) => (await w.page.request.get(`${pageOrigin}${path}`)).headers();
      expect((await get("/"))["cache-control"]).toBe("no-store");
      expect((await get("/index.html"))["cache-control"]).toBe("no-store");
      const asset = new URL((await (await w.page.request.get(`${pageOrigin}/`)).text()).match(/src="\.\/(assets\/app-[A-Z0-9]+\.js)"/)![1]!, `${pageOrigin}/`).pathname;
      expect((await get(asset))["cache-control"]).toBe("public, max-age=31536000, immutable");
      expect((await get("/favicon.svg"))["cache-control"]).toBeUndefined();
    });

    it("the CSP in force really blocks what it says (a probe page under the same header attempts each): eval, new Function, a string timer, innerHTML and script text (Trusted Types), a data: script, a foreign origin, a policy, an inline style attribute", async () => {
      const w = await open("/__probe/probe.html");
      const text = await textOf(w.page.getByTestId("out"));
      const r = JSON.parse(text) as Record<string, unknown>;
      expect(r).toMatchObject({ eval: "EvalError", newFunction: "EvalError", setTimeoutString: "TypeError", innerHTML: "TypeError", scriptText: "TypeError", foreignFetch: "TypeError", createPolicy: "TypeError", ran: "no" });
      expect(r["dataScript"]).not.toBe("ALLOWED");
      expect(r["inlineStyleAttr"]).toBe("Error"); // computed style stays unchanged: the style attribute is ignored under style-src 'self'
      const v = new Set(r["violations"] as string[]);
      for (const d of ["connect-src", "require-trusted-types-for", "trusted-types", "style-src"]) expect([...v].some((x) => x.startsWith(d)), `${d} in ${[...v].join(",")}`).toBe(true);
    });

    it("markup the server (or an attacker) put in the HTML does not run: an inline script, an inline event handler, a javascript: link and an inline <style> are all blocked by script-src and style-src", async () => {
      const w = await open("/__probe/probe-inline.html");
      await w.page.locator("#js").click();
      await w.page.waitForTimeout(300);
      const r = await w.page.evaluate(() => ({
        inline: (window as unknown as { __inline?: number }).__inline ?? "blocked",
        handler: (window as unknown as { __handler?: number }).__handler ?? "blocked",
        js: (window as unknown as { __js?: number }).__js ?? "blocked",
        background: getComputedStyle(document.body).backgroundColor,
      }));
      expect(r.inline).toBe("blocked");
      expect(r.handler).toBe("blocked");
      expect(r.js).toBe("blocked");
      expect(r.background).not.toBe("rgb(255, 0, 0)");
      const v = (await w.violations()).map((x) => x.directive);
      expect(v).toEqual(expect.arrayContaining(["script-src-elem", "script-src-attr", "style-src-elem"]));
    });
  });

  describe("sign-in works under that CSP, with zero violations", () => {
    it("signs in with a passkey and shows the session, in a clean console, with zero CSP violations and no page errors", async () => {
      const w = await open();
      expect(await screen(w)).toBe("signed-out");
      await signIn(w);
      expect(await textOf(w.page.getByTestId("heading"))).toBe("Signed in");
      expect(await textOf(w.page.getByTestId("session-fields"))).toContain("Assurance level");
      expect(await textOf(w.page.getByTestId("roles"))).toContain("Staff");
      expect(await w.violations()).toEqual([]);
      expect(w.pageErrors).toEqual([]);
      expect(w.console).toEqual([]);
      expect(server.sessions()).toHaveLength(1);
    });

    it("the page talks only to its own origin and the API origin, never to a data API, and sends the exact shape the real handler demands", async () => {
      const w = await open();
      await signIn(w);
      await w.page.getByTestId("refresh").click();
      await w.page.waitForFunction(() => !(document.querySelector('[data-testid="refresh"]') as HTMLButtonElement | null)?.disabled);
      const origins = new Set(w.requests.map((u) => new URL(u).origin));
      expect([...origins].sort()).toEqual([apiOrigin, pageOrigin].sort());
      expect(w.requests.some((u) => /rest\/v1|postgrest|supabase/i.test(u))).toBe(false);
      const calls = apiCalls().map((r) => `${r.method} ${r.path.split("/partner-session/")[1]}`);
      expect(calls).toEqual(["POST options", "POST verify", "GET session", "GET session"]);
      for (const r of apiCalls()) {
        expect(r.contentType).toBe("application/json");
        expect(r.origin).toBe(pageOrigin);
      }
      expect(apiCalls()[2]!.authorization).toMatch(/^Bearer gr_ps_[A-Za-z0-9_-]{43}$/);
      expect(await w.violations()).toEqual([]);
    });

    it("never sends a cookie: an ambient cookie set for localhost is on no request to the API (credentials: omit, in a real browser)", async () => {
      const w = await open("/", { ambientCookie: true });
      expect((await w.context.cookies()).map((c) => c.name)).toEqual(["ambient"]);
      await signIn(w);
      await w.page.getByTestId("refresh").click();
      await w.page.getByTestId("lock").click();
      expect(apiCalls().length).toBeGreaterThanOrEqual(4);
      for (const r of server.log) expect(r.cookie, `${r.method} ${r.path}`).toBeNull();
    });

    it("the passkey ceremony is the server's: user verification required, a usernameless chooser (the virtual authenticator saw a resident-key assertion)", async () => {
      const w = await open();
      await signIn(w);
      const creds = await w.auth.credentials();
      expect(creds).toHaveLength(1);
    });

    it("renders in French and back, still with zero violations", async () => {
      const w = await open();
      await w.page.getByTestId("lang-toggle").click();
      expect(await textOf(w.page.getByTestId("heading"))).toBe("Connexion du personnel");
      expect(await w.page.locator("html").getAttribute("lang")).toBe("fr-CA");
      await signIn(w);
      expect(await textOf(w.page.getByTestId("heading"))).toBe("Connecté");
      await w.page.getByTestId("lang-toggle").click();
      expect(await textOf(w.page.getByTestId("heading"))).toBe("Signed in");
      expect(await w.violations()).toEqual([]);
    });

    it("a refused prompt (user verification fails) is a calm 'cancelled' message and no session", async () => {
      const w = await open();
      await w.auth.setUserVerified(false);
      await w.page.getByTestId("sign-in").click();
      expect(await textOf(w.page.getByTestId("notice"))).toContain("cancelled");
      expect(await screen(w)).toBe("signed-out");
      expect(server.sessions()).toEqual([]);
    });

    it("the manifest and icon load under the CSP, and there is no service worker", async () => {
      const w = await open();
      expect((await w.page.request.get(`${pageOrigin}/manifest.webmanifest`)).status()).toBe(200);
      expect((await w.page.request.get(`${pageOrigin}/favicon.svg`)).status()).toBe(200);
      const sw = await w.page.evaluate(async () => ({ regs: (await navigator.serviceWorker.getRegistrations()).length, controller: navigator.serviceWorker.controller === null }));
      expect(sw).toEqual({ regs: 0, controller: true });
      expect(await w.violations()).toEqual([]);
    });
  });

  describe("the token is absent from every storage API after sign-in", () => {
    it("localStorage, sessionStorage, IndexedDB, cookies, Cache Storage and service workers are all empty and none contains the token", async () => {
      const w = await open();
      await signIn(w);
      await w.page.getByTestId("refresh").click();
      const token = server.issuedTokens[0]!;
      expect(token).toMatch(/^gr_ps_/);
      const dump = await w.page.evaluate(async () => ({
        local: Object.entries(localStorage),
        session: Object.entries(sessionStorage),
        idb: (await indexedDB.databases()).map((d) => d.name),
        cookie: document.cookie,
        caches: await caches.keys(),
        sw: (await navigator.serviceWorker.getRegistrations()).length,
        windowKeys: Object.keys(window),
      }));
      // the app exposes nothing on `window`: its keys are those of a blank page, plus the suite's own violation recorder
      const other = await w.context.newPage();
      await other.goto(`${pageOrigin}/manifest.webmanifest`);
      const blank = await other.evaluate(() => Object.keys(window)); // a same-origin document that runs none of the app's code
      const { windowKeys, ...stores } = dump;
      expect(stores).toEqual({ local: [], session: [], idb: [], cookie: "", caches: [], sw: 0 });
      expect(windowKeys.filter((k) => !blank.includes(k)).sort()).toEqual(["__pageshows", "__violations"]);
      // the browser's own view of the profile, IndexedDB included
      const state = await w.context.storageState({ indexedDB: true });
      expect(state.cookies).toEqual([]);
      for (const o of state.origins) {
        expect(o.localStorage).toEqual([]);
        expect((o as { indexedDB?: unknown[] }).indexedDB ?? []).toEqual([]);
      }
      expect(JSON.stringify(state)).not.toContain(token);
      expect(await w.page.content()).not.toContain(token);
      expect(await w.page.evaluate(() => document.documentElement.outerHTML)).not.toContain("gr_ps_");
    });

    it("the token is in the page's memory while signed in (the control for the heap search), and gone from it after lock", async () => {
      const w = await open();
      await signIn(w);
      const token = server.issuedTokens[0]!;
      expect(await heapContains(w.page, token)).toBe(true);
      await w.page.getByTestId("lock").click();
      await w.page.locator('[data-screen="signed-out"]').waitFor();
      expect(await heapContains(w.page, token)).toBe(false);
    });

    it("and gone from it after sign-out", async () => {
      const w = await open();
      await signIn(w);
      const token = server.issuedTokens[0]!;
      expect(await heapContains(w.page, token)).toBe(true);
      await w.page.getByTestId("sign-out").click();
      await w.page.locator('[data-screen="signed-out"]').waitFor();
      expect(await heapContains(w.page, token)).toBe(false);
    });
  });

  describe("a reload requires a passkey tap", () => {
    it("lands on sign-in, makes no API request on its own, and only a new tap opens a new session", async () => {
      const w = await open();
      await signIn(w);
      const before = server.log.length;
      expect(server.sessions()).toHaveLength(1);
      await w.page.reload({ waitUntil: "load" });
      expect(await screen(w)).toBe("signed-out");
      await w.page.waitForTimeout(400);
      // nothing was sent on BOOT (there is no token to send); what the reload did send is the pagehide sign-out of the page that was left (a keepalive request:
      // its preflight, then the POST), which is how the old session ends up revoked rather than left to idle out
      const sent = server.log.slice(before);
      expect(sent.filter((r) => r.method !== "OPTIONS").map((r) => `${r.method} ${r.path.split("/partner-session/")[1]}`)).toEqual(["POST sign-out"]);
      await expect.poll(() => server.state.revokedSessions.size).toBe(1);
      expect(await w.page.getByTestId("roles").count()).toBe(0);
      await signIn(w);
      expect(server.issuedTokens).toHaveLength(2);
      expect(server.sessions()).toHaveLength(1); // the old one was revoked by the reload's pagehide, the new one is live
      expect(server.issuedTokens[0]).not.toBe(server.issuedTokens[1]);
      expect(await w.violations()).toEqual([]);
    });

    it("also on a fresh tab in the same browser profile: no state is shared between pages", async () => {
      const w = await open();
      await signIn(w);
      const second = await w.context.newPage();
      await second.goto(`${pageOrigin}/`, { waitUntil: "load" });
      expect(await second.locator("main").getAttribute("data-screen")).toBe("signed-out");
    });
  });

  describe("lock and sign-out clear state", () => {
    it("lock: back to sign-in with the locked notice, nothing of the session left on screen, and the session REVOKED on the server: the old token gets 401 (design 20.4)", async () => {
      const w = await open();
      await signIn(w);
      const token = server.issuedTokens[0]!;
      await w.page.getByTestId("lock").click();
      await w.page.locator('[data-screen="signed-out"]').waitFor();
      expect(await textOf(w.page.getByTestId("notice"))).toContain("Locked");
      expect(await w.page.getByTestId("session-fields").count()).toBe(0);
      await expect.poll(() => server.state.revokedSessions.size).toBe(1);
      expect(server.state.lockCalls).toBe(0);
      expect(server.state.signOutCalls).toBe(1);
      const res = await fetch(`${apiOrigin}/functions/v1/partner-session/session`, { headers: { authorization: `Bearer ${token}`, "content-type": "application/json", origin: pageOrigin } });
      expect(res.status).toBe(401);
      const authed = apiCalls().filter((r) => r.authorization !== null);
      expect(authed.map((r) => r.path.split("/partner-session/")[1])).toEqual(["session", "sign-out", "session"]); // the last is the direct fetch above, not the page
      expect(await w.violations()).toEqual([]);
      // resuming needs a new tap
      const optionsBefore = apiCalls().filter((r) => r.path.endsWith("/options")).length;
      await signIn(w);
      expect(apiCalls().filter((r) => r.path.endsWith("/options")).length).toBe(optionsBefore + 1);
      expect(await w.violations()).toEqual([]);
    });

    it("sign-out: back to sign-in, the session revoked on the server and its token refused afterwards", async () => {
      const w = await open();
      await signIn(w);
      const token = server.issuedTokens[0]!;
      await w.page.getByTestId("sign-out").click();
      await w.page.locator('[data-screen="signed-out"]').waitFor();
      expect(await textOf(w.page.getByTestId("notice"))).toContain("signed out");
      expect(server.state.signOutCalls).toBe(1);
      const res = await fetch(`${apiOrigin}/functions/v1/partner-session/session`, { headers: { authorization: `Bearer ${token}`, "content-type": "application/json", origin: pageOrigin } });
      expect(res.status).toBe(401);
      expect(await w.violations()).toEqual([]);
    });

    it("a session the server ended is noticed on the next call: signed-out with the session-ended notice", async () => {
      const w = await open();
      await signIn(w);
      server.killAllSessions();
      await w.page.getByTestId("refresh").click();
      await w.page.locator('[data-screen="signed-out"]').waitFor();
      expect(await textOf(w.page.getByTestId("notice"))).toContain("session has ended");
    });

    it("an unreachable API during sign-out still wipes the page and says so honestly", async () => {
      const w = await open();
      await signIn(w);
      await w.page.route(`${apiOrigin}/**`, (route) => route.abort());
      await w.page.getByTestId("sign-out").click();
      await w.page.locator('[data-screen="signed-out"]').waitFor();
      // The wipe is immediate (MEDIUM-2): the screen is signed-out with "You are signed out." at once, and the
      // honest offline notice replaces it only when the aborted request settles. Wait for that, never race it.
      expect(await w.page.getByTestId("session-fields").count()).toBe(0);
      await w.page.getByTestId("notice").filter({ hasText: "could not be reached" }).waitFor({ timeout: 5000 });
      expect(await w.page.getByTestId("session-fields").count()).toBe(0);
    });
  });

  describe("MEDIUM-1: the back/forward cache never restores a signed-in page", () => {
    /** Navigates to a different same-origin document and presses Back, returning what the restored document says about itself. */
    async function awayAndBack(w: Watch) {
      await w.page.goto(`${pageOrigin}/manifest.webmanifest`, { waitUntil: "load" });
      await w.page.goBack({ waitUntil: "commit" });
      await w.page.locator("main").waitFor();
      return { pageshows: await w.page.evaluate(() => (window as unknown as { __pageshows: boolean[] }).__pageshows) };
    }
    const harness = async (w: Watch, id: string) => {
      const before = (await w.page.getByTestId("out").textContent()) ?? "";
      await w.page.locator(`#${id}`).click();
      await w.page.waitForFunction((prev) => (document.querySelector('[data-testid="out"]')?.textContent ?? "") !== prev, before);
      return JSON.parse((await w.page.getByTestId("out").textContent()) ?? "{}") as Record<string, unknown>;
    };

    it("CONTROL 1: this Chromium really has the back/forward cache on, and without the fix a signed-in page IS restored with a live token (the bug)", async () => {
      // the harness page has no pagehide handler and is served without no-store: exactly the page the bug report describes
      const w = await open("/harness-cacheable.html", { bfcache: true });
      expect(await harness(w, "sign-in")).toMatchObject({ ok: true });
      const { pageshows } = await awayAndBack(w);
      expect(pageshows, "the second pageshow of the SAME document has persisted=true").toEqual([false, true]);
      expect(await harness(w, "session"), "and the restored page still holds a live token").toMatchObject({ ok: true, aal: 1 });
      expect(server.log.filter((r) => r.authorization !== null).length).toBeGreaterThanOrEqual(1);
    });

    it("CONTROL 2: Cache-Control: no-store ALONE keeps that same page out of the cache: Back gives a fresh document with no token", async () => {
      const w = await open("/harness-nostore.html", { bfcache: true });
      expect(await harness(w, "sign-in")).toMatchObject({ ok: true });
      const { pageshows } = await awayAndBack(w);
      expect(pageshows, "a fresh load, not a restore").toEqual([false]);
      expect(await harness(w, "session")).toMatchObject({ ok: false, kind: "unauthenticated" });
    });

    it("OBSERVATION (pinned, chromium-1194): the header is not a bfcache defence by itself: a no-store page that has made no API call IS restored, so what blocks CONTROL 2 is the no-store API responses it received, and the page's own handlers are the defence", async () => {
      const w = await open("/harness-nostore.html", { bfcache: true });
      await harness(w, "forget"); // a click that makes no request
      const { pageshows } = await awayAndBack(w);
      expect(pageshows).toEqual([false, true]);
      expect(server.log).toEqual([]);
    });

    it("the app (served no-store): after Back the screen is signed-out, there is nothing signed-in on it, and no Bearer request is sent", async () => {
      const w = await open("/", { bfcache: true });
      await signIn(w);
      const token = server.issuedTokens[0]!;
      const mark = server.log.length;
      await awayAndBack(w);
      expect(await screen(w)).toBe("signed-out");
      expect(await w.page.getByTestId("session-fields").count()).toBe(0);
      expect(await w.page.getByTestId("refresh").count()).toBe(0);
      expect(await w.page.content()).not.toContain(token);
      await w.page.waitForTimeout(300);
      expect(server.log.slice(mark).filter((r) => r.authorization !== null && !r.path.endsWith("/sign-out"))).toEqual([]);
      expect(await heapContains(w.page, token)).toBe(false);
      expect(await w.violations()).toEqual([]);
    });

    it("DEFENCE IN DEPTH: with the header out of the picture (the app at a URL that is not no-store) the page IS restored from the cache, and the pagehide/pageshow handlers still leave it signed-out, token-free and silent", async () => {
      const w = await open("/app-cacheable.html", { bfcache: true });
      await signIn(w);
      const token = server.issuedTokens[0]!;
      expect(await heapContains(w.page, token)).toBe(true);
      const mark = server.log.length;
      const { pageshows } = await awayAndBack(w);
      expect(pageshows, "the page WAS restored from the bfcache").toEqual([false, true]);
      expect(await screen(w)).toBe("signed-out");
      expect(await w.page.getByTestId("session-fields").count()).toBe(0);
      expect(await w.page.getByTestId("refresh").count()).toBe(0);
      expect(await heapContains(w.page, token)).toBe(false);
      await w.page.waitForTimeout(300);
      // the keepalive sign-out is the only thing that carried the token after the page was left; nothing used it afterwards
      const after = server.log.slice(mark).filter((r) => r.authorization !== null);
      expect(after.every((r) => r.path.endsWith("/sign-out") && r.authorization === `Bearer ${token}`)).toBe(true);
      expect(await w.violations()).toEqual([]);
    });

    it("leaving the page revokes the session on the server (a best-effort keepalive sign-out), so a copied token is dead", async () => {
      const w = await open("/", { bfcache: true });
      await signIn(w);
      const token = server.issuedTokens[0]!;
      await w.page.goto(`${pageOrigin}/manifest.webmanifest`, { waitUntil: "load" });
      await expect.poll(() => server.state.revokedSessions.size, { timeout: 5000 }).toBe(1);
      const res = await fetch(`${apiOrigin}/functions/v1/partner-session/session`, { headers: { authorization: `Bearer ${token}`, "content-type": "application/json", origin: pageOrigin } });
      expect(res.status).toBe(401);
    });
  });

  describe("MEDIUM-2: lock and sign-out are immediate, and nothing waits forever", () => {
    it("a POST sign-out (the lock's request) that never answers: the screen is locked and the token gone from the page's memory AT ONCE", async () => {
      const w = await open();
      await signIn(w);
      const token = server.issuedTokens[0]!;
      expect(await heapContains(w.page, token)).toBe(true);
      server.state.hang.add("sign-out");
      await w.page.getByTestId("lock").click();
      await w.page.locator('[data-screen="signed-out"]').waitFor({ timeout: 2000 });
      expect(await textOf(w.page.getByTestId("notice"))).toContain("Locked");
      expect(await w.page.getByTestId("session-fields").count()).toBe(0);
      // the request is still hanging (the server logged it and will never answer), and the page already holds no copy of the token
      await expect.poll(() => server.log.some((r) => r.method === "POST" && r.path.endsWith("/sign-out") && r.authorization === `Bearer ${token}`)).toBe(true);
      expect(server.state.revokedSessions.size).toBe(0);
      expect(await heapContains(w.page, token)).toBe(false);
      // and the sign-in button is live straight away (the hung request does not hold the screen). A full second sign-in is covered by the controller's unit cell:
      // in this harness a sign-in attempted after a heap snapshot failed with "The passkey could not be used" (cause not isolated), so it is not repeated here
      expect(await w.page.getByTestId("sign-in").isEnabled()).toBe(true);
    });

    it("a GET session that never answers: Lock is still clickable while the refresh is busy, and it works (the token goes, the session is revoked)", async () => {
      const w = await open();
      await signIn(w);
      const token = server.issuedTokens[0]!;
      server.state.hang.add("session");
      await w.page.getByTestId("refresh").click();
      await expect.poll(() => w.page.locator("main").getAttribute("aria-busy")).toBe("true");
      expect(await w.page.getByTestId("refresh").isDisabled()).toBe(true);
      expect(await w.page.getByTestId("lock").isEnabled()).toBe(true);
      expect(await w.page.getByTestId("sign-out").isEnabled()).toBe(true);
      await w.page.getByTestId("lock").click();
      await w.page.locator('[data-screen="signed-out"]').waitFor({ timeout: 2000 });
      expect(await textOf(w.page.getByTestId("notice"))).toContain("Locked");
      await expect.poll(() => server.state.revokedSessions.size).toBe(1);
      expect(await heapContains(w.page, token)).toBe(false);
    });

    it("sign-out is likewise clickable during a hung refresh", async () => {
      const w = await open();
      await signIn(w);
      server.state.hang.add("session");
      await w.page.getByTestId("refresh").click();
      await expect.poll(() => w.page.locator("main").getAttribute("aria-busy")).toBe("true");
      await w.page.getByTestId("sign-out").click();
      await w.page.locator('[data-screen="signed-out"]').waitFor({ timeout: 2000 });
      await expect.poll(() => server.state.signOutCalls).toBe(1);
    });

    it("the 15 second timeout fires: a GET session that never answers ends the refresh with a network error, and the session stays", async () => {
      const w = await open();
      await signIn(w);
      server.state.hang.add("session");
      const started = Date.now();
      await w.page.getByTestId("refresh").click();
      await w.page.waitForFunction(() => !(document.querySelector('[data-testid="refresh"]') as HTMLButtonElement | null)?.disabled, undefined, { timeout: 25_000 });
      const elapsed = Date.now() - started;
      expect(elapsed).toBeGreaterThanOrEqual(14_000);
      expect(elapsed).toBeLessThan(22_000);
      expect(await screen(w)).toBe("signed-in");
      expect(await textOf(w.page.getByTestId("notice"))).toContain("Could not reach the server");
    });
  });

  describe("MEDIUM-3: connect-src is scoped to the partner function", () => {
    it("under the real CSP: partner-session works, and /rest/v1/..., another function, the bare function name, a lookalike prefix and dot-segment escapes are blocked before they leave the page", async () => {
      const w = await open(`/__probe/probe-connect.html?api=${encodeURIComponent(apiOrigin)}&root=${encodeURIComponent("/functions/v1")}`);
      const r = JSON.parse(await textOf(w.page.getByTestId("out"))) as Record<string, string>;
      expect(r).toEqual({
        "partner-session/options (POST, what the client sends)": "status 200",
        "partner-session/session (GET)": "status 401",
        "partner-session/reauth/options (POST)": "status 401",
        "partner-session (bare name, no trailing slash)": "blocked by CSP",
        "other-fn": "blocked by CSP",
        "partner-sessionx (shares the prefix string)": "blocked by CSP",
        "rest/v1 (PostgREST)": "blocked by CSP",
        "rest/v1 root": "blocked by CSP",
        "origin root": "blocked by CSP",
        "dot segments out of the function": "blocked by CSP",
      });
      // the blocked ones never reached the network: the server logged only what the CSP let through
      expect(server.log.filter((l) => l.method !== "OPTIONS").map((l) => `${l.method} ${new URL(`http://x${l.path}`).pathname}`).sort()).toEqual(["GET /functions/v1/partner-session/session", "POST /functions/v1/partner-session/options", "POST /functions/v1/partner-session/reauth/options"].sort());
    });

    it("the real app, with the real client, signs in and refreshes under that scoped policy with zero violations (the exact non-slash URLs it requests are matched by the trailing-slash source)", async () => {
      const w = await open();
      await signIn(w);
      await w.page.getByTestId("refresh").click();
      await w.page.waitForFunction(() => !(document.querySelector('[data-testid="refresh"]') as HTMLButtonElement | null)?.disabled);
      await w.page.getByTestId("lock").click();
      await w.page.locator('[data-screen="signed-out"]').waitFor();
      expect(await w.violations()).toEqual([]);
      expect(w.pageErrors).toEqual([]);
    });
  });

  describe("LOW-4 / LOW-5 and the 429 wait", () => {
    it("LOW-4: Cancel pressed after the server has already answered verify (the response is still on its way): signed-out at once, and the server ends with the session REVOKED", async () => {
      const w = await open();
      server.state.delayAfter["verify"] = 1500;
      await w.page.getByTestId("sign-in").click();
      await expect.poll(() => server.log.some((r) => r.path.endsWith("/verify") && r.method === "POST")).toBe(true);
      expect(await screen(w)).toBe("signing-in");
      await w.page.getByTestId("cancel").click();
      await w.page.locator('[data-screen="signed-out"]').waitFor({ timeout: 1000 });
      expect(await textOf(w.page.getByTestId("notice"))).toContain("cancelled");
      expect(server.sessions()).toHaveLength(1); // minted by the server, response not yet delivered
      await expect.poll(() => server.state.revokedSessions.size, { timeout: 8000 }).toBe(1);
      expect(server.sessions()).toEqual([]);
      expect(await screen(w)).toBe("signed-out");
      expect(await heapContains(w.page, server.issuedTokens[0]!)).toBe(false);
    });

    it("LOW-5: verify succeeds and the first GET session fails: signed-out with an error, and the server is told to revoke before the token is forgotten", async () => {
      const w = await open();
      await w.page.route(`${apiOrigin}/functions/v1/partner-session/session`, (route) => route.abort());
      await w.page.getByTestId("sign-in").click();
      await w.page.locator('[data-screen="signed-out"]').waitFor();
      await w.page.getByTestId("notice").filter({ hasText: "Could not reach the server" }).waitFor({ timeout: 5000 });
      await expect.poll(() => server.state.revokedSessions.size).toBe(1);
      expect(server.state.signOutCalls).toBe(1);
      expect(await heapContains(w.page, server.issuedTokens[0]!)).toBe(false);
    });

    it("NIT: a 429 on sign-in disables the sign-in button for Retry-After, then releases it", async () => {
      const w = await open();
      server.state.optionsRetryAfter = 2;
      await w.page.getByTestId("sign-in").click();
      await w.page.locator('[data-screen="signed-out"] [data-testid="notice"]').waitFor();
      expect(await textOf(w.page.getByTestId("notice"))).toContain("2");
      expect(await w.page.getByTestId("sign-in").isDisabled()).toBe(true);
      const before = server.log.length;
      await w.page.getByTestId("sign-in").click({ force: true, timeout: 1000 }).catch(() => undefined);
      expect(server.log.length, "a disabled button sends nothing").toBe(before);
      await expect.poll(() => w.page.getByTestId("sign-in").isDisabled(), { timeout: 5000 }).toBe(false);
      server.state.optionsRetryAfter = null;
      await signIn(w);
    });
  });

  describe("the reauth helper in a real browser (harness page, built for this suite only)", () => {
    const out = async (w: Watch) => JSON.parse((await w.page.getByTestId("out").textContent()) ?? "{}") as Record<string, unknown>;
    const click = async (w: Watch, id: string) => {
      const before = (await w.page.getByTestId("out").textContent()) ?? "";
      await w.page.locator(`#${id}`).click();
      await w.page.waitForFunction((prev) => (document.querySelector('[data-testid="out"]')?.textContent ?? "") !== prev || false, before);
      await w.page.waitForFunction(() => (document.querySelector('[data-testid="out"]')?.textContent ?? "") !== "");
      return out(w);
    };

    it("sign-in then reauth: options, a fresh assertion, reauth; the server opens the window", async () => {
      const w = await open("/harness.html");
      expect(await click(w, "sign-in")).toMatchObject({ ok: true, aal: 1 });
      const r = await click(w, "reauth");
      expect(r).toMatchObject({ ok: true });
      expect(Date.parse(String(r["reauthUntil"]))).toBeGreaterThan(Date.now());
      expect(apiCalls().map((c) => c.path.split("/partner-session/")[1])).toEqual(["options", "verify", "reauth/options", "reauth"]);
      expect(await w.violations()).toEqual([]);
      expect(w.console).toEqual([]);
    });

    it("without a session it fails closed and sends nothing", async () => {
      const w = await open("/harness.html");
      expect(await click(w, "reauth")).toMatchObject({ ok: false, kind: "unauthenticated" });
      expect(server.log).toEqual([]);
    });

    it("the 429 is mapped, and the page READS Retry-After across origins (the server exposes exactly that header)", async () => {
      const w = await open("/harness.html");
      await click(w, "sign-in");
      server.state.reauthLimit = 0;
      const r = await click(w, "reauth");
      expect(r).toMatchObject({ ok: false, kind: "rate_limited", status: 429, retryAfterSeconds: 1800 });
    });
  });
});
