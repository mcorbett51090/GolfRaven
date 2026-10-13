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
          // bfcache cells: harness with/without no-store, and the real app at a URL that omits Cache-Control so only pagehide/pageshow stand between Back and a signed-in screen
          // (`/*` is no-store in generated `_headers`; null here detaches it for the cacheable control aliases)
          alias: { "/harness-nostore.html": "/harness.html", "/harness-cacheable.html": "/harness.html", "/app-cacheable.html": "/index.html", "/invite": "/index.html" },
          extraHeaders: {
            "/harness-cacheable.html": { "Cache-Control": null },
            "/app-cacheable.html": { "Cache-Control": null },
          },
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

  async function open(path = "/", opts: { ambientCookie?: boolean; bfcache?: boolean; fakeClock?: boolean } = {}): Promise<Watch> {
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
    // Playwright's clock is installed BEFORE the page loads (its own advice), so every Date and timer the app uses is the fake one from the first line; it is paused by the cell
    if (opts.fakeClock) await page.clock.install();
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
    const noticesBefore = server.log.filter((r) => r.method === "GET" && r.path.endsWith("/credentials/notices")).length;
    await w.page.getByTestId("sign-in").click();
    await w.page.locator('[data-screen="signed-in"]').waitFor();
    // §93: maybeOpen GETs credentials/notices after the signed-in screen is shown. Lifecycle cells (reload /
    // bfcache) mark the log next — wait so an in-flight notices GET is not misread as a post-leave Bearer call.
    await expect
      .poll(() => server.log.filter((r) => r.method === "GET" && r.path.endsWith("/credentials/notices")).length)
      .toBe(noticesBefore + 1);
  };
  const screen = (w: Watch) => w.page.locator("main").getAttribute("data-screen");
  /** Playwright's locator text, awaited until it is there (vitest's `expect` has no Playwright matchers). */
  const textOf = async (l: ReturnType<Page["getByTestId"]>): Promise<string> => {
    await l.waitFor();
    return (await l.textContent()) ?? "";
  };
  const apiCalls = () => server.log.filter((r) => r.method !== "OPTIONS");
  /** Tail after the Edge function name (partner-session / partner-members / …). */
  const routeTail = (path: string): string => {
    const m = path.match(/\/functions\/v1\/([^/]+)\/(.*)$/);
    return m ? `${m[1] === "partner-session" ? "" : `${m[1]}/`}${m[2]}` : path;
  };

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

    it("/* is Cache-Control: no-store (including SPA paths); hashed assets detach and stay immutable", async () => {
      const w = await open();
      const get = async (path: string) => (await w.page.request.get(`${pageOrigin}${path}`)).headers();
      expect((await get("/"))["cache-control"]).toBe("no-store");
      expect((await get("/index.html"))["cache-control"]).toBe("no-store");
      expect((await get("/invite"))["cache-control"]).toBe("no-store");
      const asset = new URL((await (await w.page.request.get(`${pageOrigin}/`)).text()).match(/src="\.\/(assets\/app-[A-Z0-9]+\.js)"/)![1]!, `${pageOrigin}/`).pathname;
      expect((await get(asset))["cache-control"]).toBe("public, max-age=31536000, immutable");
      expect((await get("/favicon.svg"))["cache-control"]).toBe("no-store");
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
      const calls = apiCalls().map((r) => `${r.method} ${routeTail(r.path)}`);
      // §93: after session, GET credentials/notices (A0) before home; refresh is a second GET session.
      expect(calls).toEqual([
        "POST options",
        "POST verify",
        "GET session",
        "GET partner-members/credentials/notices",
        "GET session",
      ]);
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
      expect(sent.filter((r) => r.method !== "OPTIONS").map((r) => `${r.method} ${routeTail(r.path)}`)).toEqual(["POST sign-out"]);
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
    it("lock: back to sign-in with the locked notice, nothing of the session left on screen, and the session REVOKED on the server: the old token gets 401 (design 20.4 / §73)", async () => {
      const w = await open();
      await signIn(w);
      const token = server.issuedTokens[0]!;
      await w.page.getByTestId("lock").click();
      await w.page.locator('[data-screen="signed-out"]').waitFor();
      expect(await textOf(w.page.getByTestId("notice"))).toContain("Locked");
      expect(await w.page.getByTestId("session-fields").count()).toBe(0);
      await expect.poll(() => server.state.revokedSessions.size).toBe(1);
      expect(server.state.lockCalls).toBe(1);
      expect(server.state.signOutCalls).toBe(0);
      const res = await fetch(`${apiOrigin}/functions/v1/partner-session/session`, { headers: { authorization: `Bearer ${token}`, "content-type": "application/json", origin: pageOrigin } });
      expect(res.status).toBe(401);
      const authedSession = apiCalls().filter((r) => r.authorization !== null && r.path.includes("/partner-session/"));
      // page: GET session (+ notices on partner-members, omitted here), POST lock; last GET session is the direct fetch above
      expect(authedSession.map((r) => r.path.split("/partner-session/")[1])).toEqual(["session", "lock", "session"]);
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
      // The page ends the session FIRST and tells the server after (client.ts: "ending a session is immediate"), so the signed-out screen can be up before the
      // sign-out has reached the server. Wait for the revoke to be recorded before asserting on the count and on the token (the lock test does the same).
      await expect.poll(() => server.state.revokedSessions.size).toBe(1);
      expect(server.state.signOutCalls).toBe(1);
      const res = await fetch(`${apiOrigin}/functions/v1/partner-session/session`, { headers: { authorization: `Bearer ${token}`, "content-type": "application/json", origin: pageOrigin } });
      expect(res.status).toBe(401);
      expect(await w.violations()).toEqual([]);
    });

    it("a session the server ended is noticed on the next call: signed-out with the session-ended notice", async () => {
      const w = await open();
      await signIn(w);
      server.killAllSessions();
      // Click may race a render that already noticed the kill; land on signed-out either way.
      await Promise.race([
        w.page.getByTestId("refresh").click({ timeout: 10_000 }),
        w.page.locator('[data-screen="signed-out"]').waitFor({ timeout: 10_000 }),
      ]).catch(() => undefined);
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
    it("a POST lock that never answers: the screen is locked and the token gone from the page's memory AT ONCE", async () => {
      const w = await open();
      await signIn(w);
      const token = server.issuedTokens[0]!;
      expect(await heapContains(w.page, token)).toBe(true);
      server.state.hang.add("lock");
      await w.page.getByTestId("lock").click();
      await w.page.locator('[data-screen="signed-out"]').waitFor({ timeout: 2000 });
      expect(await textOf(w.page.getByTestId("notice"))).toContain("Locked");
      expect(await w.page.getByTestId("session-fields").count()).toBe(0);
      // the request is still hanging (the server logged it and will never answer), and the page already holds no copy of the token
      await expect.poll(() => server.log.some((r) => r.method === "POST" && r.path.endsWith("/lock") && r.authorization === `Bearer ${token}`)).toBe(true);
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

  describe("S7a: invite acceptance and the PIN, in a real browser under the real CSP", () => {
    const EMAIL = "new.hire@partners.example.test";
    const PIN = "7391";
    const fill = async (w: Watch, id: string, value: string) => w.page.locator(`#${id}`).fill(value);
    const wire = () => server.log.filter((r) => r.method !== "OPTIONS");

    it("an invite link opens the enrolment screen and its fragment is removed from the address bar; nothing is sent until the person asks for a code", async () => {
      const { token } = server.addInvite({ email: EMAIL });
      const w = await open(`/invite#${token}`);
      expect(await screen(w)).toBe("enrol");
      expect(w.page.url()).toBe(`${pageOrigin}/invite`);
      expect(await w.page.evaluate(() => location.hash)).toBe("");
      expect(server.log).toEqual([]);
      expect(await w.page.content()).not.toContain(token);
      expect(await w.violations()).toEqual([]);
    });

    it("link -> emailed code -> a real passkey created by the browser -> the forced PIN -> home; zero violations, a clean console, no PIN digits on the wire, nothing in storage", async () => {
      const { token } = server.addInvite({ email: EMAIL });
      const w = await open(`/invite#${token}`);
      await w.page.getByTestId("enrol-send-code").click();
      await w.page.locator('#enrol-code').waitFor();
      expect(server.state.mailed).toEqual([EMAIL]);
      await fill(w, "enrol-code", server.state.otpCode);
      await w.page.locator("#enrol-code").press("Enter"); // the form submits on Enter
      await w.page.getByTestId("enrol-create-passkey").waitFor();
      expect(await w.auth.credentials()).toHaveLength(1); // only the preloaded one: nothing is created until the button
      await w.page.getByTestId("enrol-create-passkey").click();
      await w.page.locator('[data-screen="pin-setup"]').waitFor();
      expect(await w.auth.credentials()).toHaveLength(2); // the browser's authenticator made the new resident credential
      expect(server.credentialsOf(server.userByEmail(EMAIL)!.id)).toHaveLength(1);
      expect(server.sessions()).toHaveLength(1);

      // the forced first PIN: no way to leave, a refused PIN is explained and sends nothing, a good one is saved
      expect(await w.page.getByTestId("panel-cancel").count()).toBe(0);
      await fill(w, "pin-new", "1234");
      await fill(w, "pin-confirm", "1234");
      await w.page.getByTestId("pin-save").click();
      expect(await textOf(w.page.getByTestId("notice"))).toContain("run of digits");
      expect(wire().filter((r) => r.path.endsWith("/pin/set"))).toHaveLength(0);
      await fill(w, "pin-new", PIN);
      await fill(w, "pin-confirm", PIN);
      await w.page.getByTestId("pin-save").click();
      await w.page.locator('[data-screen="signed-in"]').waitFor();
      expect(await textOf(w.page.getByTestId("notice"))).toContain("PIN is set");
      expect(server.pinRecord(server.userByEmail(EMAIL)!.id)).not.toBeNull();

      const set = wire().find((r) => r.path.endsWith("/pin/set"))!;
      expect(Object.keys(JSON.parse(set.body) as object).sort()).toEqual(["derived", "iterations", "salt"]);
      for (const r of server.log) {
        expect(r.body, `${r.method} ${r.path}`).not.toContain(`"${PIN}"`);
        expect(r.path).not.toContain(PIN);
      }
      expect(w.requests.filter((u) => u.includes(PIN))).toEqual([]);
      expect(w.requests.some((u) => /rest\/v1|postgrest|supabase/i.test(u))).toBe(false);
      expect([...new Set(w.requests.map((u) => new URL(u).origin))].sort()).toEqual([apiOrigin, pageOrigin].sort());
      expect(await w.violations()).toEqual([]);
      expect(w.pageErrors).toEqual([]);
      expect(w.console).toEqual([]);

      const stores = await w.page.evaluate(async () => ({ local: Object.entries(localStorage), session: Object.entries(sessionStorage), idb: (await indexedDB.databases()).map((d) => d.name), cookie: document.cookie, caches: await caches.keys() }));
      expect(stores).toEqual({ local: [], session: [], idb: [], cookie: "", caches: [] });
      const state = JSON.stringify(await w.context.storageState({ indexedDB: true }));
      expect(state).not.toContain(token);
      expect(state).not.toContain(server.issuedTokens[0]!);
      expect(state).not.toContain("gr_inv_");
    });

    it("a pasted token works from the plain page, and a wrong emailed code is refused with the one message", async () => {
      const { token } = server.addInvite({ email: EMAIL });
      const w = await open("/");
      await w.page.getByTestId("have-invite").click();
      expect(await screen(w)).toBe("enrol");
      await fill(w, "enrol-token", `https://partners.example.test/invite#${token}`);
      await w.page.getByTestId("enrol-send-code").click();
      await w.page.locator("#enrol-code").waitFor();
      await fill(w, "enrol-code", "000000");
      await w.page.getByTestId("enrol-submit-code").click();
      await w.page.getByTestId("notice").filter({ hasText: "was not accepted" }).waitFor();
      expect(await screen(w)).toBe("enrol");
      expect(await w.violations()).toEqual([]);
    });

    it("the enrolment screen is keyboard-first: the code field takes focus on arrival, and the screens are in French on request", async () => {
      const { token } = server.addInvite({ email: EMAIL });
      const w = await open(`/invite#${token}`);
      await w.page.getByTestId("enrol-send-code").click();
      await w.page.locator("#enrol-code").waitFor();
      expect(await w.page.evaluate(() => document.activeElement?.id)).toBe("enrol-code");
      await w.page.getByTestId("lang-toggle").click();
      expect(await textOf(w.page.getByTestId("heading"))).toBe("Accepter votre invitation");
    });

    it("the PIN prompt an A1 screen would open: masked numeric input, a refused PIN is explained, a wrong one is counted, the right one resolves with a grant; only { derived } is sent", async () => {
      await server.seedPin(PIN, { iterations: 210_000 });
      const w = await open("/harness.html");
      await w.page.locator("#mount-app").click();
      await w.page.getByTestId("sign-in").click();
      await w.page.locator('[data-screen="signed-in"]').waitFor();
      await w.page.locator("#request-pin-a1").click();
      await w.page.locator('[data-screen="pin-prompt"]').waitFor();
      const attrs = await w.page.locator("#pin").evaluate((el) => ({ type: el.getAttribute("type"), mode: el.getAttribute("inputmode"), max: el.getAttribute("maxlength"), complete: el.getAttribute("autocomplete"), focused: document.activeElement === el }));
      expect(attrs).toEqual({ type: "password", mode: "numeric", max: "4", complete: "off", focused: true });

      await fill(w, "pin", "1234");
      await w.page.locator("#pin").press("Enter");
      await w.page.getByTestId("notice").filter({ hasText: "run of digits" }).waitFor();
      expect(wire().filter((r) => r.path.endsWith("/step-up/pin"))).toHaveLength(0);
      await fill(w, "pin", "7392");
      await w.page.getByTestId("pin-submit").click();
      await w.page.getByTestId("notice").filter({ hasText: "not correct" }).waitFor();
      expect(server.pinRecord()!.failures).toBe(1);
      await fill(w, "pin", PIN);
      await w.page.getByTestId("pin-submit").click();
      await w.page.waitForFunction(() => (document.querySelector('[data-testid="out"]')?.textContent ?? "").includes("granted"));
      expect(JSON.parse((await w.page.getByTestId("out").textContent())!)).toMatchObject({ ok: true, granted: "A1" });
      expect(server.pinRecord()!.failures).toBe(0);
      expect(server.state.pinGrantsIssued).toBe(1);

      const bodies = wire().filter((r) => r.path.endsWith("/step-up/pin")).map((r) => JSON.parse(r.body) as Record<string, unknown>);
      expect(bodies).toHaveLength(2);
      for (const b of bodies) expect(Object.keys(b)).toEqual(["derived"]);
      for (const r of server.log) {
        expect(r.body).not.toContain(`"${PIN}"`);
        expect(r.body).not.toContain('"7392"');
        expect(r.path).not.toContain(PIN);
      }
      expect(w.requests.filter((u) => u.includes(PIN) || u.includes("7392"))).toEqual([]);
      expect(await w.violations()).toEqual([]);
      expect(w.pageErrors).toEqual([]);
      // the browser's own network log of the wrong PIN's 403 (and the harness page's missing favicon) is all the console holds: the page itself logs nothing
      expect(w.console.filter((m) => !m.startsWith("error: Failed to load resource"))).toEqual([]);
    });

    it("Cancel on the prompt rejects the caller with 'cancelled' and closes the prompt", async () => {
      await server.seedPin(PIN, { iterations: 210_000 });
      const w = await open("/harness.html");
      await w.page.locator("#mount-app").click();
      await w.page.getByTestId("sign-in").click();
      await w.page.locator('[data-screen="signed-in"]').waitFor();
      await w.page.locator("#request-pin-a1").click();
      await w.page.locator('[data-screen="pin-prompt"]').waitFor();
      await w.page.getByTestId("panel-cancel").click();
      await w.page.locator('[data-screen="signed-in"]').waitFor();
      await w.page.waitForFunction(() => (document.querySelector('[data-testid="out"]')?.textContent ?? "").includes("stepUp"));
      expect(JSON.parse((await w.page.getByTestId("out").textContent())!)).toMatchObject({ ok: true, stepUp: "cancelled" });
      expect(wire().filter((r) => r.path.endsWith("/step-up/pin"))).toHaveLength(0);
    });
  });

  describe("auto-lock: a page hidden for 120 000 ms locks itself (owner decision, design 140)", () => {
    /**
     * SYNTHETIC visibility. Nothing in this repo's Chromium (Playwright 1.56.1 / chromium-1194) flips `document.visibilityState` for real: pages are kept visible
     * by Playwright's focus emulation in the headless shell, in full headless and in headed mode under Xvfb; `Page.setWebLifecycleState`, a second tab with
     * `bringToFront`, a background `Target.createTarget` and a minimized window were each tried and left it `visible` (design 140, "What the browser cell does
     * and does not prove"). So the page is made to REPORT hidden or visible and the real event is fired at the real document. What this proves is the built
     * bundle's wiring and behaviour (main.ts -> the page's own document, real fetch, real timers under `page.clock`, the real handler and the real heap); what
     * it does not prove is that WebKit fires `visibilitychange` when an iPad is locked or an app is switched: that is the on-device check.
     */
    const setVisibility = (w: Watch, state: "hidden" | "visible") =>
      w.page.evaluate((st) => {
        Object.defineProperty(document, "visibilityState", { configurable: true, get: () => st });
        Object.defineProperty(document, "hidden", { configurable: true, get: () => st === "hidden" });
        document.dispatchEvent(new Event("visibilitychange"));
      }, state);
    /**
     * The page's wall clock moves forward by exactly `ms` and NO timer runs (a frozen page, a closed lid): Playwright's `clock.setSystemTime`, on a clock that
     * `openFakeClock` paused (an installed clock keeps ticking in real time until it is paused, which would add a few milliseconds to every boundary below).
     */
    const wallClockJump = async (w: Watch, ms: number) => {
      const now = await w.page.evaluate(() => Date.now());
      await w.page.clock.setSystemTime(now + ms);
    };
    /**
     * The app with Playwright's clock installed from the first line and then PAUSED: time moves only when a cell says so (`wallClockJump`, or `clock.runFor` for the timers).
     * The pause target is 10 s ahead of the page's clock, not 1 ms: an installed clock keeps running between reading it and pausing it, and a target already in the
     * past makes `pauseAt` throw ("Cannot fast-forward to the past"), which a loaded machine hit (11 of the 13 cells failed on a 300 ms gap with the old 1 ms).
     */
    const openFakeClock = async (path = "/") => {
      const w = await open(path, { fakeClock: true });
      const now = await w.page.evaluate(() => Date.now());
      await w.page.clock.pauseAt(now + 10_000);
      return w;
    };
    /**
     * SYNTHETIC monotonic advance. Playwright's clock moves `Date` and `performance.now()` together (`setSystemTime` moves `Date` alone, `runFor` moves both and fires the
     * timers), so it cannot model a device that stays awake while its page is frozen and whose date is then set back. This wraps the fake clock's `performance.now()` so
     * the page's monotonic clock reads `ms` further on: the awake half of that scenario, with no timer run. The date set back is the real `setSystemTime`.
     */
    const monotonicAdvance = (w: Watch, ms: number) =>
      w.page.evaluate((add) => {
        const orig = performance.now.bind(performance);
        performance.now = () => orig() + add;
      }, ms);
    const lockRequests = () => server.log.filter((r) => r.method === "POST" && r.path.endsWith("/partner-session/lock"));

    it("RETURN PATH (the reliable one: the page was frozen, no timer ran): hidden, the wall clock moves 120 000 ms, visible -> locked at once with the new notice; the session is REVOKED, the old token is refused, the token is out of the heap", async () => {
      const w = await openFakeClock();
      await signIn(w);
      const token = server.issuedTokens[0]!;
      expect(await heapContains(w.page, token)).toBe(true);
      await setVisibility(w, "hidden");
      await wallClockJump(w, 120_000);
      expect(await screen(w), "nothing happens while it is hidden and no timer runs").toBe("signed-in");
      await setVisibility(w, "visible");
      await w.page.locator('[data-screen="signed-out"]').waitFor({ timeout: 2000 });
      expect(await textOf(w.page.getByTestId("notice"))).toBe("Locked because you were away. Sign in again with your passkey to continue.");
      expect(await w.page.getByTestId("session-fields").count()).toBe(0);
      await expect.poll(() => server.state.revokedSessions.size).toBe(1);
      expect(lockRequests()).toHaveLength(1);
      expect(lockRequests()[0]!.authorization).toBe(`Bearer ${token}`);
      expect(server.state.lockCalls).toBe(1);
      expect(server.state.signOutCalls).toBe(0);
      const res = await fetch(`${apiOrigin}/functions/v1/partner-session/session`, { headers: { authorization: `Bearer ${token}`, "content-type": "application/json", origin: pageOrigin } });
      expect(res.status).toBe(401);
      expect(await heapContains(w.page, token)).toBe(false);
      expect(await w.violations()).toEqual([]);
      expect(w.pageErrors).toEqual([]);
    });

    it("after an auto-lock the next session needs a new passkey tap and is a NEW session, like after any lock (no heap snapshot in this cell: a passkey sign-in after one failed once in this harness, see the MEDIUM-2 cell)", async () => {
      const w = await openFakeClock();
      await signIn(w);
      await setVisibility(w, "hidden");
      await wallClockJump(w, 120_000);
      await setVisibility(w, "visible");
      await w.page.locator('[data-screen="signed-out"]').waitFor({ timeout: 2000 });
      await expect.poll(() => server.state.revokedSessions.size).toBe(1);
      const optionsBefore = apiCalls().filter((r) => r.path.endsWith("/options")).length;
      await signIn(w);
      expect(apiCalls().filter((r) => r.path.endsWith("/options")).length).toBe(optionsBefore + 1);
      expect(server.issuedTokens).toHaveLength(2);
      expect(server.issuedTokens[0]).not.toBe(server.issuedTokens[1]);
      expect(server.sessions()).toHaveLength(1);
      // the earlier hidden stretch is forgotten: a short hide does not lock the new session
      await setVisibility(w, "hidden");
      await wallClockJump(w, 30_000);
      await setVisibility(w, "visible");
      expect(await screen(w)).toBe("signed-in");
    });

    it("E1: the date is set BACK into the 2-minute window on a device that stayed awake (the monotonic advance is synthetic, see monotonicAdvance): locked on return, session revoked, token out of the heap. The wall-clock-only mutant is killed here and by the unit cell G1", async () => {
      const w = await openFakeClock();
      await signIn(w);
      const token = server.issuedTokens[0]!;
      await setVisibility(w, "hidden");
      const hiddenAt = await w.page.evaluate(() => Date.now());
      await monotonicAdvance(w, 600_000); // ten minutes pass on the device
      await w.page.clock.setSystemTime(hiddenAt + 10_000); // someone sets the date to 10 s after the page went hidden
      expect(await w.page.evaluate(() => Date.now())).toBe(hiddenAt + 10_000);
      await setVisibility(w, "visible");
      await w.page.locator('[data-screen="signed-out"]').waitFor({ timeout: 2000 });
      expect(await textOf(w.page.getByTestId("notice"))).toContain("Locked because you were away");
      await expect.poll(() => server.state.revokedSessions.size).toBe(1);
      expect(lockRequests()[0]!.authorization).toBe(`Bearer ${token}`);
      expect(await heapContains(w.page, token)).toBe(false);
    });

    it("E1 control: the date set back into the window while the monotonic clock ALSO says the page was away briefly stays signed in (both clocks agree; the browser has nothing to go on and none is needed)", async () => {
      const w = await openFakeClock();
      await signIn(w);
      await setVisibility(w, "hidden");
      const hiddenAt = await w.page.evaluate(() => Date.now());
      await w.page.clock.setSystemTime(hiddenAt + 10_000);
      await setVisibility(w, "visible");
      expect(await screen(w)).toBe("signed-in");
      await w.page.getByTestId("refresh").click();
      await w.page.waitForFunction(() => !(document.querySelector('[data-testid="refresh"]') as HTMLButtonElement | null)?.disabled);
      expect(server.state.revokedSessions.size).toBe(0);
    });

    it("the same page in French says the same thing in French", async () => {
      const w = await openFakeClock();
      await signIn(w);
      await w.page.getByTestId("lang-toggle").click();
      await setVisibility(w, "hidden");
      await wallClockJump(w, 120_000);
      await setVisibility(w, "visible");
      await w.page.locator('[data-screen="signed-out"]').waitFor({ timeout: 2000 });
      expect(await textOf(w.page.getByTestId("notice"))).toBe("Verrouillé après une période d'absence. Reconnectez-vous avec votre clé d'accès pour continuer.");
    });

    it("119 999 ms hidden is NOT enough: still signed in, the same token still works (Refresh), nothing is revoked, and a second, longer cycle then locks", async () => {
      const w = await openFakeClock();
      await signIn(w);
      const token = server.issuedTokens[0]!;
      await setVisibility(w, "hidden");
      await wallClockJump(w, 119_999);
      await setVisibility(w, "visible");
      expect(await screen(w)).toBe("signed-in");
      await w.page.getByTestId("refresh").click();
      await w.page.waitForFunction(() => !(document.querySelector('[data-testid="refresh"]') as HTMLButtonElement | null)?.disabled);
      expect(await screen(w)).toBe("signed-in");
      expect(server.state.revokedSessions.size).toBe(0);
      expect(lockRequests()).toHaveLength(0);
      // a visible event with no preceding hidden is nothing, however far the clock has moved
      await wallClockJump(w, 600_000);
      await setVisibility(w, "visible");
      expect(await screen(w)).toBe("signed-in");
      await setVisibility(w, "hidden");
      await wallClockJump(w, 130_000);
      await setVisibility(w, "visible");
      await w.page.locator('[data-screen="signed-out"]').waitFor({ timeout: 2000 });
      await expect.poll(() => server.state.revokedSessions.size).toBe(1);
      expect(await heapContains(w.page, token)).toBe(false);
    });

    it("TIMER PATH (best effort, acts while still hidden): nothing at 119 999 ms of timer time, locked at 120 000 ms with the page still hidden; the visible event afterwards sends nothing more", async () => {
      const w = await openFakeClock();
      await signIn(w);
      const token = server.issuedTokens[0]!;
      await setVisibility(w, "hidden");
      await w.page.clock.runFor(119_999);
      expect(await screen(w)).toBe("signed-in");
      expect(lockRequests()).toHaveLength(0);
      await w.page.clock.runFor(1);
      await w.page.locator('[data-screen="signed-out"]').waitFor({ timeout: 2000 });
      expect(await w.page.evaluate(() => document.visibilityState)).toBe("hidden");
      expect(await textOf(w.page.getByTestId("notice"))).toContain("Locked because you were away");
      await expect.poll(() => server.state.revokedSessions.size).toBe(1);
      expect(lockRequests()[0]!.authorization).toBe(`Bearer ${token}`);
      expect(await heapContains(w.page, token)).toBe(false);
      await setVisibility(w, "visible");
      await w.page.waitForTimeout(300);
      expect(lockRequests()).toHaveLength(1);
      expect(server.state.lockCalls).toBe(1);
      expect(await textOf(w.page.getByTestId("notice"))).toContain("Locked because you were away");
      expect(await w.violations()).toEqual([]);
    });

    it("visible cancels the timer: a short hide, then a long stretch of timer time while visible, locks nothing", async () => {
      const w = await openFakeClock();
      await signIn(w);
      await setVisibility(w, "hidden");
      await w.page.clock.runFor(10_000);
      await setVisibility(w, "visible");
      await w.page.clock.runFor(600_000);
      expect(await screen(w)).toBe("signed-in");
      expect(lockRequests()).toHaveLength(0);
    });

    it("a timer left over from an earlier hide cannot lock a later, shorter one: 120 000 ms after the FIRST hide the page is only 20 000 ms into the second and stays signed in; the second one locks at its own limit", async () => {
      const w = await openFakeClock();
      await signIn(w);
      await setVisibility(w, "hidden");
      await w.page.clock.runFor(10_000);
      await setVisibility(w, "visible");
      await w.page.clock.runFor(90_000);
      await setVisibility(w, "hidden");
      await w.page.clock.runFor(20_000);
      expect(await screen(w)).toBe("signed-in");
      expect(lockRequests()).toHaveLength(0);
      await w.page.clock.runFor(100_000);
      await w.page.locator('[data-screen="signed-out"]').waitFor({ timeout: 2000 });
      await expect.poll(() => server.state.revokedSessions.size).toBe(1);
    });

    it("a refresh that never answers when the lock fires: the screen is locked at once, the hung request is aborted, the token is out of the heap, and the refresh cannot bring the signed-in screen back", async () => {
      const w = await openFakeClock();
      await signIn(w);
      const token = server.issuedTokens[0]!;
      server.state.hang.add("session");
      await w.page.getByTestId("refresh").click();
      await expect.poll(() => w.page.locator("main").getAttribute("aria-busy")).toBe("true");
      await setVisibility(w, "hidden");
      await w.page.clock.runFor(120_000);
      await w.page.locator('[data-screen="signed-out"]').waitFor({ timeout: 2000 });
      expect(await textOf(w.page.getByTestId("notice"))).toContain("Locked because you were away");
      await expect.poll(() => server.state.revokedSessions.size).toBe(1);
      expect(await heapContains(w.page, token)).toBe(false);
      await w.page.waitForTimeout(500);
      expect(await screen(w)).toBe("signed-out");
    });

    it("a sign-in whose verify is still on the wire: a 119 999 ms hide changes nothing and the sign-in completes", async () => {
      const w = await openFakeClock();
      server.state.delayAfter["verify"] = 1500;
      await w.page.getByTestId("sign-in").click();
      await expect.poll(() => server.log.some((r) => r.path.endsWith("/verify") && r.method === "POST")).toBe(true);
      expect(await screen(w)).toBe("signing-in");
      await setVisibility(w, "hidden");
      await wallClockJump(w, 119_999);
      await setVisibility(w, "visible");
      expect(await screen(w)).toBe("signing-in");
      await w.page.locator('[data-screen="signed-in"]').waitFor({ timeout: 8000 });
      expect(server.state.revokedSessions.size).toBe(0);
    });

    it("a sign-in whose verify is still on the wire when the page has been hidden 120 000 ms: cancelled as Cancel is, and the session the server opened is REVOKED, never held", async () => {
      const w = await openFakeClock();
      server.state.delayAfter["verify"] = 1500;
      await w.page.getByTestId("sign-in").click();
      await expect.poll(() => server.log.some((r) => r.path.endsWith("/verify") && r.method === "POST")).toBe(true);
      expect(await screen(w)).toBe("signing-in");
      await setVisibility(w, "hidden");
      await wallClockJump(w, 120_000);
      await setVisibility(w, "visible");
      await w.page.locator('[data-screen="signed-out"]').waitFor({ timeout: 1000 });
      expect(await textOf(w.page.getByTestId("notice"))).toContain("cancelled");
      expect(server.sessions()).toHaveLength(1); // minted by the server, response not yet delivered
      await expect.poll(() => server.state.revokedSessions.size, { timeout: 8000 }).toBe(1);
      expect(server.sessions()).toEqual([]);
      expect(await screen(w)).toBe("signed-out");
      expect(await heapContains(w.page, server.issuedTokens[0]!)).toBe(false);
    });

    it("OBSERVATION (pinned, chromium-1194): a passkey ceremony does not hide the page. Through a whole sign-in (the virtual authenticator, verify held for a second) no visibilitychange and no pagehide fires and the page stays visible, so the auto-lock never sees it. What an iPad's own passkey sheet does is an on-device check (design 140)", async () => {
      const w = await open("/");
      await w.page.evaluate(() => {
        const g = window as unknown as { __seen: string[] };
        g.__seen = [];
        document.addEventListener("visibilitychange", () => g.__seen.push(`visibilitychange:${document.visibilityState}`));
        window.addEventListener("pagehide", () => g.__seen.push("pagehide"));
        const poll = window.setInterval(() => {
          if (document.visibilityState !== "visible") g.__seen.push(`state:${document.visibilityState}`);
        }, 20);
        window.addEventListener("pageshow", () => window.clearInterval(poll), { once: true });
      });
      server.state.delayAfter["verify"] = 1000;
      await w.page.getByTestId("sign-in").click();
      await expect.poll(() => server.log.some((r) => r.path.endsWith("/verify") && r.method === "POST")).toBe(true);
      expect(await screen(w)).toBe("signing-in");
      await w.page.locator('[data-screen="signed-in"]').waitFor({ timeout: 8000 });
      expect(await w.page.evaluate(() => (window as unknown as { __seen: string[] }).__seen)).toEqual([]);
      expect(await w.page.evaluate(() => document.visibilityState)).toBe("visible");
      expect(await w.page.evaluate(() => (window as unknown as { __pageshows: boolean[] }).__pageshows)).toEqual([false]);
    });

    describe("an enrolment left at the passkey step", () => {
      const INVITEE = "new.hire@partners.example.test";
      const wire = () => server.log.filter((r) => r.method !== "OPTIONS");
      /** Invite link -> email me a code -> the code -> the Create passkey button is up. */
      const toPasskeyStep = async () => {
        const { token } = server.addInvite({ email: INVITEE });
        const w = await openFakeClock(`/invite#${token}`);
        await w.page.getByTestId("enrol-send-code").click();
        await w.page.locator("#enrol-code").fill(server.state.otpCode);
        await w.page.locator("#enrol-code").press("Enter");
        await w.page.getByTestId("enrol-create-passkey").waitFor();
        return w;
      };

      it("hidden for 120 000 ms: back to sign-in, no Create passkey button, no credential and no session for the invitee (before this, whoever picked the iPad up could press it and be signed in as the invitee)", async () => {
        const w = await toPasskeyStep();
        await setVisibility(w, "hidden");
        await wallClockJump(w, 120_000);
        await setVisibility(w, "visible");
        await w.page.locator('[data-screen="signed-out"]').waitFor({ timeout: 2000 });
        expect(await w.page.getByTestId("enrol-create-passkey").count()).toBe(0);
        expect(await textOf(w.page.getByTestId("notice"))).toBe("Enrolment stopped because the page was left open. Ask a manager for a new link.");
        expect(await w.page.getByTestId("sign-in").isEnabled()).toBe(true);
        expect(await w.auth.credentials()).toHaveLength(1); // only the preloaded one: nothing was created
        expect(server.credentialsOf(server.userByEmail(INVITEE)!.id)).toEqual([]);
        expect(server.sessions()).toEqual([]);
        expect(wire().filter((r) => r.path.endsWith("/partner-invites/credentials"))).toEqual([]);
        expect(await w.violations()).toEqual([]);
      });

      it("hidden for the limit with the timer (the page still hidden): the same", async () => {
        const w = await toPasskeyStep();
        await setVisibility(w, "hidden");
        await w.page.clock.runFor(120_000);
        await w.page.locator('[data-screen="signed-out"]').waitFor({ timeout: 2000 });
        expect(await w.page.getByTestId("enrol-create-passkey").count()).toBe(0);
        expect(await textOf(w.page.getByTestId("notice"))).toContain("Enrolment stopped");
        expect(server.sessions()).toEqual([]);
      });

      it.each(["return", "timer"] as const)("R1 (%s path): the first session is open and GET pin answers only 1.5 s after the cancel: still signed-out when it does, no forced-PIN screen, the invitee's session REVOKED, no live session, the token out of the heap", async (path) => {
        server.state.delayAfter["pin"] = 1500;
        const w = await toPasskeyStep();
        await w.page.getByTestId("enrol-create-passkey").click();
        await expect.poll(() => server.log.some((r) => r.method === "GET" && r.path.endsWith("/partner-session/pin"))).toBe(true);
        expect(await screen(w)).toBe("enrol"); // registerFirst has adopted the first session; the PIN read is still on its way
        await setVisibility(w, "hidden");
        if (path === "return") {
          await wallClockJump(w, 120_000);
          await setVisibility(w, "visible");
        } else await w.page.clock.runFor(120_000);
        await w.page.locator('[data-screen="signed-out"]').waitFor({ timeout: 1000 });
        await w.page.waitForTimeout(2500); // the late answer has arrived by now
        expect(await screen(w)).toBe("signed-out");
        expect(await w.page.locator('[data-screen="pin-setup"]').count()).toBe(0);
        expect(await textOf(w.page.getByTestId("notice"))).toContain("Enrolment stopped"); // still the notice, not replaced by the late answer
        await expect.poll(() => server.state.revokedSessions.size).toBe(1);
        expect(server.sessions()).toEqual([]);
        expect(await heapContains(w.page, server.issuedTokens[0]!)).toBe(false);
        expect(await w.violations()).toEqual([]);
      });

      it("the earlier steps hold nothing a bystander could complete (a one-time token that still needs the code mailed to the invitee), so a long hide leaves them: the token step and the code step are still on screen", async () => {
        const { token } = server.addInvite({ email: INVITEE });
        const w = await openFakeClock(`/invite#${token}`);
        await setVisibility(w, "hidden");
        await wallClockJump(w, 120_000);
        await setVisibility(w, "visible");
        expect(await screen(w)).toBe("enrol");
        await w.page.getByTestId("enrol-send-code").click();
        await w.page.locator("#enrol-code").waitFor();
        await setVisibility(w, "hidden");
        await w.page.clock.runFor(120_000);
        await setVisibility(w, "visible");
        expect(await screen(w)).toBe("enrol");
        expect(await w.page.locator("#enrol-code").count()).toBe(1);
      });

      it("119 999 ms hidden changes nothing: the button is still there and completes the enrolment (the forced first PIN)", async () => {
        const w = await toPasskeyStep();
        await setVisibility(w, "hidden");
        await wallClockJump(w, 119_999);
        await setVisibility(w, "visible");
        expect(await screen(w)).toBe("enrol");
        await w.page.getByTestId("enrol-create-passkey").click();
        await w.page.locator('[data-screen="pin-setup"]').waitFor();
        expect(server.sessions()).toHaveLength(1);
      });
    });

    it("signed out: a long hide changes nothing and sends nothing", async () => {
      const w = await openFakeClock();
      await setVisibility(w, "hidden");
      await w.page.clock.runFor(300_000);
      await wallClockJump(w, 300_000);
      await setVisibility(w, "visible");
      await w.page.waitForTimeout(200);
      expect(await screen(w)).toBe("signed-out");
      expect(apiCalls()).toEqual([]);
    });

    it("REAL events: leaving the page and coming back through the back/forward cache fires visibilitychange hidden then visible in Chromium; with the auto-lock installed the restored page is still signed-out, holds no token, and the visible event locks nothing and sends nothing more", async () => {
      const w = await open("/app-cacheable.html", { bfcache: true });
      await w.page.evaluate(() => {
        const g = window as unknown as { __order: string[] };
        g.__order = [];
        window.addEventListener("pagehide", (ev) => g.__order.push(`pagehide:${(ev as PageTransitionEvent).persisted}`));
        document.addEventListener("visibilitychange", () => g.__order.push(`visibilitychange:${document.visibilityState}`));
        window.addEventListener("pageshow", (ev) => g.__order.push(`pageshow:${(ev as PageTransitionEvent).persisted}`));
      });
      await signIn(w);
      const token = server.issuedTokens[0]!;
      await w.page.goto(`${pageOrigin}/manifest.webmanifest`, { waitUntil: "load" });
      await w.page.goBack({ waitUntil: "commit" });
      await w.page.locator("main").waitFor();
      const order = await w.page.evaluate(() => (window as unknown as { __order: string[] }).__order);
      // observed (pinned, chromium-1194): the page left through pagehide and became hidden; the restore showed it and made it visible again
      expect(order.filter((e) => e.startsWith("visibilitychange")), JSON.stringify(order)).toEqual(["visibilitychange:hidden", "visibilitychange:visible"]);
      expect(order.indexOf("visibilitychange:hidden")).toBeGreaterThan(order.indexOf("pagehide:true"));
      expect(order).toContain("pageshow:true");
      await w.page.waitForTimeout(300);
      expect(await screen(w)).toBe("signed-out");
      expect(await heapContains(w.page, token)).toBe(false);
      expect(lockRequests()).toEqual([]); // the pagehide sign-out revoked it; the auto-lock added nothing
      expect(server.log.filter((r) => r.authorization !== null && r.path.endsWith("/sign-out"))).toHaveLength(1);
      expect(await w.violations()).toEqual([]);
    });
  });
});
