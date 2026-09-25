/**
 * forms-pages.test.ts — build-output coverage for the claim/feedback
 * pages' "forms aren't live yet" state (this task's scope: "While the
 * config is unset, a form must not pretend to submit. It shows a clear
 * 'forms aren't live yet' state, and the build still passes.") AND (gate
 * review S2) the OPPOSITE state: a real, valid, configured build. Every
 * assertion below is parameterized on `isFormsConfigured()` (the SAME
 * function `forms-config.mjs`/`gen-headers.mjs`/`SecureFormScript.astro`
 * all use) against TWO real `dist/` trees `test/global-setup.mjs` builds
 * — `real` (the committed `TODO(owner)` placeholders, unconfigured) and
 * `configured` (env-var overrides with fake-but-valid values, see
 * `test/paths.mjs`'s own doc) — never a synthetic fixture for either.
 */
import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { isFormsConfigured } from "../src/config/forms-config.mjs";
import { BUILDS } from "./paths.mjs";

async function readIn(distDir: string, relPath: string): Promise<string> {
  return readFile(join(distDir, relPath), "utf8");
}

async function walk(dir: string): Promise<string[]> {
  const entries = await readdir(dir, { withFileTypes: true });
  const out: string[] = [];
  for (const entry of entries) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...(await walk(full)));
    else out.push(full);
  }
  return out;
}

const FORM_PAGES = ["claim/index.html", "feedback/index.html", "fr/claim/index.html", "fr/feedback/index.html"];

/** The exact two build states this file parameterizes every assertion
 * on — `configuredExpected` is asserted against `isFormsConfigured()`
 * itself first, so a future change to `test/paths.mjs`'s fake values (or
 * to `isFormsConfigured()`'s own rules) that accidentally breaks the
 * "configured" build's premise fails LOUDLY here, not as a confusing
 * downstream mismatch. */
const BUILD_STATES = [
  { label: "real (unconfigured — the committed TODO(owner) placeholders)", key: "real", configuredExpected: false },
  {
    label: "configured (gate review S2 — fake-but-valid env-var-overridden values)",
    key: "configured",
    configuredExpected: true,
  },
] as const;

describe("claim/feedback pages, parameterized on isFormsConfigured() (gate review S2)", () => {
  it.each(BUILD_STATES)("$label: the build's own forms-config.mjs state matches what this file assumes", ({ key, configuredExpected }) => {
    // A sanity check on the PREMISE, not the pages — if this ever fails,
    // every other test in this file is testing the wrong thing.
    void key;
    // isFormsConfigured() reads FORMS_CONFIG (this test PROCESS's own env,
    // not the build subprocess's) — this assertion is deliberately about
    // the DOCUMENTED env vars test/paths.mjs sets for the "configured"
    // build key, re-checked directly rather than trusted blind.
    const envForBuild = BUILDS[key as "real" | "configured"].env as Record<string, string | undefined>;
    const workerUrl = envForBuild.GOLFRAVEN_FORMS_WORKER_URL;
    const turnstileSiteKey = envForBuild.GOLFRAVEN_FORMS_TURNSTILE_SITE_KEY;
    const config = {
      workerUrl: workerUrl ?? "TODO(owner): raven-site-kit secure-upload Worker URL",
      siteId: "golfraven",
      turnstileSiteKey: turnstileSiteKey ?? "TODO(owner): golfraven Turnstile site key",
      contactEmail: "",
    };
    expect(isFormsConfigured(config)).toBe(configuredExpected);
  });

  it.each(BUILD_STATES)(
    "$label: every form page builds successfully with a real <form data-secure-form>, and B1's fieldset stays `disabled` in the STATIC markup either way (enabling it is a runtime-JS decision, never baked into SSR output)",
    async ({ key }) => {
      const dist = BUILDS[key as "real" | "configured"].dist;
      for (const relPath of FORM_PAGES) {
        const html = await readIn(dist, relPath);
        expect(html, relPath).toContain("<form");
        expect(html, relPath).toContain("data-secure-form");
        // B1 (gate review, blocking): the fieldset is ALWAYS rendered
        // `disabled` server-side, in BOTH build states — SecureFormScript's
        // module script is what conditionally removes `disabled`, at
        // runtime, in the visitor's own browser, never at build time.
        expect(html, relPath).toMatch(/<fieldset\s+disabled\s+data-form-fieldset[\s>]/);
      }
    },
  );

  it("UNCONFIGURED: no Turnstile widget/loader anywhere, and every form page carries the TODO(owner) markers verbatim", async () => {
    for (const relPath of FORM_PAGES) {
      const html = await readIn(BUILDS.real.dist, relPath);
      expect(html, relPath).not.toContain("cf-turnstile");
      expect(html, relPath).not.toContain("challenges.cloudflare.com");
      // The form's config is wired on as plain, static HTML attributes on
      // the page's own <form> tag (never a script — this repo's AT(7)
      // invariant forbids inline script content anywhere but a single
      // JSON-LD block, so SecureFormScript reads config from these
      // attributes rather than stamping them on via an inline script).
      // They still carry the grep-able TODO(owner) placeholder text
      // verbatim, proving the page is honestly wired to the real (unset)
      // config, not a hard-coded "it works" stand-in.
      expect(html, relPath).toMatch(/data-worker-url="TODO\(owner\)/);
      expect(html, relPath).toMatch(/data-turnstile-site-key="TODO\(owner\)/);
      expect(html, relPath).toContain('data-site-id="golfraven"');
      // The aria-live status region SecureFormScript uses to announce
      // "forms aren't live yet" is present in the DOM from first paint
      // (SC 4.1.3 — see that component's doc for why it's never
      // conditionally rendered).
      expect(html, relPath).toContain("data-form-status");
      expect(html, relPath).toContain('role="status"');
      expect(html, relPath).toContain('aria-live="polite"');
    }
  });

  it("CONFIGURED (gate review S2): the Turnstile widget/loader DOES render, and every form page carries the REAL (fake-but-valid) values — never the placeholder", async () => {
    for (const relPath of FORM_PAGES) {
      const html = await readIn(BUILDS.configured.dist, relPath);
      expect(html, relPath).toContain('class="cf-turnstile"');
      expect(html, relPath).toContain("https://challenges.cloudflare.com/turnstile/v0/api.js");
      expect(html, relPath).toContain('data-worker-url="https://secure-upload.example.workers.dev"');
      expect(html, relPath).toContain('data-turnstile-site-key="1x00000000000000000000AA"');
      expect(html, relPath).toContain('data-site-id="golfraven"');
      expect(html, relPath).not.toMatch(/data-worker-url="TODO\(owner\)/);
      expect(html, relPath).not.toMatch(/data-turnstile-site-key="TODO\(owner\)/);
    }
  });

  it.each(BUILD_STATES)("$label: form pages are noindex and never reach the sitemap, whether forms are configured or not", async ({ key }) => {
    const dist = BUILDS[key as "real" | "configured"].dist;
    const sitemap = await readIn(dist, "sitemap-0.xml");
    for (const path of ["/claim/", "/feedback/", "/fr/claim/", "/fr/feedback/"]) {
      expect(sitemap, path).not.toContain(path);
    }
    for (const relPath of FORM_PAGES) {
      const html = await readIn(dist, relPath);
      expect(html, relPath).toMatch(/<meta name="robots" content="noindex, follow"/);
    }
  });

  it.each(BUILD_STATES)(
    "$label: the ENTIRE built dist/ (every HTML page + every bundled JS chunk) contains NO personal email and NO mailto: link, while FORMS_CONFIG.contactEmail is empty",
    async ({ key }) => {
      // Whole-tree scan, not just the four form pages: the fix this test
      // guards against was a hard-coded email default baked into
      // SecureFormScript's bundled client-script CHUNK
      // (`dist/_astro/SecureFormScript.astro_..._.js`), which no per-page
      // HTML check would ever catch. Publishing a personal address on a
      // public site/repo is the owner's call, never a default this build
      // makes for them (see forms-config.mjs's own TODO(owner) on
      // contactEmail) — so this asserts the negative directly, across
      // every file the build produces, in BOTH build states (a real
      // deployment env-overriding workerUrl/turnstileSiteKey must not
      // accidentally also leak an email that was never configured).
      // `pagefind/` is the search library's own generated bundle; its
      // language files credit upstream translators by email. That is
      // third-party attribution, not an address this site publishes, so
      // it is excluded.
      const dist = BUILDS[key as "real" | "configured"].dist;
      const files = (await walk(dist)).filter((f) => !/[\\/]pagefind[\\/]/.test(f));
      const offenders: string[] = [];
      for (const file of files) {
        const text = await readFile(file, "utf8").catch(() => "");
        // `mailto:` alone (with nothing after it) is a legitimate,
        // unrelated feature elsewhere in this codebase —
        // analytics-runtime.ts checks `href.startsWith("mailto:")` to
        // classify a contact_method click, with no address attached at
        // all. What this test actually cares about is an ADDRESS: any
        // email-shaped string in the built output, or a real `mailto:`
        // link that carries an "@" (an actual email, not just the bare
        // URI scheme prefix).
        const emails = (text.match(/[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}/g) ?? []).filter(
          (e) => !/@(?:example\.(?:test|com|org|workers\.dev))$/i.test(e),
        );
        if (emails.length > 0 || /mailto:[^"'\s)]*@/i.test(text)) {
          offenders.push(file);
        }
      }
      expect(offenders).toEqual([]);
    },
  );

  it.each(BUILD_STATES)(
    "$label: re-gate nit — no built form page ships an HTML comment mentioning 'gate' (gate-review notes must live in frontmatter/JS comments, never `.astro` markup)",
    async ({ key }) => {
      // Astro strips `{/* ... */}` template comments and frontmatter `/** */`
      // doc comments from its output entirely — only a literal `<!-- -->`
      // markup comment survives into the built HTML. This asserts that
      // whatever DOES survive never carries a gate-review annotation like
      // the old `<!-- B1 (gate review, blocking): ... -->` blocks that used
      // to sit directly above these forms' `<form>` tags.
      const dist = BUILDS[key as "real" | "configured"].dist;
      for (const relPath of FORM_PAGES) {
        const html = await readIn(dist, relPath);
        const comments = html.match(/<!--[\s\S]*?-->/g) ?? [];
        const gateComments = comments.filter((c) => /gate/i.test(c));
        expect(gateComments, `${relPath} gate-review comments: ${JSON.stringify(gateComments)}`).toEqual([]);
      }
    },
  );
});
