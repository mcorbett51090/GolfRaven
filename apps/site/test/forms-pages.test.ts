/**
 * forms-pages.test.ts — build-output coverage for the claim/feedback
 * pages' "forms aren't live yet" state (this task's scope: "While the
 * config is unset, a form must not pretend to submit. It shows a clear
 * 'forms aren't live yet' state, and the build still passes."). Runs
 * against the REAL `dist/` tree `test/global-setup.mjs` builds — the
 * SAME committed `src/config/forms-config.mjs` (still carrying its two
 * `TODO(owner)` placeholders) every other build/test in this repo uses,
 * so this is exactly the state a real `pnpm build` produces today, not a
 * synthetic fixture.
 */
import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
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

describe("claim/feedback pages: unconfigured forms never pretend to submit (real build)", () => {
  it.each([
    ["claim/index.html", "en"],
    ["feedback/index.html", "en"],
    ["fr/claim/index.html", "fr"],
    ["fr/feedback/index.html", "fr"],
  ])("%s builds successfully, renders NO Turnstile widget/loader, and carries the TODO(owner) markers", async (relPath) => {
    const html = await readIn(BUILDS.real.dist, relPath);

    // The build didn't just fail silently into an empty/error page.
    expect(html).toContain("<form");
    expect(html).toContain('data-secure-form');

    // No Turnstile widget div, no Turnstile loader script — SecureFormScript's
    // unprovisioned guard (build-time `unprovisioned` check) suppresses both
    // while any of workerUrl/siteId/turnstileSiteKey is a placeholder.
    expect(html).not.toContain("cf-turnstile");
    expect(html).not.toContain("challenges.cloudflare.com");

    // The form's config is wired on as plain, static HTML attributes on
    // the page's own <form> tag (never a script — this repo's AT(7)
    // invariant forbids inline script content anywhere but a single
    // JSON-LD block, so SecureFormScript reads config from these
    // attributes rather than stamping them on via an inline script). They
    // still carry the grep-able TODO(owner) placeholder text verbatim,
    // proving the page is honestly wired to the real (unset) config, not
    // a hard-coded "it works" stand-in.
    expect(html).toMatch(/data-worker-url="TODO\(owner\)/);
    expect(html).toMatch(/data-turnstile-site-key="TODO\(owner\)/);
    expect(html).toContain('data-site-id="golfraven"');

    // The aria-live status region SecureFormScript uses to announce
    // "forms aren't live yet" is present in the DOM from first paint (SC
    // 4.1.3 — see that component's doc for why it's never conditionally
    // rendered).
    expect(html).toContain("data-form-status");
    expect(html).toContain('role="status"');
    expect(html).toContain('aria-live="polite"');
  });

  it("claim/feedback pages are noindex and never reach the sitemap (unchanged by adding the real form)", async () => {
    const sitemap = await readIn(BUILDS.real.dist, "sitemap-0.xml");
    for (const path of ["/claim/", "/feedback/", "/fr/claim/", "/fr/feedback/"]) {
      expect(sitemap).not.toContain(path);
    }
    for (const relPath of ["claim/index.html", "feedback/index.html", "fr/claim/index.html", "fr/feedback/index.html"]) {
      const html = await readIn(BUILDS.real.dist, relPath);
      expect(html).toMatch(/<meta name="robots" content="noindex, follow"/);
    }
  });

  it("the ENTIRE built dist/ (every HTML page + every bundled JS chunk) contains NO personal email and NO mailto: link, while FORMS_CONFIG.contactEmail is empty", async () => {
    // Whole-tree scan, not just the four form pages: the fix this test
    // guards against was a hard-coded email default baked into
    // SecureFormScript's bundled client-script CHUNK
    // (`dist/_astro/SecureFormScript.astro_..._.js`), which no per-page
    // HTML check would ever catch. Publishing a personal address on a
    // public site/repo is the owner's call, never a default this build
    // makes for them (see forms-config.mjs's own TODO(owner) on
    // contactEmail) — so this asserts the negative directly, across
    // every file the build produces.
    // `pagefind/` is the search library's own generated bundle; its language
    // files credit upstream translators by email. That is third-party
    // attribution, not an address this site publishes, so it is excluded.
    const files = (await walk(BUILDS.real.dist)).filter((f) => !/[\\/]pagefind[\\/]/.test(f));
    const offenders: string[] = [];
    for (const file of files) {
      const text = await readFile(file, "utf8").catch(() => "");
      // `mailto:` alone (with nothing after it) is a legitimate, unrelated
      // feature elsewhere in this codebase — analytics-runtime.ts checks
      // `href.startsWith("mailto:")` to classify a contact_method click,
      // with no address attached at all. What this test actually cares
      // about is an ADDRESS: any email-shaped string in the built output,
      // or a real `mailto:` link that carries an "@" (an actual email, not
      // just the bare URI scheme prefix).
      const emails = (text.match(/[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}/g) ?? []).filter(
        (e) => !/@(?:example\.(?:test|com|org))$/i.test(e),
      );
      if (emails.length > 0 || /mailto:[^"'\s)]*@/i.test(text)) {
        offenders.push(file);
      }
    }
    expect(offenders).toEqual([]);
  });
});
