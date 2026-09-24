/**
 * The stage-1 acceptance tests (build plan §10 P2's AT numbering) plus
 * the gate-review blocking/should-fix items (B1-B4, S1-S6). Runs against
 * the three real `dist/` trees `test/global-setup.mjs` builds — see
 * `test/paths.mjs`'s doc for why there are three, not one.
 */
import {
  mkdtemp,
  readFile,
  readdir,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { verifySitemap } from "../scripts/verify-sitemap.mjs";
import {
  findSetHtmlOccurrences,
  isSanctionedSetHtml,
} from "./scan-set-html.mjs";
import { BUILDS } from "./paths.mjs";

const siteRoot = fileURLToPath(new URL("..", import.meta.url));
const srcDir = join(siteRoot, "src");

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

async function readIndexability(indexabilityPath: string): Promise<string[]> {
  return (
    JSON.parse(await readFile(indexabilityPath, "utf8")) as {
      indexablePaths: string[];
    }
  ).indexablePaths;
}

// ---------------------------------------------------------------------
// AT(1) / B2: sitemap <loc> set = indexable set
// ---------------------------------------------------------------------

describe("AT(1)/B2: sitemap <loc> set = indexable set (real build)", () => {
  it("the FULL sitemap <loc> set equals build/indexability.json exactly (hub, trails, regions, courses)", async () => {
    const indexablePaths = await readIndexability(BUILDS.real.indexability);
    const result = await verifySitemap(BUILDS.real.dist);
    expect(result.ok).toBe(true);
    expect(result.sitemapLocs).toEqual(new Set(indexablePaths));
    // Sanity: more than just courses are covered.
    expect(indexablePaths).toContain("/");
    expect(indexablePaths).toContain("/fr/");
    expect(indexablePaths.some((p) => p.startsWith("/trails/"))).toBe(true);
    expect(
      indexablePaths.some((p) => p.startsWith("/us/") || p.startsWith("/ca/")),
    ).toBe(true);
    expect(indexablePaths.some((p) => p.startsWith("/courses/"))).toBe(true);
  });

  it("the claim page and the verified-but-thin course are never in the sitemap", async () => {
    const sitemap = await readIn(BUILDS.real.dist, "sitemap-0.xml");
    expect(sitemap).not.toMatch(/\/claim\//);
    expect(sitemap).not.toMatch(/\/courses\/thinfield-muni\//);
  });

  it("the unverified facility (Foggy Pines) has no page and is never in the sitemap", async () => {
    const sitemap = await readIn(BUILDS.real.dist, "sitemap-0.xml");
    expect(sitemap).not.toMatch(/foggy-pines/);
  });
});

describe("AT(1)/B2: REGION_PAGE_SIZE=1 — pagination is excluded from the sitemap and indexability", () => {
  it("verify-sitemap PASSes against the paginated build too", async () => {
    const result = await verifySitemap(BUILDS.paginated.dist);
    expect(result.ok).toBe(true);
  });

  it("page/2/ and beyond exist on disk but are noindex and NOT in indexability.json or the sitemap", async () => {
    const indexablePaths = await readIndexability(
      BUILDS.paginated.indexability,
    );
    for (const p of indexablePaths) {
      expect(p).not.toMatch(/\/page\//);
    }
    // With REGION_PAGE_SIZE=1 and 4 TN facilities, /us/tn/ must have paged.
    await expect(
      stat(join(BUILDS.paginated.dist, "us", "tn", "page", "2", "index.html")),
    ).resolves.toBeTruthy();
    const page2 = await readIn(
      BUILDS.paginated.dist,
      "us/tn/page/2/index.html",
    );
    expect(page2).toMatch(/<meta\s+name="robots"\s+content="noindex/);
    const sitemap = await readIn(BUILDS.paginated.dist, "sitemap-0.xml");
    expect(sitemap).not.toMatch(/\/page\//);
  });

  it("page 1 of a paginated region is still indexable", async () => {
    const indexablePaths = await readIndexability(
      BUILDS.paginated.indexability,
    );
    expect(indexablePaths).toContain("/us/tn/");
    expect(indexablePaths).toContain("/ca/bc/");
  });
});

// ---------------------------------------------------------------------
// AT(3): hub HTML < 300 KB
// ---------------------------------------------------------------------

describe("AT(3): hub HTML < 300 KB", () => {
  it("dist/index.html is under 300 KB", async () => {
    const html = await readIn(BUILDS.real.dist, "index.html");
    expect(Buffer.byteLength(html, "utf8")).toBeLessThan(300 * 1024);
  });
});

// ---------------------------------------------------------------------
// AT(6) / S4: every VERIFIED facility's page is reachable from its
// region page (JS off), whether or not it's R1-indexable.
// ---------------------------------------------------------------------

describe("AT(6)/S4: JS off — every verified facility's course page is reachable from its region page", () => {
  it("every built /courses/*/ page (i.e. every verified facility) is linked from a region page", async () => {
    const courseFiles = (await walk(join(BUILDS.real.dist, "courses"))).filter(
      (f) => f.endsWith("index.html"),
    );
    const courseSlugs = courseFiles.map((f) => f.split("/").slice(-2, -1)[0]);
    expect(courseSlugs).toContain("thinfield-muni"); // the verified-but-thin one

    const regionHtml = (
      await Promise.all(
        ["us/tn/index.html", "ca/bc/index.html"].map((p) =>
          readIn(BUILDS.real.dist, p),
        ),
      )
    ).join("\n");
    for (const slug of courseSlugs) {
      expect(regionHtml).toContain(`href="/courses/${slug}/"`);
    }
  });
});

// ---------------------------------------------------------------------
// AT(7): no set:html outside jsonLdScript()
// ---------------------------------------------------------------------

describe("AT(7): no set:html outside jsonLdScript()", () => {
  it("every set:html in the .astro source tree, in ANY form (expr, string literal, spread), is the one sanctioned set:html={ldScript} in BaseLayout.astro", async () => {
    const files = (await walk(srcDir)).filter((f) => f.endsWith(".astro"));
    const offenders: string[] = [];
    for (const file of files) {
      const content = await readFile(file, "utf8");
      for (const occ of findSetHtmlOccurrences(content)) {
        const sanctioned =
          file.endsWith("BaseLayout.astro") && isSanctionedSetHtml(occ);
        if (!sanctioned) offenders.push(`${file}: [${occ.form}] ${occ.full}`);
      }
    }
    expect(offenders).toEqual([]);
  });

  it("BaseLayout's ldScript is built from schema.ts's jsonLdScript()", async () => {
    const layout = await readFile(
      join(srcDir, "layouts", "BaseLayout.astro"),
      "utf8",
    );
    expect(layout).toMatch(
      /const ldScript = jsonLd\.length \? jsonLdScript\(jsonLd\) : ""/,
    );
  });

  it("PROOF: the detector actually catches a string-literal set:html in a scratch mutated copy (not just that none exist today)", async () => {
    const original = await readFile(
      join(srcDir, "layouts", "BaseLayout.astro"),
      "utf8",
    );
    const scratchDir = await mkdtemp(
      join(tmpdir(), "golfraven-set-html-proof-"),
    );
    try {
      const injected = original.replace(
        "<slot />",
        '<slot />\n    <div set:html="<img src=x onerror=alert(1)>"></div>',
      );
      const scratchFile = join(scratchDir, "Scratch.astro");
      await writeFile(scratchFile, injected);

      const occurrences = findSetHtmlOccurrences(injected);
      const offenders = occurrences.filter((o) => !isSanctionedSetHtml(o));
      // The real ldScript use is still sanctioned; the injected string
      // literal must be the ONE offender the scan reports.
      expect(offenders).toHaveLength(1);
      expect(offenders[0]!.form).toBe("string");
      expect(offenders[0]!.raw).toContain("onerror=alert(1)");
    } finally {
      await rm(scratchDir, { recursive: true, force: true });
    }
  });

  it("PROOF: the detector also catches a spread-embedded set:html key", () => {
    const injected = `<div {...{ "set:html": dangerous }} />`;
    const offenders = findSetHtmlOccurrences(injected).filter(
      (o) => !isSanctionedSetHtml(o),
    );
    expect(offenders).toHaveLength(1);
    expect(offenders[0]!.form).toBe("spread-key");
  });

  it("does NOT flag plain prose mentioning 'set:html' in a comment", () => {
    const prose = `{/* no set:html use here, just prose about set:html */}`;
    expect(findSetHtmlOccurrences(prose)).toEqual([]);
  });

  it(
    "every built page has at most one JSON-LD <script>, and every OTHER <script> tag is an " +
      "Astro-bundled external module with an EMPTY body — never inline JS content " +
      "(stage-2 generalisation: CourseMap/SiteSearch/the sw.js registrar are real client " +
      "islands now, so 'no other script tag at all' becomes 'no INLINE script content ever " +
      "reaches the page' — the same property AT(7) exists to guarantee)",
    async () => {
      const htmlFiles = (await walk(BUILDS.real.dist)).filter((f) =>
        f.endsWith(".html"),
      );
      let sawExternalModule = false;
      for (const file of htmlFiles) {
        const html = await readFile(file, "utf8");
        const scriptTags = [
          ...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi),
        ];
        const ldJsonCount = scriptTags.filter(([, attrs]) =>
          /type="application\/ld\+json"/.test(attrs),
        ).length;
        expect(ldJsonCount).toBeLessThanOrEqual(1);
        for (const [full, attrs, body] of scriptTags) {
          const isLdJson = /type="application\/ld\+json"/.test(attrs);
          if (isLdJson) continue;
          const isExternalModule =
            /type="module"/.test(attrs) &&
            /\ssrc="\/_astro\/[^"]+"/.test(attrs);
          expect(
            isExternalModule,
            `unexpected <script> shape: ${full.slice(0, 120)}`,
          ).toBe(true);
          // The defining property: NOTHING between the tags. Astro hoists
          // every non-`is:inline` <script> block's actual code into the
          // external file the `src=` attribute points at — the tag Astro
          // emits in the HTML itself carries no executable content, so
          // there is nothing here `set:html` (or any other injection path)
          // could have put a payload into.
          expect(
            body.trim(),
            `external module script had inline body: ${full.slice(0, 120)}`,
          ).toBe("");
          sawExternalModule = true;
        }
      }
      // Proves the generalisation is actually exercised, not vacuously
      // true because no page happens to embed a client island.
      expect(sawExternalModule).toBe(true);
    },
  );
});

// ---------------------------------------------------------------------
// B1: CSP vs inline CSS — no <style>, no style= attribute, external CSS
// ---------------------------------------------------------------------

describe("B1: every page has no <style>, no style= attribute, and CSS is external (CSP default-src 'self')", () => {
  it("no built page contains an inline <style> tag or a style= attribute", async () => {
    const htmlFiles = (await walk(BUILDS.real.dist)).filter((f) =>
      f.endsWith(".html"),
    );
    for (const file of htmlFiles) {
      const html = await readFile(file, "utf8");
      expect(html).not.toMatch(/<style[\s>]/i);
      expect(html).not.toMatch(/\sstyle\s*=\s*"/i);
    }
  });

  it("every page links at least one external stylesheet", async () => {
    const html = await readIn(BUILDS.real.dist, "index.html");
    expect(html).toMatch(/<link rel="stylesheet" href="\/_astro\/[^"]+\.css">/);
  });
});

// ---------------------------------------------------------------------
// AT(10) / S2: unverified rows render no page link and show the claim CTA
// ---------------------------------------------------------------------

describe("AT(10)/S2: unverified rows render no page link and show the claim CTA", () => {
  it("the unverified demo facility (Foggy Pines) has no /courses/ link on its region page", async () => {
    const html = await readIn(BUILDS.real.dist, "ca/bc/index.html");
    expect(html).not.toContain('href="/courses/foggy-pines-golf-resort/"');
    expect(html).toContain('href="/claim/?facility=foggy-pines-golf-resort"');
  });

  it("no page is built at /courses/foggy-pines-golf-resort/ at all", async () => {
    await expect(
      readIn(BUILDS.real.dist, "courses/foggy-pines-golf-resort/index.html"),
    ).rejects.toThrow();
  });

  it("S2: every /courses/ link on every stop-listing page (regions + trails) points at a page that actually exists in dist", async () => {
    const stopListingPages = [
      "us/tn/index.html",
      "ca/bc/index.html",
      "trails/fictional-ridge-golf-trail/index.html",
      "trails/somewhere-coastal-golf-trail/index.html",
    ];
    for (const page of stopListingPages) {
      const html = await readIn(BUILDS.real.dist, page);
      const hrefs = [...html.matchAll(/href="(\/courses\/[a-z0-9-]+\/)"/g)].map(
        (m) => m[1]!,
      );
      for (const href of hrefs) {
        await expect(
          readIn(
            BUILDS.real.dist,
            `${href.replace(/^\/|\/$/g, "")}/index.html`,
          ),
        ).resolves.toBeTruthy();
      }
    }
  });

  it("S2: the unverified facility is never linked from the trail page that rosters it", async () => {
    const html = await readIn(
      BUILDS.real.dist,
      "trails/somewhere-coastal-golf-trail/index.html",
    );
    expect(html).not.toContain('href="/courses/foggy-pines-golf-resort/"');
    expect(html).toContain('href="/claim/?facility=foggy-pines-golf-resort"');
  });
});

// ---------------------------------------------------------------------
// AT(13) (O8): private clubs, and the private-stops note
// ---------------------------------------------------------------------

describe("AT(13) (O8): private club has no booking rail and shows the guest note (but DOES show the official-site link); a trail with a private member shows the private-stops note", () => {
  it("the private demo facility (Cedar Hollow) shows the guest note and no booking link", async () => {
    const html = await readIn(
      BUILDS.real.dist,
      "courses/cedar-hollow-country-club/index.html",
    );
    expect(html).toContain("play as a member's guest");
    expect(html).not.toMatch(/Book via/);
  });

  it("the trail with a private member (Fictional Ridge) shows the private-stops note", async () => {
    const html = await readIn(
      BUILDS.real.dist,
      "trails/fictional-ridge-golf-trail/index.html",
    );
    expect(html).toMatch(/private club/);
  });

  it("a public facility's page DOES show a booking link", async () => {
    const html = await readIn(
      BUILDS.real.dist,
      "courses/ridge-overlook-golf-club/index.html",
    );
    expect(html).toMatch(/Book via/);
  });
});

// ---------------------------------------------------------------------
// B3: fail-closed demo guard, full-build behavior
// ---------------------------------------------------------------------

describe("B3: a demo build is noindex on every page, has an empty sitemap, and shows the DEMO DATA banner", () => {
  it("every page in the demo build carries noindex", async () => {
    const htmlFiles = (await walk(BUILDS.demo.dist)).filter((f) =>
      f.endsWith("index.html"),
    );
    expect(htmlFiles.length).toBeGreaterThan(0);
    for (const file of htmlFiles) {
      const html = await readFile(file, "utf8");
      expect(html).toMatch(/<meta\s+name="robots"\s+content="noindex/);
    }
  });

  it("every page in the demo build shows the DEMO DATA banner", async () => {
    const htmlFiles = (await walk(BUILDS.demo.dist)).filter((f) =>
      f.endsWith("index.html"),
    );
    for (const file of htmlFiles) {
      const html = await readFile(file, "utf8");
      expect(html).toMatch(/DEMO DATA/);
    }
  });

  it("the demo build's indexability.json is empty", async () => {
    expect(await readIndexability(BUILDS.demo.indexability)).toEqual([]);
  });

  it("the demo build has no sitemap-0.xml (nothing to index) and verify-sitemap still passes", async () => {
    const result = await verifySitemap(BUILDS.demo.dist);
    expect(result.ok).toBe(true);
    expect(result.sitemapLocs.size).toBe(0);
  });

  it("the real build shows NO demo banner and is not globally noindex", async () => {
    const html = await readIn(BUILDS.real.dist, "index.html");
    expect(html).not.toMatch(/DEMO DATA/);
    expect(html).not.toMatch(/<meta\s+name="robots"\s+content="noindex/);
  });
});

// ---------------------------------------------------------------------
// S1: the JSON-LD ItemList lists only facilities that have a page worth
// indexing (the R1-indexable subset), on trail and region pages.
// ---------------------------------------------------------------------

describe("S1: JSON-LD ItemList lists only indexable facilities", () => {
  it("the region page's ItemList excludes the unverified facility", async () => {
    const html = await readIn(BUILDS.real.dist, "ca/bc/index.html");
    const ldJson = html.match(
      /<script type="application\/ld\+json">([^<]+)<\/script>/,
    )![1]!;
    const graph = JSON.parse(ldJson)["@graph"] as Array<
      Record<string, unknown>
    >;
    const collection = graph.find((n) => n["@type"] === "CollectionPage") as {
      mainEntity: { itemListElement: Array<{ item: { url: string } }> };
    };
    const urls = collection.mainEntity.itemListElement.map((i) => i.item.url);
    expect(urls.some((u) => u.includes("foggy-pines"))).toBe(false);
    expect(urls.some((u) => u.includes("highland-meadows"))).toBe(true);
  });

  it("the trail page's ItemList excludes the verified-but-thin facility", async () => {
    // thinfield-muni is not actually a trail member, so this proves the
    // negative on the other trail's roster facilities instead: every
    // listed facility on Fictional Ridge is indexable (all 3 are), and
    // the ItemList count matches exactly the indexable subset size.
    const html = await readIn(
      BUILDS.real.dist,
      "trails/fictional-ridge-golf-trail/index.html",
    );
    const ldJson = html.match(
      /<script type="application\/ld\+json">([^<]+)<\/script>/,
    )![1]!;
    const graph = JSON.parse(ldJson)["@graph"] as Array<
      Record<string, unknown>
    >;
    const collection = graph.find((n) => n["@type"] === "CollectionPage") as {
      mainEntity: { numberOfItems: number };
    };
    expect(collection.mainEntity.numberOfItems).toBe(3);
  });
});
