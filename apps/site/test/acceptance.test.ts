/**
 * The stage-1 acceptance tests named in this repo's stage-1 instructions
 * (build plan §10 P2's AT numbering): AT(1), AT(3), AT(6), AT(7), AT(10),
 * AT(13). Runs against the real `dist/` produced by `test/global-setup.mjs`
 * (a real `astro build` with the synthetic demo catalog forced on).
 */
import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const siteRoot = fileURLToPath(new URL("..", import.meta.url));
const distDir = join(siteRoot, "dist");
const srcDir = join(siteRoot, "src");

async function readDist(relPath: string): Promise<string> {
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

describe("AT(1): sitemap <loc> set = indexable set", () => {
  it("the sitemap's /courses/ <loc> set equals build/indexability.json exactly", async () => {
    const indexability = JSON.parse(
      await readFile(join(siteRoot, "build", "indexability.json"), "utf8"),
    ) as { indexablePaths: string[] };

    const sitemap = await readDist("sitemap-0.xml");
    const locs = [...sitemap.matchAll(/<loc>([^<]+)<\/loc>/g)].map((m) => new URL(m[1]!).pathname);
    const sitemapCoursePaths = locs.filter((p) => p.startsWith("/courses/"));

    expect(new Set(sitemapCoursePaths)).toEqual(new Set(indexability.indexablePaths));
    // And every generated course page IS in the sitemap set (never a
    // course page the sitemap silently drops).
    expect(sitemapCoursePaths.length).toBeGreaterThan(0);
  });

  it("the claim page (utility, noindex) is never in the sitemap", async () => {
    const sitemap = await readDist("sitemap-0.xml");
    expect(sitemap).not.toMatch(/\/claim\//);
  });
});

describe("AT(3): hub HTML < 300 KB", () => {
  it("dist/index.html is under 300 KB", async () => {
    const html = await readDist("index.html");
    const bytes = Buffer.byteLength(html, "utf8");
    expect(bytes).toBeLessThan(300 * 1024);
  });
});

describe("AT(6): JS off — every verified course reachable from its region page", () => {
  it("every indexable facility's course page is linked from its region's directory page", async () => {
    const indexability = JSON.parse(
      await readFile(join(siteRoot, "build", "indexability.json"), "utf8"),
    ) as { indexablePaths: string[] };

    // Demo dataset facts (fixtures/demo-catalog/bundle.json): US-TN
    // facilities render at /us/tn/, CA-BC at /ca/bc/.
    const regionPages = ["us/tn/index.html", "ca/bc/index.html"];
    const regionHtml = (await Promise.all(regionPages.map((p) => readDist(p)))).join("\n");

    for (const coursePath of indexability.indexablePaths) {
      expect(regionHtml).toContain(`href="${coursePath}"`);
    }
  });
});

describe("AT(7): no set:html outside jsonLdScript()", () => {
  it("every set:html in the .astro source tree renders schema.ts's jsonLdScript() output", async () => {
    const files = (await walk(srcDir)).filter((f) => f.endsWith(".astro"));
    const offenders: string[] = [];
    for (const file of files) {
      const content = await readFile(file, "utf8");
      const matches = [...content.matchAll(/set:html=\{([^}]*)\}/g)];
      for (const m of matches) {
        const expr = m[1]!.trim();
        // The only sanctioned shape: `ldScript` (BaseLayout's local const,
        // itself `jsonLdScript(jsonLd)` or ""). Anything else is a second
        // set:html use.
        if (expr !== "ldScript") {
          offenders.push(`${file}: set:html={${expr}}`);
        }
      }
    }
    expect(offenders).toEqual([]);
  });

  it("BaseLayout's ldScript is built from schema.ts's jsonLdScript()", async () => {
    const layout = await readFile(join(srcDir, "layouts", "BaseLayout.astro"), "utf8");
    expect(layout).toMatch(/const ldScript = jsonLd\.length \? jsonLdScript\(jsonLd\) : ""/);
  });

  it("every built page has at most one JSON-LD <script> tag", async () => {
    const htmlFiles = (await walk(distDir)).filter((f) => f.endsWith(".html"));
    for (const file of htmlFiles) {
      const html = await readFile(file, "utf8");
      const count = (html.match(/<script type="application\/ld\+json">/g) ?? []).length;
      expect(count).toBeLessThanOrEqual(1);
    }
  });
});

describe("AT(10): unverified rows render no page link and show the claim CTA", () => {
  it("the unverified demo facility (Foggy Pines) has no /courses/ link on its region page", async () => {
    const html = await readDist("ca/bc/index.html");
    expect(html).not.toContain('href="/courses/foggy-pines-golf-resort/"');
    expect(html).toContain('href="/claim/?facility=foggy-pines-golf-resort"');
  });

  it("no page is built at /courses/foggy-pines-golf-resort/ at all", async () => {
    await expect(readDist("courses/foggy-pines-golf-resort/index.html")).rejects.toThrow();
  });
});

describe("AT(13) (O8): private club has no booking rail and shows the guest note; a trail with a private member shows the private-stops note", () => {
  it("the private demo facility (Cedar Hollow) shows the guest note and no booking link", async () => {
    const html = await readDist("courses/cedar-hollow-country-club/index.html");
    expect(html).toContain("play as a member's guest");
    expect(html).not.toMatch(/Book on/);
  });

  it("the trail with a private member (Fictional Ridge) shows the private-stops note", async () => {
    const html = await readDist("trails/fictional-ridge-golf-trail/index.html");
    expect(html).toMatch(/private club/);
  });

  it("a public facility's page DOES show a booking link", async () => {
    const html = await readDist("courses/ridge-overlook-golf-club/index.html");
    expect(html).toMatch(/Book on/);
  });
});
