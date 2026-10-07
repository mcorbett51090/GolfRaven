#!/usr/bin/env node
// @ts-check
/**
 * build.mjs - builds `apps/partners` into a static bundle (`dist/`): `index.html`, hashed `assets/*.js` and `assets/*.css`, the manifest, the favicon and
 * a generated `_headers` carrying the CSP. No framework: plain TypeScript bundled by esbuild (see README "Stack").
 *
 * Environment:
 *   GOLFRAVEN_PARTNERS_API_BASE   the functions root of the partners API (default: a placeholder, see lib/config.mjs). Baked into the bundle and into the CSP.
 *   GOLFRAVEN_ENV=production      refuses the placeholder API host.
 *   DIST_DIR (or argv[2])         the output directory (default: ./dist).
 *   GOLFRAVEN_PARTNERS_E2E=1      the Playwright build only: accepts a loopback http API origin and also builds the test harness page.
 *
 * The last step scans the output (lib/scan-output.mjs); a finding fails the build.
 */
import { build } from "esbuild";
import { cp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { resolveApiBase } from "./lib/config.mjs";
import { buildCsp, buildHeadersFile } from "./lib/csp.mjs";
import { scanDist } from "./lib/scan-output.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

/**
 * @param {{ dist: string, env?: NodeJS.ProcessEnv }} opts
 * @returns {Promise<{ apiBase: string, apiOrigin: string, files: string[] }>}
 */
export async function buildPartners({ dist, env = process.env }) {
  const e2e = env["GOLFRAVEN_PARTNERS_E2E"] === "1";
  const { base, origin } = resolveApiBase(env["GOLFRAVEN_PARTNERS_API_BASE"], { allowLoopback: e2e, production: env["GOLFRAVEN_ENV"] === "production" });

  await rm(dist, { recursive: true, force: true });
  await mkdir(dist, { recursive: true });

  /** @type {Record<string, string>} */
  const entryPoints = { app: "src/main.ts", styles: "src/styles.css" };
  if (e2e) entryPoints["harness"] = "test/e2e/harness/harness.ts";

  const result = await build({
    absWorkingDir: root,
    entryPoints,
    outdir: join(dist, "assets"),
    entryNames: "[name]-[hash]",
    bundle: true,
    format: "esm",
    target: "es2022",
    platform: "browser",
    minify: true,
    sourcemap: false,
    legalComments: "none",
    metafile: true,
    logLevel: "warning",
    define: { __GR_PARTNERS_API_BASE__: JSON.stringify(base) },
  });

  /** The hashed output file of an entry point, as a page-relative URL. @param {string} entry the entry's path relative to the package root */
  const outputFor = (entry) => {
    const hit = Object.entries(result.metafile.outputs).find(([, o]) => o.entryPoint === entry);
    if (!hit) throw new Error(`no esbuild output for ${entry}`);
    return `./assets/${hit[0].split("/").pop()}`;
  };
  const scriptHref = outputFor("src/main.ts");
  const styleHref = outputFor("src/styles.css");

  const metaCsp = buildCsp(origin, { meta: true });
  const page = async (/** @type {string} */ template, /** @type {Record<string, string>} */ vars) => {
    let html = await readFile(join(root, template), "utf8");
    for (const [k, v] of Object.entries(vars)) html = html.replaceAll(`%${k}%`, v);
    return html;
  };
  await writeFile(join(dist, "index.html"), await page("index.html", { CSP_META: metaCsp, SCRIPT: scriptHref, STYLE: styleHref }));
  if (e2e) {
    await writeFile(join(dist, "harness.html"), await page("test/e2e/harness/harness.html", { CSP_META: metaCsp, SCRIPT: outputFor("test/e2e/harness/harness.ts"), STYLE: styleHref }));
  }
  await cp(join(root, "public"), dist, { recursive: true });
  await writeFile(join(dist, "_headers"), buildHeadersFile(origin));

  const findings = await scanDist(dist, { apiOrigin: origin, harness: e2e });
  if (findings.length > 0) {
    const lines = findings.map((f) => `  ${f.file}: ${f.rule} (${f.detail})`).join("\n");
    throw new Error(`build-output scan failed:\n${lines}`);
  }
  return { apiBase: base, apiOrigin: origin, files: Object.keys(result.metafile.outputs) };
}

const isMain = process.argv[1] !== undefined && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  const dist = process.env["DIST_DIR"] ?? process.argv[2] ?? join(root, "dist");
  const r = await buildPartners({ dist });
  console.log(`partners: built ${dist} (API ${r.apiBase})`);
}
