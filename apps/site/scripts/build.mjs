#!/usr/bin/env node
// P0 placeholder build for @golfraven/site.
//
// The real site is Astro 5 static (build plan §3.1 row C), ported from
// southern-wine-country in P2 (build plan §5). Pulling in Astro now would
// slow the P0 skeleton's install for no benefit, so this script just
// proves `pnpm -r build` can succeed for this workspace by writing a
// trivial placeholder page to dist/.
import { mkdir, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const distDir = join(here, "..", "dist");

await mkdir(distDir, { recursive: true });
await writeFile(
  join(distDir, "index.html"),
  `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>GolfRaven — site placeholder</title>
  </head>
  <body>
    <p>apps/site is a P0 placeholder. The real Astro 5 site ports from
    southern-wine-country in P2 (build plan §5).</p>
  </body>
</html>
`,
);

console.log("@golfraven/site: wrote placeholder dist/index.html");
