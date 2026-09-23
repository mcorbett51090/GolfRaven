#!/usr/bin/env node
// Copies apps/landing/src/* verbatim to apps/landing/dist/.
//
// The landing page is deliberately dependency-free (no bundler, no
// framework), so "build" is just "publish these static files" —
// wrangler/Cloudflare Pages (or any static host) can serve dist/ as-is.
import { cp, mkdir, rm } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const srcDir = join(here, "..", "src");
const distDir = join(here, "..", "dist");

await rm(distDir, { recursive: true, force: true });
await mkdir(distDir, { recursive: true });
await cp(srcDir, distDir, { recursive: true });

console.log(`@golfraven/landing: copied ${srcDir} -> ${distDir}`);
