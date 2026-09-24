#!/usr/bin/env node
/**
 * gen-app-icons.mjs — minimal, functional PWA icons for
 * `manifest.webmanifest` (stage-2 scope item 5: "Adapt `sw.js` and
 * `manifest.webmanifest`: cache `gr-v1`, app name 'GolfRaven'.").
 *
 * The full brand pipeline (§5.6: `brand-geometry.mjs`'s pin/ring/regime
 * gates, `BRAND.md`, `verify-brand-renderings.mjs`) is its own P2 brand
 * sub-run and explicitly out of THIS stage's scope list — but a manifest
 * that references icon files which don't exist is a real, easily-avoided
 * defect (an uninstallable PWA), not a brand decision. This writes small,
 * honestly-placeholder icons (a plain golf-flag glyph on the same fairway
 * green `og-card.ts` uses) using `sharp` (already a pinned dependency for
 * OG cards) so the manifest is genuinely valid today; the real brand
 * sub-run replaces these files wholesale later without touching the
 * manifest/sw.js that reference them.
 */
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import sharp from "sharp";

const here = dirname(fileURLToPath(import.meta.url));
const OUT_DIR = process.env.APP_ICONS_OUT_DIR ?? join(here, "..", "public");

const GREEN = "#1f4d3a";
const GOLD = "#c9a227";

/** Same golf-flag glyph `og-card.ts` uses (own geometry, no imagery of any
 * real course) — centred in a square so it rasterizes cleanly at every
 * icon size, including the maskable safe-zone. */
function iconSvg(size, { maskableSafeZone = false } = {}) {
  const pad = maskableSafeZone ? size * 0.1 : 0;
  const inner = size - pad * 2;
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 ${size} ${size}">
    <rect width="${size}" height="${size}" fill="${GREEN}"/>
    <g transform="translate(${pad},${pad}) scale(${inner / 64})">
      <circle cx="32" cy="54" r="4" fill="${GOLD}"/>
      <rect x="30.5" y="10" width="3" height="44" rx="1.2" fill="${GOLD}"/>
      <path d="M33.5 12 L54 20 L33.5 28 Z" fill="#ffffff" stroke="${GOLD}" stroke-width="1.4" stroke-linejoin="round"/>
    </g>
  </svg>`;
}

async function main() {
  await mkdir(OUT_DIR, { recursive: true });

  const targets = [
    { file: "icon-192.png", size: 192 },
    { file: "icon-512.png", size: 512 },
    { file: "icon-maskable-512.png", size: 512, maskableSafeZone: true },
    { file: "apple-touch-icon.png", size: 180 },
  ];
  for (const t of targets) {
    const svg = iconSvg(t.size, { maskableSafeZone: t.maskableSafeZone });
    await sharp(Buffer.from(svg)).png().toFile(join(OUT_DIR, t.file));
  }

  // favicon.svg — vector, scales natively; no rasterization needed.
  await writeFile(join(OUT_DIR, "favicon.svg"), iconSvg(64));

  console.log(`gen-app-icons: wrote ${targets.length + 1} icon file(s) to ${OUT_DIR}`);
}

await main();
