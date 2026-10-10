#!/usr/bin/env node
/**
 * gen-applinks.mjs — writes Apple AASA + Android assetlinks into `<dist>/.well-known/`
 * after `astro build` (P5 §54). Team ID and Play cert SHA-256 are deploy-time env only
 * (never committed); when unset, files still ship with empty details so the paths exist
 * and Content-Type can be asserted, but OS verification will not claim the app yet.
 *
 * Env:
 *   GOLFRAVEN_APPLE_TEAM_ID — 10-char Apple Team ID → AASA appID `TEAMID.com.golfraven.app`
 *   GOLFRAVEN_PLAY_CERT_SHA256 — colon-hex SHA-256 of the Play signing cert
 */
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const PACKAGE = "com.golfraven.app";
const PATHS = ["/q/m", "/q/m/", "/q/f/*"];

/** @param {string | undefined} teamId */
export function buildAasa(teamId) {
  const trimmed = (teamId ?? "").trim();
  const details =
    /^[A-Z0-9]{10}$/.test(trimmed)
      ? [{ appID: `${trimmed}.${PACKAGE}`, paths: PATHS }]
      : [];
  return {
    applinks: {
      apps: [],
      details,
    },
  };
}

/** @param {string | undefined} sha256 */
export function buildAssetLinks(sha256) {
  const fp = (sha256 ?? "").trim().toUpperCase();
  if (!/^[0-9A-F]{2}(:[0-9A-F]{2}){31}$/.test(fp)) return [];
  return [
    {
      relation: ["delegate_permission/common.handle_all_urls"],
      target: {
        namespace: "android_app",
        package_name: PACKAGE,
        sha256_cert_fingerprints: [fp],
      },
    },
  ];
}

/** Rewrite so any `/q/f/<slug>` hits the static bounce page (trailing-slash site). */
export const QF_REWRITE = "/q/f/*  /q/f/  200\n";

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  const distDir = process.env.DIST_DIR ?? process.argv[2] ?? join(here, "..", "dist");
  const dir = join(distDir, ".well-known");
  await mkdir(dir, { recursive: true });
  const aasa = buildAasa(process.env.GOLFRAVEN_APPLE_TEAM_ID);
  const asset = buildAssetLinks(process.env.GOLFRAVEN_PLAY_CERT_SHA256);
  await writeFile(join(dir, "apple-app-site-association"), JSON.stringify(aasa, null, 2) + "\n");
  await writeFile(join(dir, "assetlinks.json"), JSON.stringify(asset, null, 2) + "\n");
  const redirectsPath = join(distDir, "_redirects");
  const { readFile } = await import("node:fs/promises");
  let existing = "";
  try {
    existing = await readFile(redirectsPath, "utf8");
  } catch {
    existing = "";
  }
  if (!existing.includes("/q/f/*")) {
    await writeFile(redirectsPath, existing + (existing.endsWith("\n") || existing.length === 0 ? "" : "\n") + QF_REWRITE);
  }
  console.log(
    `gen-applinks: wrote ${dir} (AASA details=${aasa.applinks.details.length}, assetlinks=${asset.length}); ensured /q/f/* rewrite`,
  );
}
