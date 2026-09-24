/**
 * og-store.ts — a local stand-in for the §5.2 R2 object store ("OG PNGs
 * are stored in an object store (Cloudflare R2) keyed by content hash,
 * not in `actions/cache` ... A build fetches existing cards and renders
 * only cards whose hash is missing"). Deploy/R2 wiring is out of stage-2
 * scope (this repo's own "Out of scope: ... deploy"); this module gives
 * the SAME cache-by-content-hash contract locally, backed by a directory
 * (`GOLFRAVEN_OG_STORE_DIR`), so a real R2 client can be swapped in later
 * behind the same three functions without touching the OG endpoint.
 *
 * **AT9's "simulated empty OG store"**: `GOLFRAVEN_OG_STORE_SIMULATE_EMPTY=1`
 * makes `storeAvailable()` report false regardless of the directory's real
 * state — standing in for "R2 is unreachable this build" (a network
 * outage, a misconfigured bucket) rather than "R2 is reachable but has 0
 * matching keys yet" (the normal cold-cache case, which just means every
 * card renders fresh — not a failure at all, and not what AT9 is about).
 * `og/courses/[slug].png.ts` reads `storeAvailable()` once and falls back
 * to the template card for the whole build when it's false — never
 * per-request, since a real R2 outage doesn't recover mid-build either.
 */
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join } from "node:path";

export function ogStoreDir(env: NodeJS.ProcessEnv = process.env): string {
  return env.GOLFRAVEN_OG_STORE_DIR ?? join(process.cwd(), ".og-store");
}

/** False only when the store is unreachable this build (AT9) — a real,
 * empty-but-reachable directory still counts as "available" (every card
 * simply misses cache and renders fresh, §5.2's normal cold-cache case). */
export function storeAvailable(env: NodeJS.ProcessEnv = process.env): boolean {
  if (env.GOLFRAVEN_OG_STORE_SIMULATE_EMPTY === "1") return false;
  return true;
}

export async function readCachedCard(
  hash: string,
  env: NodeJS.ProcessEnv = process.env,
): Promise<Buffer | null> {
  const path = join(ogStoreDir(env), `${hash}.png`);
  if (!existsSync(path)) return null;
  try {
    return await readFile(path);
  } catch {
    return null;
  }
}

export async function writeCachedCard(
  hash: string,
  buffer: Buffer,
  env: NodeJS.ProcessEnv = process.env,
): Promise<void> {
  const dir = ogStoreDir(env);
  await mkdir(dir, { recursive: true });
  await writeFile(join(dir, `${hash}.png`), buffer);
}
