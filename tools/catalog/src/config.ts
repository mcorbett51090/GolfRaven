/**
 * The booking-host allow-list — a committed, out-of-band config file
 * (`config/booking-hosts.json`), never something a bundle can assert about
 * itself (see `bundle.ts`'s module doc for why that matters). Decision
 * 0003 S2 names this as a "fixture allow-list" until the real contents are
 * settled by X4/X6 (build plan §10 P1); `config/booking-hosts.json` is
 * that fixture list today, synthetic hosts only.
 */
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";

export const BookingHostConfigSchema = z.strictObject({
  _comment: z.string().optional(),
  /** true while the list is a placeholder (X4/X6 pending); a production
   * site build refuses unless this is explicitly false. */
  synthetic: z.boolean().optional(),
  hosts: z.array(z.string().min(1)),
});
export type BookingHostConfig = z.infer<typeof BookingHostConfigSchema>;

/** Repo-root-relative default path, resolved from this module's own file
 * location (works from any `cwd`) — same pattern as
 * `verify-contract.ts`'s `defaultContractPath`. */
export function defaultBookingHostsConfigPath(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  // dist/config.js -> tools/catalog/dist -> up 3 = repo root.
  return join(here, "..", "..", "..", "config", "booking-hosts.json");
}

export async function loadBookingHostAllowList(path?: string): Promise<string[]> {
  const configPath = path ?? defaultBookingHostsConfigPath();
  const raw = JSON.parse(await readFile(configPath, "utf8"));
  const parsed = BookingHostConfigSchema.parse(raw);
  return parsed.hosts;
}
