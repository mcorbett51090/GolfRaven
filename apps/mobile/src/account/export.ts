/**
 * Me → Export my data (`GET me-export`). The server returns the caller's personal data as JSON; this hands it to the player through the
 * system share sheet as a `.json` file.
 *
 * The file is written to the app's CACHE directory (private to the app) under a date-only name and shared. It is NOT deleted when the share sheet
 * returns: on Android the receiving app may read the URI after the sheet has closed (deleting it then can hand that app an empty or missing file).
 * Instead every export file still in the cache is deleted at the NEXT export and at app start (`purgeStaleExports`), so the personal data
 * lingers at most until then (and the OS may purge the cache sooner). Nothing is logged; the content is never put in an error message. A
 * text-only share was rejected because the export can be megabytes (the server documents an 8 MiB ceiling) and the Android share intent cannot
 * carry that.
 */
import type { ApiClient, ExportResult } from "../api/types";

/** Writes `content` to a private cache file and shows the share sheet for it. The file is left in place for the receiving app (see above) and is
 * removed by the next `shareJson` or `purgeStale`. `unavailable` = no share sheet on this device. */
export interface FileSharer {
  shareJson(filename: string, content: string): Promise<"shared" | "unavailable">;
  /** Deletes export files left by an earlier export. Best effort: never throws. Called once at app start. */
  purgeStale(): Promise<void>;
}

/** Exactly the names `exportFileName` makes. Anything else in the cache is not ours and is never touched. */
export const EXPORT_FILE_PATTERN = /^golfraven-export-\d{4}-\d{2}-\d{2}\.json$/;
export function isExportFileName(name: string): boolean {
  return EXPORT_FILE_PATTERN.test(name);
}

/** The app's private cache directory, as far as exports are concerned (`expo-share.ts` adapts `expo-file-system`; tests use a fake). */
export interface ExportCache {
  listNames(): string[];
  remove(name: string): void;
  /** Creates (or replaces) the file and returns its URI. */
  write(name: string, content: string): string;
}

/** Deletes every export file in the cache; a file that cannot be deleted does not stop the rest. Returns how many were removed. */
export function purgeStaleExports(cache: ExportCache): number {
  let removed = 0;
  let names: string[];
  try {
    names = cache.listNames();
  } catch {
    return 0;
  }
  for (const name of names) {
    if (!isExportFileName(name)) continue;
    try {
      cache.remove(name);
      removed += 1;
    } catch {
      // the OS purges the cache directory regardless; try again next time
    }
  }
  return removed;
}

/** The sharer: purge older exports, write the new one, share it, and LEAVE it (the receiving app may still be reading it). */
export function createCacheFileSharer(cache: ExportCache, system: { isAvailable(): Promise<boolean>; share(uri: string, filename: string): Promise<void> }): FileSharer {
  return {
    async shareJson(filename, content) {
      if (!(await system.isAvailable())) return "unavailable";
      purgeStaleExports(cache);
      const uri = cache.write(filename, content);
      await system.share(uri, filename);
      return "shared";
    },
    purgeStale() {
      purgeStaleExports(cache);
      return Promise.resolve();
    },
  };
}

export type ExportOutcome = { status: "shared"; bytes: number } | { status: "unavailable" } | { status: "failed"; stage: "fetch" | "share"; error: unknown };

/** `golfraven-export-2026-10-03.json` (a date only: nothing personal in the file name). */
export function exportFileName(now: Date): string {
  return `golfraven-export-${now.toISOString().slice(0, 10)}.json`;
}

export function serializeExport(result: ExportResult): string {
  return JSON.stringify(result, null, 2);
}

export async function exportAndShare(deps: { api: Pick<ApiClient, "exportData">; sharer: FileSharer; now?: () => Date }): Promise<ExportOutcome> {
  let result: ExportResult;
  try {
    result = await deps.api.exportData();
  } catch (error) {
    return { status: "failed", stage: "fetch", error };
  }
  const content = serializeExport(result);
  try {
    const r = await deps.sharer.shareJson(exportFileName((deps.now ?? (() => new Date()))()), content);
    return r === "shared" ? { status: "shared", bytes: content.length } : { status: "unavailable" };
  } catch (error) {
    return { status: "failed", stage: "share", error };
  }
}
