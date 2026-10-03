/**
 * Me → Export my data (`GET me-export`). The server returns the caller's personal data as JSON; this hands it to the player through the
 * system share sheet as a `.json` file.
 *
 * The file is written to the app's CACHE directory (private to the app), shared, and DELETED again in a `finally`, so the export (personal data)
 * never outlives the share, even if the sheet throws. Nothing is logged; the content is never put in an error message. A text-only share was
 * rejected because the export can be megabytes (the server documents an 8 MiB ceiling) and the Android share intent cannot carry that.
 */
import type { ApiClient, ExportResult } from "../api/types";

/** Writes `content` to a private temp file, shows the share sheet for it, and removes the file. `unavailable` = no share sheet on this device. */
export interface FileSharer {
  shareJson(filename: string, content: string): Promise<"shared" | "unavailable">;
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
