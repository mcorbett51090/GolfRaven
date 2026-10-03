/**
 * `FileSharer` over `expo-file-system` 57.0.7 (the `File` / `Paths` API) and `expo-sharing` 57.0.21. Imported only by the composition root.
 * Type-checked against the packages' `.d.ts`; never run on a device `[unverified]`.
 */
import { File, Paths } from "expo-file-system";
import * as Sharing from "expo-sharing";
import type { FileSharer } from "./export";

export function createExpoFileSharer(): FileSharer {
  return {
    async shareJson(filename, content) {
      if (!(await Sharing.isAvailableAsync())) return "unavailable";
      const file = new File(Paths.cache, filename);
      try {
        if (file.exists) file.delete();
        file.create();
        file.write(content);
        await Sharing.shareAsync(file.uri, { mimeType: "application/json", UTI: "public.json", dialogTitle: filename });
        return "shared";
      } finally {
        try {
          if (file.exists) file.delete();
        } catch {
          // the cache directory is purgeable by the OS regardless
        }
      }
    },
  };
}
