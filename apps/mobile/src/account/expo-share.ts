/**
 * `FileSharer` over `expo-file-system` 57.0.7 (the `File` / `Directory` / `Paths` API) and `expo-sharing` 57.0.21. Imported only by the composition
 * root. The logic (what is deleted, when) is `createCacheFileSharer` in `export.ts`, tested there against a fake cache; this file only adapts the
 * two Expo packages. Type-checked against the packages' `.d.ts`; never run on a device `[unverified]`.
 */
import { Directory, File, Paths } from "expo-file-system";
import * as Sharing from "expo-sharing";
import { createCacheFileSharer, type ExportCache, type FileSharer } from "./export";

function expoExportCache(): ExportCache {
  return {
    listNames: () =>
      new Directory(Paths.cache)
        .list()
        .filter((e): e is File => e instanceof File)
        .map((f) => f.name),
    remove: (name) => {
      const f = new File(Paths.cache, name);
      if (f.exists) f.delete();
    },
    write: (name, content) => {
      const f = new File(Paths.cache, name);
      if (f.exists) f.delete();
      f.create();
      f.write(content);
      return f.uri;
    },
  };
}

export function createExpoFileSharer(): FileSharer {
  return createCacheFileSharer(expoExportCache(), {
    isAvailable: () => Sharing.isAvailableAsync(),
    share: (uri, filename) => Sharing.shareAsync(uri, { mimeType: "application/json", UTI: "public.json", dialogTitle: filename }),
  });
}
