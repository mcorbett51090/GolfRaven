/**
 * Build-time app configuration. Values come from Expo's public env
 * (`EXPO_PUBLIC_*`, inlined by Metro at build time — written as
 * `process.env.EXPO_PUBLIC_X`, the static form Expo's Babel preset inlines)
 * — never a secret: the catalog is public data and the keyset is public keys.
 */
import Constants from "expo-constants";
import { SUPPORTED_CONTRACT_MAJOR, parseCatalogBaseUrl, parseStoreUrl } from "./config-values";

export { SUPPORTED_CONTRACT_MAJOR, parseCatalogBaseUrl } from "./config-values";

export interface AppConfig {
  /** Where `catalog/v1/` is served from; `null` = no network catalog. */
  catalogBaseUrl: string | null;
  /** The running build's version (`app.json` `version`), compared with the
   * manifest's `minAppVersion`. */
  appVersion: string;
  /** The contract MAJOR this build reads (`CONTRACT_VERSION` in
   * `@golfraven/catalog`; pinned equal by `test/config.test.ts`). The M-freeze
   * moves it to 1. */
  supportedContractMajor: number;
  /** Where the force-update screen sends the player. */
  storeUrl: string | null;
}

export function readAppConfig(): AppConfig {
  return {
    catalogBaseUrl: parseCatalogBaseUrl(process.env.EXPO_PUBLIC_CATALOG_BASE_URL, { allowLocalHttp: __DEV__ }),
    appVersion: Constants.expoConfig?.version ?? "0.0.0",
    supportedContractMajor: SUPPORTED_CONTRACT_MAJOR,
    storeUrl: parseStoreUrl(process.env.EXPO_PUBLIC_STORE_URL),
  };
}
