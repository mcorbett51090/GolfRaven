/**
 * Build-time app configuration. Values come from Expo's public env
 * (`EXPO_PUBLIC_*`, inlined by Metro at build time — written as
 * `process.env.EXPO_PUBLIC_X`, the static form Expo's Babel preset inlines)
 * — never a secret: the catalog is public data, the keyset is public keys, and the Supabase key is the PUBLIC anon/publishable one.
 */
import Constants from "expo-constants";
import { SUPPORTED_CONTRACT_MAJOR, parseApiBaseUrl, parseCatalogBaseUrl, parsePlayCloudProjectNumber, parseStoreUrl, parseSupabaseAnonKey, parseSupabaseUrl } from "./config-values";

export { SUPPORTED_CONTRACT_MAJOR, parseApiBaseUrl, parseCatalogBaseUrl, parseSupabaseAnonKey, parseSupabaseUrl } from "./config-values";

export interface AppConfig {
  /** Where `catalog/v1/` is served from; `null` = no network catalog. */
  catalogBaseUrl: string | null;
  /** The running build's version (`app.json` `version`), compared with the
   * manifest's `minAppVersion`. */
  appVersion: string;
  /** The contract MAJOR this build reads (`CONTRACT_VERSION` in
   * `@golfraven/catalog`; pinned equal by `test/wallet-config.test.ts`). The M-freeze
   * moves it to 1. */
  supportedContractMajor: number;
  /** Where the force-update screen sends the player. */
  storeUrl: string | null;
  /** The Edge Functions root (`EXPO_PUBLIC_API_BASE_URL`); `null` = no network API. */
  apiBaseUrl: string | null;
  /** The Supabase project URL and PUBLIC key for Auth (`EXPO_PUBLIC_SUPABASE_URL` / `EXPO_PUBLIC_SUPABASE_ANON_KEY`). Both public by design. */
  supabaseUrl: string | null;
  supabaseAnonKey: string | null;
  /** `EXPO_PUBLIC_PLAY_CLOUD_PROJECT_NUMBER`: the Cloud project number Play Integrity requests are made for (public). `null` = Android cannot attest. */
  playCloudProjectNumber: string | null;
}

export function readAppConfig(): AppConfig {
  return {
    catalogBaseUrl: parseCatalogBaseUrl(process.env.EXPO_PUBLIC_CATALOG_BASE_URL, { allowLocalHttp: __DEV__ }),
    appVersion: Constants.expoConfig?.version ?? "0.0.0",
    supportedContractMajor: SUPPORTED_CONTRACT_MAJOR,
    storeUrl: parseStoreUrl(process.env.EXPO_PUBLIC_STORE_URL),
    apiBaseUrl: parseApiBaseUrl(process.env.EXPO_PUBLIC_API_BASE_URL, { allowLocalHttp: __DEV__ }),
    supabaseUrl: parseSupabaseUrl(process.env.EXPO_PUBLIC_SUPABASE_URL, { allowLocalHttp: __DEV__ }),
    supabaseAnonKey: parseSupabaseAnonKey(process.env.EXPO_PUBLIC_SUPABASE_ANON_KEY),
    playCloudProjectNumber: parsePlayCloudProjectNumber(process.env.EXPO_PUBLIC_PLAY_CLOUD_PROJECT_NUMBER),
  };
}
