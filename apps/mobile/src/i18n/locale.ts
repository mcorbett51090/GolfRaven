/**
 * Supported UI locales (build plan §7.1 "i18n `en`, `fr-CA`"). The catalog
 * itself carries `nameFr` / `blurbFr` (§4.1) so content localizes with the UI.
 */
export const LOCALES = ["en", "fr-CA"] as const;
export type Locale = (typeof LOCALES)[number];
export const DEFAULT_LOCALE: Locale = "en";

/** Picks the UI locale from the device's preferred-language tags
 * (BCP-47, most preferred first). Every French variant (fr, fr-FR, fr-CH …)
 * maps to `fr-CA`, the only French catalogue shipped; anything else is `en`.
 * An explicit user choice, if any, is applied by the caller and wins. */
export function resolveLocale(deviceTags: readonly string[], explicit?: Locale | null): Locale {
  if (explicit) return explicit;
  for (const tag of deviceTags) {
    const lang = tag.toLowerCase().split(/[-_]/)[0];
    if (lang === "fr") return "fr-CA";
    if (lang === "en") return "en";
  }
  return DEFAULT_LOCALE;
}
