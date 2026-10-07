/** Supported UI locales (build plan §7.1 "i18n `en`, `fr-CA`"), the same two as apps/mobile. */
export const LOCALES = ["en", "fr-CA"] as const;
export type Locale = (typeof LOCALES)[number];
export const DEFAULT_LOCALE: Locale = "en";

/**
 * Picks the UI locale from the browser's preferred-language tags (BCP-47, most preferred first). Every French variant maps to `fr-CA`, the
 * only French catalogue shipped; anything else is `en`. An explicit choice made on the page wins. Nothing is stored: a reload starts again
 * from the browser's own preference, because this app writes to no storage API at all (design 4.6).
 */
export function resolveLocale(tags: readonly string[], explicit?: Locale | null): Locale {
  if (explicit) return explicit;
  for (const tag of tags) {
    const lang = tag.toLowerCase().split(/[-_]/)[0];
    if (lang === "fr") return "fr-CA";
    if (lang === "en") return "en";
  }
  return DEFAULT_LOCALE;
}
