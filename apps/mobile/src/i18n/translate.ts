import { en, type MessageKey } from "./messages/en";
import { frCA } from "./messages/fr-CA";
import type { Locale } from "./locale";

export type { MessageKey } from "./messages/en";

const CATALOGUES: Record<Locale, Record<MessageKey, string>> = { en, "fr-CA": frCA };

export type Params = Readonly<Record<string, string | number>>;

/** Keys written `base.one` / `base.other` — selected by `plural`. */
export type PluralBase = {
  [K in MessageKey]: K extends `${infer B}.one` ? B : never;
}[MessageKey];

function interpolate(template: string, params?: Params): string {
  if (!params) return template;
  return template.replace(/\{(\w+)\}/g, (whole, name: string) => {
    const v = params[name];
    return v === undefined ? whole : String(v);
  });
}

/** Plain lookup with `{name}` interpolation. A missing key never throws in
 * production: it falls back to English, then to the key itself (so a gap is
 * visible rather than blank); `test/i18n.test.ts` guarantees there are none. */
export function translate(locale: Locale, key: MessageKey, params?: Params): string {
  return interpolate(CATALOGUES[locale][key] ?? en[key] ?? key, params);
}

/** CLDR-style category for a count: English `one` is exactly 1; French `one`
 * covers 0 and 1 (and any fraction below 2). Hand-rolled, not
 * `Intl.PluralRules`, so it does not depend on Hermes' Intl coverage
 * `[unverified — training knowledge on Hermes Intl.PluralRules for fr-CA]`. */
export function pluralCategory(locale: Locale, count: number): "one" | "other" {
  if (locale === "fr-CA") return count >= 0 && count < 2 ? "one" : "other";
  return count === 1 ? "one" : "other";
}

export function plural(locale: Locale, base: PluralBase, count: number, params?: Params): string {
  const key = `${base}.${pluralCategory(locale, count)}` as MessageKey;
  return interpolate(CATALOGUES[locale][key] ?? en[key] ?? key, { count, ...params });
}

export const catalogues = CATALOGUES;
