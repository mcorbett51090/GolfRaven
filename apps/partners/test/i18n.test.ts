import { describe, expect, it } from "vitest";
import { en } from "../src/i18n/messages/en";
import { frCA } from "../src/i18n/messages/fr-CA";
import { plural, pluralCategory, resolveLocale, translate, type MessageKey, type PluralBase } from "../src/i18n";

const placeholders = (s: string): string[] => [...s.matchAll(/\{(\w+)\}/g)].map((m) => m[1]!).sort();
const keys = Object.keys(en) as MessageKey[];

describe("catalogue parity (EN / FR-CA)", () => {
  it("fr-CA has exactly the English keys", () => {
    expect(Object.keys(frCA).sort()).toEqual([...keys].sort());
  });

  it.each(keys)("%s: non-empty in both, same {placeholders}", (k) => {
    expect(en[k].trim().length).toBeGreaterThan(0);
    expect(frCA[k].trim().length).toBeGreaterThan(0);
    expect(placeholders(frCA[k])).toEqual(placeholders(en[k]));
  });

  it("every plural base has both .one and .other", () => {
    const bases = keys.filter((k) => k.endsWith(".one")).map((k) => k.slice(0, -4));
    expect(bases.length).toBeGreaterThan(0);
    for (const b of bases) for (const cat of ["one", "other"]) expect(keys).toContain(`${b}.${cat}`);
    for (const k of keys.filter((x) => x.endsWith(".other"))) expect(keys).toContain(`${k.slice(0, -6)}.one`);
  });

  it("French is translated, not copied: only brand names and true cognates match English", () => {
    // a string that is only placeholders and punctuation has nothing to translate
    const allowed = new Set<MessageKey>(["home.roles.scope"]);
    expect(keys.filter((k) => en[k] === frCA[k] && !allowed.has(k))).toEqual([]);
  });

  it("no catalogue string contains markup (every string is set as text, but a string that looks like HTML is a mistake)", () => {
    for (const k of keys) {
      expect(en[k], k).not.toMatch(/[<>]/);
      expect(frCA[k], k).not.toMatch(/[<>]/);
    }
  });
});

describe("translate / plural / resolveLocale", () => {
  it("interpolates and leaves unknown placeholders visible", () => {
    expect(translate("en", "home.field.assurance.value", { aal: 1, required: 2 })).toBe("1 (this access needs 2)");
    expect(translate("fr-CA", "home.field.assurance.value", { aal: 1, required: 2 })).toBe("1 (cet accès exige 2)");
    expect(translate("en", "error.rateLimited.wait")).toBe("Too many attempts. Try again in {seconds} s.");
  });

  it("an interpolated value is inserted as text, not interpreted", () => {
    expect(translate("en", "error.rateLimited.wait", { seconds: "<img src=x onerror=alert(1)>" })).toContain("<img src=x onerror=alert(1)>");
  });

  it("English: 1 is singular; French: 0 and 1 are singular", () => {
    expect(plural("en", "home.facilities" as PluralBase, 1)).toBe("1 facility");
    expect(plural("en", "home.facilities" as PluralBase, 0)).toBe("0 facilities");
    expect(plural("fr-CA", "home.facilities" as PluralBase, 0)).toBe("0 installation");
    expect(plural("fr-CA", "home.facilities" as PluralBase, 2)).toBe("2 installations");
    expect(pluralCategory("fr-CA", 1.5)).toBe("one");
    expect(pluralCategory("en", 1.5)).toBe("other");
  });

  it("every French variant is fr-CA; anything else is English; an explicit choice wins", () => {
    expect(resolveLocale(["fr-FR", "en"])).toBe("fr-CA");
    expect(resolveLocale(["fr"])).toBe("fr-CA");
    expect(resolveLocale(["de", "fr-CA"])).toBe("fr-CA");
    expect(resolveLocale(["en-GB"])).toBe("en");
    expect(resolveLocale(["de"])).toBe("en");
    expect(resolveLocale([])).toBe("en");
    expect(resolveLocale(["fr"], "en")).toBe("en");
  });
});
