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

  it("every plural base has both .one and .other in both languages", () => {
    const bases = keys.filter((k) => k.endsWith(".one")).map((k) => k.slice(0, -4));
    expect(bases.length).toBeGreaterThan(0);
    for (const b of bases) {
      for (const cat of ["one", "other"]) {
        expect(keys).toContain(`${b}.${cat}`);
      }
    }
    for (const k of keys.filter((x) => x.endsWith(".other"))) expect(keys).toContain(`${k.slice(0, -6)}.one`);
  });

  it("French is actually translated, not copied: only brand names, endonyms and true cognates match English", () => {
    const allowed = new Set<MessageKey>(["app.name", "me.language.en", "me.language.fr-CA", "facility.access.public", "facility.access.municipal", "me.catalog.version", "me.sources", "me.notifications", "signIn.code.label", "methods.proof.codeLabel"]);
    const identical = keys.filter((k) => en[k] === frCA[k]);
    expect(identical.filter((k) => !allowed.has(k))).toEqual([]);
  });

  it("never states the age cutoff on the age screen (O18: neutral, no hint)", () => {
    for (const k of keys.filter((x) => x.startsWith("ageGate."))) {
      expect(en[k]).not.toMatch(/\b1[0-9]\b|\bsixteen\b|\bunder\b|\bat least\b/i);
      expect(frCA[k]).not.toMatch(/\b1[0-9]\b|\bseize\b|\bmoins de\b|\bau moins\b/i);
    }
  });
});

describe("translate / plural", () => {
  it("interpolates and leaves unknown placeholders visible", () => {
    expect(translate("en", "trail.operator", { name: "TN State Parks" })).toBe("Operated by TN State Parks");
    expect(translate("fr-CA", "trail.operator", { name: "Parcs du TN" })).toBe("Exploité par Parcs du TN");
    expect(translate("en", "trail.operator")).toBe("Operated by {name}");
  });

  it("English plural: 1 is one, everything else other", () => {
    expect(plural("en", "trails.count" as PluralBase, 1)).toBe("1 trail");
    expect(plural("en", "trails.count" as PluralBase, 0)).toBe("0 trails");
    expect(plural("en", "trails.count" as PluralBase, 2)).toBe("2 trails");
  });

  it("French plural: 0 and 1 are singular, 2+ plural", () => {
    expect(pluralCategory("fr-CA", 0)).toBe("one");
    expect(pluralCategory("fr-CA", 1)).toBe("one");
    expect(pluralCategory("fr-CA", 1.5)).toBe("one");
    expect(pluralCategory("fr-CA", 2)).toBe("other");
    expect(plural("fr-CA", "stops.count" as PluralBase, 0)).toBe("0 étape");
    expect(plural("fr-CA", "stops.count" as PluralBase, 5)).toBe("5 étapes");
  });
});

describe("resolveLocale", () => {
  it("maps any French variant to fr-CA and everything else to en", () => {
    expect(resolveLocale(["fr-CA"])).toBe("fr-CA");
    expect(resolveLocale(["fr-FR", "en-US"])).toBe("fr-CA");
    expect(resolveLocale(["fr"])).toBe("fr-CA");
    expect(resolveLocale(["en-US", "fr-CA"])).toBe("en");
    expect(resolveLocale(["de-DE", "fr-CA"])).toBe("fr-CA"); // first SUPPORTED language wins
    expect(resolveLocale(["de-DE"])).toBe("en");
    expect(resolveLocale([])).toBe("en");
    expect(resolveLocale(["fr_CA"])).toBe("fr-CA");
  });
  it("an explicit choice wins", () => {
    expect(resolveLocale(["fr-CA"], "en")).toBe("en");
    expect(resolveLocale(["en-US"], "fr-CA")).toBe("fr-CA");
  });
});
