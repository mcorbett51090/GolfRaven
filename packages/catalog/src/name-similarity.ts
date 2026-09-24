/**
 * Normalised name similarity for the re-seed spatial-match rule (§4.2
 * G-P1-12: "centroid within 150 m **and** normalised-name similarity
 * ≥ 0.8"). The plan does not name an algorithm, so this is a Sørensen–Dice
 * bigram coefficient over a normalised (lowercased, punctuation-stripped,
 * whitespace-collapsed) form of each name — a standard, dependency-free
 * choice for short place-name matching. See the P1a report's ambiguity
 * list.
 */

export function normalizeName(name: string): string {
  return name
    .toLowerCase()
    .normalize("NFKD")
    .replace(/[̀-ͯ]/g, "") // strip diacritics
    .replace(/[^a-z0-9\s]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function bigrams(value: string): string[] {
  if (value.length < 2) return value.length === 1 ? [value] : [];
  const result: string[] = [];
  for (let i = 0; i < value.length - 1; i += 1) {
    result.push(value.slice(i, i + 2));
  }
  return result;
}

/** Sørensen–Dice coefficient in [0, 1]; 1 = identical bigram multisets. */
export function diceCoefficient(a: string, b: string): number {
  const normA = normalizeName(a);
  const normB = normalizeName(b);
  if (normA === normB) return 1;
  const bigramsA = bigrams(normA);
  const bigramsB = bigrams(normB);
  if (bigramsA.length === 0 || bigramsB.length === 0) return 0;

  const countsB = new Map<string, number>();
  for (const bg of bigramsB) {
    countsB.set(bg, (countsB.get(bg) ?? 0) + 1);
  }
  let overlap = 0;
  for (const bg of bigramsA) {
    const remaining = countsB.get(bg) ?? 0;
    if (remaining > 0) {
      overlap += 1;
      countsB.set(bg, remaining - 1);
    }
  }
  return (2 * overlap) / (bigramsA.length + bigramsB.length);
}

/** `normalised-name similarity` as G-P1-12 names it. */
export function normalizedNameSimilarity(a: string, b: string): number {
  return diceCoefficient(a, b);
}
