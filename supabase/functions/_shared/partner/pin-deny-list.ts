// supabase/functions/_shared/partner/pin-deny-list.ts
//
// THE PIN RULES AND THE DENY-LIST (docs/security/partner-auth-design.md 6.3 "PIN rules", L11). Pure data and one pure function; no import, no environment, no database. This is the COMMITTED FIXTURE the design asks for
// ("a deny-list of the most common 4-digit PINs ... chosen and committed"), as a module so a browser build and a Deno or Node test import the same bytes.
//
// WHERE IT IS ENFORCED, AND WHERE IT CANNOT BE. The PIN is derived IN THE BROWSER (pin-contract.ts) and never leaves it, so the database and the Edge only ever see 32 derived bytes: neither can tell a denied PIN from
// any other (a probe the client computes under a fixed salt would let them, but it would be client-asserted, so no stronger against a custom client, and it would hand the Edge a PIN-equivalent that a 10,000-row table
// inverts instantly). The rules are therefore enforced at the only place the PIN exists: the S7 set-PIN form calls `pinRejection` before it derives anything, and supabase/tests/unit/partner-pin-contract.test.ts holds
// the module to its own table. A custom client can set any four digits; what bounds that is the lockout (5 consecutive failures, 20 a day, a manager's reset), the email-proof requirement to set it and the per-action
// grant, not this list (S1.3 departure, design 19.3).
//
// THE RULES (a PIN is refused for the FIRST reason that applies):
//   format    not exactly four ASCII digits
//   repeated  all four digits equal (0000, 7777), or a repeated pair (1212, 6969), or two doubled digits (1122, 3344)
//   run       four consecutive ascending or descending digits (0123, 1234, 6789, 3210, 9876)
//   year      1900 to 2099 (a birth year, this year)
//   date      a valid MMDD OR DDMM calendar date (0101 to 1231 month-first, 0101 to 3112 day-first; February to the 29th): a day-first date is as guessable as a month-first one (S1.3 gate N4)
//   common    a member of PIN_DENY_LIST
//
// THE LIST was assembled by the author from published four-digit-PIN frequency studies and the usual keypad patterns, from training knowledge: `[unverified - training knowledge]`. It is deliberately a superset of what the
// structural rules already refuse (so the list stays correct if a rule is relaxed) and adds what they cannot see: keypad columns and diagonals, repeated words and the like. The owner may replace it in a PR; the unit test
// pins the structural rules, that every entry is refused, and that the list holds four-digit strings only, once each.

export type PinRejection = "format" | "repeated" | "run" | "year" | "date" | "common";

/** The explicit list. Sorted, unique, four digits each. */
export const PIN_DENY_LIST: readonly string[] = Object.freeze([
  "0000", "0007", "0069", "0110", "0123", "0420", "0852", "0987",
  "1000", "1004", "1010", "1020", "1111", "1114", "1122", "1212", "1221", "1230", "1234", "1236", "1313", "1357", "1379", "1397", "1472", "1478", "1590", "1881", "1984",
  "2000", "2001", "2002", "2112", "2121", "2222", "2323", "2345", "2424", "2468", "2580",
  "3000", "3131", "3210", "3333", "3456", "3698",
  "4040", "4141", "4200", "4321", "4444", "4545", "4567",
  "5000", "5050", "5555", "5678", "5683",
  "6666", "6677", "6900", "6969", "6996",
  "7410", "7547", "7777", "7890",
  "8080", "8520", "8765", "8888",
  "9630", "9876", "9999",
]);

const DENY_SET: ReadonlySet<string> = new Set(PIN_DENY_LIST);
const DAYS_IN_MONTH = [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31] as const; // February to the 29th: a leap-year date is a date

/** True when `month` and `day` are a calendar date (February to the 29th). */
function isCalendarDate(month: number, day: number): boolean {
  return month >= 1 && month <= 12 && day >= 1 && day <= DAYS_IN_MONTH[month - 1]!;
}

/** Why this PIN is not acceptable, or null when it is. */
export function pinRejection(pin: unknown): PinRejection | null {
  if (typeof pin !== "string" || !/^[0-9]{4}$/.test(pin)) return "format";
  const d = [...pin].map(Number) as [number, number, number, number];
  if ((d[0] === d[1] && d[1] === d[2] && d[2] === d[3]) || (d[0] === d[2] && d[1] === d[3]) || (d[0] === d[1] && d[2] === d[3])) return "repeated";
  const step = d[1] - d[0];
  if ((step === 1 || step === -1) && d[2] - d[1] === step && d[3] - d[2] === step) return "run";
  const n = Number(pin);
  if (n >= 1900 && n <= 2099) return "year";
  const first = Number(pin.slice(0, 2));
  const second = Number(pin.slice(2));
  if (isCalendarDate(first, second) || isCalendarDate(second, first)) return "date"; // MMDD, then DDMM
  if (DENY_SET.has(pin)) return "common";
  return null;
}

/** True when the PIN may be set. */
export function isAcceptablePin(pin: unknown): boolean {
  return pinRejection(pin) === null;
}
