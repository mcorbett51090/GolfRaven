// A plain, non-privileged helper — used only by good/legit-remote-import.ts
// to prove a relative import staying INSIDE supabase/functions is never
// flagged by the M1 relative-escape check.
export function helper(x: unknown) {
  return x;
}
