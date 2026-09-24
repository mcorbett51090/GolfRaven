// MUST-FAIL (MEDIUM 3 re-gate, bypass 12): `(self as any).Deno` reaches
// the Deno global through `self` (the Worker/global-scope indirection
// point) instead of referencing the bare `Deno` identifier at all — a
// check that only looks for a bare `Deno` Identifier reference misses
// this shape entirely.
export function readSecret() {
  return (self as any).Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
}

declare const self: unknown;
