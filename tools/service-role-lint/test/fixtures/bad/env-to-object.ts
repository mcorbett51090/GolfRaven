// MUST-FAIL (M3(3), post-P3a gate): Deno.env.toObject() grabs every
// environment variable at once, then a plain property/computed access
// reads the secret out of the resulting plain object -- no ".get(...)"
// call ever appears in the source at all.
export function readSecretComputed() {
  const all = Deno.env.toObject();
  return all["SUPABASE_SERVICE_ROLE_KEY"];
}

export function readSecretStatic() {
  return Deno.env.toObject().SUPABASE_SERVICE_ROLE_KEY;
}

declare const Deno: { env: { toObject(): Record<string, string> } };
