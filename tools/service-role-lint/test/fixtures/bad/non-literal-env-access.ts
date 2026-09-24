// MUST-FAIL: the env var NAME is read through a variable, so a check that
// only scans string literals for "SERVICE_ROLE"/"DB_URL" text sees
// nothing — the literal "SUPABASE_SERVICE_ROLE_KEY" string never appears
// verbatim in this file's source.
const parts = ["SUPABASE", "SERVICE", "ROLE", "KEY"];
const keyName = parts.join("_");

export function readSecret() {
  return Deno.env.get(keyName);
}

declare const Deno: { env: { get(name: string): string | undefined } };
