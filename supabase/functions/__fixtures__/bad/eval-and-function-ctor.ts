// MUST-FAIL (MEDIUM 3 re-gate, bypass 9 + requirement 5): eval(...),
// new Function(...) and Function(...) — dynamically executed code built
// from a string, which could reach Deno/process without that reference
// ever appearing as ordinary, statically-visible syntax in this file.
export function readSecretViaEval() {
  // eslint-disable-next-line no-eval
  return eval("Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')");
}

export function readSecretViaFunctionCtor() {
  const f = new Function("return Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')");
  return f();
}

export function readSecretViaBareFunctionCall() {
  const f = Function("return Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')");
  return f();
}
