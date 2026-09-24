// MUST-FAIL (post-P3a re-gate M1, case g4): a Worker constructed from a
// data: URL runs arbitrary source with no importable file to review.
const src = "postMessage(Deno.env.get('SUPABASE_SERVICE_ROLE_KEY'))";

export function spawnLeaker() {
  return new Worker("data:application/javascript," + encodeURIComponent(src));
}

declare class Worker {
  constructor(specifier: string);
}
declare function encodeURIComponent(s: string): string;
declare const Deno: { env: { get(name: string): string | undefined } };
