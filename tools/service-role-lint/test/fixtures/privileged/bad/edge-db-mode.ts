// MUST-FAIL (privileged-edge-db-mode): the mode switch is gone; reading (or naming) it again brings a second mode back.
declare const Deno: { env: { get(name: string): string | undefined } };
export function mode(): string {
  return Deno.env.get("EDGE_DB_MODE") ?? "edge";
}
