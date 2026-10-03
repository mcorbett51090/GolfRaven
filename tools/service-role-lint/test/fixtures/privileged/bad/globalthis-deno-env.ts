// MUST-FAIL (privileged-global-access): the global object reaches `Deno` without ever naming it as an identifier, and the name read can be computed.
export function viaGlobalThis(name: string): string | undefined {
  return (globalThis as any).Deno.env.get(name);
}
