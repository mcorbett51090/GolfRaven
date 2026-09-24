// MUST-FAIL: any reference to globalThis, which can be used to stash or
// retrieve a privileged client outside the normal import graph a static
// specifier check can see.
export function stashClient(client: unknown) {
  (globalThis as Record<string, unknown>).__privilegedClient = client;
}
