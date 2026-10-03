// MUST-FAIL (privileged-global-access): `globalThis["Deno"]` and `globalThis.Deno` are the same reach; only `globalThis.addEventListener` is sanctioned.
export const d = (globalThis as any)["Deno"];
