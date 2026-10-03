// MUST-FAIL (privileged-global-access): the allowed globalThis.addEventListener hands its listener an event whose currentTarget IS the global object.
export const h = (e: any) => e.currentTarget.Deno.env.get("X");
