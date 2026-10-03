// MUST-FAIL (privileged-global-access): a function listener's `this` is the global object.
export function h(this: any) {
  return this.Deno.env.get("X");
}
