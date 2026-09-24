// MUST-FAIL (M2 BLOCKING, post-P3a re-gate): reaches the Function
// constructor via a COMPUTED member access whose key is built at
// runtime ("constr" + "uctor") -- never the literal string "constructor"
// anywhere in the static source, so the existing bare/literal
// `.constructor` check (which only matches an Identifier property or a
// plain string Literal computed key) never sees it.
export function reachFunctionCtor() {
  const ctor = (() => {})["constr" + "uctor"] as unknown as (...args: string[]) => (n: string) => unknown;
  return ctor("return globalThis")();
}
