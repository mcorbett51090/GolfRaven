// MUST-FAIL (M2 BLOCKING, post-P3a re-gate): walks the prototype chain
// with Object.getPrototypeOf, then reads a property descriptor's VALUE
// with a non-literal, built key -- reaches the Function constructor
// without ever writing a `.constructor` (or `["constructor"]`) token
// anywhere in the source, and without a string-building COMPUTED MEMBER
// access either (the built key here is a plain call argument, not a
// MemberExpression property).
export function reachFunctionCtorViaReflection() {
  const proto = Object.getPrototypeOf(() => {});
  const descriptor = Object.getOwnPropertyDescriptor(proto, "constr" + "uctor");
  const ctor = descriptor?.value as unknown as (...args: string[]) => (n: string) => unknown;
  return ctor("return globalThis")();
}
