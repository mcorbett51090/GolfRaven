// MUST-FAIL (privileged-global-access): taking `Deno` off another object by destructuring is the same reach as `x.Deno`.
export const h = (e: any) => {
  const { Deno: d } = e.currentTarget;
  return d;
};
