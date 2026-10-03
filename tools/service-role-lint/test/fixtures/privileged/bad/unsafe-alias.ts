// MUST-FAIL (privileged-unsafe-sql): `unsafe` taken off a connection and used elsewhere.
export function alias(t: { unsafe(sql: string): Promise<unknown> }) {
  const run = t.unsafe;
  return run("select 1");
}
