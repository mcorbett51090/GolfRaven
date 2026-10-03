// MUST-FAIL (privileged-unsafe-sql): `unsafe` destructured off a connection.
export function alias(t: { unsafe(sql: string): Promise<unknown> }) {
  const { unsafe } = t;
  return unsafe;
}
