// MUST-FAIL (privileged-computed-member): a key held in a variable reaches any member of any object (a method name, `unsafe`, `begin`).
export function pick(conn: Record<string, unknown>, which: string): unknown {
  return conn[which];
}
