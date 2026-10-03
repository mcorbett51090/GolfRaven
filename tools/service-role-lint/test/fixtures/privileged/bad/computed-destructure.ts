// MUST-FAIL (privileged-computed-member): the destructuring form of the same access.
export function pick(conn: Record<string, unknown>, which: string): unknown {
  const { [which]: member } = conn;
  return member;
}
