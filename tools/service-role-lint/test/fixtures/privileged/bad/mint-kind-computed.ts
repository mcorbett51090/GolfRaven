// MUST-FAIL (privileged-mint-scope): a kind that is not a literal hides which scope the call runs in.
declare function openScopedTx(kind: string, bind: unknown, op: () => Promise<number>): Promise<number>;
export function other(kind: string) {
  return openScopedTx(kind, { expectedUid: null }, async () => 1);
}
