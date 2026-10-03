// MUST-FAIL (privileged-mint-scope): only signinEmailProofs may ask openScopedTx for the minter kind.
declare function openScopedTx(kind: string, bind: unknown, op: () => Promise<number>): Promise<number>;
export function other() {
  return openScopedTx("signin_mint", { expectedUid: null }, async () => 1);
}
