// MUST-FAIL (privileged-mint-scope): each mint kind has its OWN caller: the sign-in proof minter's caller may not open a partner mint transaction (and the other way round).
declare function openScopedTx(kind: string, bind: unknown, op: () => Promise<number>): Promise<number>;
export function signinEmailProofs() {
  return openScopedTx("partner_mint", { expectedUid: null }, async () => 1);
}
