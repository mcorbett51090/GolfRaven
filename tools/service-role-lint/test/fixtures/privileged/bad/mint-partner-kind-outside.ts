// MUST-FAIL (privileged-mint-scope): only withPartnerMint may ask openScopedTx for the partner minter kind (PA-13: a mint kind used outside its caller).
declare function openScopedTx(kind: string, bind: unknown, op: () => Promise<number>): Promise<number>;
export function handlerHelper() {
  return openScopedTx("partner_mint", { expectedUid: null }, async () => 1);
}
