// MUST-FAIL (privileged-mint-scope): the partner minter role is switched to only inside openScopedTx; anywhere else is a second way to mint a partner session.
export const q = async (t: any) => t`set local role edge_partner_minter`;
