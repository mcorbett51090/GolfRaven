// MUST-FAIL (privileged-mint-scope): the minter role is switched to only inside openScopedTx; anywhere else is a second way to write the proof table.
export const q = async (t: any) => t`set local role edge_signin_minter`;
