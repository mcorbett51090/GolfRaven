// MUST-FAIL (privileged-mint-scope): an alias of openScopedTx escapes the literal-kind check.
declare function openScopedTx(kind: string, bind: unknown, op: () => Promise<number>): Promise<number>;
export const open = openScopedTx;
