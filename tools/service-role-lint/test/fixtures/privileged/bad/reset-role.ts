// MUST-FAIL (privileged-forbidden-role): RESET ROLE would return a transaction to the session user; the only role-switch is SET LOCAL ROLE
// edge_actor | edge_system.
export async function resetIt(trx: (s: TemplateStringsArray) => Promise<unknown>) {
  await trx`reset role`;
}
