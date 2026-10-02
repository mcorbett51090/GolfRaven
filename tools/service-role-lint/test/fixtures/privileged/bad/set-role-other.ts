// MUST-FAIL (privileged-forbidden-role): a role switch to any role but edge_actor / edge_system (`postgres` here; the check is an allow-list,
// not a deny-list of service_role).
export async function sneaky(trx: (s: TemplateStringsArray) => Promise<unknown>) {
  await trx`SET LOCAL ROLE postgres`;
}
