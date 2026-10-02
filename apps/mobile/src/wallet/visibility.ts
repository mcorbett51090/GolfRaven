/**
 * Wallet visibility (build plan §7.2 Wallet row, O17 DECIDED 2026-09-23;
 * §10 P4 pre-build gates: "the Wallet is shown per trail while that trail's
 * `trail_programme.status` is `pilot` or `live`, and is hidden while no
 * trail is live").
 */
export type ProgrammeStatus = "none" | "pilot" | "live";

export function programmeIsOn(status: ProgrammeStatus | undefined): boolean {
  return status === "pilot" || status === "live";
}

/** The Wallet TAB is shown iff at least one trail's programme is on. */
export function walletTabVisible(statuses: Readonly<Record<string, ProgrammeStatus>>): boolean {
  return Object.values(statuses).some(programmeIsOn);
}

/** The trails the Wallet shows sections for. */
export function walletTrailIds(statuses: Readonly<Record<string, ProgrammeStatus>>): string[] {
  return Object.entries(statuses)
    .filter(([, s]) => programmeIsOn(s))
    .map(([id]) => id)
    .sort();
}
