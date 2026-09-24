/**
 * N7 (gate review): deterministic fixture ids, no `Date.now()` — every
 * test file imports this instead of seeding `mintId` off the wall clock,
 * so a re-run (or a mutation-testing run, which re-executes the whole
 * suite many times in one process) never produces different ids between
 * runs.
 */
import { mintId, type IdKind } from "@golfraven/catalog";

const EPOCH = new Date("2026-01-01T00:00:00.000Z").getTime();
let counter = 0;

/** A deterministic, monotonically-increasing id of the given kind — same
 * sequence every run, same process or not. */
export function nextId(kind: IdKind): string {
  counter += 1;
  return mintId(kind, new Date(EPOCH + counter));
}

/** Resets the counter — call in a `beforeEach` if a test file wants ids
 * to start from the same point every test (most don't need to: unique
 * ids across the whole file are exactly what deterministic-but-distinct
 * fixtures need). */
export function resetIdCounter(): void {
  counter = 0;
}
