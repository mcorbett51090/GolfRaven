import { CHECKIN_UI_ENABLED } from "../features";

/**
 * The ONLY way the app tops up the prefetched check-in challenge pool. Until a screen can USE a challenge (`CHECKIN_UI_ENABLED`, `src/features.ts`),
 * a prefetch only mints single-use challenges that expire unused after 24 h and count against the user's hourly challenge limit: so while the flag
 * is false this does nothing at all (no request, no token fetch). `enabled` is a parameter so tests can exercise both states; the app never passes it.
 */
export async function prefetchChallenges(manager: { prefetch(): Promise<unknown> }, enabled: boolean = CHECKIN_UI_ENABLED): Promise<void> {
  if (!enabled) return;
  await manager.prefetch();
}
