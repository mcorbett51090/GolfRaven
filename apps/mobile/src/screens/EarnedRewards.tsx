import { useCallback, useEffect, useState } from "react";
import type { EarnedReward } from "../api";
import type { MessageKey } from "../i18n";
import { activationMessage, isRetryableActivation, type ActivationOutcome } from "../rewards";
import { useApp } from "../runtime/AppProvider";
import { Body, Button, Card, H2 } from "../ui/components";

/**
 * Wallet → Earned rewards (build plan §7.5): each reward the server has earned for the player and that is not yet active, with an "Activate" action (`POST rewards-activate`, run under the
 * assertion lock check-in shares). Shown only while `WALLET_ACTIVATION_UI_ENABLED` (`src/features.ts`; the caller checks it): no server endpoint lists earned rewards yet.
 *
 * A reward the server holds for review is "under review", not an error; a repeat of an activation that already happened is reported as such (the server answers it idempotently).
 */
export function EarnedRewards() {
  const { t, services, session } = useApp();
  const userId = session?.userId ?? null;
  const [rewards, setRewards] = useState<EarnedReward[]>([]);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [outcomes, setOutcomes] = useState<Record<string, ActivationOutcome>>({});

  useEffect(() => {
    let alive = true;
    setRewards([]);
    setOutcomes({});
    if (userId !== null) void services.api.listEarnedRewards().then((r) => alive && setRewards(r), () => undefined);
    return () => {
      alive = false;
    };
  }, [userId, services]);

  const activate = useCallback(
    async (id: string) => {
      setBusyId(id);
      try {
        const outcome = await services.activateReward(id);
        // An answer is for the user who asked: it is dropped if someone else is signed in by now.
        if ((services.auth.current()?.userId ?? null) === userId) setOutcomes((o) => ({ ...o, [id]: outcome }));
      } finally {
        setBusyId(null);
      }
    },
    [services, userId],
  );

  return (
    <Card>
      <H2>{t("wallet.rewards")}</H2>
      {rewards.length === 0 ? <Body muted>{t("wallet.rewards.empty")}</Body> : null}
      {rewards.map((r) => {
        const outcome = outcomes[r.id];
        const done = outcome !== undefined && !isRetryableActivation(outcome) && (outcome.status === "activated" || outcome.status === "held_review");
        const msg = outcome ? activationMessage(outcome) : null;
        return (
          <Card key={r.id}>
            <Body>{t(`wallet.reward.${r.kind}` as MessageKey)}</Body>
            {done ? null : <Button disabled={busyId !== null} title={busyId === r.id ? t("wallet.activate.working") : t("wallet.activate")} onPress={() => void activate(r.id)} />}
            {msg ? <Body muted>{t(msg.key, msg.params)}</Body> : null}
          </Card>
        );
      })}
    </Card>
  );
}
