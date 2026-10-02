import { useEffect, useState } from "react";
import type { AchievementSummary } from "../../src/api";
import { useApp } from "../../src/runtime/AppProvider";
import { Body, Card, H2, Screen } from "../../src/ui/components";

/** Achievements tab: earned / in progress / locked. P4.1 shows whatever the
 * mock `api.*` returns (nothing, for a guest); share cards are not built. */
export default function AchievementsScreen() {
  const { t, services, session } = useApp();
  const [items, setItems] = useState<AchievementSummary[]>([]);

  useEffect(() => {
    void services.api.listAchievements().then(setItems);
  }, [services, session]);

  const groups: { title: string; list: AchievementSummary[] }[] = [
    { title: t("achievements.earned"), list: items.filter((a) => a.state === "earned") },
    { title: t("achievements.inProgress"), list: items.filter((a) => a.state === "in_progress") },
    { title: t("achievements.locked"), list: items.filter((a) => a.state === "locked") },
  ];

  return (
    <Screen>
      {session === null ? <Body muted>{t("played.guest")}</Body> : null}
      {items.length === 0 ? <Body muted>{t("achievements.empty")}</Body> : null}
      {groups
        .filter((g) => g.list.length > 0)
        .map((g) => (
          <Card key={g.title}>
            <H2>{g.title}</H2>
            {g.list.map((a) => (
              <Body key={a.id}>{a.progress ? `${a.name} (${t("trail.progress", { k: a.progress.k, n: a.progress.n })})` : a.name}</Body>
            ))}
          </Card>
        ))}
    </Screen>
  );
}
