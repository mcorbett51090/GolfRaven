import { useEffect, useState } from "react";
import type { PlaySummary } from "../../src/api";
import { useApp } from "../../src/runtime/AppProvider";
import { courseName } from "../../src/browse";
import { OutboxCard } from "../../src/screens/OutboxCard";
import { Body, Button, Card, Chip, Screen } from "../../src/ui/components";
import { useRouter } from "expo-router";

/** Played tab: the player's timeline. Guests see a sign-in prompt (sign-in is
 * requested only to record a play, Apple 5.1.1, build plan §7.8) and any
 * outbox items; "no item is dropped silently" (§7.6) so the outbox is always
 * listed, newest first. */
export default function PlayedScreen() {
  const { t, locale, index, session, outboxItems, syncOutbox, services } = useApp();
  const router = useRouter();
  const [plays, setPlays] = useState<PlaySummary[]>([]);

  useEffect(() => {
    void services.api.listPlays().then(setPlays);
  }, [services, session]);

  const items = [...outboxItems].reverse();

  return (
    <Screen>
      {session === null ? (
        <>
          <Body muted>{t("played.guest")}</Body>
          <Button title={t("me.signIn")} onPress={() => router.push("/sign-in")} />
        </>
      ) : null}
      {items.length > 0 ? <Button variant="secondary" title={t("played.sync")} onPress={() => void syncOutbox()} /> : null}
      {items.map((item) => (
        <OutboxCard key={item.id} item={item} />
      ))}
      {plays.map((p) => {
        const entry = index?.courses.get(p.courseId);
        return (
          <Card key={p.id}>
            <Body>{entry ? courseName(entry, locale) : p.courseId}</Body>
            <Body muted>{p.playedAt}</Body>
            {p.confidence === "pending_verification" ? <Chip tone="warn" label={t("played.pendingVerification")} /> : null}
          </Card>
        );
      })}
      {items.length === 0 && plays.length === 0 ? <Body muted>{t("played.empty")}</Body> : null}
    </Screen>
  );
}
