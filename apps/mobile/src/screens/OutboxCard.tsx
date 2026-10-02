import { Alert } from "react-native";
import { useApp } from "../runtime/AppProvider";
import { markReported, playedStatus, type OutboxItem } from "../outbox";
import { Body, Button, Card, Chip, Row } from "../ui/components";
import { courseName } from "../browse";

/** One outbox item as the player sees it in Played (build plan §7.6, right-hand column). */
export function OutboxCard({ item }: { item: OutboxItem }) {
  const { t, locale, index, services, reloadOutbox } = useApp();
  const status = playedStatus(item, Date.now());
  const entry = item.courseId && index ? index.courses.get(item.courseId) : undefined;
  const title = entry ? courseName(entry, locale) : t("played.status.unlisted_course");
  const tone = status === "needs_attention" ? "danger" : status === "accepted" ? "ok" : status === "saving" ? "neutral" : "warn";

  async function report(): Promise<void> {
    // The server half (`POST` the stored summary into a `review_item`) is P4.2;
    // locally the report is remembered so it is not offered twice.
    await services.outboxStore.update(markReported(item, Date.now()));
    await reloadOutbox();
    Alert.alert(t("played.reported"));
  }

  return (
    <Card>
      <Body>{title}</Body>
      <Row wrap>
        <Chip label={t(`played.status.${status}`)} tone={tone} />
        {item.catalogVersion === null ? null : <Chip label={item.catalogVersion} />}
      </Row>
      {status === "needs_attention" ? (
        <>
          {item.reason ? <Body muted>{t(`played.reason.${item.reason}`)}</Body> : null}
          {item.reported ? <Chip label={t("played.reported")} /> : <Button variant="secondary" title={t("played.reportProblem")} onPress={() => void report()} />}
        </>
      ) : null}
    </Card>
  );
}
