import { useRouter } from "expo-router";
import { useState } from "react";
import { Linking } from "react-native";
import { useApp } from "../runtime/AppProvider";
import { courseName, facilityName, type CourseEntry } from "../browse";
import { checkInFailureText, needsSettings, type CheckInFailure, type CheckInOutcome } from "../checkin";
import { playedStatus } from "../outbox";
import { Banner, Body, Button, Card, Chip, H2, Row } from "../ui/components";

/**
 * The foreground check-in on the course page (build plan §7.2 "I'm here", §7.4 step 5, §7.6). It is rendered ONLY while `CHECKIN_UI_ENABLED` is true (`checkinUiAvailable()`, the course
 * screen decides) and `services.checkin` refuses anyway while it is false.
 *
 * THE PROMPT. Location permission is requested inside `services.checkin`, which this card calls from `onCheckInPress`, which is only ever the button's `onPress` (never an effect, never at
 * launch: `test/checkin-no-prompt-at-launch.test.ts`).
 *
 * At a multi-course site the geometry cannot say which course was played, so the card shows the site's courses to pick from (§4.3 user pick; one pick per facility per day is enforced by the
 * flow). After a check-in it shows the outbox state of the item, which follows the outbox as it syncs.
 */
export function CheckInCard({ entry }: { entry: CourseEntry }) {
  const { t, locale, index, session, services, snapshot, outboxItems, syncOutbox, reloadOutbox } = useApp();
  const router = useRouter();
  const [courseId, setCourseId] = useState(entry.course.id);
  const [busy, setBusy] = useState(false);
  const [outcome, setOutcome] = useState<CheckInOutcome | null>(null);
  const picked: CourseEntry = index?.courses.get(courseId) ?? entry;
  const siblings = entry.facility.courses;
  const nameOf = (id: string): string => {
    const e = index?.courses.get(id);
    return e ? courseName(e, locale) : id;
  };

  async function onCheckInPress(): Promise<void> {
    if (busy) return;
    if (session === null) {
      router.push("/sign-in"); // a guest is asked to sign in only when they try to record a play (Apple 5.1.1, §7.8); sign-in goes through the age screen
      return;
    }
    setBusy(true);
    setOutcome(null);
    try {
      const o = await services.checkin({ entry: picked, catalogVersion: snapshot?.catalogVersion ?? "", index });
      setOutcome(o);
      if (o.kind === "queued") {
        await reloadOutbox();
        await syncOutbox(); // try to send it now; offline it stays saved and is sent when the connection returns
      }
    } finally {
      setBusy(false);
    }
  }

  const renderSaved = (o: Extract<CheckInOutcome, { kind: "queued" }>, course: string) => {
    const live = outboxItems.find((i) => i.id === o.item.id) ?? o.item;
    const status = playedStatus(live, Date.now());
    return (
      <>
        <Banner tone="info" text={t("checkin.saved", { course })} />
        <Row wrap>
          <Chip label={t(`played.status.${status}`)} tone={status === "needs_attention" ? "danger" : status === "accepted" ? "ok" : status === "saving" ? "neutral" : "warn"} />
          {o.challenge === "none" ? null : <Chip label={t(`checkin.challenge.${o.challenge}`)} />}
        </Row>
        <Body muted>{t("checkin.accuracy", { meters: Math.round(o.accuracyMeters) })}</Body>
        {o.geometryKind === "radius" ? <Body muted>{t("checkin.geometry.radius")}</Body> : null}
        {o.penalty ? <Body muted>{t("checkin.penalty")}</Body> : null}
      </>
    );
  };

  const renderFailure = (o: CheckInFailure, course: string, nameFor: (id: string) => string) => {
    return (
      <>
        <Banner text={checkInFailureText(o, t, { course, ...(o.kind === "already_picked" ? { picked: nameFor(o.courseId) } : {}) })} />
        {needsSettings(o) ? <Button variant="secondary" title={t("checkin.openSettings")} onPress={() => void Linking.openSettings()} /> : null}
        {o.kind === "not_here" && o.nearby.length > 0 ? (
          <>
            <Body muted>{t("checkin.nearby")}</Body>
            {o.nearby.map((n) => {
              const e = index?.courses.get(n.courseId);
              return e ? <Button key={n.courseId} variant="secondary" title={facilityName(e.facility, locale)} onPress={() => router.push({ pathname: "/course/[id]", params: { id: n.courseId } })} /> : null;
            })}
          </>
        ) : null}
      </>
    );
  };

  return (
    <Card>
      <H2>{t("course.checkIn")}</H2>
      {siblings.length > 1 ? (
        <>
          <Body muted>{t("checkin.pick")}</Body>
          <Row wrap>
            {siblings.map((c) => (
              <Chip key={c.id} label={nameOf(c.id)} selected={c.id === courseId} onPress={() => setCourseId(c.id)} />
            ))}
          </Row>
          <Body muted>{t("checkin.pick.hint")}</Body>
        </>
      ) : null}
      <Button title={t("course.checkIn")} onPress={() => void onCheckInPress()} busy={busy} accessibilityHint={t("checkin.a11y.hint")} />
      {busy ? <Body muted>{t("checkin.working")}</Body> : null}
      {outcome === null ? null : outcome.kind === "queued" ? renderSaved(outcome, courseName(picked, locale)) : renderFailure(outcome, courseName(picked, locale), nameOf)}
    </Card>
  );
}
