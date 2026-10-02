import { Stack, useLocalSearchParams, useRouter } from "expo-router";
import { Alert, Linking } from "react-native";
import { useApp } from "../../src/runtime/AppProvider";
import { bookingLinks, courseName, facilityName } from "../../src/browse";
import { Body, Button, Card, EmptyState, H1, H2, Row, Screen } from "../../src/ui/components";

/** Course page: details, booking rail, and "I'm here" / "Done" (build plan
 * §7.2). The check-in itself (foreground location, matching, evidence) is
 * not built in this slice. A guest is asked to sign in only when they try to
 * record a play (Apple 5.1.1, §7.8), and sign-in goes through the age screen. */
export default function CourseScreen() {
  const { id } = useLocalSearchParams<{ id: string }>();
  const { t, tp, locale, index, session } = useApp();
  const router = useRouter();
  const entry = index?.courses.get(id);
  if (!index || !entry) {
    return (
      <Screen>
        <EmptyState title={t("course.notFound")} />
      </Screen>
    );
  }
  const { course, facility } = entry;
  const bookings = bookingLinks(facility);

  function record(): void {
    if (session === null) router.push("/sign-in");
    else Alert.alert(t("course.checkIn.unavailable"));
  }

  return (
    <Screen>
      <Stack.Screen options={{ title: courseName(entry, locale) }} />
      <H1>{courseName(entry, locale)}</H1>
      <Card onPress={() => router.push({ pathname: "/facility/[id]", params: { id: facility.id } })}>
        <Body>{t("course.at", { facility: facilityName(facility, locale) })}</Body>
      </Card>
      <Row wrap>
        {course.holes ? <Body muted>{tp("course.holes", course.holes)}</Body> : null}
        {course.par ? <Body muted>{t("course.par", { par: course.par })}</Body> : null}
      </Row>

      {bookings.length > 0 ? (
        <>
          <H2>{t("facility.booking")}</H2>
          {bookings.map((b) => (
            <Button key={b.url} variant="secondary" title={t("facility.booking.book", { provider: b.provider })} onPress={() => void Linking.openURL(b.url)} />
          ))}
        </>
      ) : null}

      <Row>
        <Button title={t("course.checkIn")} onPress={record} />
        <Button variant="secondary" title={t("course.done")} onPress={record} />
      </Row>
      {session === null ? <Body muted>{t("course.guestNote")}</Body> : null}
    </Screen>
  );
}
