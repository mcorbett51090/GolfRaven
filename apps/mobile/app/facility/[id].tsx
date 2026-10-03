import { Stack, useLocalSearchParams, useRouter } from "expo-router";
import { Linking } from "react-native";
import { useApp } from "../../src/runtime/AppProvider";
import { bookingLinks, courseName, facilityBlurb, facilityName, isSafeHttpsUrl } from "../../src/browse";
import { markerCosignalUiAvailable } from "../../src/checkin/gate";
import { MarkerCard } from "../../src/screens/MarkerCard";
import { Banner, Body, Button, Card, Chip, EmptyState, H1, H2, Row, Screen } from "../../src/ui/components";

/** Directory entry: a facility with its courses, access, booking rail and
 * website — all readable with no account (P4 AT 13). */
export default function FacilityScreen() {
  const { id } = useLocalSearchParams<{ id: string }>();
  const { t, tp, locale, index } = useApp();
  const router = useRouter();
  const facility = index?.facilities.get(id);
  if (!index || !facility) {
    return (
      <Screen>
        <EmptyState title={t("facility.notFound")} />
      </Screen>
    );
  }
  const blurb = facilityBlurb(facility, locale);
  const bookings = bookingLinks(facility);

  return (
    <Screen>
      <Stack.Screen options={{ title: facilityName(facility, locale) }} />
      <H1>{facilityName(facility, locale)}</H1>
      <Row wrap>
        <Chip label={[facility.town, facility.region].filter(Boolean).join(", ")} />
        {facility.access ? <Chip label={t(`facility.access.${facility.access}`)} /> : null}
      </Row>
      {facility.verification.status === "unverified" ? <Banner tone="info" text={t("facility.unverified")} /> : null}
      {blurb ? <Body>{blurb}</Body> : null}
      {facility.url && isSafeHttpsUrl(facility.url) ? <Button variant="secondary" title={t("facility.website")} onPress={() => void Linking.openURL(facility.url as string)} /> : null}

      <H2>{t("facility.courses")}</H2>
      {facility.courses.map((c) => (
        <Card key={c.id} onPress={() => router.push({ pathname: "/course/[id]", params: { id: c.id } })}>
          <Body>{courseName({ course: c, facility }, locale)}</Body>
          {c.holes ? <Body muted>{tp("course.holes", c.holes)}</Body> : null}
        </Card>
      ))}

      {bookings.length > 0 ? (
        <>
          <H2>{t("facility.booking")}</H2>
          {bookings.map((b) => (
            <Button key={b.url} variant="secondary" title={t("facility.booking.book", { provider: b.provider })} onPress={() => void Linking.openURL(b.url)} />
          ))}
        </>
      ) : null}

      {markerCosignalUiAvailable() && facility.courses[0] ? <MarkerCard entry={{ course: facility.courses[0], facility }} /> : null}
    </Screen>
  );
}
