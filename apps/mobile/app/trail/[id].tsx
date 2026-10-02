import { Stack, useLocalSearchParams, useRouter } from "expo-router";
import { Linking } from "react-native";
import { useApp } from "../../src/runtime/AppProvider";
import { currentRoster, isSafeHttpsUrl, rosterStops, trailBlurb, trailName } from "../../src/browse";
import { Banner, Body, Button, Card, EmptyState, H1, H2, Screen } from "../../src/ui/components";

/** Trail page: roster checklist in the shown version's completion unit with
 * `k/n` (build plan §7.2). A guest sees `0 of n` and a sign-in note; stops
 * link to their course/facility page. */
export default function TrailScreen() {
  const { id } = useLocalSearchParams<{ id: string }>();
  const { t, tp, locale, index, session } = useApp();
  const router = useRouter();
  const trail = index?.trails.get(id);
  if (!index || !trail) {
    return (
      <Screen>
        <EmptyState title={t("trail.notFound")} />
      </Screen>
    );
  }
  const stops = rosterStops(trail, index, locale, {
    anyOf: (count) => t("trail.stop.anyOf", { count }),
    hole: (course) => t("trail.stop.hole", { course }),
  });
  const blurb = trailBlurb(trail, locale);

  return (
    <Screen>
      <Stack.Screen options={{ title: trailName(trail, locale) }} />
      <H1>{trailName(trail, locale)}</H1>
      {blurb ? <Body>{blurb}</Body> : null}
      <Body muted>{t("trail.operator", { name: trail.operator.name })}</Body>
      {isSafeHttpsUrl(trail.officialUrl) ? <Button variant="secondary" title={t("trail.officialSite")} onPress={() => void Linking.openURL(trail.officialUrl)} /> : null}
      {trail.rosterStatus === "unverified" ? <Banner tone="info" text={t("trail.rosterStatus.unverified")} /> : null}
      {trail.rosterStatus === "conflicting" ? <Banner text={t("trail.rosterStatus.conflicting")} /> : null}

      <H2>{`${t("trail.stops")} · ${t("trail.progress", { k: 0, n: stops.length })}`}</H2>
      <Body muted>{tp("stops.count", stops.length)}</Body>
      {session === null ? <Body muted>{t("trail.guestNote")}</Body> : null}
      {stops.map((s) => (
        <Card
          key={s.key}
          onPress={
            s.courseId
              ? () => router.push({ pathname: "/course/[id]", params: { id: s.courseId as string } })
              : s.facilityId
                ? () => router.push({ pathname: "/facility/[id]", params: { id: s.facilityId as string } })
                : undefined
          }
        >
          <Body>{s.label}</Body>
        </Card>
      ))}
      <Body muted>{`v${currentRoster(trail).version}`}</Body>
    </Screen>
  );
}
