import { useRouter } from "expo-router";
import { useMemo, useState } from "react";
import { useApp } from "../../src/runtime/AppProvider";
import { facilitiesInRegion, facilityName, regionSummaries, trailName, trailsInRegion, currentRoster } from "../../src/browse";
import { CatalogBanners } from "../../src/screens/CatalogBanners";
import { Body, Card, Chip, EmptyState, Row, Screen } from "../../src/ui/components";

type Segment = "trails" | "directory";

/** Trails tab: guest-browsable list of trails and the directory, filtered by
 * region (build plan §7.2; P4 AT 13 — no account needed). "Near me" and "in
 * progress" need a location fix / plays and are not built in this slice. */
export default function TrailsScreen() {
  const { t, tp, locale, snapshot, services } = useApp();
  const router = useRouter();
  const [segment, setSegment] = useState<Segment>("trails");
  const [region, setRegion] = useState<string | null>(null);

  const regions = useMemo(() => (snapshot ? regionSummaries(snapshot) : []), [snapshot]);
  const trails = useMemo(() => (snapshot ? trailsInRegion(snapshot, region) : []), [snapshot, region]);
  const facilities = useMemo(() => (snapshot ? facilitiesInRegion(snapshot, region, locale) : []), [snapshot, region, locale]);

  if (!snapshot) {
    return (
      <Screen>
        <CatalogBanners />
        <EmptyState
          title={t("catalog.empty.title")}
          body={services.config.catalogBaseUrl === null ? t("catalog.empty.noSource") : t("catalog.empty.body")}
        />
      </Screen>
    );
  }

  return (
    <Screen>
      <CatalogBanners />
      <Row wrap>
        <Chip label={t("trails.segment.trails")} selected={segment === "trails"} onPress={() => setSegment("trails")} />
        <Chip label={t("trails.segment.directory")} selected={segment === "directory"} onPress={() => setSegment("directory")} />
      </Row>
      <Row wrap>
        <Chip label={t("trails.filter.allRegions")} selected={region === null} onPress={() => setRegion(null)} />
        {regions.map((r) => (
          <Chip key={r.region} label={r.region} selected={region === r.region} onPress={() => setRegion(r.region)} />
        ))}
      </Row>

      {segment === "trails" ? (
        <>
          <Body muted>{tp("trails.count", trails.length)}</Body>
          {trails.length === 0 ? <Body muted>{t("trails.empty")}</Body> : null}
          {trails.map((trail) => (
            <Card key={trail.id} onPress={() => router.push({ pathname: "/trail/[id]", params: { id: trail.id } })}>
              <Body>{trailName(trail, locale)}</Body>
              <Body muted>{tp("stops.count", currentRoster(trail).members.length)}</Body>
            </Card>
          ))}
        </>
      ) : (
        <>
          <Body muted>{tp("directory.count", facilities.length)}</Body>
          {facilities.length === 0 ? <Body muted>{t("trails.empty")}</Body> : null}
          {facilities.map((f) => (
            <Card key={f.id} onPress={() => router.push({ pathname: "/facility/[id]", params: { id: f.id } })}>
              <Body>{facilityName(f, locale)}</Body>
              <Body muted>{[f.town, f.region].filter(Boolean).join(", ")}</Body>
            </Card>
          ))}
        </>
      )}
    </Screen>
  );
}
