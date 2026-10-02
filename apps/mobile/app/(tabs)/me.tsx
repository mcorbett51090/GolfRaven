import { useRouter } from "expo-router";
import { useState } from "react";
import { useApp } from "../../src/runtime/AppProvider";
import { LOCALES, type MessageKey } from "../../src/i18n";
import { CatalogBanners } from "../../src/screens/CatalogBanners";
import { Body, Button, Card, Chip, H2, Row, Screen } from "../../src/ui/components";

/** Required lazily under `__DEV__` so Metro drops the panel (and what it imports)
 * from release bundles; a static import would ship it, merely un-rendered. */
const DevPanel = __DEV__ ? (require("../../src/screens/DevPanel") as typeof import("../../src/screens/DevPanel")).DevPanel : null;

/** Me tab: language, account (sign-in goes through the age screen), sources,
 * privacy, and the catalog's status. Export/delete land in P4.2 (§7.8). */
export default function MeScreen() {
  const app = useApp();
  const { t, session, explicitLocale, setExplicitLocale, catalogState, refreshCatalog, services } = app;
  const router = useRouter();
  const [outcome, setOutcome] = useState<MessageKey | null>(null);

  async function check(): Promise<void> {
    const o = await refreshCatalog();
    setOutcome(`me.catalog.outcome.${o.kind}`);
  }

  return (
    <Screen>
      <CatalogBanners />
      <Card>
        <H2>{t("me.language")}</H2>
        <Row wrap>
          <Chip label={t("me.language.system")} selected={explicitLocale === null} onPress={() => setExplicitLocale(null)} />
          {LOCALES.map((l) => (
            <Chip key={l} label={t(`me.language.${l}`)} selected={explicitLocale === l} onPress={() => setExplicitLocale(l)} />
          ))}
        </Row>
      </Card>

      <Card>
        <H2>{t("me.account")}</H2>
        {session ? (
          <>
            <Body>{t("me.signedIn", { provider: session.provider })}</Body>
            {session.stub ? <Body muted>{t("me.signedIn.stub")}</Body> : null}
            <Button variant="secondary" title={t("me.signOut")} onPress={app.endSession} />
          </>
        ) : (
          <Button title={t("me.signIn")} onPress={() => router.push("/sign-in")} />
        )}
      </Card>

      <Card>
        <H2>{t("me.sources")}</H2>
        <Body muted>{t("me.sources.body")}</Body>
      </Card>

      <Card>
        <H2>{t("me.privacy")}</H2>
        <Button variant="secondary" disabled title={`${t("me.privacy.export")} — ${t("common.notYet")}`} onPress={() => undefined} />
        <Button variant="danger" disabled title={`${t("me.privacy.delete")} — ${t("common.notYet")}`} onPress={() => undefined} />
      </Card>

      <Card>
        <H2>{t("me.catalog")}</H2>
        <Body>{catalogState.snapshot ? t("me.catalog.version", { version: catalogState.snapshot.catalogVersion }) : t("me.catalog.none")}</Body>
        <Button variant="secondary" title={t("me.catalog.refresh")} onPress={() => void check()} />
        {outcome ? <Body muted>{t(outcome)}</Body> : null}
        {services.keysetProblem ? <Body muted>{t("me.catalog.keysetProblem")}</Body> : null}
        <Body muted>{t("me.version", { version: services.config.appVersion })}</Body>
      </Card>

      {DevPanel ? <DevPanel /> : null}
    </Screen>
  );
}
