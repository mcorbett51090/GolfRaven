import { useRouter } from "expo-router";
import { useState } from "react";
import { Alert } from "react-native";
import { exportAndShare } from "../../src/account";
import { ApiError } from "../../src/api";
import { isTrustStateCorrupt } from "../../src/catalog/manager";
import { enablePushNotifications } from "../../src/push";
import { useApp } from "../../src/runtime/AppProvider";
import { LOCALES, type MessageKey } from "../../src/i18n";
import { CatalogBanners } from "../../src/screens/CatalogBanners";
import { Body, Button, Card, Chip, H2, Row, Screen } from "../../src/ui/components";

/** Required lazily under `__DEV__` so Metro drops the panel (and what it imports)
 * from release bundles; a static import would ship it, merely un-rendered. */
const DevPanel = __DEV__ ? (require("../../src/screens/DevPanel") as typeof import("../../src/screens/DevPanel")).DevPanel : null;

/** Me tab: language, account (sign-in goes through the age screen; sign-in methods), sources, privacy (export and delete, §7.8),
 * notifications (the permission is asked only when the player taps the button), and the catalog's status. */
export default function MeScreen() {
  const app = useApp();
  const { t, session, explicitLocale, setExplicitLocale, catalogState, refreshCatalog, services } = app;
  const router = useRouter();
  const [outcome, setOutcome] = useState<MessageKey | null>(null);
  const [resetNote, setResetNote] = useState<MessageKey | null>(null);
  const [privacyNote, setPrivacyNote] = useState<MessageKey | null>(null);
  const [pushNote, setPushNote] = useState<MessageKey | null>(null);
  const [busy, setBusy] = useState(false);

  async function check(): Promise<void> {
    const o = await refreshCatalog();
    setResetNote(null);
    // A corrupt trust state is explained by the banner (with the way out); "failed verification" would be wrong.
    setOutcome(o.kind === "rejected" && o.issues.some((i) => i.code === "TRUST_STATE_CORRUPT") ? null : `me.catalog.outcome.${o.kind}`);
  }

  async function reset(): Promise<void> {
    const report = await app.resetCatalog();
    setOutcome(null);
    setResetNote(!report.performed ? "me.catalog.reset.nothing" : report.stillCorrupt ? "me.catalog.reset.failed" : "me.catalog.reset.done");
  }
  function confirmReset(): void {
    Alert.alert(t("me.catalog.reset.confirmTitle"), t("me.catalog.reset.confirmBody"), [
      { text: t("common.cancel"), style: "cancel" },
      { text: t("me.catalog.reset.confirm"), style: "destructive", onPress: () => void reset() },
    ]);
  }

  async function exportData(): Promise<void> {
    setBusy(true);
    setPrivacyNote("me.export.working");
    try {
      const r = await exportAndShare({ api: services.api, sharer: services.sharer });
      if (r.status === "shared") setPrivacyNote("me.export.shared");
      else if (r.status === "unavailable") setPrivacyNote("me.export.unavailable");
      else if (r.error instanceof ApiError && r.error.kind === "rate_limited") setPrivacyNote("me.export.rateLimited");
      else if (r.error instanceof ApiError && (r.error.kind === "unauthenticated" || r.error.kind === "not_configured")) setPrivacyNote(r.error.kind === "unauthenticated" ? "me.signInRequired" : "me.notConfigured");
      else setPrivacyNote("me.export.failed");
    } finally {
      setBusy(false);
    }
  }

  async function deleteAccount(): Promise<void> {
    setBusy(true);
    setPrivacyNote("me.delete.working");
    try {
      const r = await app.deleteAccount();
      if (r.status === "deleted") setPrivacyNote(r.localWipe === "complete" ? "me.delete.done" : "me.delete.partial");
      else if (r.status === "deleted_or_session_ended") setPrivacyNote(r.localWipe === "complete" ? "me.delete.maybeDone" : "me.delete.maybePartial");
      else if (r.error instanceof ApiError && r.error.kind === "not_configured") setPrivacyNote("me.notConfigured");
      else if (r.error instanceof ApiError && (r.error.kind === "network" || r.error.kind === "server" || r.error.kind === "unavailable")) setPrivacyNote("me.delete.unreachable");
      else setPrivacyNote("me.delete.failed");
    } finally {
      setBusy(false);
    }
  }
  function confirmDelete(): void {
    Alert.alert(t("me.delete.confirmTitle"), t("me.delete.confirmBody"), [
      { text: t("common.cancel"), style: "cancel" },
      { text: t("me.delete.confirm"), style: "destructive", onPress: () => void deleteAccount() },
    ]);
  }

  // Player-initiated only: this is the sole caller of the permission prompt; nothing at launch asks for it.
  async function turnOnNotifications(): Promise<void> {
    const r = await enablePushNotifications({
      adapter: services.push,
      api: services.api,
      deviceId: services.deviceId,
      platform: services.platform === "ios" || services.platform === "android" ? services.platform : null,
    });
    setPushNote(
      r.status === "registered" ? "me.notifications.registered" : r.status === "denied" ? "me.notifications.denied" : r.status === "unavailable" ? "me.notifications.unavailable" : "me.notifications.failed",
    );
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
            <Button variant="secondary" title={t("me.signInMethods")} onPress={() => router.push("/sign-in-methods")} />
            <Button variant="secondary" title={t("me.signOut")} onPress={() => void app.signOut()} />
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
        <Button variant="secondary" disabled={busy || !session} title={t("me.privacy.export")} onPress={() => void exportData()} />
        <Button variant="danger" disabled={busy || !session} title={t("me.privacy.delete")} onPress={confirmDelete} />
        {!session ? <Body muted>{t("me.signInRequired")}</Body> : null}
        {privacyNote ? <Body muted>{t(privacyNote)}</Body> : null}
      </Card>

      <Card>
        <H2>{t("me.notifications")}</H2>
        <Button
          variant="secondary"
          disabled={!session || !services.push.isAvailable()}
          title={t("me.notifications.enable")}
          onPress={() => void turnOnNotifications()}
        />
        {!services.push.isAvailable() ? <Body muted>{t("me.notifications.unavailable")}</Body> : null}
        {pushNote ? <Body muted>{t(pushNote)}</Body> : null}
      </Card>

      <Card>
        <H2>{t("me.catalog")}</H2>
        <Body>{catalogState.snapshot ? t("me.catalog.version", { version: catalogState.snapshot.catalogVersion }) : t("me.catalog.none")}</Body>
        <Button variant="secondary" title={t("me.catalog.refresh")} onPress={() => void check()} />
        {outcome ? <Body muted>{t(outcome)}</Body> : null}
        {/* Only offered when the install's own trust state is unreadable — the one case a reset can fix. On a healthy install
            it would delete a readable catalog that the re-download may then be unable to replace (force-update state,
            refresh off, no keyset, offline). `resetCatalogData()` refuses to run on a healthy install as well. */}
        {isTrustStateCorrupt(catalogState) ? <Button variant="secondary" title={t("me.catalog.reset")} onPress={confirmReset} /> : null}
        {resetNote ? <Body muted>{t(resetNote)}</Body> : null}
        {services.keysetProblem ? <Body muted>{t("me.catalog.keysetProblem")}</Body> : null}
        <Body muted>{t("me.version", { version: services.config.appVersion })}</Body>
      </Card>

      {DevPanel ? <DevPanel /> : null}
    </Screen>
  );
}
