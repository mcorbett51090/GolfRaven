import { useState } from "react";
import { Linking } from "react-native";
import { useApp } from "../runtime/AppProvider";
import { facilityName, type CourseEntry } from "../browse";
import { markerFailureText, needsSettings } from "../checkin";
import type { MarkerCaptureOutcome } from "../marker";
import { Banner, Body, Button, Card, H2 } from "../ui/components";

/**
 * "Buying a marker" on the facility page (build plan §7.6 "Offline marker purchase", G2-03). Rendered ONLY while `markerCosignalUiAvailable()` (both `CHECKIN_UI_ENABLED` and
 * `MARKER_COSIGNAL_UI_ENABLED`); the capture refuses anyway while either is false. The location prompt is `services.markerCosignal`'s, called from `onMarkerPress`, the button's `onPress` only.
 * What it captures stays on the phone: no server path takes it yet (`marker/capture.ts`).
 */
export function MarkerCard({ entry }: { entry: CourseEntry }) {
  const { t, locale, session, services, snapshot } = useApp();
  const [busy, setBusy] = useState(false);
  const [outcome, setOutcome] = useState<MarkerCaptureOutcome | null>(null);

  async function onMarkerPress(): Promise<void> {
    if (busy || session === null) return;
    setBusy(true);
    setOutcome(null);
    try {
      setOutcome(await services.markerCosignal({ entry, catalogVersion: snapshot?.catalogVersion ?? "" }));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card>
      <H2>{t("marker.title")}</H2>
      <Body muted>{t("marker.hint")}</Body>
      <Button title={t("marker.button")} onPress={() => void onMarkerPress()} busy={busy} disabled={session === null} accessibilityHint={t("marker.a11y.hint")} />
      {busy ? <Body muted>{t("checkin.working")}</Body> : null}
      {session === null ? <Body muted>{t("marker.err.signed_out")}</Body> : null}
      {outcome === null ? null : outcome.kind === "captured" ? (
        <Banner tone="info" text={t("marker.captured")} />
      ) : (
        <>
          <Banner text={markerFailureText(outcome, t, facilityName(entry.facility, locale))} />
          {needsSettings(outcome) ? <Button variant="secondary" title={t("checkin.openSettings")} onPress={() => void Linking.openSettings()} /> : null}
        </>
      )}
    </Card>
  );
}
