import { useState } from "react";
import { Linking, TextInput } from "react-native";
import { useApp } from "../runtime/AppProvider";
import { facilityName, type CourseEntry } from "../browse";
import { markerFailureText, needsSettings } from "../checkin";
import type { MarkerCaptureOutcome, MarkerScanOutcome } from "../marker";
import { useTheme } from "../ui/theme";
import { Banner, Body, Button, Card, H2 } from "../ui/components";
import type { MessageKey, Params } from "../i18n";

/**
 * "Buying a marker" on the facility page (build plan §7.6 "Offline marker purchase", G2-03). Rendered ONLY while `markerCosignalUiAvailable()` (both `CHECKIN_UI_ENABLED` and
 * `MARKER_COSIGNAL_UI_ENABLED`); capture and paste-scan refuse while either is false. Offline capture queues a local co-signal (`marker/capture.ts`); paste scan POSTs `marker-scan`
 * with the shop QR (`marker/scan.ts`, P5 §53). Both flags stay false in release builds.
 */
export function MarkerCard({ entry }: { entry: CourseEntry }) {
  const { t, locale, session, services, snapshot } = useApp();
  const theme = useTheme();
  const [busy, setBusy] = useState(false);
  const [outcome, setOutcome] = useState<MarkerCaptureOutcome | null>(null);
  const [scanOutcome, setScanOutcome] = useState<MarkerScanOutcome | null>(null);
  const [link, setLink] = useState("");
  const [pin, setPin] = useState("");

  async function onMarkerPress(): Promise<void> {
    if (busy || session === null) return;
    setBusy(true);
    setOutcome(null);
    setScanOutcome(null);
    try {
      setOutcome(await services.markerCosignal({ entry, catalogVersion: snapshot?.catalogVersion ?? "" }));
    } finally {
      setBusy(false);
    }
  }

  async function onScanPress(): Promise<void> {
    if (busy || session === null) return;
    setBusy(true);
    setOutcome(null);
    setScanOutcome(null);
    try {
      setScanOutcome(await services.markerScanFromLink({ entry, link, pin }));
    } finally {
      setBusy(false);
    }
  }

  const input = {
    borderWidth: 1,
    borderColor: theme.border,
    borderRadius: 8,
    paddingHorizontal: 12,
    paddingVertical: 10,
    color: theme.text,
    marginTop: 8,
  } as const;

  return (
    <Card>
      <H2>{t("marker.title")}</H2>
      <Body muted>{t("marker.hint")}</Body>
      <Button title={t("marker.button")} onPress={() => void onMarkerPress()} busy={busy} disabled={session === null} accessibilityHint={t("marker.a11y.hint")} />
      <Body muted>{t("marker.scan.hint")}</Body>
      <TextInput
        accessibilityLabel={t("marker.scan.link.label")}
        placeholder={t("marker.scan.link.label")}
        placeholderTextColor={theme.subtext}
        autoCapitalize="none"
        autoCorrect={false}
        value={link}
        onChangeText={setLink}
        style={input}
      />
      <TextInput
        accessibilityLabel={t("marker.scan.pin.label")}
        placeholder={t("marker.scan.pin.label")}
        placeholderTextColor={theme.subtext}
        keyboardType="number-pad"
        maxLength={4}
        value={pin}
        onChangeText={(v) => setPin(v.replace(/\D/g, "").slice(0, 4))}
        style={input}
      />
      <Button
        title={t("marker.scan.button")}
        onPress={() => void onScanPress()}
        busy={busy}
        disabled={session === null || link.trim().length === 0}
        accessibilityHint={t("marker.scan.a11y.hint")}
      />
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
      {scanOutcome === null ? null : scanOutcome.kind === "scanned" ? (
        <Banner tone="info" text={t("marker.scan.ok", { outcome: scanOutcome.result.outcome })} />
      ) : (
        <>
          <Banner text={markerScanFailureText(scanOutcome, t, facilityName(entry.facility, locale))} />
          {scanOutcome.kind === "permission" && needsSettings(scanOutcome) ? (
            <Button variant="secondary" title={t("checkin.openSettings")} onPress={() => void Linking.openSettings()} />
          ) : null}
        </>
      )}
    </Card>
  );
}

function markerScanFailureText(o: MarkerScanOutcome, t: (key: MessageKey, params?: Params) => string, facility: string): string {
  switch (o.kind) {
    case "scanned":
      return t("marker.scan.ok", { outcome: o.result.outcome });
    case "invalid_link":
      return t("marker.scan.err.invalid_link");
    case "need_pin":
      return t("marker.scan.err.need_pin");
    case "invalid_pin":
      return t("marker.scan.err.invalid_pin");
    case "wrong_facility":
      return t("marker.scan.err.wrong_facility");
    case "attestation_deferred":
      return t("marker.scan.err.attestation_deferred");
    case "rejected":
      return t("marker.scan.err.rejected", { code: o.code ?? "error" });
    case "transport":
      return t("marker.scan.err.transport");
    case "not_here":
      return t("marker.err.not_here", { facility });
    case "no_challenge":
      return t("marker.err.no_challenge");
    case "signed_out":
      return t("marker.err.signed_out");
    case "disabled":
      return t("checkin.err.disabled");
    case "no_geometry":
      return t("checkin.err.no_geometry");
    case "permission":
      return t(o.status === "denied" ? "checkin.err.denied" : o.status === "blocked" ? "checkin.err.blocked" : "checkin.err.approximate");
    case "services_off":
      return t("checkin.err.services_off");
    case "no_fix":
      return t(o.reason === "timeout" ? "checkin.err.no_fix.timeout" : "checkin.err.no_fix.unavailable");
    case "stale_fix":
      return t("checkin.err.stale_fix");
    case "simulated":
      return t("checkin.err.simulated");
    case "inaccurate":
      return Number.isFinite(o.accuracyMeters) ? t("checkin.err.inaccurate", { meters: Math.round(o.accuracyMeters) }) : t("checkin.err.inaccurate.unknown");
    case "failed":
      return t("checkin.err.failed");
  }
}
