import { useState } from "react";
import { Linking } from "react-native";
import { useApp } from "../runtime/AppProvider";
import { needsSettings, receiptOutcomeMessage, type ReceiptUploadOutcome } from "../receipts";
import { Banner, Body, Button, Card, H2 } from "../ui/components";

/**
 * Receipt upload on the facility page (P5 §50). Rendered ONLY while `receiptsUploadUiAvailable()`.
 * The picker prompt runs from the button `onPress` only; the upload service refuses while the flag is off.
 */
export function ReceiptUploadCard({ facilityId }: { facilityId: string }) {
  const { t, session, services } = useApp();
  const [busy, setBusy] = useState(false);
  const [outcome, setOutcome] = useState<ReceiptUploadOutcome | null>(null);

  async function onUploadPress(): Promise<void> {
    if (busy || session === null) return;
    setBusy(true);
    setOutcome(null);
    try {
      setOutcome(await services.uploadReceipt({ facilityId }));
    } finally {
      setBusy(false);
    }
  }

  const msg = outcome === null || outcome.status === "cancelled" ? null : receiptOutcomeMessage(outcome);
  const tone =
    outcome !== null && (outcome.status === "ok" || outcome.status === "duplicate" || outcome.status === "review") ? "info" : undefined;

  return (
    <Card>
      <H2>{t("receipt.title")}</H2>
      <Body muted>{t("receipt.hint")}</Body>
      <Button title={t("receipt.button")} onPress={() => void onUploadPress()} busy={busy} disabled={session === null} accessibilityHint={t("receipt.a11y.hint")} />
      {busy ? <Body muted>{t("receipt.working")}</Body> : null}
      {session === null ? <Body muted>{t("receipt.err.signed_out")}</Body> : null}
      {msg !== null ? <Banner tone={tone} text={t(msg.key, msg.params)} /> : null}
      {outcome !== null && needsSettings(outcome) ? (
        <Button variant="secondary" title={t("checkin.openSettings")} onPress={() => void Linking.openSettings()} />
      ) : null}
    </Card>
  );
}
