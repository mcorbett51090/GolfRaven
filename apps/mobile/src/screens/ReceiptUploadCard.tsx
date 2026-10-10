import { useState } from "react";
import { Linking, TextInput } from "react-native";
import { useApp } from "../runtime/AppProvider";
import { needsSettings, receiptOutcomeMessage, type ReceiptUploadOutcome } from "../receipts";
import { useTheme } from "../ui/theme";
import { Banner, Body, Button, Card, H2 } from "../ui/components";

/**
 * Receipt upload on the facility page (P5 §50 / §55). Rendered ONLY while `receiptsUploadUiAvailable()`.
 * The picker prompt runs from the button `onPress` only; the upload service refuses while the flag is off.
 * Optional typed receipt number fills Edge `receiptNumberOcr` (manual entry; no OCR).
 */
export function ReceiptUploadCard({ facilityId }: { facilityId: string }) {
  const { t, session, services } = useApp();
  const theme = useTheme();
  const [busy, setBusy] = useState(false);
  const [outcome, setOutcome] = useState<ReceiptUploadOutcome | null>(null);
  const [receiptNumber, setReceiptNumber] = useState("");

  async function onUploadPress(): Promise<void> {
    if (busy || session === null) return;
    setBusy(true);
    setOutcome(null);
    try {
      setOutcome(await services.uploadReceipt({ facilityId, receiptNumberOcr: receiptNumber }));
    } finally {
      setBusy(false);
    }
  }

  const msg = outcome === null || outcome.status === "cancelled" ? null : receiptOutcomeMessage(outcome);
  const tone =
    outcome !== null && (outcome.status === "ok" || outcome.status === "duplicate" || outcome.status === "review") ? "info" : undefined;

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
      <H2>{t("receipt.title")}</H2>
      <Body muted>{t("receipt.hint")}</Body>
      <TextInput
        accessibilityLabel={t("receipt.number.label")}
        placeholder={t("receipt.number.label")}
        placeholderTextColor={theme.subtext}
        autoCapitalize="characters"
        autoCorrect={false}
        maxLength={64}
        value={receiptNumber}
        onChangeText={setReceiptNumber}
        style={input}
      />
      <Body muted>{t("receipt.number.hint")}</Body>
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
