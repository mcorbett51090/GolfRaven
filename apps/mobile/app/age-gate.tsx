import { useRouter } from "expo-router";
import { useEffect, useState } from "react";
import { TextInput } from "react-native";
import { useApp } from "../src/runtime/AppProvider";
import { Body, Button, H1, Screen } from "../src/ui/components";
import { useTheme } from "../src/ui/theme";

type View = "loading" | "ask" | "ineligible" | "blocked";

/** The neutral age screen (build plan §7.8, O18): asks for a birth year only
 * and never mentions the cutoff; runs before any sign-in provider is called.
 * Under the minimum, no account is created and only a device-local flag is
 * kept, so the retry with another year is refused on this install. */
export default function AgeGateScreen() {
  const { services, t } = useApp();
  const router = useRouter();
  const theme = useTheme();
  const [view, setView] = useState<View>("loading");
  const [year, setYear] = useState("");
  const [invalid, setInvalid] = useState(false);

  useEffect(() => {
    void services.ageGate.state().then((s) => {
      if (s === "eligible") router.replace("/sign-in");
      else setView(s === "ineligible" ? "blocked" : "ask");
    });
  }, [services, router]);

  async function submit(): Promise<void> {
    const { minAge } = await services.api.getPolicy();
    const r = await services.ageGate.submitBirthYear(Number(year), minAge);
    if (r.status === "invalid") setInvalid(true);
    else if (r.status === "eligible") router.replace("/sign-in");
    else setView(r.status === "blocked" ? "blocked" : "ineligible");
  }

  if (view === "loading") return <Screen />;
  if (view === "ineligible" || view === "blocked") {
    return (
      <Screen>
        <H1>{t("ageGate.ineligible.title")}</H1>
        <Body>{view === "blocked" ? t("ageGate.blocked") : t("ageGate.ineligible.body")}</Body>
        <Button variant="secondary" title={t("common.close")} onPress={() => router.back()} />
      </Screen>
    );
  }
  return (
    <Screen>
      <H1>{t("ageGate.prompt")}</H1>
      <TextInput
        accessibilityLabel={t("ageGate.yearLabel")}
        placeholder={t("ageGate.yearLabel")}
        placeholderTextColor={theme.subtext}
        keyboardType="number-pad"
        maxLength={4}
        value={year}
        onChangeText={(v) => {
          setInvalid(false);
          setYear(v.replace(/\D/g, ""));
        }}
        style={{ borderWidth: 1, borderColor: theme.border, borderRadius: 8, padding: 12, fontSize: 18, color: theme.text }}
      />
      {invalid ? <Body>{t("ageGate.invalid")}</Body> : null}
      <Button title={t("ageGate.submit")} disabled={year.length !== 4} onPress={() => void submit()} />
      <Body muted>{t("ageGate.note")}</Body>
    </Screen>
  );
}
