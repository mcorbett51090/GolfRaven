import { useState } from "react";
import { Platform, ScrollView, StyleSheet, Text } from "react-native";
import { Body, Button, Screen } from "../ui/components";
import { useTheme } from "../ui/theme";
import { runX1HealthConnectCheck } from "../health-connect";

/**
 * The P0 check-X1 screen (build plan §10 P0, row X1), moved here unchanged in
 * behaviour from the old placeholder `App.tsx` and reachable only from
 * Me → Developer tools in development builds. See apps/mobile/README.md for
 * how Matt runs it on a real Android device (it cannot be run here).
 * Dev-only text: deliberately not localized.
 */
export function X1Screen() {
  const t = useTheme();
  const [output, setOutput] = useState("");
  const [error, setError] = useState("");

  async function handleRunCheck(): Promise<void> {
    setError("");
    setOutput("Reading…");
    try {
      setOutput(await runX1HealthConnectCheck(30));
    } catch (err) {
      setOutput("");
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  return (
    <Screen>
      {Platform.OS === "android" ? (
        <>
          <Button title="Run X1 Health Connect check" onPress={() => void handleRunCheck()} />
          {error ? <Text style={{ color: t.danger }}>{error}</Text> : null}
          {output ? (
            <ScrollView style={[styles.output, { borderColor: t.border }]}>
              <Text selectable style={[styles.outputText, { color: t.text }]}>
                {output}
              </Text>
            </ScrollView>
          ) : null}
        </>
      ) : (
        <Body muted>The Health Connect reader is Android-only (build plan §10 P0, row X1: iOS uses Apple Health's export.xml export instead).</Body>
      )}
    </Screen>
  );
}

const styles = StyleSheet.create({
  output: { marginTop: 12, maxHeight: 320, borderWidth: 1, borderRadius: 6, padding: 8 },
  outputText: { fontFamily: Platform.select({ ios: "Menlo", android: "monospace", default: "monospace" }), fontSize: 12 },
});
