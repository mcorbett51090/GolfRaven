import { useState } from "react";
import { Button, Platform, ScrollView, StyleSheet, Text, View } from "react-native";
import { runX1HealthConnectCheck } from "./src/health-connect/index.js";

/**
 * P0 placeholder screen. The real app's screens are §7.2 (Trails / Played
 * / Achievements / Wallet / Me); none of that is built yet. This screen
 * exists only to exercise `runX1HealthConnectCheck` for the P0-X1 Android
 * pass — see apps/mobile/README.md for how Matt runs it on a real device
 * (it cannot be run here).
 */
export default function App() {
  const [output, setOutput] = useState<string>("");
  const [error, setError] = useState<string>("");

  async function handleRunCheck(): Promise<void> {
    setError("");
    setOutput("Reading…");
    try {
      const json = await runX1HealthConnectCheck(30);
      setOutput(json);
    } catch (err) {
      setOutput("");
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  return (
    <View style={styles.container}>
      <Text style={styles.title}>GolfRaven — P0 skeleton</Text>
      <Text style={styles.body}>
        This is a placeholder screen. The real app's screens land from P4
        (build plan §7.2).
      </Text>

      {Platform.OS === "android" ? (
        <>
          <Button title="Run X1 Health Connect check" onPress={handleRunCheck} />
          {error ? <Text style={styles.error}>{error}</Text> : null}
          {output ? (
            <ScrollView style={styles.output}>
              <Text selectable style={styles.outputText}>
                {output}
              </Text>
            </ScrollView>
          ) : null}
        </>
      ) : (
        <Text style={styles.body}>
          The Health Connect reader is Android-only (build plan §10 P0, row
          X1: iOS uses Apple Health's export.xml export instead).
        </Text>
      )}
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    paddingTop: 64,
    paddingHorizontal: 16,
    gap: 12,
  },
  title: {
    fontSize: 20,
    fontWeight: "600",
  },
  body: {
    fontSize: 14,
  },
  error: {
    color: "#b3261e",
  },
  output: {
    marginTop: 12,
    maxHeight: 320,
    borderWidth: 1,
    borderColor: "#cfe1d7",
    borderRadius: 6,
    padding: 8,
  },
  outputText: {
    fontFamily: Platform.select({ ios: "Menlo", android: "monospace", default: "monospace" }),
    fontSize: 12,
  },
});
