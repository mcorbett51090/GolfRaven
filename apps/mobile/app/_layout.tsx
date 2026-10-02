import { Stack, useRouter } from "expo-router";
import { useEffect } from "react";
import { AppProvider, useApp } from "../src/runtime/AppProvider";

export default function RootLayout() {
  return (
    <AppProvider>
      <Gate />
    </AppProvider>
  );
}

/** The signed catalog's `minAppVersion` gate (build plan §3.5, P4 AT 12):
 * when the newest manifest needs a newer app, show the force-update screen —
 * which keeps the last good cached catalog readable. */
function Gate() {
  const { catalogState, updateDismissed, t } = useApp();
  const router = useRouter();
  const mustUpdate = catalogState.updateRequired !== null && !updateDismissed;

  useEffect(() => {
    if (mustUpdate) router.replace("/force-update");
  }, [mustUpdate, router]);

  return (
    <Stack>
      <Stack.Screen name="(tabs)" options={{ headerShown: false }} />
      <Stack.Screen name="trail/[id]" options={{ title: t("tab.trails") }} />
      <Stack.Screen name="facility/[id]" options={{ title: t("tab.trails") }} />
      <Stack.Screen name="course/[id]" options={{ title: t("tab.trails") }} />
      <Stack.Screen name="age-gate" options={{ title: t("ageGate.title"), presentation: "modal" }} />
      <Stack.Screen name="sign-in" options={{ title: t("signIn.title"), presentation: "modal" }} />
      <Stack.Screen name="force-update" options={{ title: t("forceUpdate.title"), headerBackVisible: false, gestureEnabled: false }} />
      <Stack.Screen name="dev/x1" options={{ title: "X1" }} />
    </Stack>
  );
}
