import { Tabs } from "expo-router";
import { useApp } from "../../src/runtime/AppProvider";

export default function TabsLayout() {
  const { t, walletVisible } = useApp();
  return (
    <Tabs screenOptions={{ tabBarIcon: () => null, tabBarLabelStyle: { fontSize: 13 } }}>
      <Tabs.Screen name="index" options={{ title: t("tab.trails") }} />
      <Tabs.Screen name="played" options={{ title: t("tab.played") }} />
      <Tabs.Screen name="achievements" options={{ title: t("tab.achievements") }} />
      {/* O17: the Wallet exists only while some trail's programme is pilot/live. */}
      <Tabs.Screen name="wallet" options={{ title: t("tab.wallet"), href: walletVisible ? undefined : null }} />
      <Tabs.Screen name="me" options={{ title: t("tab.me") }} />
    </Tabs>
  );
}
