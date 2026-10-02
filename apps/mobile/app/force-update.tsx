import { useRouter } from "expo-router";
import { Linking } from "react-native";
import { useApp } from "../src/runtime/AppProvider";
import { Body, Button, H1, Screen } from "../src/ui/components";

/** The force-update screen (build plan §3.5 FM-24, P4 AT 12): the newest
 * signed manifest needs a newer app. The last good cached catalog stays
 * readable, so "keep browsing" is offered whenever one exists. */
export default function ForceUpdateScreen() {
  const { t, catalogState, snapshot, services, dismissUpdate } = useApp();
  const router = useRouter();
  const storeUrl = services.config.storeUrl;
  return (
    <Screen>
      <H1>{t("forceUpdate.title")}</H1>
      <Body>{t("forceUpdate.body", { minVersion: catalogState.updateRequired?.minAppVersion ?? "" })}</Body>
      {storeUrl ? <Button title={t("forceUpdate.update")} onPress={() => void Linking.openURL(storeUrl)} /> : null}
      {snapshot ? (
        <Button
          variant="secondary"
          title={t("forceUpdate.continue")}
          onPress={() => {
            dismissUpdate();
            router.replace("/");
          }}
        />
      ) : (
        <Body muted>{t("forceUpdate.noCache")}</Body>
      )}
    </Screen>
  );
}
