import { useApp } from "../../src/runtime/AppProvider";
import { trailName } from "../../src/browse";
import { walletTrailIds } from "../../src/wallet";
import { Body, Card, H2, Screen } from "../../src/ui/components";

/** Wallet tab (build plan §7.2; visible only while some trail's programme is
 * `pilot`/`live`, O17). P5 content — the section list below is a placeholder
 * that shows the per-trail gating works; none of it is functional. */
export default function WalletScreen() {
  const { t, locale, programmes, index } = useApp();
  const trailIds = walletTrailIds(programmes);
  return (
    <Screen>
      <Body muted>{t("wallet.intro")}</Body>
      {trailIds.map((id) => {
        const trail = index?.trails.get(id);
        return (
          <Card key={id}>
            <H2>{trail ? trailName(trail, locale) : id}</H2>
            {(["wallet.scanCourseQr", "wallet.playerQr", "wallet.offerCodes", "wallet.markerCredits", "wallet.specialMarker"] as const).map((k) => (
              <Body key={k} muted>{`${t(k)} — ${t("common.notYet")}`}</Body>
            ))}
          </Card>
        );
      })}
    </Screen>
  );
}
