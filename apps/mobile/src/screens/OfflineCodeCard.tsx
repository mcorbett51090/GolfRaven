import { useCallback, useEffect, useState } from "react";
import { Alert } from "react-native";
import { formatCountdown, provisionMessage, skewMinutes, type StoredSeed } from "../offline-code";
import { useApp } from "../runtime/AppProvider";
import type { MessageKey } from "../i18n";
import { Body, Button, Card, H1, H2 } from "../ui/components";

/**
 * Me → Offline code (build plan §7.6, "Offline staff path"): the player's handle (when the app has one), the current 6-digit code, a countdown to the next change, and "Reset code".
 * Shown only while `OFFLINE_CODE_UI_ENABLED` (`src/features.ts`; the caller checks it): the staff side that accepts the code is P5.
 *
 * The code is computed from the device clock and the seed in the secure store, so it works with no network. The seed's bytes are held in this component's state ONLY while it is mounted
 * (dropped on unmount and whenever the signed-in user changes), never rendered, logged or put in a message; the screen shows only the six digits.
 */
export function OfflineCodeCard({ handle = null }: { handle?: string | null }) {
  const { t, services, session } = useApp();
  const userId = session?.userId ?? null;
  const [seed, setSeed] = useState<StoredSeed | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [note, setNote] = useState<MessageKey | null>(null);
  const [busy, setBusy] = useState(false);
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    let alive = true;
    setSeed(null);
    setLoaded(false);
    if (userId !== null) {
      void services.offlineCode.loadSeed().then((s) => {
        if (alive) {
          setSeed(s);
          setLoaded(true);
        }
      });
    }
    return () => {
      alive = false;
      setSeed(null); // the bytes do not outlive the card or the user
    };
  }, [userId, services]);

  useEffect(() => {
    if (seed === null) return undefined;
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, [seed]);

  const run = useCallback(
    async (rotate: boolean) => {
      setBusy(true);
      setNote("offline.status.working");
      try {
        const outcome = await services.offlineCode.provision(rotate ? { rotate: true } : {});
        setNote(provisionMessage(outcome, rotate));
        if (outcome.status === "ready") setSeed(await services.offlineCode.loadSeed());
      } finally {
        setBusy(false);
      }
    },
    [services],
  );

  function confirmReset(): void {
    Alert.alert(t("offline.reset.confirmTitle"), t("offline.reset.confirmBody"), [
      { text: t("common.cancel"), style: "cancel" },
      { text: t("offline.reset.confirm"), style: "destructive", onPress: () => void run(true) },
    ]);
  }

  const view = seed ? services.offlineCode.viewOf(seed, now) : null;
  return (
    <Card>
      <H2>{t("offline.title")}</H2>
      <Body muted>{t("offline.body")}</Body>
      {handle !== null ? <Body>{t("offline.handle", { handle })}</Body> : null}
      {view ? (
        <>
          <Body muted>{t("offline.code.label")}</Body>
          <H1>{`${view.code.slice(0, 3)} ${view.code.slice(3)}`}</H1>
          <Body muted>{t("offline.countdown", { time: formatCountdown(view.secondsRemaining) })}</Body>
          <Body muted>{t("offline.version", { version: view.seedVersion })}</Body>
          {view.clock.warn ? <Body>{t("offline.clock.warn", { minutes: skewMinutes(view.clock.offsetMs) })}</Body> : null}
          {view.resyncNeeded ? <Body>{t("offline.resync")}</Body> : null}
          <Button variant="secondary" disabled={busy} title={t("offline.reset")} onPress={confirmReset} />
        </>
      ) : loaded ? (
        <>
          <Body muted>{t("offline.noSeed")}</Body>
          <Button disabled={busy} title={t("offline.setup")} onPress={() => void run(false)} />
        </>
      ) : null}
      {note ? <Body muted>{t(note)}</Body> : null}
    </Card>
  );
}
