import { useIsFocused } from "expo-router";
import { useCallback, useEffect, useState } from "react";
import { Alert, AppState } from "react-native";
import { countdownSeconds, formatCountdown, isStale, mayShowCode, provisionMessage, shownFrom, skewMinutes, type ShownCode } from "../offline-code";
import { useApp } from "../runtime/AppProvider";
import type { MessageKey } from "../i18n";
import { Body, Button, Card, H1, H2 } from "../ui/components";

/**
 * Me → Offline code (build plan §7.6, "Offline staff path"): the player's handle (when the app has one), the current 6-digit code, a countdown to the next change, and "Reset code".
 * Shown only while `OFFLINE_CODE_UI_ENABLED` (`src/features.ts`; the caller checks it): the staff side that accepts the code is P5.
 *
 * The code is computed from the device clock and the seed in the secure store, so it works with no network. THE SEED NEVER REACHES THIS COMPONENT (PR #44 gate NIT): the manager reads it
 * from the secure store, computes the digits and drops it (`OfflineCodeManager.view()`); the state here is only the derived digits, their version and the end of their 600 s step
 * (`ShownCode`, `offline-code/display.ts`), and the countdown is computed from the clock alone. The digits are re-read when the step ends, and DROPPED whenever the card is not on screen:
 * the tab loses focus (tabs stay mounted) or the app leaves the foreground (`AppState`). Nothing here is rendered beyond the six digits, logged or put in a message.
 */
export function OfflineCodeCard({ handle = null }: { handle?: string | null }) {
  const { t, services, session } = useApp();
  const userId = session?.userId ?? null;
  const focused = useIsFocused();
  const [appState, setAppState] = useState<string>(AppState.currentState);
  const [shown, setShown] = useState<ShownCode | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [note, setNote] = useState<MessageKey | null>(null);
  const [busy, setBusy] = useState(false);
  const [now, setNow] = useState(() => Date.now());
  /** Bumped to make the effect below read the code again (after a provisioning, or when its step ended). */
  const [reload, setReload] = useState(0);
  const visible = userId !== null && mayShowCode({ focused, appState });

  useEffect(() => {
    const sub = AppState.addEventListener("change", (next) => setAppState(next));
    return () => sub.remove();
  }, []);

  // Forget the digits the moment the card is not on screen, the user changes, or the card unmounts: what is derived from the seed does not outlive them.
  useEffect(() => {
    setShown(null);
    setLoaded(false);
    return () => setShown(null);
  }, [visible, userId]);

  // (Re)compute the digits while the card is on screen: on appearing, when their step ends, after a provisioning. The manager reads the seed from the secure store and drops it.
  useEffect(() => {
    if (!visible) return undefined;
    let alive = true;
    const at = Date.now();
    void services.offlineCode.view(at).then((v) => {
      if (!alive) return;
      setShown(v.status === "ready" ? shownFrom(v, at) : null);
      setNow(Date.now());
      setLoaded(true);
    });
    return () => {
      alive = false;
    };
  }, [visible, userId, services, reload]);

  useEffect(() => {
    if (shown === null) return undefined;
    const id = setInterval(() => {
      const at = Date.now();
      setNow(at);
      if (isStale(shown, at)) setReload((n) => n + 1);
    }, 1000);
    return () => clearInterval(id);
  }, [shown]);

  const run = useCallback(
    async (rotate: boolean) => {
      setBusy(true);
      setNote("offline.status.working");
      try {
        const outcome = await services.offlineCode.provision(rotate ? { rotate: true } : {});
        setNote(provisionMessage(outcome, rotate));
        if (outcome.status === "ready") setReload((n) => n + 1);
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

  return (
    <Card>
      <H2>{t("offline.title")}</H2>
      <Body muted>{t("offline.body")}</Body>
      {handle !== null ? <Body>{t("offline.handle", { handle })}</Body> : null}
      {shown ? (
        <>
          <Body muted>{t("offline.code.label")}</Body>
          <H1>{`${shown.code.slice(0, 3)} ${shown.code.slice(3)}`}</H1>
          <Body muted>{t("offline.countdown", { time: formatCountdown(countdownSeconds(now)) })}</Body>
          <Body muted>{t("offline.version", { version: shown.seedVersion })}</Body>
          {shown.clock.warn ? <Body>{t("offline.clock.warn", { minutes: skewMinutes(shown.clock.offsetMs) })}</Body> : null}
          {shown.resyncNeeded ? <Body>{t("offline.resync")}</Body> : null}
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
