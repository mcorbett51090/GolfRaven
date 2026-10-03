import { useRouter } from "expo-router";
import { useEffect, useMemo, useState } from "react";
import { Alert, TextInput } from "react-native";
import { useApp } from "../src/runtime/AppProvider";
import {
  offeredProviders,
  requestEmailSignInCode,
  startSignIn,
  verifyEmailSignInCode,
  type SignInDeps,
  type SignInOutcome,
  type SignInProviderId,
} from "../src/signin";
import { Banner, Body, Button, H1, Screen } from "../src/ui/components";
import { useTheme } from "../src/ui/theme";
import type { MessageKey } from "../src/i18n";

type View = "loading" | "choose" | "email" | "code";

/** Sign-in: Sign in with Apple, Google (when this build has it) and an email one-time code. Every route into a provider goes through
 * `src/signin/flow.ts`, which refuses unless the age gate has passed; this screen also sends the player to the age screen first (O18),
 * and a verdict of `age_required` / `blocked` from any flow sends them back there. */
export default function SignInScreen() {
  const { services, t } = useApp();
  const router = useRouter();
  const theme = useTheme();
  const [view, setView] = useState<View>("loading");
  const [providers, setProviders] = useState<SignInProviderId[]>([]);
  const [email, setEmail] = useState("");
  const [code, setCode] = useState("");
  const [error, setError] = useState<MessageKey | null>(null);
  const [busy, setBusy] = useState(false);

  const deps: SignInDeps = useMemo(
    () => ({ gate: services.ageGate, auth: services.auth, api: services.api, apple: services.apple, google: services.google, random: services.random }),
    [services],
  );

  // O18: provider choices are shown only after the age screen has passed.
  useEffect(() => {
    void (async () => {
      const s = await services.ageGate.state();
      if (s !== "eligible") {
        router.replace("/age-gate");
        return;
      }
      const googleConfigured = (await services.google.availability()) === "available";
      setProviders(offeredProviders({ platform: services.platform, googleConfigured }));
      setView("choose");
    })();
  }, [services, router]);

  function handle(o: SignInOutcome): void {
    switch (o.status) {
      case "signed_in":
        if (o.grantCaptured === false) Alert.alert(t("signIn.grantNotCaptured"));
        router.dismissAll();
        return;
      case "age_required":
      case "blocked":
        router.replace("/age-gate");
        return;
      case "cancelled":
        return;
      case "not_configured":
        setError("signIn.googleNotConfigured");
        return;
      case "unsupported_platform":
        setError("signIn.appleUnsupported");
        return;
      case "failed":
        setError(`signIn.error.${o.reason}`);
        return;
    }
  }

  async function run(fn: () => Promise<void>): Promise<void> {
    if (busy) return;
    setBusy(true);
    setError(null);
    try {
      await fn();
    } catch {
      setError("signIn.error.unknown");
    } finally {
      setBusy(false);
    }
  }

  const choose = (id: SignInProviderId): Promise<void> =>
    run(async () => {
      if (id === "email") {
        setView("email");
        return;
      }
      handle(await startSignIn(id, deps));
    });

  const sendCode = (): Promise<void> =>
    run(async () => {
      const r = await requestEmailSignInCode(email, deps);
      if (r.status === "sent") setView("code");
      else if (r.status === "failed") setError(`signIn.error.${r.reason}`);
      else router.replace("/age-gate");
    });

  const verify = (): Promise<void> => run(async () => handle(await verifyEmailSignInCode(email, code, deps)));

  if (view === "loading") return <Screen />;
  if (services.backend === "unconfigured" || services.ageStoreProblem) {
    return (
      <Screen>
        <Banner tone="info" text={t(services.ageStoreProblem ? "signIn.ageStoreProblem" : "signIn.unconfigured")} />
        <Button variant="secondary" title={t("common.close")} onPress={() => router.back()} />
      </Screen>
    );
  }
  const input = {
    borderWidth: 1,
    borderColor: theme.border,
    borderRadius: 8,
    padding: 12,
    fontSize: 18,
    color: theme.text,
  } as const;
  return (
    <Screen>
      {services.backend === "demo" ? <Banner tone="info" text={t("signIn.stubNote")} /> : null}
      {error ? <Banner tone="warn" text={t(error)} /> : null}
      {view === "choose" ? (
        // Sign in with Apple is listed first, with equal prominence, and is present whenever Google is (Apple 4.8, AT 17): `offeredProviders`.
        providers.map((id) => <Button key={id} variant={id === "email" ? "secondary" : "primary"} disabled={busy} title={t(`signIn.${id}`)} onPress={() => void choose(id)} />)
      ) : null}
      {view === "email" ? (
        <>
          <H1>{t("signIn.email")}</H1>
          <Body muted>{t("signIn.email.prompt")}</Body>
          <TextInput
            accessibilityLabel={t("signIn.email.label")}
            placeholder={t("signIn.email.label")}
            placeholderTextColor={theme.subtext}
            keyboardType="email-address"
            autoCapitalize="none"
            autoComplete="email"
            autoCorrect={false}
            textContentType="emailAddress"
            value={email}
            onChangeText={setEmail}
            style={input}
          />
          <Button title={t("signIn.email.send")} disabled={busy || email.trim().length === 0} onPress={() => void sendCode()} />
        </>
      ) : null}
      {view === "code" ? (
        <>
          <Body>{t("signIn.code.prompt", { email: email.trim() })}</Body>
          <TextInput
            accessibilityLabel={t("signIn.code.label")}
            placeholder={t("signIn.code.label")}
            placeholderTextColor={theme.subtext}
            keyboardType="number-pad"
            autoComplete="one-time-code"
            textContentType="oneTimeCode"
            maxLength={10}
            value={code}
            onChangeText={(v) => setCode(v.replace(/\D/g, ""))}
            style={input}
          />
          <Button title={t("signIn.code.verify")} disabled={busy || code.length < 6} onPress={() => void verify()} />
          <Button
            variant="secondary"
            title={t("signIn.code.change")}
            onPress={() => {
              setCode("");
              setError(null);
              setView("email");
            }}
          />
        </>
      ) : null}
    </Screen>
  );
}
