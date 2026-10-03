import { useRouter } from "expo-router";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Alert, TextInput } from "react-native";
import { AppleLinkFlow, type LinkState } from "../src/account";
import { ApiError, type SignInMethod } from "../src/api";
import { useApp } from "../src/runtime/AppProvider";
import type { MessageKey } from "../src/i18n";
import { Banner, Body, Button, Card, Chip, H2, Row, Screen } from "../src/ui/components";
import { useTheme } from "../src/ui/theme";

/** Me → Sign-in methods (build plan §3.4, P4 AT 18): the methods on this account, remove one (never the last: the server answers 422
 * `last_sign_in_method`), and add Sign in with Apple. Adding goes through `AppleLinkFlow` (`src/account/link-flow.ts`), which never links by
 * email match on its own: when an account with the Apple address already exists the flow STOPS and waits for the player to ask for a code,
 * type it, and confirm. */
export default function SignInMethodsScreen() {
  const { services, t, session, signOut } = useApp();
  const router = useRouter();
  const theme = useTheme();
  const [methods, setMethods] = useState<SignInMethod[] | null>(null);
  const [note, setNote] = useState<MessageKey | null>(null);
  const [link, setLink] = useState<LinkState>({ step: "idle" });
  const [typedEmail, setTypedEmail] = useState("");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);

  const flow = useRef<AppleLinkFlow | null>(null);
  const linkFlow = useMemo(() => {
    flow.current ??= new AppleLinkFlow({ gate: services.ageGate, auth: services.auth, api: services.api, apple: services.apple, random: services.random });
    return flow.current;
  }, [services]);
  useEffect(() => linkFlow.subscribe(setLink), [linkFlow]);

  const load = useCallback(async () => {
    try {
      setMethods(await services.api.listSignInMethods());
    } catch (e) {
      setMethods([]);
      setNote(e instanceof ApiError && e.kind === "network" ? "methods.error.network" : e instanceof ApiError && e.kind === "not_configured" ? "me.notConfigured" : "methods.error.unknown");
    }
  }, [services]);
  useEffect(() => {
    if (session) void load();
  }, [session, load]);

  // The age screen is the only way to a provider: the flow itself reports it.
  useEffect(() => {
    if (link.step === "age_required" || link.step === "blocked") router.replace("/age-gate");
    if (link.step === "linked" && link.where === "self") void load();
  }, [link, router, load]);

  async function unlink(m: SignInMethod): Promise<void> {
    if (m.provider !== "email" && m.provider !== "apple" && m.provider !== "google") return;
    const provider = m.provider;
    setBusy(true);
    setNote(null);
    try {
      const r = await services.api.unlinkSignInMethod(provider);
      setMethods(r.methods);
      setNote("methods.unlinked");
    } catch (e) {
      if (e instanceof ApiError && e.code === "last_sign_in_method") setNote("methods.unlink.last");
      else if (e instanceof ApiError && e.kind === "network") setNote("methods.error.network");
      else if (e instanceof ApiError && e.kind === "rate_limited") setNote("methods.error.rate_limited");
      else setNote("methods.unlink.failed");
      await load();
    } finally {
      setBusy(false);
    }
  }
  const label = (provider: string): string => (provider === "email" ? t("methods.provider.email") : provider === "apple" ? "Apple" : provider === "google" ? "Google" : provider);
  function confirmUnlink(m: SignInMethod): void {
    Alert.alert(t("methods.unlink.confirmTitle", { provider: label(m.provider) }), t("methods.unlink.confirmBody", { provider: label(m.provider) }), [
      { text: t("common.cancel"), style: "cancel" },
      { text: t("methods.unlink"), style: "destructive", onPress: () => void unlink(m) },
    ]);
  }

  async function act(fn: () => Promise<unknown>): Promise<void> {
    setBusy(true);
    try {
      await fn();
    } finally {
      setBusy(false);
    }
  }

  if (!session) {
    return (
      <Screen>
        <Body muted>{t("me.signInRequired")}</Body>
      </Screen>
    );
  }
  const input = { borderWidth: 1, borderColor: theme.border, borderRadius: 8, padding: 12, fontSize: 18, color: theme.text } as const;
  const hasApple = (methods ?? []).some((m) => m.provider === "apple");
  const failure: MessageKey | null =
    link.step === "failed"
      ? `methods.error.${link.reason}`
      : (link.step === "needs_proof" || link.step === "code_sent") && link.notice
        ? `methods.error.${link.notice}`
        : null;

  return (
    <Screen>
      <Body muted>{t("methods.intro")}</Body>
      {note ? <Banner tone="info" text={t(note)} /> : null}
      {(methods ?? []).map((m) => (
        <Card key={m.provider}>
          <H2>{label(m.provider)}</H2>
          {m.isPrivateRelay ? <Body muted>{t("methods.relay")}</Body> : null}
          <Button variant="danger" disabled={busy || !m.canUnlink} title={t("methods.unlink")} onPress={() => confirmUnlink(m)} />
          {!m.canUnlink ? <Body muted>{t("methods.unlink.last")}</Body> : null}
        </Card>
      ))}

      <Card>
        {link.step === "linked" ? (
          link.where === "self" ? (
            <Body>{t("methods.linked")}</Body>
          ) : (
            <>
              <Body>{t("methods.linked.elsewhere")}</Body>
              <Button
                title={t("methods.linked.elsewhere.action")}
                onPress={() =>
                  void signOut().then(() => {
                    router.dismissAll();
                  })
                }
              />
            </>
          )
        ) : null}

        {link.step === "needs_proof" ? (
          <>
            <H2>{t("methods.proof.title")}</H2>
            <Body>{link.email ? t("methods.proof.body", { email: link.email }) : t("methods.proof.bodyNoEmail")}</Body>
            {link.email === null ? (
              <TextInput
                accessibilityLabel={t("methods.proof.emailLabel")}
                placeholder={t("methods.proof.emailLabel")}
                placeholderTextColor={theme.subtext}
                keyboardType="email-address"
                autoCapitalize="none"
                autoCorrect={false}
                value={typedEmail}
                onChangeText={setTypedEmail}
                style={input}
              />
            ) : null}
            {/* Nothing is sent until the player taps this: the app never links by email match on its own. */}
            <Button title={t("methods.proof.send")} disabled={busy} onPress={() => void act(() => linkFlow.sendCode(typedEmail))} />
            <Button variant="secondary" title={t("methods.proof.cancel")} onPress={() => linkFlow.cancel()} />
          </>
        ) : null}

        {link.step === "code_sent" ? (
          <>
            <Body>{t("methods.proof.codeSent", { email: link.email })}</Body>
            {link.wrongCode ? <Body>{t("methods.proof.wrong")}</Body> : null}
            {link.attemptsRemaining !== null ? <Body muted>{t("methods.proof.attempts", { count: link.attemptsRemaining })}</Body> : null}
            <TextInput
              accessibilityLabel={t("methods.proof.codeLabel")}
              placeholder={t("methods.proof.codeLabel")}
              placeholderTextColor={theme.subtext}
              keyboardType="number-pad"
              autoComplete="one-time-code"
              maxLength={10}
              value={code}
              onChangeText={(v) => setCode(v.replace(/\D/g, ""))}
              style={input}
            />
            <Button title={t("methods.proof.submit")} disabled={busy || code.length < 6} onPress={() => void act(() => linkFlow.submitCode(code))} />
            <Button variant="secondary" title={t("methods.proof.cancel")} onPress={() => linkFlow.cancel()} />
          </>
        ) : null}

        {failure ? <Banner text={t(failure)} /> : null}
        {link.step === "unsupported_platform" ? <Body muted>{t("methods.link.unsupported")}</Body> : null}

        {!hasApple && link.step !== "needs_proof" && link.step !== "code_sent" && link.step !== "linked" && methods !== null ? (
          <Button title={t("methods.link.apple")} disabled={busy || link.step === "working"} onPress={() => void act(() => linkFlow.start())} />
        ) : null}
        <Row>
          <Chip label={t("methods.link.googleLater")} />
        </Row>
      </Card>
    </Screen>
  );
}
