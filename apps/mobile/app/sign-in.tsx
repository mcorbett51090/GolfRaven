import { useRouter } from "expo-router";
import { useEffect, useState } from "react";
import { useApp } from "../src/runtime/AppProvider";
import { offeredProviders, startSignIn, type SignInProviderId } from "../src/signin";
import { Banner, Button, Screen } from "../src/ui/components";

/** Sign-in with STUB providers (real Apple / Google / email OTP are P4.2).
 * The only way to a provider is `startSignIn`, which refuses unless the age
 * gate has passed; if it has not, this screen sends the player to the age
 * screen first (O18). */
export default function SignInScreen() {
  const { services, t, startMockSession } = useApp();
  const router = useRouter();
  const [ready, setReady] = useState(false);

  // O18: provider choices are shown only after the age screen has passed.
  useEffect(() => {
    void services.ageGate.state().then((s) => {
      if (s === "eligible") setReady(true);
      else router.replace("/age-gate");
    });
  }, [services, router]);

  async function choose(id: SignInProviderId): Promise<void> {
    const r = await startSignIn(id, { gate: services.ageGate, providers: services.providers });
    if (r.status === "age_required" || r.status === "blocked") {
      router.replace("/age-gate");
      return;
    }
    startMockSession(r.result.provider);
    router.dismissAll();
  }

  if (!ready) return <Screen />;
  return (
    <Screen>
      <Banner tone="info" text={t("signIn.stubNote")} />
      {/* Sign in with Apple is listed first, with equal prominence (Apple 4.8). */}
      {offeredProviders().map((id) => (
        <Button key={id} variant={id === "email" ? "secondary" : "primary"} title={t(`signIn.${id}`)} onPress={() => void choose(id)} />
      ))}
    </Screen>
  );
}
