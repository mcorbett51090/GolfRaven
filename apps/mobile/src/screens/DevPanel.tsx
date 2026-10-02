import { useRouter } from "expo-router";
import { Platform } from "react-native";
import { useApp } from "../runtime/AppProvider";
import { createItem, type ServerAnswer } from "../outbox";
import { Body, Button, Card, H2 } from "../ui/components";

/**
 * Development-only controls (rendered only when `__DEV__`): drive the §7.6
 * outbox states against the MOCK `api.*` without a server. Not localized.
 */
export function DevPanel() {
  const { services, index, syncOutbox, reloadOutbox, snapshot } = useApp();
  const router = useRouter();
  const answer = (status: number, code?: string, retryAfterSeconds?: number): ServerAnswer => ({ kind: "response", status, code, retryAfterSeconds });

  async function enqueue(listed: boolean): Promise<void> {
    const course = index ? [...index.courses.keys()][0] : undefined;
    const now = Date.now();
    await services.outboxStore.insertIfAbsent(
      createItem(
        {
          id: `dev-${now}`,
          sourceRef: `dev:${now}`,
          courseId: listed ? (course ?? null) : null,
          catalogVersion: snapshot?.catalogVersion ?? null,
          payload: { dev: true },
        },
        now,
      ),
    );
    await reloadOutbox();
  }

  return (
    <Card>
      <H2>Developer tools (mock api)</H2>
      <Body muted>Queue a server answer, then enqueue a play and sync.</Body>
      <Button variant="secondary" title="Script next answer: 202 queued_catalog" onPress={() => services.api.script(answer(202, "queued_catalog"))} />
      <Button variant="secondary" title="Script next answer: 422 catalog_stale" onPress={() => services.api.script(answer(422, "catalog_stale"))} />
      <Button variant="secondary" title="Script next answer: 429 (Retry-After 60 s)" onPress={() => services.api.script(answer(429, undefined, 60))} />
      <Button variant="secondary" title="Script next answer: 500" onPress={() => services.api.script(answer(500))} />
      <Button variant="secondary" title="Script next answer: 422 unknown_id (dead letter)" onPress={() => services.api.script(answer(422, "unknown_id"))} />
      <Button title="Enqueue a play" onPress={() => void enqueue(true)} />
      <Button title="Enqueue an unlisted-course play" onPress={() => void enqueue(false)} />
      <Button title="Run sync" onPress={() => void syncOutbox()} />
      {Platform.OS === "android" ? <Button variant="secondary" title="P0 check X1 (Health Connect)" onPress={() => router.push("/dev/x1")} /> : null}
    </Card>
  );
}
