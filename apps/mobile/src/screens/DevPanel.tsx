import { useRouter } from "expo-router";
import type { MockApi } from "../api/mock";
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
  // Only the demo backend (a `__DEV__` build with no server configured) has a scriptable mock; `null` against a real server.
  const mock = services.devHandle as MockApi | null;
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
      <H2>Developer tools</H2>
      <Body muted>Backend: {services.backend}. {mock ? "Queue a server answer, then enqueue a play and sync." : "Scriptable answers exist only in the demo backend."}</Body>
      {mock ? (
        <>
          <Button variant="secondary" title="Script next answer: 202 queued_catalog" onPress={() => mock.script(answer(202, "queued_catalog"))} />
          <Button variant="secondary" title="Script next answer: 422 catalog_stale" onPress={() => mock.script(answer(422, "catalog_stale"))} />
          <Button variant="secondary" title="Script next answer: 429 (Retry-After 60 s)" onPress={() => mock.script(answer(429, undefined, 60))} />
          <Button variant="secondary" title="Script next answer: 500" onPress={() => mock.script(answer(500))} />
          <Button variant="secondary" title="Script next answer: 422 unknown_id (dead letter)" onPress={() => mock.script(answer(422, "unknown_id"))} />
        </>
      ) : null}
      <Button title="Enqueue a play" onPress={() => void enqueue(true)} />
      <Button title="Enqueue an unlisted-course play" onPress={() => void enqueue(false)} />
      <Button title="Run sync" onPress={() => void syncOutbox()} />
      {Platform.OS === "android" ? <Button variant="secondary" title="P0 check X1 (Health Connect)" onPress={() => router.push("/dev/x1")} /> : null}
    </Card>
  );
}
