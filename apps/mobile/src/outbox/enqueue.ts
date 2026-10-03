/**
 * The ONLY way an item enters the outbox from the app: it takes the owner from the auth session, never from the caller.
 *
 * Fail closed (P4.2b-0): signed out means NO row is written and the call throws `OutboxEnqueueError("signed_out")`. A screen that has a
 * play to record must get the player signed in first (sign-in is requested only to record a play, Apple 5.1.1, build plan §7.8); it must
 * never queue the play "for whoever signs in next", because the next person to sign in on this device may be someone else.
 */
import { createItem } from "./machine";
import type { InsertResult, OutboxStore } from "./store";
import { UNOWNED, type NewOutboxItem, type OutboxItem } from "./types";

/** What a caller supplies. There is deliberately no `ownerUserId`: it is read from the session. */
export type OutboxDraft = Omit<NewOutboxItem, "ownerUserId">;

/** `account_changed`: the caller started the work for one user and a different one is signed in now (P4.2c-1): nothing is written for either. */
export type OutboxEnqueueFailure = "signed_out" | "account_changed";

export class OutboxEnqueueError extends Error {
  readonly code: OutboxEnqueueFailure;
  constructor(code: OutboxEnqueueFailure) {
    super(code === "signed_out" ? `outbox: cannot enqueue (${code}): sign in first` : `outbox: cannot enqueue (${code}): the signed-in account changed`);
    this.name = "OutboxEnqueueError";
    this.code = code;
  }
}

export interface EnqueueDeps {
  store: OutboxStore;
  /** The signed-in user's id from the auth session (`AuthService.current()?.userId`), or `null` when signed out. */
  currentUserId: () => string | null;
  now: () => number;
}

export async function enqueueOutboxItem(deps: EnqueueDeps, draft: OutboxDraft): Promise<InsertResult> {
  const owner = deps.currentUserId();
  if (owner === null || owner === UNOWNED) throw new OutboxEnqueueError("signed_out");
  // Spread FIRST: even a caller that smuggles an `ownerUserId` into the draft cannot choose the owner.
  return deps.store.insertIfAbsent(createItem({ ...draft, ownerUserId: owner }, deps.now()));
}

/** Keeps the items `userId` may see: theirs only, and none when signed out (or for the unowned sentinel). Pure: the provider applies it again to
 * what it holds in state, so a list loaded for one user can never be rendered under another. */
export function filterVisibleOutboxItems(items: readonly OutboxItem[], userId: string | null): OutboxItem[] {
  if (userId === null || userId === UNOWNED) return [];
  return items.filter((i) => i.ownerUserId === userId);
}

/** The items the signed-in user may see, read from the store. This is the single read the UI list goes through. */
export async function visibleOutboxItems(store: OutboxStore, currentUserId: string | null): Promise<OutboxItem[]> {
  if (currentUserId === null || currentUserId === UNOWNED) return [];
  return filterVisibleOutboxItems(await store.listByOwner(currentUserId), currentUserId);
}
