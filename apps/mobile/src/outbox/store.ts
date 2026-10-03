/**
 * Outbox persistence behind an interface (build plan §7.1: `expo-sqlite`
 * "for the catalog cache and evidence outbox"). `MemoryOutboxStore` is the
 * reference implementation the machine tests run against;
 * `SqliteOutboxStore` is the real one, exercised against `node:sqlite` in
 * the tests through the shared `SqlDatabase` interface.
 */
import type { SqlDatabase } from "../db/sql";
import { UNOWNED, type OutboxItem } from "./types";

export interface InsertResult {
  inserted: boolean;
  /** The stored item: the new one, or the EXISTING one when `sourceRef` was a duplicate. */
  item: OutboxItem;
}

export interface OutboxStore {
  /** Idempotent on `(ownerUserId, sourceRef)`: a second insert by the SAME owner with the same `sourceRef` returns the existing item and
   * changes nothing (append-only identity). Another owner's identical `sourceRef` is a different item (the server's key is per user), and
   * never returns the first owner's item. Throws for an item with no owner (fail closed). */
  insertIfAbsent(item: OutboxItem): Promise<InsertResult>;
  get(id: string): Promise<OutboxItem | null>;
  /** EVERY owner's items, oldest first. Only housekeeping and tests read this: nothing that sends or shows items may. */
  list(): Promise<OutboxItem[]>;
  /** One owner's items, oldest first (event-time order, the order batches are sent in, FM-28). `UNOWNED` is nobody: it returns `[]`. */
  listByOwner(ownerUserId: string): Promise<OutboxItem[]>;
  /** Replaces a stored item. `id`, `sourceRef`, `ownerUserId` and `createdAt` must not change. */
  update(item: OutboxItem): Promise<void>;
  /** Only the runner's 90-day dead-letter expiry calls this. */
  delete(id: string): Promise<void>;
  /** Account deletion only (`account/delete.ts`): the outbox is the deleted player's own data, so it is wiped with the account. */
  deleteAll(): Promise<void>;
}

function assertSameIdentity(prev: OutboxItem, next: OutboxItem): void {
  if (prev.sourceRef !== next.sourceRef || prev.createdAt !== next.createdAt || prev.id !== next.id || prev.ownerUserId !== next.ownerUserId) {
    throw new Error("outbox: id, sourceRef, ownerUserId and createdAt are immutable");
  }
}

function assertOwned(item: OutboxItem): void {
  if (typeof item.ownerUserId !== "string" || item.ownerUserId === UNOWNED) throw new Error("outbox: refusing to store an item with no owner");
}

function clone<T>(v: T): T {
  return JSON.parse(JSON.stringify(v)) as T;
}

export class MemoryOutboxStore implements OutboxStore {
  private readonly byId = new Map<string, OutboxItem>();

  insertIfAbsent(item: OutboxItem): Promise<InsertResult> {
    try {
      assertOwned(item);
    } catch (e) {
      return Promise.reject(e instanceof Error ? e : new Error(String(e)));
    }
    for (const existing of this.byId.values()) {
      if (existing.sourceRef === item.sourceRef && existing.ownerUserId === item.ownerUserId) return Promise.resolve({ inserted: false, item: clone(existing) });
    }
    this.byId.set(item.id, clone(item));
    return Promise.resolve({ inserted: true, item: clone(item) });
  }
  get(id: string): Promise<OutboxItem | null> {
    const v = this.byId.get(id);
    return Promise.resolve(v ? clone(v) : null);
  }
  list(): Promise<OutboxItem[]> {
    return Promise.resolve([...this.byId.values()].map(clone).sort((a, b) => a.createdAt - b.createdAt || (a.id < b.id ? -1 : 1)));
  }
  listByOwner(ownerUserId: string): Promise<OutboxItem[]> {
    if (ownerUserId === UNOWNED) return Promise.resolve([]);
    return this.list().then((all) => all.filter((i) => i.ownerUserId === ownerUserId));
  }
  async update(item: OutboxItem): Promise<void> {
    const prev = this.byId.get(item.id);
    if (!prev) throw new Error(`outbox: no item ${item.id}`);
    assertSameIdentity(prev, item);
    this.byId.set(item.id, clone(item));
  }
  delete(id: string): Promise<void> {
    this.byId.delete(id);
    return Promise.resolve();
  }
  deleteAll(): Promise<void> {
    this.byId.clear();
    return Promise.resolve();
  }
}

interface Row {
  item_json: string;
  owner_user_id: string;
}

const COLS = "item_json, owner_user_id";

/** The `owner_user_id` COLUMN is authoritative (it is what the selection query and the index use); the JSON copy is overwritten by it. */
function parse(row: Row): OutboxItem {
  return { ...(JSON.parse(row.item_json) as OutboxItem), ownerUserId: row.owner_user_id };
}

export class SqliteOutboxStore implements OutboxStore {
  constructor(private readonly db: SqlDatabase) {}

  async insertIfAbsent(item: OutboxItem): Promise<InsertResult> {
    assertOwned(item);
    return this.db.transaction(async (tx) => {
      const existing = await tx.all<Row>(`SELECT ${COLS} FROM outbox WHERE owner_user_id = ? AND source_ref = ?`, [item.ownerUserId, item.sourceRef]);
      if (existing[0]) return { inserted: false, item: parse(existing[0]) };
      await tx.run("INSERT INTO outbox (id, source_ref, owner_user_id, status, next_attempt_at, created_at, item_json) VALUES (?, ?, ?, ?, ?, ?, ?)", [
        item.id,
        item.sourceRef,
        item.ownerUserId,
        item.status,
        item.nextAttemptAt,
        item.createdAt,
        JSON.stringify(item),
      ]);
      return { inserted: true, item };
    });
  }

  async get(id: string): Promise<OutboxItem | null> {
    const rows = await this.db.all<Row>(`SELECT ${COLS} FROM outbox WHERE id = ?`, [id]);
    return rows[0] ? parse(rows[0]) : null;
  }

  async list(): Promise<OutboxItem[]> {
    const rows = await this.db.all<Row>(`SELECT ${COLS} FROM outbox ORDER BY created_at ASC, id ASC`);
    return rows.map(parse);
  }

  async listByOwner(ownerUserId: string): Promise<OutboxItem[]> {
    if (ownerUserId === UNOWNED) return [];
    const rows = await this.db.all<Row>(`SELECT ${COLS} FROM outbox WHERE owner_user_id = ? ORDER BY created_at ASC, id ASC`, [ownerUserId]);
    return rows.map(parse);
  }

  async update(item: OutboxItem): Promise<void> {
    await this.db.transaction(async (tx) => {
      const rows = await tx.all<Row>(`SELECT ${COLS} FROM outbox WHERE id = ?`, [item.id]);
      if (!rows[0]) throw new Error(`outbox: no item ${item.id}`);
      assertSameIdentity(parse(rows[0]), item);
      await tx.run("UPDATE outbox SET status = ?, next_attempt_at = ?, item_json = ? WHERE id = ?", [
        item.status,
        item.nextAttemptAt,
        JSON.stringify(item),
        item.id,
      ]);
    });
  }

  async delete(id: string): Promise<void> {
    await this.db.run("DELETE FROM outbox WHERE id = ?", [id]);
  }

  async deleteAll(): Promise<void> {
    await this.db.run("DELETE FROM outbox");
  }
}
