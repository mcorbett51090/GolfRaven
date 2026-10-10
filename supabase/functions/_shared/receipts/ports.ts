export type ReceiptIntakeStatus =
  | "ok"
  | "duplicate"
  | "review"
  | "no_facility"
  | "no_programme"
  | "review_account"
  | "bad_args";

export type ReceiptDedupe = "clean" | "same_user" | "cross_user";

export interface ReceiptPurchaseRow {
  purchaseId: string;
  trailId: string;
  purchaseStatus: string;
  creditId: string;
  creditStatus: string;
}

export interface ReceiptIntakeInput {
  facilityId: string;
  storageObject: string;
  phash: string;
  localDate: string | null;
  receiptNumberOcr: string | null;
}

export interface ReceiptIntakeResult {
  status: ReceiptIntakeStatus;
  localDate: string | null;
  dedupe: ReceiptDedupe | null;
  purchases: ReceiptPurchaseRow[];
}

export interface ReceiptsStoragePort {
  putObject(path: string, body: Uint8Array, contentType: string): Promise<void>;
  /** Best-effort delete when intake refuses after upload (orphan compensation). */
  removeObject(path: string): Promise<void>;
  /** System-lane retention: delete objects with created_at older than the cutoff (epoch ms). */
  purgeOlderThan(olderThanMs: number): Promise<number>;
}
