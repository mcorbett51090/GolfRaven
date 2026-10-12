export interface ParseIssue {
  path: string;
  message: string;
}
export type ParseResult<T> = { ok: true; value: T } | { ok: false; issues: ParseIssue[] };

export const RECEIPTS_MAX_BYTES = 5 * 1024 * 1024;
/** Small overhead for multipart boundaries and field names (0012_storage.sql 5 MB object cap). */
export const RECEIPTS_MAX_BODY_BYTES = RECEIPTS_MAX_BYTES + 16 * 1024;

const LOCAL_DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

export interface ParsedReceiptUpload {
  facilityId: string;
  fileBytes: Uint8Array;
  fileName: string;
  localDate: string | null;
  receiptNumberOcr: string | null;
}

function issue(issues: ParseIssue[], path: string, message: string): void {
  issues.push({ path, message });
}

export async function parseReceiptMultipart(form: FormData): Promise<ParseResult<ParsedReceiptUpload>> {
  const issues: ParseIssue[] = [];
  const keys = [...form.keys()];
  const allowed = new Set(["facilityId", "file", "localDate", "receiptNumberOcr"]);
  for (const k of keys) {
    if (!allowed.has(k)) issue(issues, k, "unknown field");
  }

  const facilityRaw = form.get("facilityId");
  if (typeof facilityRaw !== "string" || facilityRaw.trim() === "") {
    issue(issues, "facilityId", "required");
  }

  const file = form.get("file");
  if (!(file instanceof File)) {
    issue(issues, "file", "required file");
  }

  let localDate: string | null = null;
  const localRaw = form.get("localDate");
  if (localRaw !== null && localRaw !== "") {
    if (typeof localRaw !== "string" || !LOCAL_DATE_RE.test(localRaw)) {
      issue(issues, "localDate", "expected YYYY-MM-DD");
    } else {
      localDate = localRaw;
    }
  }

  let receiptNumberOcr: string | null = null;
  const ocrRaw = form.get("receiptNumberOcr");
  if (ocrRaw !== null && ocrRaw !== "") {
    if (typeof ocrRaw !== "string") issue(issues, "receiptNumberOcr", "expected string");
    else receiptNumberOcr = ocrRaw.trim() === "" ? null : ocrRaw.trim();
  }

  if (issues.length > 0) return { ok: false, issues };

  const facilityId = (facilityRaw as string).trim();
  const upload = file as File;
  if (upload.size > RECEIPTS_MAX_BYTES) {
    issue(issues, "file", `exceeds ${RECEIPTS_MAX_BYTES} bytes`);
    return { ok: false, issues };
  }

  const fileBytes = new Uint8Array(await upload.arrayBuffer());
  if (fileBytes.byteLength > RECEIPTS_MAX_BYTES) {
    issue(issues, "file", `exceeds ${RECEIPTS_MAX_BYTES} bytes`);
    return { ok: false, issues };
  }

  return {
    ok: true,
    value: {
      facilityId,
      fileBytes,
      fileName: upload.name || "receipt",
      localDate,
      receiptNumberOcr,
    },
  };
}
