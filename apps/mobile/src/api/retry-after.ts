import { retryDetailsSchema } from "./schemas";

/** The server's wait hint: a `Retry-After` header of whole seconds, else the error envelope's `details.retryAfterSeconds` (the server's own 429s
 * carry only the latter, `_shared/http.ts#Errors.tooManyRequests`). `null` when neither is present or usable. */
export function retryAfterSecondsFrom(res: Pick<Response, "headers">, details: unknown): number | null {
  const header = res.headers.get("retry-after");
  if (header !== null && /^\d{1,7}$/.test(header.trim())) return Number(header.trim());
  const d = retryDetailsSchema.safeParse(details);
  return d.success ? d.data.retryAfterSeconds : null;
}
