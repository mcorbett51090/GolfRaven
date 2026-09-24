// Clean fixture: NO import of "@supabase/supabase-js" (or any banned
// specifier) at all — per the gate-round-2 tightened rule, that import is
// confined entirely to supabase/functions/_shared/privileged.ts, even for
// a plain JWT-forwarded read (§4.7.1a line 1187). A read-only handler
// receives an already-constructed, already-scoped client/query object as
// a parameter instead of constructing one itself.
interface QueryClient {
  from(table: string): { select(cols: string): Promise<unknown> };
}

export function readOwnProfile(client: QueryClient) {
  return client.from("profile").select("*");
}
