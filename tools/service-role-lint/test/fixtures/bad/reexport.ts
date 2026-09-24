// MUST-FAIL: re-exporting the client-constructing symbol from a banned
// specifier — this creates a second, indirect construction site (anything
// importing `createClient` FROM THIS FILE gets it without this file ever
// calling it directly).
export { createClient } from "@supabase/supabase-js";
