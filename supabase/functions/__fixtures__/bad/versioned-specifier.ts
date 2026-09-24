// MUST-FAIL (M3(1), post-P3a gate): versioned/URL specifiers dress up the
// exact same banned packages an anchored regex on the bare name would
// have caught — none of these equal "@supabase/supabase-js", "pg", or
// "postgres" literally, so an unanchored-name check must normalise the
// specifier (strip host/scheme prefix + trailing @version) before
// comparing.
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.45.0";
import postgres from "https://deno.land/x/postgresjs@0.19.0/mod.js";
import pg from "npm:pg@8";

export function connectAll() {
  return [createClient, postgres, pg];
}
