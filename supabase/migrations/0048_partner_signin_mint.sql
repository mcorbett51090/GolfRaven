-- 0048_partner_signin_mint.sql
--
-- P5.1a, slice S1.1b: the DATABASE SIDE OF PARTNER (STAFF) SIGN-IN MINTING. docs/security/partner-auth-design.md (revision 5 + the S0 gate ruling of 15.2 / 16.4) is the specification: section 4.4
-- (the minter, the DB-side assertion checks, stateless challenges), 5.1 (the HMAC encoding), 6.2 (sign-in, the counter policy), 8 (rate limits), 12 (the S1.1 row; PA-7, PA-8, PA-9, PA-9b) and,
-- above all, 16.5 (the seams 0047 left for this file, followed exactly). Migrations 0001-0047 are untouched; everything below is CREATE, or ALTER / CREATE OR REPLACE of an object 0047 made.
--
-- WHAT THIS ADDS
--   1. THE SQL SIGNATURE VERIFIERS (the S0 gate ruling: database-side verification is the plan of record). ES256 (ECDSA P-256 / SHA-256) and RS256 (RSASSA-PKCS1-v1_5, e = 65537, SHA-256), ported from
--      the S0 spike (tools/db/spikes/partner-sig) as PURE functions in core PostgreSQL (numeric, bytea, sha256(); no extension), plus a strict COSE_Key parser. Every strictness rule of the spike is kept
--      and is now a small named predicate, so each one has a pgTAP cell of its own (S0-L1): ECDSA r and s in [1, n-1], the public key a point ON the curve with both coordinates below p, the point at
--      infinity refused, a strict DER signature, no low-s requirement (WebAuthn does not ask for it); RSA e = 65537, a full-length odd modulus of 2048 to 4096 bits, len(sig) = k, s < n, and the
--      EMSA-PKCS1-v1_5 message built FRESH and compared as an integer, never parsed (Bleichenbacher). The entry point is private.partner_sig_verify(alg, cose_key, message, signature); the helpers are owner-only.
--   2. THE STATELESS SIGN-IN CHALLENGE (5.1): private.partner_challenge_issue_sign_in() returns 32 random bytes, an expiry and an HMAC-SHA256 under the Vault key partner_challenge_key over the fixed-width
--      message  label || 0x00 || purpose || exp || nonce || binding.  It takes NO purpose and NO binding argument, writes NO row, and is executable by edge_partner_minter only. The Vault key is read in ONE core
--      (private.partner_challenge_core: the offline_seed_derive shape; no role may execute it) and a presented token is compared as HMAC(K, presented) = HMAC(K, expected).
--   3. THE SIGN-IN MINT: private.partner_session_mint(...), owned by partner_session_issuer (the 0047 seam), EXECUTE for edge_partner_minter only. Its steps run in this order, each refusing with a STATUS, never a
--      RAISE, wherever the transaction must commit something (the 0020 lesson): (1) the HMAC, the purpose and the expiry; (2) the credential LOOKED UP FROM app.partner_credential (the key is never an argument);
--      (3) at most 60 successful sign-ins per credential per hour, BEFORE any verification (S0-L5); (4) the structural checks against app.partner_rp_config (clientDataJSON type, crossOrigin, origin, challenge;
--      authenticatorData rpIdHash, UP, UV, the counter); (5) the SQL signature verification, LAST of the checks; (6) the used nonce is INSERTED (primary key = single use); (7) the counter compare-and-set (PA-9);
--      (8) the session is inserted with the mint_* evidence. A signature that fails here, after the Edge verified it, is an ALARM: a distinct status, one audit_log row and one app.partner_auth_alarm row (both
--      committed, deduplicated per credential per minute so a flood cannot grow them without bound). A counter regression is the same alarm.
--   4. The grants the issuer needs to do that (column-level, registered in private.partner_owner_privilege and its fixture), the alarm table, and the registry rows.
--
-- WHAT THIS DOES NOT BUILD (the 16.5 seam stays intact): partner_credential_register_first, the register / reauth challenge issuers, the invite and enrolment accept definers, the eviction of the oldest session
-- beyond three live ones (4.1), the purge definers (section 9), and the TypeScript half (S1.2).

-- ============================================================================
-- 1. The issuer owns the mint: the migrating role holds SET on it for the length of this file only (the 0047 bracket, R5-L3)
-- ============================================================================
GRANT partner_session_issuer TO CURRENT_USER WITH INHERIT FALSE, SET TRUE;

-- ============================================================================
-- 2. app.partner_auth_alarm: the operator-facing record of a sign-in the database refused AFTER the Edge passed it
-- ============================================================================
CREATE TABLE app.partner_auth_alarm (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  kind text NOT NULL CHECK (kind IN ('signature_invalid', 'counter_regression')),
  -- the credential's row id. NO foreign key and NO user id: the alarm is not a personal table (course_pin_alarm, 0046), and it must survive the credential's deletion.
  credential_id uuid NOT NULL,
  -- floor(epoch / 60): one alarm per (kind, credential, minute), so a flood of refusals writes one row a minute, not one per request
  minute_bucket bigint NOT NULL,
  detail jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (pg_column_size(detail) <= 400),
  raised_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (kind, credential_id, minute_bucket)
);
COMMENT ON TABLE app.partner_auth_alarm IS
  '0048. One row per (kind, credential, minute) when private.partner_session_mint refused a sign-in the Edge had already passed: signature_invalid (the SQL verifier disagrees with the Edge: a compromised runtime, a library gap, a corrupt key) or counter_regression (a non-zero counter that did not strictly rise: a cloned authenticator, 6.2 step 4). Operator-facing (the portal reads it, S6). Holds no user id and no assertion bytes. Written only by private.partner_mint_alarm_write, which also writes the audit_log row; no client role, no edge role and not service_role has any privilege on it. Retention is a purge step (follow-up).';
ALTER TABLE app.partner_auth_alarm ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.partner_auth_alarm FORCE ROW LEVEL SECURITY;
REVOKE ALL ON app.partner_auth_alarm FROM PUBLIC, anon, authenticated, service_role;

-- ============================================================================
-- 3. Grants and policies the new definers rely on
-- ============================================================================
-- 3a. private_definer owns the alarm writer. INSERT (+ SELECT on the arbiter columns: INSERT ... ON CONFLICT reads them, 0046) only; the policies are keyed on the transaction's own binding, never a GUC, and
-- admit the write only when NO binding exists (the mint transaction binds nothing): a partner- or user-bound definer cannot use the alarm writer as a noise lever.
GRANT INSERT, SELECT (kind, credential_id, minute_bucket) ON app.partner_auth_alarm TO private_definer;
CREATE POLICY pd_partner_auth_alarm_insert ON app.partner_auth_alarm FOR INSERT TO private_definer WITH CHECK ((SELECT private.partner_binding_kind()) IS NULL);
CREATE POLICY pd_partner_auth_alarm_select ON app.partner_auth_alarm FOR SELECT TO private_definer USING ((SELECT private.partner_binding_kind()) IS NULL);

-- 3b. partner_session_issuer (the mint's owner): every privilege is COLUMN-level wherever a whole-row grant would reach more than the mint reads or writes, and is registered in
-- private.partner_owner_privilege (section 8) and its checked-in fixture.
--   partner_session: the rate limit counts a credential's recent sign-in mints (credential_id, mint_kind, created_at)
GRANT SELECT (credential_id, mint_kind) ON app.partner_session TO partner_session_issuer;
--   partner_credential: the mint reads the key it verifies against (never an argument) and advances the counter by compare-and-set (partner_credential_guard: sign_count never decreases)
GRANT SELECT (public_key, alg, sign_count) ON app.partner_credential TO partner_session_issuer;
GRANT UPDATE (sign_count, last_used_at) ON app.partner_credential TO partner_session_issuer;
CREATE POLICY psi_update_partner_credential ON app.partner_credential FOR UPDATE TO partner_session_issuer USING (true) WITH CHECK (true);
--   partner_rp_config: the relying party the assertion is checked against
GRANT SELECT (rp_id, origin) ON app.partner_rp_config TO partner_session_issuer;
CREATE POLICY psi_read_partner_rp_config ON app.partner_rp_config FOR SELECT TO partner_session_issuer USING (true);
--   partner_auth_challenge: the used nonce (the primary key is the single-use guarantee); SELECT of the key column for ON CONFLICT
GRANT INSERT, SELECT (nonce_hash) ON app.partner_auth_challenge TO partner_session_issuer;
CREATE POLICY psi_insert_partner_auth_challenge ON app.partner_auth_challenge FOR INSERT TO partner_session_issuer WITH CHECK (true);
CREATE POLICY psi_read_partner_auth_challenge ON app.partner_auth_challenge FOR SELECT TO partner_session_issuer USING (true);

-- ============================================================================
-- 4. The SQL signature verifiers (ownership bracket: private_definer, as 0045 / 0047)
-- ============================================================================
-- Everything here is PURE: it reads no table, no setting and no clock, and writes nothing. The helpers are plpgsql IMMUTABLE functions owned by private_definer with NO EXECUTE for anyone; the one entry point
-- (partner_sig_verify) is SECURITY DEFINER with search_path = '' and is executable by partner_session_issuer only, so every helper runs as its owner under an empty search_path. NOT constant-time, deliberately:
-- everything verified is public (a signature, a public key, a message). `numeric` is arbitrary precision; `%` is a TRUNCATING remainder, so every subtraction below stays non-negative before the `%`.
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

-- big-endian bytes -> non-negative integer (OS2IP)
CREATE FUNCTION private.partner_sig_os2ip(p_b bytea) RETURNS numeric
LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
  acc numeric := 0;
  i int;
BEGIN
  FOR i IN 0 .. pg_catalog.length(p_b) - 1 LOOP
    acc := acc * 256 + pg_catalog.get_byte(p_b, i);
  END LOOP;
  RETURN acc;
END
$$;

-- x^e mod m for non-negative integers (right-to-left: needs only % and div)
CREATE FUNCTION private.partner_sig_modexp(p_base numeric, p_ex numeric, p_m numeric) RETURNS numeric
LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
  result numeric := 1;
  b      numeric := p_base % p_m;
  e      numeric := p_ex;
BEGIN
  WHILE e > 0 LOOP
    IF e % 2 = 1 THEN
      result := (result * b) % p_m;
    END IF;
    e := pg_catalog.div(e, 2);
    IF e > 0 THEN
      b := (b * b) % p_m;
    END IF;
  END LOOP;
  RETURN result;
END
$$;

-- the 256 low bits of x as a text of '0'/'1', most significant first
CREATE FUNCTION private.partner_sig_bits256(p_x numeric) RETURNS text
LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
  v   numeric := p_x;
  out text := '';
  i   int;
BEGIN
  FOR i IN 1 .. 256 LOOP
    out := (v % 2)::int::text || out;
    v := pg_catalog.div(v, 2);
  END LOOP;
  RETURN out;
END
$$;

-- ===== ES256: P-256 ECDSA ===================================================================================================================
-- secp256r1 / NIST P-256 domain parameters (FIPS 186-4 D.1.2.3). a = -3.
CREATE FUNCTION private.partner_sig_p256_p() RETURNS numeric LANGUAGE sql IMMUTABLE AS
  $$ SELECT 115792089210356248762697446949407573530086143415290314195533631308867097853951::numeric $$;
CREATE FUNCTION private.partner_sig_p256_n() RETURNS numeric LANGUAGE sql IMMUTABLE AS
  $$ SELECT 115792089210356248762697446949407573529996955224135760342422259061068512044369::numeric $$;
CREATE FUNCTION private.partner_sig_p256_b() RETURNS numeric LANGUAGE sql IMMUTABLE AS
  $$ SELECT 41058363725152142129326129780047268409114441015993725554835256314039467401291::numeric $$;
CREATE FUNCTION private.partner_sig_p256_gx() RETURNS numeric LANGUAGE sql IMMUTABLE AS
  $$ SELECT 48439561293906451759052585252797914202762949526041747995844080717082404635286::numeric $$;
CREATE FUNCTION private.partner_sig_p256_gy() RETURNS numeric LANGUAGE sql IMMUTABLE AS
  $$ SELECT 36134250956749795798585127919587881956611106672985015071877198253568414405109::numeric $$;

CREATE TYPE private.partner_sig_jpoint AS (x numeric, y numeric, z numeric);   -- Jacobian; z = 0 is the point at infinity

-- 2P, a = -3 (EFD "dbl-2001-b"). Inputs reduced mod p.
CREATE FUNCTION private.partner_sig_jdouble(pt private.partner_sig_jpoint) RETURNS private.partner_sig_jpoint
LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
  pm numeric := private.partner_sig_p256_p();
  delta numeric; gamma numeric; beta numeric; alpha numeric; gamma2 numeric;
  x3 numeric; y3 numeric; z3 numeric;
BEGIN
  IF pt.z = 0 OR pt.y = 0 THEN
    RETURN ROW(1, 1, 0)::private.partner_sig_jpoint;
  END IF;
  delta  := (pt.z * pt.z) % pm;
  gamma  := (pt.y * pt.y) % pm;
  beta   := (pt.x * gamma) % pm;
  alpha  := (3 * ((pt.x + pm - delta) % pm) * ((pt.x + delta) % pm)) % pm;
  gamma2 := (gamma * gamma) % pm;
  x3 := (alpha * alpha + 8 * (pm - beta)) % pm;
  z3 := ((pt.y + pt.z) * (pt.y + pt.z) + 2 * pm - gamma - delta) % pm;
  y3 := (alpha * ((4 * beta + pm - x3) % pm) + 8 * (pm - gamma2)) % pm;
  RETURN ROW(x3, y3, z3)::private.partner_sig_jpoint;
END
$$;

-- P + Q (EFD "add-2007-bl"), with the degenerate cases made explicit: P = Q doubles, P = -Q is the point at infinity, either operand at infinity returns the other.
CREATE FUNCTION private.partner_sig_jadd(pa private.partner_sig_jpoint, pb private.partner_sig_jpoint) RETURNS private.partner_sig_jpoint
LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
  pm numeric := private.partner_sig_p256_p();
  z1z1 numeric; z2z2 numeric; u1 numeric; u2 numeric; s1 numeric; s2 numeric;
  h numeric; i numeric; j numeric; rr numeric; v numeric;
  x3 numeric; y3 numeric; z3 numeric;
BEGIN
  IF pa.z = 0 THEN RETURN pb; END IF;
  IF pb.z = 0 THEN RETURN pa; END IF;
  z1z1 := (pa.z * pa.z) % pm;
  z2z2 := (pb.z * pb.z) % pm;
  u1 := (pa.x * z2z2) % pm;
  u2 := (pb.x * z1z1) % pm;
  s1 := (((pa.y * pb.z) % pm) * z2z2) % pm;
  s2 := (((pb.y * pa.z) % pm) * z1z1) % pm;
  h := (u2 + pm - u1) % pm;
  IF h = 0 THEN
    IF s1 = s2 THEN
      RETURN private.partner_sig_jdouble(pa);                      -- P = Q
    END IF;
    RETURN ROW(1, 1, 0)::private.partner_sig_jpoint;               -- P = -Q
  END IF;
  i  := (4 * h * h) % pm;
  j  := (h * i) % pm;
  rr := (2 * ((s2 + pm - s1) % pm)) % pm;
  v  := (u1 * i) % pm;
  x3 := (rr * rr + 2 * (pm - v) + (pm - j)) % pm;
  y3 := (rr * ((v + pm - x3) % pm) + 2 * (pm - ((s1 * j) % pm))) % pm;
  z3 := ((((pa.z + pb.z) * (pa.z + pb.z) + 2 * pm - z1z1 - z2z2) % pm) * h) % pm;
  RETURN ROW(x3, y3, z3)::private.partner_sig_jpoint;
END
$$;

-- u1*G + u2*Q by Shamir's trick: one shared 256-step double-and-add pass over the bits of both scalars.
CREATE FUNCTION private.partner_sig_p256_shamir(p_u1 numeric, p_u2 numeric, p_qx numeric, p_qy numeric) RETURNS private.partner_sig_jpoint
LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
  G  private.partner_sig_jpoint := ROW(private.partner_sig_p256_gx(), private.partner_sig_p256_gy(), 1)::private.partner_sig_jpoint;
  Q  private.partner_sig_jpoint := ROW(p_qx, p_qy, 1)::private.partner_sig_jpoint;
  GQ private.partner_sig_jpoint;
  R  private.partner_sig_jpoint := ROW(1, 1, 0)::private.partner_sig_jpoint;
  b1 text := private.partner_sig_bits256(p_u1);
  b2 text := private.partner_sig_bits256(p_u2);
  i  int;
  sel int;
BEGIN
  GQ := private.partner_sig_jadd(G, Q);
  FOR i IN 1 .. 256 LOOP
    R := private.partner_sig_jdouble(R);
    sel := (pg_catalog.substr(b1, i, 1) = '1')::int + 2 * (pg_catalog.substr(b2, i, 1) = '1')::int;
    IF sel = 1 THEN R := private.partner_sig_jadd(R, G);
    ELSIF sel = 2 THEN R := private.partner_sig_jadd(R, Q);
    ELSIF sel = 3 THEN R := private.partner_sig_jadd(R, GQ);
    END IF;
  END LOOP;
  RETURN R;
END
$$;

-- strict DER Ecdsa-Sig-Value -> {r, s}; NULL on ANY deviation (a WebAuthn ES256 signature is DER, and short enough that every length is one byte): SEQUENCE of two INTEGERs, exact lengths, no trailing
-- bytes, positive (a set top bit needs a leading 0x00), minimal (no redundant leading 0x00), 1 to 33 bytes each.
CREATE FUNCTION private.partner_sig_der_rs(p_sig bytea) RETURNS numeric[]
LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
  total int; rl int; sl int; pos int := 2;
  r bytea; s bytea;
BEGIN
  IF p_sig IS NULL OR pg_catalog.length(p_sig) < 8 OR pg_catalog.length(p_sig) > 72 THEN RETURN NULL; END IF;
  IF pg_catalog.get_byte(p_sig, 0) <> 48 THEN RETURN NULL; END IF;                                   -- 0x30 SEQUENCE
  total := pg_catalog.get_byte(p_sig, 1);
  IF total >= 128 OR total <> pg_catalog.length(p_sig) - 2 THEN RETURN NULL; END IF;                -- single-byte length, exact
  IF pg_catalog.get_byte(p_sig, pos) <> 2 THEN RETURN NULL; END IF;                                   -- 0x02 INTEGER
  rl := pg_catalog.get_byte(p_sig, pos + 1);
  IF rl = 0 OR rl > 33 OR pos + 2 + rl + 2 > pg_catalog.length(p_sig) THEN RETURN NULL; END IF;
  r := pg_catalog.substring(p_sig, pos + 3, rl);
  pos := pos + 2 + rl;
  IF pg_catalog.get_byte(p_sig, pos) <> 2 THEN RETURN NULL; END IF;
  sl := pg_catalog.get_byte(p_sig, pos + 1);
  IF sl = 0 OR sl > 33 OR pos + 2 + sl <> pg_catalog.length(p_sig) THEN RETURN NULL; END IF;
  s := pg_catalog.substring(p_sig, pos + 3, sl);
  -- minimal and non-negative integers
  IF pg_catalog.get_byte(r, 0) >= 128 OR pg_catalog.get_byte(s, 0) >= 128 THEN RETURN NULL; END IF;
  IF rl > 1 AND pg_catalog.get_byte(r, 0) = 0 AND pg_catalog.get_byte(r, 1) < 128 THEN RETURN NULL; END IF;
  IF sl > 1 AND pg_catalog.get_byte(s, 0) = 0 AND pg_catalog.get_byte(s, 1) < 128 THEN RETURN NULL; END IF;
  RETURN ARRAY[private.partner_sig_os2ip(r), private.partner_sig_os2ip(s)];
END
$$;

-- The public key is a field-element pair: BOTH coordinates strictly below p (a coordinate >= p is a second encoding of the same point, which a verifier that reduces mod p would accept) and the point is ON the
-- curve y^2 = x^3 - 3x + b (mod p). P-256 has prime order and cofactor 1, so on the curve is sufficient: there is no small-subgroup case. The point at infinity has no (x, y) form and is refused with them.
CREATE FUNCTION private.partner_sig_p256_key_ok(p_qx numeric, p_qy numeric) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
  p numeric := private.partner_sig_p256_p();
BEGIN
  IF p_qx IS NULL OR p_qy IS NULL OR p_qx < 0 OR p_qy < 0 THEN RETURN false; END IF;
  IF p_qx >= p OR p_qy >= p THEN RETURN false; END IF;
  RETURN (p_qy * p_qy) % p = (((p_qx * p_qx % p) * p_qx) + 3 * (p - p_qx) + private.partner_sig_p256_b()) % p;
END
$$;

-- r and s are both in [1, n - 1] (so r + n and s + n, which reduce to valid values, are refused, and r = 0 / s = 0 are never divided by or multiplied with)
CREATE FUNCTION private.partner_sig_p256_rs_ok(p_r numeric, p_s numeric) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
  n numeric := private.partner_sig_p256_n();
BEGIN
  IF p_r IS NULL OR p_s IS NULL THEN RETURN false; END IF;
  IF p_r < 1 OR p_r >= n THEN RETURN false; END IF;
  IF p_s < 1 OR p_s >= n THEN RETURN false; END IF;
  RETURN true;
END
$$;

-- x(R) mod n = r, from the Jacobian X and Z of R (z <> 0), with no inversion: x(R) = X / Z^2 (mod p). x(R) is a field element below p, n < p, so it reduces mod n to itself when it is below n and to x - n when it
-- is in [n, p): accept x(R) = r, or x(R) = r + n when r + n is still below p. p - n is about 2^224, so the second branch is reached with probability about 2^-32 for a random signature: it needs its own vector.
CREATE FUNCTION private.partner_sig_p256_xr_ok(p_x numeric, p_z numeric, p_r numeric) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
  p numeric := private.partner_sig_p256_p();
  n numeric := private.partner_sig_p256_n();
  zz numeric := (p_z * p_z) % p;
BEGIN
  IF (p_r * zz) % p = p_x THEN RETURN true; END IF;
  IF p_r + n < p AND ((p_r + n) * zz) % p = p_x THEN RETURN true; END IF;
  RETURN false;
END
$$;

-- ES256 verify: x, y are the 32-byte big-endian public-key coordinates; msg is the signed data (SHA-256 is applied here); sig is the DER signature.
CREATE FUNCTION private.partner_sig_es256_verify(p_qx_b bytea, p_qy_b bytea, p_msg bytea, p_sig bytea) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
  n numeric := private.partner_sig_p256_n();
  qx numeric; qy numeric; rs numeric[]; r numeric; s numeric;
  e numeric; w numeric; u1 numeric; u2 numeric;
  rp private.partner_sig_jpoint;
BEGIN
  IF p_qx_b IS NULL OR p_qy_b IS NULL OR p_msg IS NULL OR p_sig IS NULL THEN RETURN false; END IF;
  IF pg_catalog.length(p_qx_b) <> 32 OR pg_catalog.length(p_qy_b) <> 32 THEN RETURN false; END IF;
  qx := private.partner_sig_os2ip(p_qx_b);
  qy := private.partner_sig_os2ip(p_qy_b);
  IF NOT private.partner_sig_p256_key_ok(qx, qy) THEN RETURN false; END IF;
  rs := private.partner_sig_der_rs(p_sig);
  IF rs IS NULL THEN RETURN false; END IF;
  r := rs[1]; s := rs[2];
  IF NOT private.partner_sig_p256_rs_ok(r, s) THEN RETURN false; END IF;
  e  := private.partner_sig_os2ip(pg_catalog.sha256(p_msg));        -- a 256-bit hash for a 256-bit order: no truncation (e may exceed n; it is reduced below)
  w  := private.partner_sig_modexp(s, n - 2, n);                    -- s^-1 (n is prime)
  u1 := (e * w) % n;
  u2 := (r * w) % n;
  rp := private.partner_sig_p256_shamir(u1, u2, qx, qy);
  IF rp.z = 0 THEN RETURN false; END IF;                            -- the point at infinity
  RETURN private.partner_sig_p256_xr_ok(rp.x, rp.z, r);
END
$$;

-- ===== RS256: RSASSA-PKCS1-v1_5, SHA-256, e = 65537 ==========================================================================================
-- The key: a modulus of 256 to 512 bytes (2048 to 4096 bits), full length (no leading 0x00), odd, and the exponent EXACTLY 01 00 01 (65537; a longer or shorter spelling of it is refused).
CREATE FUNCTION private.partner_sig_rsa_key_ok(p_n_b bytea, p_e_b bytea) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
  k int;
BEGIN
  IF p_n_b IS NULL OR p_e_b IS NULL THEN RETURN false; END IF;
  k := pg_catalog.length(p_n_b);
  IF k < 256 OR k > 512 THEN RETURN false; END IF;
  IF pg_catalog.get_byte(p_n_b, 0) = 0 OR pg_catalog.get_byte(p_n_b, k - 1) % 2 = 0 THEN RETURN false; END IF;
  RETURN p_e_b = '\x010001'::bytea;
END
$$;

-- The signature: exactly as long as the modulus (so a left-padded or truncated spelling is refused) and, as an integer, strictly below it (so s + n, which has the same residue, is refused).
CREATE FUNCTION private.partner_sig_rsa_sig_ok(p_sig bytea, p_k int, p_n numeric) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE AS $$
BEGIN
  IF p_sig IS NULL OR p_k IS NULL OR p_n IS NULL THEN RETURN false; END IF;
  IF pg_catalog.length(p_sig) <> p_k THEN RETURN false; END IF;
  RETURN private.partner_sig_os2ip(p_sig) < p_n;
END
$$;

-- RS256 verify: n_b the big-endian modulus, e_b the exponent (must be 65537), sig the signature (as long as the modulus).
CREATE FUNCTION private.partner_sig_rs256_verify(p_n_b bytea, p_e_b bytea, p_msg bytea, p_sig bytea) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
  k int;
  n numeric; s numeric; m numeric; em bytea;
  -- DigestInfo for SHA-256: 30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20
  prefix bytea := '\x3031300d060960864801650304020105000420'::bytea;
  ps_len int;
BEGIN
  IF p_msg IS NULL OR NOT private.partner_sig_rsa_key_ok(p_n_b, p_e_b) THEN RETURN false; END IF;
  k := pg_catalog.length(p_n_b);
  n := private.partner_sig_os2ip(p_n_b);
  IF NOT private.partner_sig_rsa_sig_ok(p_sig, k, n) THEN RETURN false; END IF;
  s := private.partner_sig_os2ip(p_sig);
  m := private.partner_sig_modexp(s, 65537, n);
  -- EM = 0x00 || 0x01 || PS (0xff ...) || 0x00 || DigestInfo || H, built FRESH and compared as an integer (never parsed out of m: the Bleichenbacher trap)
  ps_len := k - 3 - pg_catalog.length(prefix) - 32;
  em := '\x0001'::bytea || pg_catalog.decode(pg_catalog.repeat('ff', ps_len), 'hex') || '\x00'::bytea || prefix || pg_catalog.sha256(p_msg);
  RETURN m = private.partner_sig_os2ip(em);
END
$$;

-- ===== COSE_Key parsing (RFC 9052 section 7, as WebAuthn stores it) ============================================================================
-- One CBOR item head, STRICT: only the forms a COSE_Key of this lane uses (an argument below 24, or one byte for 24..255, or two bytes for 256..65535), and ONLY the shortest form (a non-minimal head is a
-- different encoding of the same value, refused); indefinite lengths, 4- and 8-byte arguments and the reserved additional-information values 28 to 30 are refused. Zero rows = invalid or truncated.
CREATE FUNCTION private.partner_cbor_head(p_b bytea, p_pos int) RETURNS TABLE (o_major int, o_arg int, o_next int)
LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
  len int := pg_catalog.length(p_b);
  ib int;
  ai int;
  v int;
BEGIN
  IF p_b IS NULL OR p_pos IS NULL OR p_pos < 0 OR p_pos >= len THEN RETURN; END IF;
  ib := pg_catalog.get_byte(p_b, p_pos);
  ai := ib % 32;
  o_major := ib / 32;
  IF ai < 24 THEN
    o_arg := ai; o_next := p_pos + 1;
  ELSIF ai = 24 THEN
    IF p_pos + 1 >= len THEN RETURN; END IF;
    v := pg_catalog.get_byte(p_b, p_pos + 1);
    IF v < 24 THEN RETURN; END IF;
    o_arg := v; o_next := p_pos + 2;
  ELSIF ai = 25 THEN
    IF p_pos + 2 >= len THEN RETURN; END IF;
    v := pg_catalog.get_byte(p_b, p_pos + 1) * 256 + pg_catalog.get_byte(p_b, p_pos + 2);
    IF v < 256 THEN RETURN; END IF;
    o_arg := v; o_next := p_pos + 3;
  ELSE
    RETURN;
  END IF;
  RETURN NEXT;
END
$$;

-- A COSE_Key of the two shapes the partner lane accepts, the wrapper's key-shape rules (supabase/functions/_shared/partner/webauthn.ts assertKeyAllowed), and nothing else:
--   ES256 (alg -7):   {1: 2, 3: -7, -1: 1, -2: x (32 bytes), -3: y (32 bytes)}   EC2, curve P-256 only (curve id 1: a P-384 key labelled -7 is refused), 32-byte coordinates
--   RS256 (alg -257): {1: 3, 3: -257, -1: n (256..512 bytes, first byte not 0), -2: e = 01 00 01}   RSA, 2048 to 4096 bits, e = 65537, no leading zero byte
-- The map holds EXACTLY those pairs (WebAuthn: the key MUST NOT carry other optional parameters), in any order, each key once, definite lengths, shortest-form heads, no trailing bytes. Returns the algorithm and
-- the two raw components (x, y) or (n, e); ZERO ROWS for anything else. Whether the point is ON the curve is the verifier's check, not this parser's.
CREATE FUNCTION private.partner_cose_parse(p_cose bytea) RETURNS TABLE (o_alg smallint, o_a bytea, o_b bytea)
LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
  len int;
  pos int := 0;
  h record;
  v record;
  npairs int;
  i int;
  k int;
  seen int := 0;      -- bit set of the keys seen: 1 -> 1, 3 -> 2, -1 -> 4, -2 -> 8, -3 -> 16
  kbit int;
  v_kty int; v_alg int;
  v_m1_int int; v_m1_has_int boolean := false;
  v_m1_b bytea; v_m2 bytea; v_m3 bytea;
BEGIN
  IF p_cose IS NULL THEN RETURN; END IF;
  len := pg_catalog.length(p_cose);
  IF len < 8 OR len > 1024 THEN RETURN; END IF;
  SELECT * INTO h FROM private.partner_cbor_head(p_cose, pos);
  IF NOT FOUND OR h.o_major <> 5 OR h.o_arg NOT IN (4, 5) THEN RETURN; END IF;     -- a map of 4 (RSA) or 5 (EC2) pairs
  npairs := h.o_arg;
  pos := h.o_next;
  FOR i IN 1 .. npairs LOOP
    SELECT * INTO h FROM private.partner_cbor_head(p_cose, pos);
    IF NOT FOUND OR h.o_major NOT IN (0, 1) THEN RETURN; END IF;                    -- the key is an integer
    k := CASE WHEN h.o_major = 0 THEN h.o_arg ELSE -1 - h.o_arg END;
    kbit := CASE k WHEN 1 THEN 1 WHEN 3 THEN 2 WHEN -1 THEN 4 WHEN -2 THEN 8 WHEN -3 THEN 16 ELSE 0 END;
    IF kbit = 0 OR (seen & kbit) <> 0 THEN RETURN; END IF;                            -- an unknown key, or a repeated one
    seen := seen | kbit;
    pos := h.o_next;
    SELECT * INTO v FROM private.partner_cbor_head(p_cose, pos);
    IF NOT FOUND THEN RETURN; END IF;
    IF k IN (1, 3) OR (k = -1 AND v.o_major IN (0, 1)) THEN
      IF v.o_major NOT IN (0, 1) THEN RETURN; END IF;                               -- an integer value
      IF k = 1 THEN v_kty := CASE WHEN v.o_major = 0 THEN v.o_arg ELSE -1 - v.o_arg END;
      ELSIF k = 3 THEN v_alg := CASE WHEN v.o_major = 0 THEN v.o_arg ELSE -1 - v.o_arg END;
      ELSE v_m1_int := CASE WHEN v.o_major = 0 THEN v.o_arg ELSE -1 - v.o_arg END; v_m1_has_int := true;
      END IF;
      pos := v.o_next;
    ELSE
      IF v.o_major <> 2 OR v.o_next + v.o_arg > len THEN RETURN; END IF;             -- a byte string that fits in what is left
      IF k = -1 THEN v_m1_b := pg_catalog.substring(p_cose, v.o_next + 1, v.o_arg);
      ELSIF k = -2 THEN v_m2 := pg_catalog.substring(p_cose, v.o_next + 1, v.o_arg);
      ELSE v_m3 := pg_catalog.substring(p_cose, v.o_next + 1, v.o_arg);
      END IF;
      pos := v.o_next + v.o_arg;
    END IF;
  END LOOP;
  IF pos <> len THEN RETURN; END IF;                                                -- no trailing bytes
  IF v_alg = -7 THEN
    IF seen <> 31 OR v_kty <> 2 OR NOT v_m1_has_int OR v_m1_int <> 1 THEN RETURN; END IF;
    IF v_m2 IS NULL OR v_m3 IS NULL OR pg_catalog.length(v_m2) <> 32 OR pg_catalog.length(v_m3) <> 32 THEN RETURN; END IF;
    o_alg := -7; o_a := v_m2; o_b := v_m3;
  ELSIF v_alg = -257 THEN
    IF seen <> 15 OR v_kty <> 3 OR v_m1_has_int OR v_m1_b IS NULL OR v_m2 IS NULL THEN RETURN; END IF;
    IF pg_catalog.length(v_m1_b) < 256 OR pg_catalog.length(v_m1_b) > 512 OR pg_catalog.get_byte(v_m1_b, 0) = 0 THEN RETURN; END IF;
    IF v_m2 <> '\x010001'::bytea THEN RETURN; END IF;
    o_alg := -257; o_a := v_m1_b; o_b := v_m2;
  ELSE
    RETURN;
  END IF;
  RETURN NEXT;
END
$$;

-- THE ENTRY POINT: does `p_sig` verify over `p_msg` under the COSE key `p_cose`, which must be of algorithm `p_alg`? SECURITY DEFINER, search_path = '' (so every helper above runs as its owner under an empty path);
-- executable by partner_session_issuer only. Fail closed: a NULL argument, a key that does not parse, a key whose algorithm is not `p_alg`, or any verifier refusal is plain `false`.
CREATE FUNCTION private.partner_sig_verify(p_alg smallint, p_cose bytea, p_msg bytea, p_sig bytea) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v record;
BEGIN
  IF p_alg IS NULL OR p_cose IS NULL OR p_msg IS NULL OR p_sig IS NULL THEN RETURN false; END IF;
  SELECT * INTO v FROM private.partner_cose_parse(p_cose);
  IF NOT FOUND OR v.o_alg <> p_alg THEN RETURN false; END IF;
  IF v.o_alg = -7 THEN
    RETURN private.partner_sig_es256_verify(v.o_a, v.o_b, p_msg, p_sig);
  ELSIF v.o_alg = -257 THEN
    RETURN private.partner_sig_rs256_verify(v.o_a, v.o_b, p_msg, p_sig);
  END IF;
  RETURN false;
END
$$;

-- ============================================================================
-- 5. The stateless sign-in challenge (5.1) and the alarm writer
-- ============================================================================
-- 5a. THE core. The only place the Vault key partner_challenge_key is read (the 0045 offline_seed_derive shape). EXECUTE for NOBODY: it computes the MAC for ANY (purpose, exp, nonce, binding) it is handed, so it must
-- never be reachable from a session. The message is FIXED WIDTH after the label (5.1), so no two different tuples produce the same bytes:
--     "golfraven/partner-challenge/v1" (UTF-8) || 0x00 || purpose (1 byte: 1 sign_in, 2 register, 3 reauth) || exp (8 bytes, big-endian epoch seconds) || nonce (32 bytes) || binding (16 bytes: zeros for sign_in)
-- and the MAC is HMAC-SHA256 under the Vault key (at least 32 bytes). A presented token is compared as HMAC(K, presented) = HMAC(K, expected), so the comparison never depends on a byte-by-byte equality of a
-- secret-derived value. The failure message names no key material (the Edge maps 55000 to a bare 503).
CREATE FUNCTION private.partner_challenge_core(p_purpose smallint, p_exp bigint, p_nonce bytea, p_binding uuid, p_presented bytea)
RETURNS TABLE (o_mac bytea, o_ok boolean)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_key text;
  v_k bytea;
  v_msg bytea;
BEGIN
  IF p_purpose IS NULL OR p_purpose NOT IN (1, 2, 3) OR p_exp IS NULL OR p_exp < 0 OR p_nonce IS NULL OR pg_catalog.octet_length(p_nonce) <> 32 OR p_binding IS NULL THEN
    RAISE EXCEPTION 'partner_challenge_core: a purpose (1 to 3), an expiry, a 32-byte nonce and a binding are required' USING ERRCODE = '22023';
  END IF;
  SELECT s.decrypted_secret INTO v_key FROM vault.decrypted_secrets s WHERE s.name = 'partner_challenge_key';
  IF v_key IS NULL OR pg_catalog.octet_length(pg_catalog.convert_to(v_key, 'UTF8')) < 32 THEN
    RAISE EXCEPTION 'partner_challenge_core: the partner challenge key is not provisioned in Vault' USING ERRCODE = '55000';
  END IF;
  v_k := pg_catalog.convert_to(v_key, 'UTF8');
  v_msg := pg_catalog.convert_to('golfraven/partner-challenge/v1', 'UTF8')
        || pg_catalog.decode('00', 'hex')
        || pg_catalog.set_byte('\x00'::bytea, 0, p_purpose::int)
        || pg_catalog.int8send(p_exp)
        || p_nonce
        || pg_catalog.decode(pg_catalog.replace(p_binding::text, '-', ''), 'hex');
  o_mac := public.hmac(v_msg, v_k, 'sha256');
  o_ok := p_presented IS NOT NULL AND public.hmac(p_presented, v_k, 'sha256') = public.hmac(o_mac, v_k, 'sha256');
  RETURN NEXT;
END
$$;

-- 5b. THE issuer. Stateless: nothing is written. 32 random bytes, an expiry 120 s ahead (the ceremony timeout of the options call) and the MAC. There is NO purpose and NO binding argument to choose: this issues
-- sign_in challenges and nothing else (R3-M2). Refused inside ANY bound transaction (the 0041 rule: a minter binds nothing), so a transaction that has been bound by some other lane cannot reach it.
CREATE FUNCTION private.partner_challenge_issue_sign_in()
RETURNS TABLE (o_nonce bytea, o_exp bigint, o_mac bytea)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  IF private.partner_binding_kind() IS NOT NULL THEN
    RAISE EXCEPTION 'partner_challenge_issue_sign_in: refused inside a bound transaction' USING ERRCODE = '42501';
  END IF;
  o_nonce := public.gen_random_bytes(32);
  o_exp := pg_catalog.floor(pg_catalog.date_part('epoch', pg_catalog.clock_timestamp()))::bigint + 120;
  SELECT c.o_mac INTO o_mac FROM private.partner_challenge_core(1::smallint, o_exp, o_nonce, '00000000-0000-0000-0000-000000000000'::uuid, NULL) c;
  RETURN NEXT;
END
$$;

-- 5c. Does this presented MAC belong to (purpose, exp, nonce, binding)? The ONLY thing the mint may ask of the key. EXECUTE for partner_session_issuer.
CREATE FUNCTION private.partner_challenge_verify(p_purpose smallint, p_exp bigint, p_nonce bytea, p_binding uuid, p_mac bytea)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_ok boolean;
BEGIN
  SELECT c.o_ok INTO v_ok FROM private.partner_challenge_core(p_purpose, p_exp, p_nonce, p_binding, p_mac) c;
  RETURN coalesce(v_ok, false);
END
$$;

-- 5d. THE alarm writer. One app.partner_auth_alarm row per (kind, credential, minute) and, only when that row is new, one audit_log row (actor NULL: nobody is bound in the mint transaction). It writes nothing
-- else and returns nothing: the mint calls it and then RETURNS a status, so both rows commit with the refusal. EXECUTE for partner_session_issuer.
CREATE FUNCTION private.partner_mint_alarm_write(p_kind text, p_credential_id uuid, p_detail jsonb)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_n integer;
BEGIN
  IF p_kind IS NULL OR p_kind NOT IN ('signature_invalid', 'counter_regression') OR p_credential_id IS NULL THEN
    RAISE EXCEPTION 'partner_mint_alarm_write: a kind (signature_invalid or counter_regression) and a credential are required' USING ERRCODE = '22023';
  END IF;
  INSERT INTO app.partner_auth_alarm (kind, credential_id, minute_bucket, detail)
  VALUES (p_kind, p_credential_id, pg_catalog.floor(pg_catalog.date_part('epoch', pg_catalog.clock_timestamp()) / 60)::bigint, coalesce(p_detail, '{}'::jsonb))
  ON CONFLICT (kind, credential_id, minute_bucket) DO NOTHING;
  GET DIAGNOSTICS v_n = ROW_COUNT;
  IF v_n = 1 THEN
    INSERT INTO app.audit_log (actor_user_id, action, subject_table, subject_id, detail)
    VALUES (NULL, 'partner.mint.' || p_kind, 'app.partner_credential', p_credential_id::text, coalesce(p_detail, '{}'::jsonb));
  END IF;
END
$$;

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

-- ============================================================================
-- 6. THE MINT (owned by partner_session_issuer, the 0047 seam: 16.5)
-- ============================================================================
GRANT CREATE ON SCHEMA private TO partner_session_issuer;
SET ROLE partner_session_issuer;

-- Mints a sign-in session from a WebAuthn assertion, in the order of design 4.4 / the S1.1b brief. Every refusal is a STATUS row (o_status), never a RAISE, so what the refusal must commit (the alarm rows, the nonce)
-- commits with it; only malformed arguments (22023), a bound transaction (42501) and a missing relying-party row (55000: a deploy fault, not a client refusal) raise, and none of those has written anything.
--   arguments: p_token_hash   sha256 hex of the opaque session token the Edge generated (the raw token never reaches the database)
--              p_credential_id the WebAuthn credential id bytes (looked up in app.partner_credential: the KEY is never an argument)
--              p_nonce, p_exp, p_mac  the challenge token (5.1): the 32-byte nonce, its expiry (epoch seconds) and its HMAC
--              p_authenticator_data, p_client_data_json, p_signature  the assertion, as bytes
--   statuses (o_status): ok | bad_challenge | expired | unknown_credential | rate_limited | bad_client_data | bad_client_type | cross_origin | bad_origin | challenge_mismatch | bad_authenticator_data |
--                        bad_rp_id_hash | user_not_present | user_not_verified | signature_invalid (ALARM) | replayed | counter_regression (ALARM)
-- The signed message is authenticatorData || SHA-256(clientDataJSON) (WebAuthn 7.2 step 20). The counter is read FROM the signed authenticatorData: there is no argument to differ from it.
CREATE FUNCTION private.partner_session_mint(
  p_token_hash text, p_credential_id bytea, p_nonce bytea, p_exp bigint, p_mac bytea,
  p_authenticator_data bytea, p_client_data_json bytea, p_signature bytea)
RETURNS TABLE (o_status text, o_session_id uuid, o_aal smallint, o_expires_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_cred record;
  v_rp record;
  v_pol record;
  v_cd jsonb;
  v_sid uuid := gen_random_uuid();
  v_nonce_hash bytea;
  v_counter bigint;
  v_n integer;
  v_expires timestamptz;
  v_zero constant uuid := '00000000-0000-0000-0000-000000000000';
BEGIN
  -- 0. malformed arguments raise (nothing has been written); a minter binds nothing (the 0041 rule)
  IF p_token_hash IS NULL OR p_token_hash !~ '^[0-9a-f]{64}$' OR p_credential_id IS NULL OR pg_catalog.octet_length(p_credential_id) NOT BETWEEN 16 AND 1023
     OR p_nonce IS NULL OR pg_catalog.octet_length(p_nonce) <> 32 OR p_exp IS NULL OR p_mac IS NULL OR pg_catalog.octet_length(p_mac) > 128
     OR p_authenticator_data IS NULL OR p_client_data_json IS NULL OR p_signature IS NULL THEN
    RAISE EXCEPTION 'partner_session_mint: a token hash, a credential id, a 32-byte nonce, an expiry, a MAC, the authenticator data, the client data and a signature are required' USING ERRCODE = '22023';
  END IF;
  IF private.partner_binding_kind() IS NOT NULL THEN
    RAISE EXCEPTION 'partner_session_mint: refused inside a bound transaction' USING ERRCODE = '42501';
  END IF;

  -- 1. the HMAC, the purpose (sign_in: the one purpose this function mints) and the expiry. A tampered MAC, a tampered expiry and a challenge of any other purpose all fail the HMAC.
  IF NOT private.partner_challenge_verify(1::smallint, p_exp, p_nonce, v_zero, p_mac) THEN
    RETURN QUERY SELECT 'bad_challenge'::text, NULL::uuid, NULL::smallint, NULL::timestamptz;
    RETURN;
  END IF;
  IF p_exp <= pg_catalog.floor(pg_catalog.date_part('epoch', pg_catalog.clock_timestamp()))::bigint THEN
    RETURN QUERY SELECT 'expired'::text, NULL::uuid, NULL::smallint, NULL::timestamptz;
    RETURN;
  END IF;

  -- 2. the credential, FROM THE TABLE. Unknown and revoked are one answer.
  SELECT c.id, c.user_id, c.public_key, c.alg, c.sign_count INTO v_cred
  FROM app.partner_credential c WHERE c.credential_id = p_credential_id AND c.revoked_at IS NULL;
  IF NOT FOUND THEN
    RETURN QUERY SELECT 'unknown_credential'::text, NULL::uuid, NULL::smallint, NULL::timestamptz;
    RETURN;
  END IF;

  -- 3. S0-L5: at most 60 successful sign-ins per credential per hour, enforced BEFORE any verification (a refusal here costs the database nothing but this count)
  -- The count and the later insert must be one critical section PER CREDENTIAL, or N concurrent mints at 58 all read 58 and all succeed (the gate's M-1: 8 concurrent mints made 66). Taking the credential's row lock
  -- here serialises mints of one credential from this point on (the lock is held to the end of the transaction, past the session insert), so each count sees every earlier mint's session. FOR NO KEY UPDATE:
  -- the same lock the counter's compare-and-set takes, and it does not block the foreign-key checks of the session insert.
  PERFORM 1 FROM app.partner_credential c WHERE c.id = v_cred.id FOR NO KEY UPDATE;
  SELECT pg_catalog.count(*) INTO v_n FROM app.partner_session s
  WHERE s.credential_id = v_cred.id AND s.mint_kind = 'sign_in' AND s.created_at > pg_catalog.clock_timestamp() - interval '1 hour';
  IF v_n >= 60 THEN
    RETURN QUERY SELECT 'rate_limited'::text, NULL::uuid, NULL::smallint, NULL::timestamptz;
    RETURN;
  END IF;

  -- 4. structural checks, against the relying party configured at deploy. No row = a deploy fault (the mint refuses).
  SELECT r.rp_id, r.origin INTO v_rp FROM app.partner_rp_config r;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'partner_session_mint: app.partner_rp_config holds no relying party (a deploy step)' USING ERRCODE = '55000';
  END IF;
  -- clientDataJSON: valid UTF-8 JSON, an object, type webauthn.get, no crossOrigin (absent or false) and no topOrigin, the exact origin, and the challenge the token carries
  IF pg_catalog.octet_length(p_client_data_json) NOT BETWEEN 2 AND 4096 THEN
    RETURN QUERY SELECT 'bad_client_data'::text, NULL::uuid, NULL::smallint, NULL::timestamptz;
    RETURN;
  END IF;
  BEGIN
    v_cd := pg_catalog.convert_from(p_client_data_json, 'UTF8')::jsonb;
  EXCEPTION WHEN others THEN
    v_cd := NULL;
  END;
  IF v_cd IS NULL OR pg_catalog.jsonb_typeof(v_cd) <> 'object' THEN
    RETURN QUERY SELECT 'bad_client_data'::text, NULL::uuid, NULL::smallint, NULL::timestamptz;
    RETURN;
  END IF;
  IF pg_catalog.jsonb_typeof(v_cd -> 'type') IS DISTINCT FROM 'string' OR (v_cd ->> 'type') <> 'webauthn.get' THEN
    RETURN QUERY SELECT 'bad_client_type'::text, NULL::uuid, NULL::smallint, NULL::timestamptz;
    RETURN;
  END IF;
  IF (v_cd ? 'crossOrigin' AND (v_cd -> 'crossOrigin') <> 'false'::jsonb) OR v_cd ? 'topOrigin' THEN
    RETURN QUERY SELECT 'cross_origin'::text, NULL::uuid, NULL::smallint, NULL::timestamptz;
    RETURN;
  END IF;
  IF pg_catalog.jsonb_typeof(v_cd -> 'origin') IS DISTINCT FROM 'string' OR (v_cd ->> 'origin') <> v_rp.origin THEN
    RETURN QUERY SELECT 'bad_origin'::text, NULL::uuid, NULL::smallint, NULL::timestamptz;
    RETURN;
  END IF;
  IF pg_catalog.jsonb_typeof(v_cd -> 'challenge') IS DISTINCT FROM 'string'
     OR (v_cd ->> 'challenge') <> pg_catalog.rtrim(pg_catalog.translate(pg_catalog.encode(p_nonce, 'base64'), '+/', '-_'), '=') THEN
    RETURN QUERY SELECT 'challenge_mismatch'::text, NULL::uuid, NULL::smallint, NULL::timestamptz;
    RETURN;
  END IF;
  -- authenticatorData: rpIdHash (32) | flags (1) | counter (4, big-endian) | ...; the hash of the configured RP ID, user presence (0x01) and user verification (0x04)
  IF pg_catalog.octet_length(p_authenticator_data) NOT BETWEEN 37 AND 4096 THEN
    RETURN QUERY SELECT 'bad_authenticator_data'::text, NULL::uuid, NULL::smallint, NULL::timestamptz;
    RETURN;
  END IF;
  IF pg_catalog.substring(p_authenticator_data, 1, 32) <> pg_catalog.sha256(pg_catalog.convert_to(v_rp.rp_id, 'UTF8')) THEN
    RETURN QUERY SELECT 'bad_rp_id_hash'::text, NULL::uuid, NULL::smallint, NULL::timestamptz;
    RETURN;
  END IF;
  IF pg_catalog.get_byte(p_authenticator_data, 32) & 1 = 0 THEN
    RETURN QUERY SELECT 'user_not_present'::text, NULL::uuid, NULL::smallint, NULL::timestamptz;
    RETURN;
  END IF;
  IF pg_catalog.get_byte(p_authenticator_data, 32) & 4 = 0 THEN
    RETURN QUERY SELECT 'user_not_verified'::text, NULL::uuid, NULL::smallint, NULL::timestamptz;
    RETURN;
  END IF;
  v_counter := pg_catalog.get_byte(p_authenticator_data, 33)::bigint * 16777216 + pg_catalog.get_byte(p_authenticator_data, 34) * 65536
             + pg_catalog.get_byte(p_authenticator_data, 35) * 256 + pg_catalog.get_byte(p_authenticator_data, 36);

  -- 5. the signature, in SQL, LAST of the checks. The Edge verified it first, so a failure here is an ALARM (a compromised runtime, a library gap, a corrupt stored key): a distinct status, and the audit_log and
  -- app.partner_auth_alarm rows commit with it. A failed verification does NOT burn the challenge (5.1): it may be presented again within its 120 s, and each try needs a real signature.
  IF NOT private.partner_sig_verify(v_cred.alg, v_cred.public_key, p_authenticator_data || pg_catalog.sha256(p_client_data_json), p_signature) THEN
    PERFORM private.partner_mint_alarm_write('signature_invalid', v_cred.id, pg_catalog.jsonb_build_object('stage', 'mint', 'alg', v_cred.alg));
    RETURN QUERY SELECT 'signature_invalid'::text, NULL::uuid, NULL::smallint, NULL::timestamptz;
    RETURN;
  END IF;

  -- 6. the used nonce: the primary key is the single use. A concurrent mint of the SAME challenge waits here for the first to finish and then finds the row.
  v_nonce_hash := pg_catalog.sha256(p_nonce);
  INSERT INTO app.partner_auth_challenge (nonce_hash, purpose, user_id, minted_session_id)
  VALUES (v_nonce_hash, 'sign_in', v_cred.user_id, v_sid)
  ON CONFLICT (nonce_hash) DO NOTHING;
  GET DIAGNOSTICS v_n = ROW_COUNT;
  IF v_n = 0 THEN
    RETURN QUERY SELECT 'replayed'::text, NULL::uuid, NULL::smallint, NULL::timestamptz;
    RETURN;
  END IF;

  -- 7. the counter, by compare-and-set (PA-9): it advances only if the stored value is still below the presented one (or both are 0: a synced passkey never counts). Two assertions racing for one credential
  -- cannot both win and neither can lower it; the loser sees the winner's value (READ COMMITTED re-evaluates the WHERE after the row lock). A regression is the clone indicator of 6.2 step 4.
  UPDATE app.partner_credential c SET sign_count = v_counter, last_used_at = pg_catalog.clock_timestamp()
  WHERE c.id = v_cred.id AND c.revoked_at IS NULL AND (c.sign_count < v_counter OR (c.sign_count = 0 AND v_counter = 0));
  GET DIAGNOSTICS v_n = ROW_COUNT;
  IF v_n = 0 THEN
    IF NOT EXISTS (SELECT 1 FROM app.partner_credential c WHERE c.id = v_cred.id AND c.revoked_at IS NULL) THEN
      RETURN QUERY SELECT 'unknown_credential'::text, NULL::uuid, NULL::smallint, NULL::timestamptz;
      RETURN;
    END IF;
    PERFORM private.partner_mint_alarm_write('counter_regression', v_cred.id, pg_catalog.jsonb_build_object('stage', 'mint', 'presented', v_counter));
    RETURN QUERY SELECT 'counter_regression'::text, NULL::uuid, NULL::smallint, NULL::timestamptz;
    RETURN;
  END IF;

  -- 8. the session, with the evidence of what was verified (mint_*). Born at aal 1 with nothing verified; its absolute life is the person's role ceiling (partner_session_insert_guard re-checks it).
  SELECT p.* INTO v_pol FROM private.partner_session_policy(v_cred.user_id) p;
  v_expires := pg_catalog.clock_timestamp() + v_pol.absolute;
  INSERT INTO app.partner_session (id, token_hash, user_id, credential_id, aal, created_at, last_seen_at, expires_at,
                                   mint_kind, mint_nonce_hash, mint_authenticator_data, mint_client_data_json, mint_signature)
  VALUES (v_sid, p_token_hash, v_cred.user_id, v_cred.id, 1, pg_catalog.clock_timestamp(), pg_catalog.clock_timestamp(), v_expires,
          'sign_in', v_nonce_hash, p_authenticator_data, p_client_data_json, p_signature);
  RETURN QUERY SELECT 'ok'::text, v_sid, 1::smallint, v_expires;
END
$$;

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM partner_session_issuer;

-- ============================================================================
-- 7. EXECUTE grants (PUBLIC revoked first: a function created by a role other than the migrating role defaults to PUBLIC EXECUTE). Each as its OWNER.
-- ============================================================================
SET ROLE private_definer;
REVOKE EXECUTE ON FUNCTION
  private.partner_sig_os2ip(bytea), private.partner_sig_modexp(numeric, numeric, numeric), private.partner_sig_bits256(numeric),
  private.partner_sig_p256_p(), private.partner_sig_p256_n(), private.partner_sig_p256_b(), private.partner_sig_p256_gx(), private.partner_sig_p256_gy(),
  private.partner_sig_jdouble(private.partner_sig_jpoint), private.partner_sig_jadd(private.partner_sig_jpoint, private.partner_sig_jpoint),
  private.partner_sig_p256_shamir(numeric, numeric, numeric, numeric), private.partner_sig_der_rs(bytea),
  private.partner_sig_p256_key_ok(numeric, numeric), private.partner_sig_p256_rs_ok(numeric, numeric), private.partner_sig_p256_xr_ok(numeric, numeric, numeric),
  private.partner_sig_es256_verify(bytea, bytea, bytea, bytea),
  private.partner_sig_rsa_key_ok(bytea, bytea), private.partner_sig_rsa_sig_ok(bytea, int, numeric), private.partner_sig_rs256_verify(bytea, bytea, bytea, bytea),
  private.partner_cbor_head(bytea, int), private.partner_cose_parse(bytea),
  private.partner_sig_verify(smallint, bytea, bytea, bytea),
  private.partner_challenge_core(smallint, bigint, bytea, uuid, bytea), private.partner_challenge_issue_sign_in(), private.partner_challenge_verify(smallint, bigint, bytea, uuid, bytea),
  private.partner_mint_alarm_write(text, uuid, jsonb)
FROM PUBLIC;
-- the issuer (the mint's owner) may call exactly these five; the helpers above them are reached only from inside these definers, as private_definer
GRANT EXECUTE ON FUNCTION private.partner_sig_verify(smallint, bytea, bytea, bytea) TO partner_session_issuer;
GRANT EXECUTE ON FUNCTION private.partner_challenge_verify(smallint, bigint, bytea, uuid, bytea) TO partner_session_issuer;
GRANT EXECUTE ON FUNCTION private.partner_mint_alarm_write(text, uuid, jsonb) TO partner_session_issuer;
GRANT EXECUTE ON FUNCTION private.partner_session_policy(uuid) TO partner_session_issuer;
-- the mint refuses inside any bound transaction (the 0041 rule), which it reads from the binding helper edge_partner already has
GRANT EXECUTE ON FUNCTION private.partner_binding_kind() TO partner_session_issuer;
-- the sign-in challenge issuer: the minter role, and nobody else
GRANT EXECUTE ON FUNCTION private.partner_challenge_issue_sign_in() TO edge_partner_minter;
COMMENT ON FUNCTION private.partner_challenge_issue_sign_in() IS
  '0048. edge_partner_minter only. The stateless sign-in challenge: 32 random bytes, an expiry 120 s ahead and HMAC-SHA256 under Vault key partner_challenge_key over label || 0x00 || purpose || exp || nonce || binding. No purpose or binding argument; writes no row; refused inside any bound transaction.';
COMMENT ON FUNCTION private.partner_sig_verify(smallint, bytea, bytea, bytea) IS
  '0048. Pure SQL signature verification (no extension): a strict COSE_Key parse, then ES256 (ECDSA P-256 / SHA-256) or RS256 (RSASSA-PKCS1-v1_5 / SHA-256, e = 65537). Fail closed: false for any NULL, any key that does not parse, an algorithm mismatch or any refusal. EXECUTE for partner_session_issuer only. About 20 to 35 ms for ES256 and 2 to 10 ms for RS256 on the S0 spike host.';
RESET ROLE;

SET ROLE partner_session_issuer;
REVOKE EXECUTE ON FUNCTION private.partner_session_mint(text, bytea, bytea, bigint, bytea, bytea, bytea, bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.partner_session_mint(text, bytea, bytea, bigint, bytea, bytea, bytea, bytea) TO edge_partner_minter;
COMMENT ON FUNCTION private.partner_session_mint(text, bytea, bytea, bigint, bytea, bytea, bytea, bytea) IS
  '0048. edge_partner_minter only; owned by partner_session_issuer. Mints a sign-in session from a WebAuthn assertion. Order: HMAC / purpose / expiry (the nonce is the challenge in clientDataJSON), the credential FROM app.partner_credential, at most 60 sign-ins per credential per hour (before any verification), the structural checks against app.partner_rp_config, the SQL signature check, the used nonce (primary key = single use), the counter compare-and-set, the session with its mint_* evidence. Returns a status row; never raises over a refusal. A signature that fails here and a counter regression write audit_log and app.partner_auth_alarm rows that commit with the refusal.';
RESET ROLE;
-- R5-L3: the migrating role keeps NO way to become the issuer (a PG16+ CREATEROLE creator keeps ADMIN on the roles it creates, which is all that may remain)
REVOKE partner_session_issuer FROM CURRENT_USER;

-- ============================================================================
-- 8. Registries
-- ============================================================================
-- 8a. private.function_inventory: every function above, with the minter column true for exactly the two it may execute
INSERT INTO private.function_inventory
  (schema_name, function_name, identity_args, expected_anon, expected_authenticated, expected_service_role, expected_edge_actor, expected_edge_system, expected_edge_partner, expected_edge_partner_minter, note)
VALUES
  ('private', 'partner_cbor_head', 'p_b bytea, p_pos integer', false, false, false, false, false, false, false, '0048: pure; one strict CBOR item head (shortest form only, definite lengths, 1- and 2-byte arguments); owner only'),
  ('private', 'partner_challenge_core', 'p_purpose smallint, p_exp bigint, p_nonce bytea, p_binding uuid, p_presented bytea', false, false, false, false, false, false, false, '0048: the ONLY reader of Vault secret partner_challenge_key: HMAC-SHA256(K, label || 0x00 || purpose || exp || nonce || binding) and the HMAC(K, presented) = HMAC(K, expected) comparison; no role has EXECUTE (the wrappers below call it as private_definer); K is never returned'),
  ('private', 'partner_challenge_issue_sign_in', '', false, false, false, false, false, false, true, '0048: edge_partner_minter only; the stateless sign-in challenge (32 random bytes, exp = now + 120 s, the MAC); writes nothing; takes no purpose and no binding argument; refuses inside any bound transaction'),
  ('private', 'partner_challenge_verify', 'p_purpose smallint, p_exp bigint, p_nonce bytea, p_binding uuid, p_mac bytea', false, false, false, false, false, false, false, '0048: does a presented MAC belong to (purpose, exp, nonce, binding); the only thing the mint may ask of the key; EXECUTE for partner_session_issuer only (private.partner_owner_privilege)'),
  ('private', 'partner_cose_parse', 'p_cose bytea', false, false, false, false, false, false, false, '0048: pure; a COSE_Key of exactly the two shapes the partner lane accepts (EC2 P-256 with 32-byte coordinates, RSA 2048 to 4096 bits with e = 65537 and no leading zero byte) or zero rows; owner only (partner_sig_verify calls it)'),
  ('private', 'partner_mint_alarm_write', 'p_kind text, p_credential_id uuid, p_detail jsonb', false, false, false, false, false, false, false, '0048: one app.partner_auth_alarm row per (kind, credential, minute) and, when new, one audit_log row; EXECUTE for partner_session_issuer only (private.partner_owner_privilege)'),
  ('private', 'partner_session_mint', 'p_token_hash text, p_credential_id bytea, p_nonce bytea, p_exp bigint, p_mac bytea, p_authenticator_data bytea, p_client_data_json bytea, p_signature bytea', false, false, false, false, false, false, true, '0048: edge_partner_minter only; owned by partner_session_issuer; mints a sign-in session from a WebAuthn assertion: HMAC / purpose / expiry, the credential from the table, 60 per hour per credential, structural checks against partner_rp_config, the SQL signature check, the used nonce, the counter compare-and-set, the session with its mint_* evidence; every refusal is a status, never a RAISE'),
  ('private', 'partner_sig_bits256', 'p_x numeric', false, false, false, false, false, false, false, '0048: pure helper of the ES256 verifier; owner only'),
  ('private', 'partner_sig_der_rs', 'p_sig bytea', false, false, false, false, false, false, false, '0048: pure; strict DER Ecdsa-Sig-Value to {r, s} or NULL; owner only'),
  ('private', 'partner_sig_es256_verify', 'p_qx_b bytea, p_qy_b bytea, p_msg bytea, p_sig bytea', false, false, false, false, false, false, false, '0048: pure; strict ECDSA P-256 / SHA-256 verification over raw public-key coordinates; owner only (partner_sig_verify calls it)'),
  ('private', 'partner_sig_jadd', 'pa private.partner_sig_jpoint, pb private.partner_sig_jpoint', false, false, false, false, false, false, false, '0048: pure; Jacobian point addition on P-256 with the degenerate cases explicit; owner only'),
  ('private', 'partner_sig_jdouble', 'pt private.partner_sig_jpoint', false, false, false, false, false, false, false, '0048: pure; Jacobian point doubling on P-256; owner only'),
  ('private', 'partner_sig_modexp', 'p_base numeric, p_ex numeric, p_m numeric', false, false, false, false, false, false, false, '0048: pure; modular exponentiation over numeric; owner only'),
  ('private', 'partner_sig_os2ip', 'p_b bytea', false, false, false, false, false, false, false, '0048: pure; big-endian bytes to a non-negative integer; owner only'),
  ('private', 'partner_sig_p256_b', '', false, false, false, false, false, false, false, '0048: pure; the P-256 curve constant b; owner only'),
  ('private', 'partner_sig_p256_gx', '', false, false, false, false, false, false, false, '0048: pure; the P-256 generator x; owner only'),
  ('private', 'partner_sig_p256_gy', '', false, false, false, false, false, false, false, '0048: pure; the P-256 generator y; owner only'),
  ('private', 'partner_sig_p256_key_ok', 'p_qx numeric, p_qy numeric', false, false, false, false, false, false, false, '0048: pure predicate; both coordinates below p and the point ON the curve; owner only'),
  ('private', 'partner_sig_p256_n', '', false, false, false, false, false, false, false, '0048: pure; the P-256 group order n; owner only'),
  ('private', 'partner_sig_p256_p', '', false, false, false, false, false, false, false, '0048: pure; the P-256 field prime p; owner only'),
  ('private', 'partner_sig_p256_rs_ok', 'p_r numeric, p_s numeric', false, false, false, false, false, false, false, '0048: pure predicate; r and s both in [1, n - 1]; owner only'),
  ('private', 'partner_sig_p256_shamir', 'p_u1 numeric, p_u2 numeric, p_qx numeric, p_qy numeric', false, false, false, false, false, false, false, '0048: pure; u1*G + u2*Q by Shamir''s trick over Jacobian coordinates; owner only'),
  ('private', 'partner_sig_p256_xr_ok', 'p_x numeric, p_z numeric, p_r numeric', false, false, false, false, false, false, false, '0048: pure predicate; x(R) mod n = r from the Jacobian X and Z, including the x(R) in [n, p) branch (r + n); owner only'),
  ('private', 'partner_sig_rs256_verify', 'p_n_b bytea, p_e_b bytea, p_msg bytea, p_sig bytea', false, false, false, false, false, false, false, '0048: pure; RSASSA-PKCS1-v1_5 / SHA-256 verification, the encoded message built fresh and compared whole; owner only (partner_sig_verify calls it)'),
  ('private', 'partner_sig_rsa_key_ok', 'p_n_b bytea, p_e_b bytea', false, false, false, false, false, false, false, '0048: pure predicate; a full-length odd modulus of 2048 to 4096 bits and the exponent exactly 65537; owner only'),
  ('private', 'partner_sig_rsa_sig_ok', 'p_sig bytea, p_k integer, p_n numeric', false, false, false, false, false, false, false, '0048: pure predicate; the signature is exactly as long as the modulus and, as an integer, below it; owner only'),
  ('private', 'partner_sig_verify', 'p_alg smallint, p_cose bytea, p_msg bytea, p_sig bytea', false, false, false, false, false, false, false, '0048: the SQL signature verification entry point (COSE key + algorithm + message + signature -> boolean, fail closed); SECURITY DEFINER, search_path empty; EXECUTE for partner_session_issuer only (private.partner_owner_privilege)');

-- 8b. private.definer_policy_allowlist: the six new policies (two for private_definer, four for the issuer), their expressions derived from the live policies
GRANT INSERT, UPDATE ON private.definer_policy_allowlist TO CURRENT_USER;
CREATE POLICY current_user_seed_definer_policy_allowlist_0048 ON private.definer_policy_allowlist
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
INSERT INTO private.definer_policy_allowlist (schema_name, table_name, policy_name, command, scoped, note, role_name) VALUES
  ('app', 'partner_auth_alarm', 'pd_partner_auth_alarm_insert', 'INSERT', true, 'private.partner_mint_alarm_write: the one alarm row per (kind, credential, minute); keyed on the transaction''s own binding (no binding at all: the mint transaction binds nothing), never a GUC; no user id is stored', 'private_definer'),
  ('app', 'partner_auth_alarm', 'pd_partner_auth_alarm_select', 'SELECT', true, 'private.partner_mint_alarm_write: INSERT ... ON CONFLICT reads the arbiter columns (kind, credential_id, minute_bucket; column-level grant); no binding at all', 'private_definer'),
  ('app', 'partner_credential', 'psi_update_partner_credential', 'UPDATE', true, 'S1.1b partner_session_mint: the counter compare-and-set and last_used_at ONLY (column-level grant: sign_count, last_used_at); partner_credential_guard refuses a decrease, an identity change and an un-revoke; nobody can become partner_session_issuer', 'partner_session_issuer'),
  ('app', 'partner_rp_config', 'psi_read_partner_rp_config', 'SELECT', true, 'S1.1b partner_session_mint: the relying party (rp_id, origin: column-level grant) the assertion is checked against; nobody can become partner_session_issuer', 'partner_session_issuer'),
  ('app', 'partner_auth_challenge', 'psi_insert_partner_auth_challenge', 'INSERT', false, 'S1.1b partner_session_mint: the used nonce (the primary key is the single-use guarantee); nobody can become partner_session_issuer', 'partner_session_issuer'),
  ('app', 'partner_auth_challenge', 'psi_read_partner_auth_challenge', 'SELECT', true, 'S1.1b partner_session_mint: INSERT ... ON CONFLICT reads the arbiter column (nonce_hash: column-level grant); nobody can become partner_session_issuer', 'partner_session_issuer');
UPDATE private.definer_policy_allowlist al
SET using_expr = pg_get_expr(pol.polqual, pol.polrelid),
    with_check_expr = pg_get_expr(pol.polwithcheck, pol.polrelid)
FROM pg_policy pol
JOIN pg_class cl ON cl.oid = pol.polrelid
JOIN pg_namespace n ON n.oid = cl.relnamespace
WHERE n.nspname = al.schema_name AND cl.relname = al.table_name AND pol.polname = al.policy_name
  -- the six new policies (their stored snapshot is the live text; checks 5 / 6 compare the two)
  AND pol.polname IN ('pd_partner_auth_alarm_insert', 'pd_partner_auth_alarm_select', 'psi_update_partner_credential', 'psi_read_partner_rp_config', 'psi_insert_partner_auth_challenge', 'psi_read_partner_auth_challenge');
DO $assert_0048_allowlist$
BEGIN
  IF (SELECT count(*) FROM private.definer_policy_allowlist WHERE policy_name IN ('pd_partner_auth_alarm_insert', 'pd_partner_auth_alarm_select', 'psi_update_partner_credential', 'psi_read_partner_rp_config', 'psi_insert_partner_auth_challenge', 'psi_read_partner_auth_challenge')
        AND (using_expr IS NOT NULL OR with_check_expr IS NOT NULL)) <> 6 THEN
    RAISE EXCEPTION '0048: an allowlist row names no live policy (its expressions were not derived)';
  END IF;
END
$assert_0048_allowlist$;
DROP POLICY current_user_seed_definer_policy_allowlist_0048 ON private.definer_policy_allowlist;
REVOKE INSERT, UPDATE ON private.definer_policy_allowlist FROM CURRENT_USER;

-- 8c. private.partner_owner_privilege: what the issuer holds now, beyond 0047's rows (checks 9 / 12 re-derive the real set from the catalog and compare both ways; the fixture is its checked-in twin)
CREATE POLICY current_user_seed_partner_owner_privilege_0048 ON private.partner_owner_privilege
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
INSERT INTO private.partner_owner_privilege (role_name, object_kind, object_name, privilege, column_name) VALUES
  ('partner_session_issuer', 'column', 'app.partner_session', 'SELECT', 'credential_id'),
  ('partner_session_issuer', 'column', 'app.partner_session', 'SELECT', 'mint_kind'),
  ('partner_session_issuer', 'column', 'app.partner_credential', 'SELECT', 'public_key'),
  ('partner_session_issuer', 'column', 'app.partner_credential', 'SELECT', 'alg'),
  ('partner_session_issuer', 'column', 'app.partner_credential', 'SELECT', 'sign_count'),
  ('partner_session_issuer', 'column', 'app.partner_credential', 'UPDATE', 'sign_count'),
  ('partner_session_issuer', 'column', 'app.partner_credential', 'UPDATE', 'last_used_at'),
  ('partner_session_issuer', 'column', 'app.partner_rp_config', 'SELECT', 'rp_id'),
  ('partner_session_issuer', 'column', 'app.partner_rp_config', 'SELECT', 'origin'),
  ('partner_session_issuer', 'relation', 'app.partner_auth_challenge', 'INSERT', NULL),
  ('partner_session_issuer', 'column', 'app.partner_auth_challenge', 'SELECT', 'nonce_hash'),
  ('partner_session_issuer', 'function', 'private.partner_sig_verify(smallint,bytea,bytea,bytea)', 'EXECUTE', NULL),
  ('partner_session_issuer', 'function', 'private.partner_challenge_verify(smallint,bigint,bytea,uuid,bytea)', 'EXECUTE', NULL),
  ('partner_session_issuer', 'function', 'private.partner_mint_alarm_write(text,uuid,jsonb)', 'EXECUTE', NULL),
  ('partner_session_issuer', 'function', 'private.partner_session_policy(uuid)', 'EXECUTE', NULL),
  ('partner_session_issuer', 'function', 'private.partner_binding_kind()', 'EXECUTE', NULL);
DROP POLICY current_user_seed_partner_owner_privilege_0048 ON private.partner_owner_privilege;

-- ============================================================================
-- 9. Prove the grants (a refused or misapplied GRANT only warns, so the migration fails HERE rather than on the first sign-in)
-- ============================================================================
DO $assert_0048_grants$
DECLARE
  v_mint regprocedure := 'private.partner_session_mint(text, bytea, bytea, bigint, bytea, bytea, bytea, bytea)'::regprocedure;
  v_issue regprocedure := 'private.partner_challenge_issue_sign_in()'::regprocedure;
  v_role text;
  v_bad text;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_proc p WHERE p.oid = v_mint AND p.prosecdef AND p.proowner = 'partner_session_issuer'::regrole AND p.proconfig = ARRAY['search_path=""']) THEN
    RAISE EXCEPTION '0048: the mint is not SECURITY DEFINER owned by partner_session_issuer with search_path=''''';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_proc p WHERE p.oid = v_issue AND p.prosecdef AND p.proowner = 'private_definer'::regrole AND p.proconfig = ARRAY['search_path=""']) THEN
    RAISE EXCEPTION '0048: the challenge issuer is not SECURITY DEFINER owned by private_definer with search_path=''''';
  END IF;
  -- the two minter functions: edge_partner_minter, exactly one role
  FOREACH v_role IN ARRAY ARRAY['edge_system', 'edge_actor', 'edge_partner', 'edge_gateway', 'service_role', 'anon', 'authenticated'] LOOP
    IF has_function_privilege(v_role, v_mint, 'EXECUTE') OR has_function_privilege(v_role, v_issue, 'EXECUTE') THEN
      RAISE EXCEPTION '0048: % can execute a mint function; only edge_partner_minter may', v_role;
    END IF;
  END LOOP;
  IF NOT (has_function_privilege('edge_partner_minter', v_mint, 'EXECUTE') AND has_function_privilege('edge_partner_minter', v_issue, 'EXECUTE')) THEN
    RAISE EXCEPTION '0048: edge_partner_minter cannot execute the mint functions';
  END IF;
  -- the minter executes exactly those two functions in app / api / private, and holds no privilege on any relation
  SELECT string_agg(n.nspname || '.' || p.proname, ', ') INTO v_bad
  FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
  WHERE n.nspname IN ('app', 'api', 'private') AND p.prokind IN ('f', 'p') AND has_function_privilege('edge_partner_minter', p.oid, 'EXECUTE') AND p.oid NOT IN (v_mint, v_issue);
  IF v_bad IS NOT NULL THEN
    RAISE EXCEPTION '0048: edge_partner_minter can execute more than the two mint functions: %', v_bad;
  END IF;
  -- no helper of the verifier is reachable by anyone but its owner (and, for the four entry points, the issuer)
  SELECT string_agg(p.proname || ' -> ' || r.rolname, ', ') INTO v_bad
  FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
  CROSS JOIN (SELECT rolname FROM pg_roles WHERE rolname IN ('anon', 'authenticated', 'service_role', 'edge_gateway', 'edge_actor', 'edge_system', 'edge_partner', 'edge_partner_minter')) r
  WHERE n.nspname = 'private' AND (p.proname LIKE 'partner\_sig\_%' OR p.proname IN ('partner_cbor_head', 'partner_cose_parse', 'partner_challenge_core', 'partner_challenge_verify', 'partner_mint_alarm_write'))
    AND has_function_privilege(r.rolname, p.oid, 'EXECUTE');
  IF v_bad IS NOT NULL THEN
    RAISE EXCEPTION '0048: a verifier / challenge helper is executable by a role that must not run it: %', v_bad;
  END IF;
  -- the column and relation grants the mint needs took effect
  IF NOT (has_column_privilege('partner_session_issuer', 'app.partner_credential', 'public_key', 'SELECT')
          AND has_column_privilege('partner_session_issuer', 'app.partner_credential', 'sign_count', 'UPDATE')
          AND has_column_privilege('partner_session_issuer', 'app.partner_rp_config', 'origin', 'SELECT')
          AND has_table_privilege('partner_session_issuer', 'app.partner_auth_challenge', 'INSERT')
          AND has_table_privilege('private_definer', 'app.partner_auth_alarm', 'INSERT')) THEN
    RAISE EXCEPTION '0048: a grant the mint needs did not take effect';
  END IF;
END
$assert_0048_grants$;
