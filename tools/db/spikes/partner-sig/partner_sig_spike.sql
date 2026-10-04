-- tools/db/spikes/partner-sig/partner_sig_spike.sql
--
-- docs/security/partner-auth-design.md, slice S0, acceptance PA-0c: THE DATABASE-SIDE SIGNATURE SPIKE. Can PL/pgSQL with `numeric` arithmetic and NO
-- extension verify an ES256 (ECDSA P-256 / SHA-256) assertion signature and an RS256 (RSASSA-PKCS1-v1_5, e = 65537, SHA-256) one in under 200 ms each?
--
-- THIS IS EVIDENCE, NOT A MIGRATION. It is not under supabase/migrations, nothing in the application calls it, and it must not be copied there as it
-- stands: S1.1 decides whether to adopt database-side verification at all (the S0 delta gate reads the numbers). It creates one scratch schema,
-- `spike_sig`, in whatever database it is loaded into, uses only core PostgreSQL (`numeric`, `bytea`, `sha256()`, PL/pgSQL), and creates no role and
-- no extension. Run it with run.sh in this directory (a throwaway cluster).
--
-- WHAT IS AND IS NOT HERE.
--   * Verification of a signature over a message the caller supplies (for a WebAuthn assertion: authenticatorData || SHA-256(clientDataJSON)), with the
--     public key given as raw bytes: x and y (32 bytes each) for P-256; modulus and exponent for RSA. Parsing a COSE key out of the stored CBOR is not
--     done here (S1.1 would store the parsed columns or parse in SQL; either is small next to the arithmetic measured here).
--   * Strict checks, because a verifier that accepts malformed input is worse than none: DER structure of the ECDSA signature (minimal, positive
--     integers, exact lengths), 0 < r, s < n, the public key on the curve with coordinates below p, RSA signature length equal to the modulus length and
--     the integer below the modulus, e fixed at 65537, a full PKCS#1 v1.5 encoded-message comparison against a freshly built EMSA-PKCS1-v1_5 for SHA-256
--     (so a signature over another hash's DigestInfo, or with bad padding, is refused: no "parse the padding" shortcuts, the classic Bleichenbacher trap).
--   * NOT constant-time. Everything verified is public (a signature, a public key, a message), so there is no secret to leak through timing.
--   * ECDSA is Jacobian-coordinate Shamir's trick (u1*G + u2*Q in one double-and-add pass); the point at infinity is z = 0; the add routine handles the
--     doubling and cancellation cases (H = 0) explicitly.
--
-- Everything is `numeric`: PostgreSQL's numeric is arbitrary precision (up to 131072 decimal digits before the point), `%` is a truncating remainder
-- (so every subtraction below is written to stay non-negative before the `%`).

DROP SCHEMA IF EXISTS spike_sig CASCADE;
CREATE SCHEMA spike_sig;

-- ===== byte and integer plumbing ==============================================================================================================

-- big-endian bytes -> non-negative integer (OS2IP)
CREATE FUNCTION spike_sig.os2ip(b bytea) RETURNS numeric
LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
  acc numeric := 0;
  i   int;
  len int := length(b);
BEGIN
  FOR i IN 0 .. len - 1 LOOP
    acc := acc * 256 + get_byte(b, i);
  END LOOP;
  RETURN acc;
END
$$;

-- x^e mod m for non-negative integers (left-to-right would need bit access; right-to-left needs only % and div)
CREATE FUNCTION spike_sig.modexp(base numeric, ex numeric, m numeric) RETURNS numeric
LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
  result numeric := 1;
  b      numeric := base % m;
  e      numeric := ex;
BEGIN
  WHILE e > 0 LOOP
    IF e % 2 = 1 THEN
      result := (result * b) % m;
    END IF;
    e := div(e, 2);
    IF e > 0 THEN
      b := (b * b) % m;
    END IF;
  END LOOP;
  RETURN result;
END
$$;

-- the 256 low bits of x as a text of '0'/'1', most significant first
CREATE FUNCTION spike_sig.bits256(x numeric) RETURNS text
LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
  v   numeric := x;
  out text := '';
  i   int;
BEGIN
  FOR i IN 1 .. 256 LOOP
    out := (v % 2)::int::text || out;
    v := div(v, 2);
  END LOOP;
  RETURN out;
END
$$;

-- ===== ES256: P-256 ECDSA ======================================================================================================================

-- secp256r1 / NIST P-256 domain parameters (FIPS 186-4 D.1.2.3). a = -3.
CREATE FUNCTION spike_sig.p256_p() RETURNS numeric LANGUAGE sql IMMUTABLE AS
  $$ SELECT 115792089210356248762697446949407573530086143415290314195533631308867097853951::numeric $$;
CREATE FUNCTION spike_sig.p256_n() RETURNS numeric LANGUAGE sql IMMUTABLE AS
  $$ SELECT 115792089210356248762697446949407573529996955224135760342422259061068512044369::numeric $$;
CREATE FUNCTION spike_sig.p256_b() RETURNS numeric LANGUAGE sql IMMUTABLE AS
  $$ SELECT 41058363725152142129326129780047268409114441015993725554835256314039467401291::numeric $$;
CREATE FUNCTION spike_sig.p256_gx() RETURNS numeric LANGUAGE sql IMMUTABLE AS
  $$ SELECT 48439561293906451759052585252797914202762949526041747995844080717082404635286::numeric $$;
CREATE FUNCTION spike_sig.p256_gy() RETURNS numeric LANGUAGE sql IMMUTABLE AS
  $$ SELECT 36134250956749795798585127919587881956611106672985015071877198253568414405109::numeric $$;

CREATE TYPE spike_sig.jpoint AS (x numeric, y numeric, z numeric);   -- Jacobian; z = 0 is the point at infinity

-- 2P, a = -3 (EFD "dbl-2001-b"). Inputs reduced mod p.
CREATE FUNCTION spike_sig.jdouble(pt spike_sig.jpoint) RETURNS spike_sig.jpoint
LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
  pm numeric := spike_sig.p256_p();
  delta numeric; gamma numeric; beta numeric; alpha numeric; gamma2 numeric;
  x3 numeric; y3 numeric; z3 numeric;
BEGIN
  IF pt.z = 0 OR pt.y = 0 THEN
    RETURN ROW(1, 1, 0)::spike_sig.jpoint;
  END IF;
  delta  := (pt.z * pt.z) % pm;
  gamma  := (pt.y * pt.y) % pm;
  beta   := (pt.x * gamma) % pm;
  alpha  := (3 * ((pt.x + pm - delta) % pm) * ((pt.x + delta) % pm)) % pm;
  gamma2 := (gamma * gamma) % pm;
  x3 := (alpha * alpha + 8 * (pm - beta)) % pm;
  z3 := ((pt.y + pt.z) * (pt.y + pt.z) + 2 * pm - gamma - delta) % pm;
  y3 := (alpha * ((4 * beta + pm - x3) % pm) + 8 * (pm - gamma2)) % pm;
  RETURN ROW(x3, y3, z3)::spike_sig.jpoint;
END
$$;

-- P + Q (EFD "add-2007-bl"), with the degenerate cases made explicit.
CREATE FUNCTION spike_sig.jadd(pa spike_sig.jpoint, pb spike_sig.jpoint) RETURNS spike_sig.jpoint
LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
  pm numeric := spike_sig.p256_p();
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
      RETURN spike_sig.jdouble(pa);                        -- P = Q
    END IF;
    RETURN ROW(1, 1, 0)::spike_sig.jpoint;                -- P = -Q
  END IF;
  i  := (4 * h * h) % pm;
  j  := (h * i) % pm;
  rr := (2 * ((s2 + pm - s1) % pm)) % pm;
  v  := (u1 * i) % pm;
  x3 := (rr * rr + 2 * (pm - v) + (pm - j)) % pm;
  y3 := (rr * ((v + pm - x3) % pm) + 2 * (pm - ((s1 * j) % pm))) % pm;
  z3 := ((((pa.z + pb.z) * (pa.z + pb.z) + 2 * pm - z1z1 - z2z2) % pm) * h) % pm;
  RETURN ROW(x3, y3, z3)::spike_sig.jpoint;
END
$$;

-- u1*G + u2*Q by Shamir's trick: one shared 256-step double-and-add pass over the bits of both scalars.
CREATE FUNCTION spike_sig.p256_shamir(u1 numeric, u2 numeric, qx numeric, qy numeric) RETURNS spike_sig.jpoint
LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
  G  spike_sig.jpoint := ROW(spike_sig.p256_gx(), spike_sig.p256_gy(), 1)::spike_sig.jpoint;
  Q  spike_sig.jpoint := ROW(qx, qy, 1)::spike_sig.jpoint;
  GQ spike_sig.jpoint;
  R  spike_sig.jpoint := ROW(1, 1, 0)::spike_sig.jpoint;
  b1 text := spike_sig.bits256(u1);
  b2 text := spike_sig.bits256(u2);
  i  int;
  sel int;
BEGIN
  GQ := spike_sig.jadd(G, Q);
  FOR i IN 1 .. 256 LOOP
    R := spike_sig.jdouble(R);
    sel := (substr(b1, i, 1) = '1')::int + 2 * (substr(b2, i, 1) = '1')::int;
    IF sel = 1 THEN R := spike_sig.jadd(R, G);
    ELSIF sel = 2 THEN R := spike_sig.jadd(R, Q);
    ELSIF sel = 3 THEN R := spike_sig.jadd(R, GQ);
    END IF;
  END LOOP;
  RETURN R;
END
$$;

-- strict DER Ecdsa-Sig-Value -> {r, s}; NULL on any deviation (a WebAuthn ES256 signature is DER, and short enough that every length is one byte)
CREATE FUNCTION spike_sig.der_rs(sig bytea) RETURNS numeric[]
LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
  total int; rl int; sl int; pos int := 2;
  r bytea; s bytea;
BEGIN
  IF sig IS NULL OR length(sig) < 8 OR length(sig) > 72 THEN RETURN NULL; END IF;
  IF get_byte(sig, 0) <> 48 THEN RETURN NULL; END IF;                    -- 0x30 SEQUENCE
  total := get_byte(sig, 1);
  IF total >= 128 OR total <> length(sig) - 2 THEN RETURN NULL; END IF;  -- single-byte length, exact
  IF get_byte(sig, pos) <> 2 THEN RETURN NULL; END IF;                   -- 0x02 INTEGER
  rl := get_byte(sig, pos + 1);
  IF rl = 0 OR rl > 33 OR pos + 2 + rl + 2 > length(sig) THEN RETURN NULL; END IF;
  r := substring(sig FROM pos + 3 FOR rl);
  pos := pos + 2 + rl;
  IF get_byte(sig, pos) <> 2 THEN RETURN NULL; END IF;
  sl := get_byte(sig, pos + 1);
  IF sl = 0 OR sl > 33 OR pos + 2 + sl <> length(sig) THEN RETURN NULL; END IF;
  s := substring(sig FROM pos + 3 FOR sl);
  -- minimal and non-negative integers
  IF get_byte(r, 0) >= 128 OR get_byte(s, 0) >= 128 THEN RETURN NULL; END IF;
  IF rl > 1 AND get_byte(r, 0) = 0 AND get_byte(r, 1) < 128 THEN RETURN NULL; END IF;
  IF sl > 1 AND get_byte(s, 0) = 0 AND get_byte(s, 1) < 128 THEN RETURN NULL; END IF;
  RETURN ARRAY[spike_sig.os2ip(r), spike_sig.os2ip(s)];
END
$$;

-- ES256 verify: x, y are the 32-byte big-endian public-key coordinates; msg is the signed data (SHA-256 is applied here); sig is the DER signature.
CREATE FUNCTION spike_sig.es256_verify(qx_b bytea, qy_b bytea, msg bytea, sig bytea) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
  p numeric := spike_sig.p256_p();
  n numeric := spike_sig.p256_n();
  qx numeric; qy numeric; rs numeric[]; r numeric; s numeric;
  e numeric; w numeric; u1 numeric; u2 numeric;
  rp spike_sig.jpoint; zz numeric;
BEGIN
  IF length(qx_b) <> 32 OR length(qy_b) <> 32 THEN RETURN false; END IF;
  qx := spike_sig.os2ip(qx_b);
  qy := spike_sig.os2ip(qy_b);
  IF qx >= p OR qy >= p THEN RETURN false; END IF;
  -- on the curve: y^2 = x^3 - 3x + b (mod p). (Prime-order curve with cofactor 1: on the curve is sufficient, there is no small-subgroup case.)
  IF (qy * qy) % p <> (((qx * qx % p) * qx) + 3 * (p - qx) + spike_sig.p256_b()) % p THEN RETURN false; END IF;
  rs := spike_sig.der_rs(sig);
  IF rs IS NULL THEN RETURN false; END IF;
  r := rs[1]; s := rs[2];
  IF r < 1 OR r >= n OR s < 1 OR s >= n THEN RETURN false; END IF;
  e  := spike_sig.os2ip(sha256(msg));                      -- 256-bit hash, 256-bit order: no truncation
  w  := spike_sig.modexp(s, n - 2, n);                     -- s^-1 (n is prime)
  u1 := (e * w) % n;
  u2 := (r * w) % n;
  rp := spike_sig.p256_shamir(u1, u2, qx, qy);
  IF rp.z = 0 THEN RETURN false; END IF;
  -- x(R) = X / Z^2 (mod p); accept when x(R) mod n = r, i.e. x(R) = r, or x(R) = r + n when that is still below p. No inversion needed.
  zz := (rp.z * rp.z) % p;
  IF (r * zz) % p = rp.x THEN RETURN true; END IF;
  IF r + n < p AND ((r + n) * zz) % p = rp.x THEN RETURN true; END IF;
  RETURN false;
END
$$;

-- ===== RS256: RSASSA-PKCS1-v1_5, SHA-256, e = 65537 ============================================================================================

-- RS256 verify: n_b the big-endian modulus (2048 to 4096 bits, odd), e_b the exponent (must be 65537), sig the signature (as long as the modulus).
CREATE FUNCTION spike_sig.rs256_verify(n_b bytea, e_b bytea, msg bytea, sig bytea) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
  k int := length(n_b);
  n numeric; s numeric; m numeric; em bytea;
  -- DigestInfo for SHA-256: 30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20
  prefix bytea := '\x3031300d060960864801650304020105000420'::bytea;
  ps_len int;
BEGIN
  IF k < 256 OR k > 512 THEN RETURN false; END IF;
  IF get_byte(n_b, 0) = 0 OR get_byte(n_b, k - 1) % 2 = 0 THEN RETURN false; END IF;   -- full length, odd
  IF spike_sig.os2ip(e_b) <> 65537 THEN RETURN false; END IF;
  IF length(sig) <> k THEN RETURN false; END IF;
  n := spike_sig.os2ip(n_b);
  s := spike_sig.os2ip(sig);
  IF s >= n THEN RETURN false; END IF;
  m := spike_sig.modexp(s, 65537, n);
  -- EM = 0x00 || 0x01 || PS (0xff ...) || 0x00 || DigestInfo || H, built fresh and compared as integers (never parsed from m)
  ps_len := k - 3 - length(prefix) - 32;
  em := '\x0001'::bytea || decode(repeat('ff', ps_len), 'hex') || '\x00'::bytea || prefix || sha256(msg);
  RETURN m = spike_sig.os2ip(em);
END
$$;

-- ===== the vectors and the timing table =========================================================================================================

CREATE TABLE spike_sig.vector (
  id     serial PRIMARY KEY,
  alg    text    NOT NULL CHECK (alg IN ('ES256', 'RS256')),
  label  text    NOT NULL,
  expect boolean NOT NULL,         -- what a correct verifier must answer
  k1     bytea   NOT NULL,         -- ES256: x          RS256: modulus
  k2     bytea   NOT NULL,         -- ES256: y          RS256: exponent
  msg    bytea   NOT NULL,
  sig    bytea   NOT NULL,
  source text    NOT NULL          -- where the bytes came from (the software authenticator, or Web Crypto directly)
);

CREATE TABLE spike_sig.timing (
  vector_id int  NOT NULL,
  run       int  NOT NULL,
  verdict   boolean,
  ms        double precision NOT NULL
);
