-- supabase/tests/partner-sign-helpers.sql
--
-- TEST-ONLY helpers for the partner sign-in mint (migration 0048, docs/security/partner-auth-design.md S1.1b): an ES256 SIGNER written in SQL on top of the verifier's own P-256 arithmetic,
-- and an ASSERTION BUILDER that produces exactly the bytes a WebAuthn authenticator and a browser hand the Edge (clientDataJSON, authenticatorData, a DER signature over
-- authenticatorData || SHA-256(clientDataJSON)) bound to a challenge the database issued. It exists so that a pgTAP file (which cannot run Deno) and a shell script can drive the mint with REAL signatures
-- generated at RUN TIME: every key is generated when the test runs and lives only in the transaction that made it. Nothing here is loaded by a migration and nothing here is a secret.
--
-- Everything is created in the session's temp schema (pg_temp), so it vanishes with the session and can never be called by anything else. It must be CALLED AS private_definer (it uses the verifier's
-- helper functions, which nobody else may execute). Load it with:  \i supabase/tests/partner-sign-helpers.sql   (psql, run from the repository root).
--
--   pg_temp.ps_i2b(x, len)                      an integer as a fixed-width big-endian byte string
--   pg_temp.ps_pub(d)                           the public key (x, y) of the private scalar d, as numeric[]
--   pg_temp.ps_sign(d, msg)                     an ES256 signature (DER) of msg under d
--   pg_temp.ps_cose_es256(x, y)                 the canonical COSE_Key bytes of a P-256 public key
--   pg_temp.ps_assertion(d, rp_id, origin, counter, opts)   one assertion bound to a fresh challenge, as a row
-- ps_assertion's `opts` (every key optional; the default is a perfectly valid assertion):
--   exp_offset      seconds from now the challenge expires (default 120; negative = already expired, with a VALID MAC over that expiry)
--   exp_abs         the absolute expiry (epoch seconds), replacing exp_offset (to re-present a challenge issued earlier)
--   mac_purpose     the purpose byte the MAC is computed for (default 1 = sign_in; 2 / 3 = a challenge of another purpose)
--   mac_binding     the binding uuid the MAC is computed for (default the zero uuid)
--   mac_exp_shift   compute the MAC over exp + shift but present exp (a tampered expiry)
--   mac_tamper      flip one bit of the MAC
--   nonce_hex       use this nonce (32 bytes, hex) instead of a random one; mac_hex presents this MAC
--   client          a jsonb object merged over the default client data (type, challenge, origin, crossOrigin)
--   client_drop     a jsonb array of keys removed from the client data after the merge
--   client_raw      the exact clientDataJSON text, replacing the object (invalid JSON, a non-object, ...)
--   client_raw_hex  the exact clientDataJSON BYTES (invalid UTF-8, ...)
--   rp              the RP ID hashed into authenticatorData (default the rp_id argument)
--   flags           the authenticatorData flags byte (default 5 = UP | UV)
--   ad_hex          the exact authenticatorData, replacing the built one
--   sign_d          sign with this private scalar instead of d (a signature by another key)
--   sig_tamper      flip one bit of the signature
--   sig_hex         the exact signature, replacing the built one

CREATE FUNCTION pg_temp.ps_i2b(p_x numeric, p_len int) RETURNS bytea LANGUAGE plpgsql IMMUTABLE AS $f$
DECLARE
  v numeric := p_x;
  b bytea := pg_catalog.decode(pg_catalog.repeat('00', p_len), 'hex');
  i int;
BEGIN
  FOR i IN REVERSE p_len - 1 .. 0 LOOP
    b := pg_catalog.set_byte(b, i, (v % 256)::int);
    v := pg_catalog.div(v, 256);
  END LOOP;
  RETURN b;
END
$f$;

CREATE FUNCTION pg_temp.ps_affine(p_j private.partner_sig_jpoint) RETURNS numeric[] LANGUAGE plpgsql IMMUTABLE AS $f$
DECLARE
  p numeric := private.partner_sig_p256_p();
  zi numeric := private.partner_sig_modexp(p_j.z, p - 2, p);
  zi2 numeric := (zi * zi) % p;
BEGIN
  RETURN ARRAY[(p_j.x * zi2) % p, (((p_j.y * zi2) % p) * zi) % p];
END
$f$;

CREATE FUNCTION pg_temp.ps_pub(p_d numeric) RETURNS numeric[] LANGUAGE sql IMMUTABLE AS $f$
  SELECT pg_temp.ps_affine(private.partner_sig_p256_shamir(p_d, 0, private.partner_sig_p256_gx(), private.partner_sig_p256_gy()))
$f$;

CREATE FUNCTION pg_temp.ps_der_int(p_v numeric) RETURNS bytea LANGUAGE plpgsql IMMUTABLE AS $f$
DECLARE
  b bytea := pg_temp.ps_i2b(p_v, 33);
  i int := 0;
BEGIN
  WHILE i < 32 AND pg_catalog.get_byte(b, i) = 0 LOOP
    i := i + 1;
  END LOOP;
  b := pg_catalog.substring(b, i + 1);
  IF pg_catalog.get_byte(b, 0) >= 128 THEN b := '\x00'::bytea || b; END IF;
  RETURN '\x02'::bytea || pg_catalog.set_byte('\x00'::bytea, 0, pg_catalog.length(b)) || b;
END
$f$;

CREATE FUNCTION pg_temp.ps_sign(p_d numeric, p_msg bytea) RETURNS bytea LANGUAGE plpgsql AS $f$
DECLARE
  n numeric := private.partner_sig_p256_n();
  e numeric := private.partner_sig_os2ip(pg_catalog.sha256(p_msg));
  k numeric; r numeric; s numeric;
  ri bytea; si bytea;
BEGIN
  LOOP
    k := private.partner_sig_os2ip(public.gen_random_bytes(32)) % (n - 1) + 1;
    r := (pg_temp.ps_affine(private.partner_sig_p256_shamir(k, 0, private.partner_sig_p256_gx(), private.partner_sig_p256_gy())))[1] % n;
    CONTINUE WHEN r = 0;
    s := (private.partner_sig_modexp(k, n - 2, n) * ((e + r * p_d) % n)) % n;
    CONTINUE WHEN s = 0;
    ri := pg_temp.ps_der_int(r);
    si := pg_temp.ps_der_int(s);
    RETURN '\x30'::bytea || pg_catalog.set_byte('\x00'::bytea, 0, pg_catalog.length(ri) + pg_catalog.length(si)) || ri || si;
  END LOOP;
END
$f$;

CREATE FUNCTION pg_temp.ps_cose_es256(p_x numeric, p_y numeric) RETURNS bytea LANGUAGE sql IMMUTABLE AS $f$
  SELECT pg_catalog.decode('a5010203262001215820', 'hex') || pg_temp.ps_i2b(p_x, 32) || pg_catalog.decode('225820', 'hex') || pg_temp.ps_i2b(p_y, 32)
$f$;

CREATE FUNCTION pg_temp.ps_b64u(p_b bytea) RETURNS text LANGUAGE sql IMMUTABLE AS $f$
  SELECT pg_catalog.rtrim(pg_catalog.translate(pg_catalog.replace(pg_catalog.encode(p_b, 'base64'), E'\n', ''), '+/', '-_'), '=')
$f$;

CREATE FUNCTION pg_temp.ps_assertion(p_d numeric, p_rp_id text, p_origin text, p_counter bigint, p_opts jsonb DEFAULT '{}'::jsonb)
RETURNS TABLE (o_nonce bytea, o_exp bigint, o_mac bytea, o_ad bytea, o_cd bytea, o_sig bytea)
LANGUAGE plpgsql AS $f$
DECLARE
  v_nonce bytea := coalesce(pg_catalog.decode(p_opts ->> 'nonce_hex', 'hex'), public.gen_random_bytes(32));
  v_exp bigint := coalesce((p_opts ->> 'exp_abs')::bigint, pg_catalog.floor(pg_catalog.date_part('epoch', pg_catalog.clock_timestamp()))::bigint + coalesce((p_opts ->> 'exp_offset')::int, 120));
  v_mac bytea;
  v_obj jsonb;
  v_cd bytea;
  v_ad bytea;
  v_sig bytea;
  v_drop text[];
BEGIN
  IF p_opts ? 'mac_hex' THEN
    v_mac := pg_catalog.decode(p_opts ->> 'mac_hex', 'hex');
  ELSE
    SELECT c.o_mac INTO v_mac FROM private.partner_challenge_core(coalesce((p_opts ->> 'mac_purpose')::smallint, 1::smallint), v_exp + coalesce((p_opts ->> 'mac_exp_shift')::bigint, 0), v_nonce,
                                                                 coalesce((p_opts ->> 'mac_binding')::uuid, '00000000-0000-0000-0000-000000000000'::uuid), NULL) c;
    IF coalesce((p_opts ->> 'mac_tamper')::boolean, false) THEN
      v_mac := pg_catalog.set_byte(v_mac, 5, pg_catalog.get_byte(v_mac, 5) # 1);
    END IF;
  END IF;
  v_obj := pg_catalog.jsonb_build_object('type', 'webauthn.get', 'challenge', pg_temp.ps_b64u(v_nonce), 'origin', p_origin, 'crossOrigin', false) || coalesce(p_opts -> 'client', '{}'::jsonb);
  IF p_opts ? 'client_drop' THEN
    SELECT coalesce(pg_catalog.array_agg(x), '{}') INTO v_drop FROM pg_catalog.jsonb_array_elements_text(p_opts -> 'client_drop') x;
    v_obj := v_obj - v_drop;
  END IF;
  v_cd := CASE WHEN p_opts ? 'client_raw_hex' THEN pg_catalog.decode(p_opts ->> 'client_raw_hex', 'hex')
               WHEN p_opts ? 'client_raw' THEN pg_catalog.convert_to(p_opts ->> 'client_raw', 'UTF8')
               ELSE pg_catalog.convert_to(v_obj::text, 'UTF8') END;
  v_ad := CASE WHEN p_opts ? 'ad_hex' THEN pg_catalog.decode(p_opts ->> 'ad_hex', 'hex')
               ELSE pg_catalog.sha256(pg_catalog.convert_to(coalesce(p_opts ->> 'rp', p_rp_id), 'UTF8'))
                    || pg_catalog.set_byte('\x00'::bytea, 0, coalesce((p_opts ->> 'flags')::int, 5))
                    || pg_temp.ps_i2b(p_counter, 4) END;
  IF p_opts ? 'sig_hex' THEN
    v_sig := pg_catalog.decode(p_opts ->> 'sig_hex', 'hex');
  ELSE
    v_sig := pg_temp.ps_sign(coalesce((p_opts ->> 'sign_d')::numeric, p_d), v_ad || pg_catalog.sha256(v_cd));
    IF coalesce((p_opts ->> 'sig_tamper')::boolean, false) THEN
      v_sig := pg_catalog.set_byte(v_sig, pg_catalog.length(v_sig) - 1, pg_catalog.get_byte(v_sig, pg_catalog.length(v_sig) - 1) # 1);
    END IF;
  END IF;
  o_nonce := v_nonce; o_exp := v_exp; o_mac := v_mac; o_ad := v_ad; o_cd := v_cd; o_sig := v_sig;
  RETURN NEXT;
END
$f$;
