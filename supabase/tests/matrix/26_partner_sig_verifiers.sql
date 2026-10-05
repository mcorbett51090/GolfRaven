-- 26_partner_sig_verifiers.sql
-- P5.1a S1.1b (0048): the SQL SIGNATURE VERIFIERS and the COSE_Key parser (design 15.2 / 16.4: database-side verification is the plan of record), S0-L1 "discriminating vectors".
--
-- WHAT THIS FILE PROVES, AND HOW IT IS MADE NON-VACUOUS.
--   * EVERY test of two vendored Project Wycheproof corpora (supabase/tests/fixtures/partner-sig/wycheproof/, Apache-2.0, see its NOTICE.md): ecdsa_secp256r1_sha256_test.json (484 tests, DER
--     signatures) through private.partner_sig_es256_verify, and rsa_signature_2048_sha256_test.json (259 tests, PKCS#1 v1.5) through private.partner_sig_rs256_verify. A strict verifier must accept
--     exactly the `valid` ES256 vectors and refuse every `invalid` one; for RSA the same, except that the vectors with a public exponent other than 65537 and the one `acceptable` vector (a missing NULL in
--     the DigestInfo) are refused BY POLICY (e = 65537 only; the encoded message is built fresh and compared whole, never parsed).
--   * the HAND-BUILT vectors of tools/db/partner-sig/gen-handbuilt-vectors.py (supabase/tests/fixtures/partner-sig/handbuilt-vectors.json): the cases Wycheproof does not contain and that a specific weakening of
--     the verifier WOULD accept: s + n and r + n, x(R) in [n, p) (the `r + n` branch), r not reduced mod n, an OFF-curve public key that verifies when the on-curve check is removed, negative and non-minimal DER,
--     an RSA s + n and an RSA signature one byte short / long, and the key-shape refusals.
--   * every strictness rule is a small NAMED PREDICATE (key_ok, rs_ok, xr_ok, rsa_key_ok, rsa_sig_ok, der_rs, cbor_head, cose_parse) with boundary cells of its own, so a mutant that weakens one conjunct is
--     killed by a cell that touches exactly that conjunct (the spike's survivors: on-curve, coordinate < p, r < n, s >= 1, RSA s < n, RSA length, the r + n branch, negative DER).
--   * the COSE_Key parser against the wrapper's key-shape rules (P-256 only with 32-byte coordinates; RSA 2048 to 4096 bits, e = 65537, no leading zero byte): S0-L2's variants, one field at a time.
--   * the timing of a verification in THIS harness (diag lines: median and maximum), against the S0 criterion of 200 ms.
--
-- The vendored JSON is read with psql's backtick (`cat`), relative to the repository root (the harness runs pg_prove from there), and is expanded into a temp table ONCE.

\set QUIET 1
\set wp_ec `cat supabase/tests/fixtures/partner-sig/wycheproof/ecdsa_secp256r1_sha256_test.json`
\set wp_rsa `cat supabase/tests/fixtures/partner-sig/wycheproof/rsa_signature_2048_sha256_test.json`
\set handbuilt `cat supabase/tests/fixtures/partner-sig/handbuilt-vectors.json`
BEGIN;
SELECT plan(191);

-- ----------------------------------------------------------------------------
-- 0. Posture: who can run what
-- ----------------------------------------------------------------------------
SELECT is((SELECT count(*)::int FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
           WHERE n.nspname = 'private' AND (p.proname LIKE 'partner\_sig\_%' OR p.proname IN ('partner_cbor_head', 'partner_cose_parse')) AND p.proowner <> 'private_definer'::regrole), 0,
  'every verifier function and the COSE parser is owned by private_definer');
SELECT is((SELECT count(*)::int FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
           WHERE n.nspname = 'private' AND (p.proname LIKE 'partner\_sig\_%' OR p.proname IN ('partner_cbor_head', 'partner_cose_parse'))
             AND p.proname <> 'partner_sig_verify'
             AND (has_function_privilege('anon', p.oid, 'EXECUTE') OR has_function_privilege('authenticated', p.oid, 'EXECUTE') OR has_function_privilege('service_role', p.oid, 'EXECUTE')
                  OR has_function_privilege('edge_actor', p.oid, 'EXECUTE') OR has_function_privilege('edge_system', p.oid, 'EXECUTE') OR has_function_privilege('edge_partner', p.oid, 'EXECUTE')
                  OR has_function_privilege('edge_partner_minter', p.oid, 'EXECUTE') OR has_function_privilege('partner_session_issuer', p.oid, 'EXECUTE'))), 0,
  'no helper of the verifier is executable by any role but its owner: reached only from inside partner_sig_verify, as private_definer');
SELECT is((SELECT p.prosecdef AND p.proconfig = ARRAY['search_path=""'] AND p.proowner = 'private_definer'::regrole FROM pg_proc p WHERE p.oid = 'private.partner_sig_verify(smallint, bytea, bytea, bytea)'::regprocedure), true,
  'the entry point is SECURITY DEFINER with search_path = '''' (so every helper runs as its owner under an empty path)');
SELECT is((SELECT array_agg(r.n ORDER BY r.n) FROM (VALUES ('anon'), ('authenticated'), ('service_role'), ('edge_gateway'), ('edge_actor'), ('edge_system'), ('edge_partner'), ('edge_partner_minter'), ('partner_session_issuer')) r(n)
           WHERE has_function_privilege(r.n, 'private.partner_sig_verify(smallint, bytea, bytea, bytea)', 'EXECUTE')), ARRAY['partner_session_issuer'],
  'partner_sig_verify is executable by partner_session_issuer (the mint''s owner) and by no other listed role');
SELECT is((SELECT count(*)::int FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
           WHERE n.nspname = 'private' AND (p.proname LIKE 'partner\_sig\_%' OR p.proname IN ('partner_cbor_head', 'partner_cose_parse'))
             AND p.proname <> 'partner_sig_verify' AND p.prosecdef), 0, 'the helpers are plain (SECURITY INVOKER) pure functions: they read no table and need no definer rights');
SELECT is((SELECT count(*)::int FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
           WHERE n.nspname = 'private' AND (p.proname LIKE 'partner\_sig\_%' OR p.proname IN ('partner_cbor_head', 'partner_cose_parse')) AND p.proname <> 'partner_sig_verify'
             AND p.provolatile <> 'i'), 0, 'and every one is IMMUTABLE: no clock, no setting, no table');
SELECT is((SELECT count(*)::int FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
           WHERE n.nspname = 'private' AND (p.proname LIKE 'partner\_sig\_%' OR p.proname IN ('partner_cbor_head', 'partner_cose_parse'))
             AND p.prosrc ~* '\m(app|auth|vault|pg_stat_activity)\.|clock_timestamp|now\(\)|current_setting|set_config|random\(\)|gen_random'), 0,
  'no verifier body names a schema table, the clock, a setting or a random source (pure)');

SET LOCAL ROLE private_definer;

-- an integer as a fixed-width big-endian byte string (test helper)
CREATE FUNCTION pg_temp.i2b(p_x numeric, p_len int) RETURNS bytea LANGUAGE plpgsql IMMUTABLE AS $f$
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

-- ----------------------------------------------------------------------------
-- 1. Wycheproof ES256: every vector, strict verdicts
-- ----------------------------------------------------------------------------
CREATE TEMP TABLE wp_ec_doc AS SELECT :'wp_ec'::jsonb AS j;
CREATE TEMP TABLE wp_ec AS
SELECT (grp.ord)::int AS gi, (tc->>'tcId')::int AS tcid, tc->>'comment' AS comment, tc->>'result' AS result, tc->'flags' AS flags,
       decode(tc->>'msg', 'hex') AS msg, decode(tc->>'sig', 'hex') AS sig,
       decode(right(lpad(grp.g->'publicKey'->>'wx', 66, '0'), 64), 'hex') AS qx, decode(right(lpad(grp.g->'publicKey'->>'wy', 66, '0'), 64), 'hex') AS qy
FROM wp_ec_doc d, jsonb_array_elements(d.j->'testGroups') WITH ORDINALITY AS grp(g, ord), jsonb_array_elements(grp.g->'tests') tc;
CREATE TEMP TABLE wp_ec_res AS
SELECT w.*, private.partner_sig_es256_verify(w.qx, w.qy, w.msg, w.sig) AS got FROM wp_ec w;

SELECT is((SELECT count(*)::int FROM wp_ec_res), 484, 'ES256 corpus: all 484 Wycheproof tests were loaded and run (a vacuous loop would be 0)');
SELECT is((SELECT count(*)::int FROM wp_ec_res WHERE result = 'valid'), 174, 'ES256 corpus: 174 of them are valid signatures');
SELECT is((SELECT count(*)::int FROM wp_ec_res WHERE result = 'valid' AND got IS TRUE), 174, 'ES256: EVERY valid Wycheproof signature verifies (edge-case keys, small r and s, special hashes, the Shamir and doubling cases)');
SELECT is((SELECT count(*)::int FROM wp_ec_res WHERE result = 'invalid' AND got IS NOT FALSE), 0, 'ES256: EVERY invalid Wycheproof signature is refused (310 of them: BER and every malformed DER, r or s out of range, replaced by r + n or s + n, modified, wrong types)');
SELECT is((SELECT count(*)::int FROM wp_ec_res WHERE got IS NULL), 0, 'ES256: no vector gives NULL (every refusal is a plain false)');
SELECT is((SELECT count(*)::int FROM wp_ec_res WHERE result NOT IN ('valid', 'invalid')), 0, 'ES256 corpus: it holds no "acceptable" verdict (so the verdict mapping above is total)');
-- the vectors that matter most for the branches, named so a failure says which:
SELECT is((SELECT got FROM wp_ec_res WHERE tcid = 479), true,  'Wycheproof 479 "r = 3, x = n + 3 is the smallest possible x with a reduction": VALID, and only through the r + n branch of xr_ok');
SELECT is((SELECT got FROM wp_ec_res WHERE tcid = 480), false, 'Wycheproof 480 "r = 4, x = n + 3 is invalid"');
SELECT is((SELECT got FROM wp_ec_res WHERE tcid = 350), true,  'Wycheproof 350 "k*G has a large x-coordinate": valid');
SELECT is((SELECT got FROM wp_ec_res WHERE tcid = 475), true,  'Wycheproof 475 "r = 5, x = 5 is valid"');
SELECT ok((SELECT count(*) FROM wp_ec_res WHERE comment ~ '^replaced (r|s) by (r|s) \+ n$') >= 2 AND (SELECT count(*) FROM wp_ec_res WHERE comment ~ '^replaced (r|s) by (r|s) \+ n$' AND got IS NOT FALSE) = 0, 'Wycheproof "replaced r by r + n" and "replaced s by s + n" exist and are all refused');
SELECT ok((SELECT count(*) FROM wp_ec_res WHERE comment = 'Legacy: ASN encoding of s misses leading 0') >= 1 AND (SELECT count(*) FROM wp_ec_res WHERE comment = 'Legacy: ASN encoding of s misses leading 0' AND got IS NOT FALSE) = 0, 'Wycheproof "ASN encoding of s misses leading 0" (a negative INTEGER) exists and is refused');
SELECT ok((SELECT count(*) FROM wp_ec_res WHERE comment ~ '^signature with non-minimal INTEGER tag on (r|s)$') >= 2 AND (SELECT count(*) FROM wp_ec_res WHERE comment ~ '^signature with non-minimal INTEGER tag on (r|s)$' AND got IS NOT FALSE) = 0, 'Wycheproof non-minimal INTEGER tags exist and are all refused');
-- "coordinate < p": the corpus's group with a SMALL y coordinate, replayed with y + p (the same point mod p, a second encoding). The valid signatures of that group verify; with y + p they must not.
CREATE TEMP TABLE wp_small_y AS
SELECT w.* FROM wp_ec_res w WHERE w.result = 'valid' AND private.partner_sig_os2ip(w.qy) < power(2::numeric, 256) - private.partner_sig_p256_p() AND w.got;
SELECT ok((SELECT count(*) FROM wp_small_y) >= 1, 'the corpus holds a valid vector whose public key has a small y coordinate (so y + p still fits in 32 bytes)');
SELECT is((SELECT count(*)::int FROM wp_small_y w
           WHERE private.partner_sig_es256_verify(w.qx, pg_temp.i2b(private.partner_sig_os2ip(w.qy) + private.partner_sig_p256_p(), 32), w.msg, w.sig)), 0,
  'a valid signature under the small-y key verifies; the SAME key with y + p (a second encoding of the point) is refused: both coordinates must be below p');
SELECT is((SELECT count(*)::int FROM wp_small_y w WHERE private.partner_sig_es256_verify(w.qx, w.qy, w.msg, w.sig)), (SELECT count(*)::int FROM wp_small_y), 'control: with its own y the same vectors verify');

-- ----------------------------------------------------------------------------
-- 2. Wycheproof RS256 (e = 65537 group, and the policy for the rest)
-- ----------------------------------------------------------------------------
CREATE TEMP TABLE wp_rsa_doc AS SELECT :'wp_rsa'::jsonb AS j;
CREATE TEMP TABLE wp_rsa AS
SELECT (grp.ord)::int AS gi, (tc->>'tcId')::int AS tcid, tc->>'comment' AS comment, tc->>'result' AS result, tc->'flags' AS flags, decode(tc->>'msg', 'hex') AS msg, decode(tc->>'sig', 'hex') AS sig,
       decode(regexp_replace(grp.g->'publicKey'->>'modulus', '^00', ''), 'hex') AS n, decode(grp.g->'publicKey'->>'publicExponent', 'hex') AS e
FROM wp_rsa_doc d, jsonb_array_elements(d.j->'testGroups') WITH ORDINALITY AS grp(g, ord), jsonb_array_elements(grp.g->'tests') tc;
CREATE TEMP TABLE wp_rsa_res AS
SELECT w.*, private.partner_sig_rs256_verify(w.n, w.e, w.msg, w.sig) AS got,
       -- the policy: e = 65537 only (the corpus's e = 3 groups hold VALID signatures this lane refuses), and the one "acceptable" vector (a legacy missing NULL) is refused
       (w.result = 'valid' AND w.e = '\x010001'::bytea) AS must_accept FROM wp_rsa w;
SELECT is((SELECT count(*)::int FROM wp_rsa_res), 259, 'RSA corpus: all 259 Wycheproof tests were loaded and run');
SELECT is((SELECT count(*)::int FROM wp_rsa_res WHERE must_accept), 7, 'RSA corpus: 7 valid signatures under e = 65537');
SELECT is((SELECT count(*)::int FROM wp_rsa_res WHERE must_accept AND got IS TRUE), 7, 'RS256: every valid Wycheproof signature under e = 65537 verifies');
SELECT is((SELECT count(*)::int FROM wp_rsa_res WHERE NOT must_accept AND got IS NOT FALSE), 0,
  'RS256: every other vector is refused: 249 invalid (BER paddings, bad ASN.1 in the padding, wrong hashes, short padding, PSS, no hash, malleability), the legacy acceptable one, and the e = 3 valid ones by policy');
SELECT is((SELECT count(*)::int FROM wp_rsa_res WHERE result = 'acceptable' AND got IS FALSE), 1, 'RS256: "missing NULL in the ASN encoding" (acceptable to some libraries) is refused: the DigestInfo is built fresh and compared whole');
SELECT is((SELECT count(*)::int FROM wp_rsa_res WHERE e = '\x03'::bytea AND result = 'valid' AND got IS FALSE), 2, 'RS256: the two VALID e = 3 vectors (edge-case and small signatures) are refused by policy: e is 65537 only');
SELECT ok((SELECT count(*) FROM wp_rsa_res WHERE comment = 'RSASSA-PSS signature') >= 1 AND (SELECT count(*) FROM wp_rsa_res WHERE comment = 'RSASSA-PSS signature' AND got IS NOT FALSE) = 0, 'RS256: a PSS signature exists in the corpus and is refused');
SELECT is((SELECT count(*)::int FROM wp_rsa_res WHERE comment ~ '^The message is hashed with .* instead of SHA-256' AND got IS FALSE), (SELECT count(*)::int FROM wp_rsa_res WHERE comment ~ '^The message is hashed with .* instead of SHA-256'),
  'RS256: a signature over another hash is refused (all of them)');

-- ----------------------------------------------------------------------------
-- 3. The hand-built vectors
-- ----------------------------------------------------------------------------
CREATE TEMP TABLE hb_doc AS SELECT :'handbuilt'::jsonb AS j;
CREATE TEMP TABLE hb AS
SELECT r.alg, r.label, r.expect, decode(r.k1, 'hex') AS k1, decode(r.k2, 'hex') AS k2, decode(r.msg, 'hex') AS msg, decode(r.sig, 'hex') AS sig, r.note
FROM hb_doc d, jsonb_to_recordset(d.j->'vectors') AS r(alg text, label text, expect boolean, k1 text, k2 text, msg text, sig text, note text);
CREATE TEMP TABLE hb_res AS
SELECT h.*, CASE h.alg WHEN 'ES256' THEN private.partner_sig_es256_verify(h.k1, h.k2, h.msg, h.sig) ELSE private.partner_sig_rs256_verify(h.k1, h.k2, h.msg, h.sig) END AS got FROM hb h;
SELECT is((SELECT count(*)::int FROM hb_res), 47, 'hand-built vectors: all 47 were loaded and run');
SELECT is((SELECT count(*)::int FROM hb_res WHERE expect AND got IS TRUE), (SELECT count(*)::int FROM hb_res WHERE expect), 'every hand-built control that must verify does (genuine ES256 and RS256 signatures at 2048, 3072 and 4096 bits, high-s, DER with and without a 0x00 pad, x(R) >= n)');
SELECT is((SELECT count(*)::int FROM hb_res WHERE NOT expect AND got IS NOT FALSE), 0, 'every hand-built refusal is a refusal');
SELECT is((SELECT count(*)::int FROM hb_res WHERE expect), 13, 'there are 13 controls (so "all refusals" is not "everything refused")');
SELECT is((SELECT got FROM hb_res WHERE label = 'es.valid-high-s'), true, 'ES256 low-s is NOT required: s -> n - s verifies (WebAuthn does not ask for it; replay is stopped by the nonce and the counter)');
SELECT is((SELECT got FROM hb_res WHERE label = 'es.valid-key-is-G'), true, 'ES256: a genuine signature under the public key G itself verifies (the precomputed G + Q is a DOUBLING)');
SELECT is((SELECT got FROM hb_res WHERE label = 'es.valid-key-is-minus-G'), true, 'ES256: a genuine signature under the public key -G verifies (the precomputed G + Q is the POINT AT INFINITY and adding it must leave the accumulator alone)');
SELECT is((SELECT got FROM hb_res WHERE label = 'es.xr-ge-n'), true, 'ES256 x(R) in [n, p): a signature that verifies ONLY through the r + n branch (r = x(R) - n) is accepted');
SELECT is((SELECT got FROM hb_res WHERE label = 'es.r-not-reduced'), false, 'ES256: the same R with r = x(R) (not reduced mod n) is refused: r < n');
SELECT is((SELECT got FROM hb_res WHERE label = 'es.s-plus-n'), false, 'ES256: s + n (valid DER, the residue of s) is refused: s < n');
SELECT is((SELECT got FROM hb_res WHERE label = 'es.off-curve-accepted-without-check'), false, 'ES256: an OFF-curve public key under which the signature verifies arithmetically is refused: the key must be on the curve');
SELECT is((SELECT got FROM hb_res WHERE label = 'es.neg-der-r'), false, 'ES256: r written as a negative INTEGER (top bit set, no 0x00 pad) is refused');
SELECT is((SELECT got FROM hb_res WHERE label = 'es.non-minimal-der-r'), false, 'ES256: a redundant leading 0x00 on r is refused');
SELECT is((SELECT got FROM hb_res WHERE label = 'es.trailing-in-sequence'), false, 'ES256: a valid signature with one extra byte INSIDE the SEQUENCE after s (the length counts it) is refused: the parser must consume exactly r and s');
SELECT is((SELECT got FROM hb_res WHERE label = 'es.trailing-after-sequence'), false, 'ES256: a valid signature with one extra byte AFTER the SEQUENCE is refused');
SELECT is((SELECT got FROM hb_res WHERE label = 'rs.s-plus-n'), false, 'RS256: s + n (the same length, the same residue) is refused: s < n');
SELECT is((SELECT got FROM hb_res WHERE label = 'rs.len-minus-one'), false, 'RS256: the same integer one byte short is refused: len(sig) = k');
SELECT is((SELECT got FROM hb_res WHERE label = 'rs.len-plus-one'), false, 'RS256: the same integer one byte long is refused: len(sig) = k');
SELECT is((SELECT got FROM hb_res WHERE label = 'rs.valid-leading-zero'), true, 'RS256 control: a full-length signature whose first byte is 0x00 verifies');

-- ----------------------------------------------------------------------------
-- 4. The predicates, one conjunct at a time
-- ----------------------------------------------------------------------------
-- 4a. partner_sig_p256_key_ok: both coordinates below p, and ON the curve
CREATE TEMP TABLE pts AS
SELECT private.partner_sig_p256_p() AS p, private.partner_sig_p256_n() AS n, private.partner_sig_p256_gx() AS gx, private.partner_sig_p256_gy() AS gy,
       private.partner_sig_os2ip(decode(d.j->'points'->'small_x'->>'x', 'hex')) AS sx, private.partner_sig_os2ip(decode(d.j->'points'->'small_x'->>'y', 'hex')) AS sy,
       (SELECT private.partner_sig_os2ip(w.qx) FROM wp_small_y w LIMIT 1) AS ax, (SELECT private.partner_sig_os2ip(w.qy) FROM wp_small_y w LIMIT 1) AS ay
FROM hb_doc d;
SELECT is((SELECT private.partner_sig_p256_key_ok(gx, gy) FROM pts), true, 'key_ok: the generator is a valid key');
SELECT is((SELECT private.partner_sig_p256_key_ok(sx, sy) FROM pts), true, 'key_ok: a point with a small x (5) is valid (control for the x + p cell)');
SELECT is((SELECT private.partner_sig_p256_key_ok(ax, ay) FROM pts), true, 'key_ok: the corpus point with a small y is valid (control for the y + p cell)');
SELECT is((SELECT private.partner_sig_p256_key_ok(sx + p, sy) FROM pts), false, 'key_ok: x + p with the same y (a second encoding of a VALID point) is refused: x < p');
SELECT is((SELECT private.partner_sig_p256_key_ok(ax, ay + p) FROM pts), false, 'key_ok: y + p with the same x is refused: y < p');
SELECT is((SELECT private.partner_sig_p256_key_ok(p, sy) FROM pts), false, 'key_ok: x = p is refused');
SELECT is((SELECT private.partner_sig_p256_key_ok(sx, p) FROM pts), false, 'key_ok: y = p is refused');
SELECT is((SELECT private.partner_sig_p256_key_ok(gx, gy + 1) FROM pts), false, 'key_ok: a point one off the curve is refused: on the curve');
SELECT is((SELECT private.partner_sig_p256_key_ok(gx + 1, gy) FROM pts), false, 'key_ok: x + 1 with the generator''s y is refused');
SELECT is((SELECT private.partner_sig_p256_key_ok(gx, p - gy) FROM pts), true, 'key_ok: the negation of the generator is a valid key');
SELECT is((SELECT private.partner_sig_p256_key_ok(0, 0)), false, 'key_ok: (0, 0), the usual "point at infinity" spelling, is refused');
SELECT is((SELECT private.partner_sig_p256_key_ok(NULL, 1)), false, 'key_ok: NULL is refused');
SELECT is((SELECT private.partner_sig_p256_key_ok(-1, 1)), false, 'key_ok: a negative coordinate is refused');
-- 4b. partner_sig_p256_rs_ok
SELECT is((SELECT private.partner_sig_p256_rs_ok(1, 1)), true, 'rs_ok: r = s = 1 is in range');
SELECT is((SELECT private.partner_sig_p256_rs_ok(n - 1, n - 1) FROM pts), true, 'rs_ok: r = s = n - 1 is in range');
SELECT is((SELECT private.partner_sig_p256_rs_ok(0, 1)), false, 'rs_ok: r = 0 is refused: r >= 1');
SELECT is((SELECT private.partner_sig_p256_rs_ok(1, 0)), false, 'rs_ok: s = 0 is refused: s >= 1 (s = 0 would be inverted to 0 and give the point at infinity)');
SELECT is((SELECT private.partner_sig_p256_rs_ok(n, 1) FROM pts), false, 'rs_ok: r = n is refused: r < n');
SELECT is((SELECT private.partner_sig_p256_rs_ok(1, n) FROM pts), false, 'rs_ok: s = n is refused: s < n');
SELECT is((SELECT private.partner_sig_p256_rs_ok(n + 1, 1) FROM pts), false, 'rs_ok: r = n + 1 is refused');
SELECT is((SELECT private.partner_sig_p256_rs_ok(1, n + 1) FROM pts), false, 'rs_ok: s = n + 1 is refused');
SELECT is((SELECT private.partner_sig_p256_rs_ok(NULL, 1)), false, 'rs_ok: NULL is refused');
-- 4c. partner_sig_p256_xr_ok: x(R) = r, or x(R) = r + n while r + n < p
SELECT is((SELECT private.partner_sig_p256_xr_ok(7, 1, 7)), true, 'xr_ok: x(R) = r');
SELECT is((SELECT private.partner_sig_p256_xr_ok(8, 1, 7)), false, 'xr_ok: x(R) <> r');
SELECT is((SELECT private.partner_sig_p256_xr_ok((7 * 25) % p, 5, 7) FROM pts), true, 'xr_ok: the Jacobian X = r * Z^2: it compares without inverting');
SELECT is((SELECT private.partner_sig_p256_xr_ok(n + 3, 1, 3) FROM pts), true, 'xr_ok: x(R) = n + 3 with r = 3 (the reduction): the r + n branch');
SELECT is((SELECT private.partner_sig_p256_xr_ok(n + 3, 1, 4) FROM pts), false, 'xr_ok: x(R) = n + 3 with r = 4 is not accepted');
SELECT is((SELECT private.partner_sig_p256_xr_ok(((n + 3) * 49) % p, 7, 3) FROM pts), true, 'xr_ok: the r + n branch with Z <> 1');
SELECT is((SELECT private.partner_sig_p256_xr_ok(0, 1, p - n) FROM pts), false, 'xr_ok: r + n = p is NOT below p, so that branch is not taken (the boundary: x = 0 would "match" r + n mod p)');
SELECT is((SELECT private.partner_sig_p256_xr_ok(p - 1, 1, p - n - 1) FROM pts), true, 'xr_ok: r + n = p - 1 IS below p: the branch is taken at its last value');
-- 4d. partner_sig_der_rs: strict DER Ecdsa-Sig-Value
SELECT is((SELECT private.partner_sig_der_rs('\x3006020101020102'::bytea)), ARRAY[1, 2]::numeric[], 'der_rs: the smallest valid signature, r = 1 and s = 2');
SELECT is((SELECT private.partner_sig_der_rs('\x300602020080020101'::bytea)), NULL, 'der_rs: a length that does not match the body (the SEQUENCE says 6, the body is 7) is refused');
SELECT is((SELECT private.partner_sig_der_rs('\x3006020101020102ff'::bytea)), NULL, 'der_rs: a trailing byte is refused');
SELECT is((SELECT private.partner_sig_der_rs('\x3106020101020102'::bytea)), NULL, 'der_rs: a wrong SEQUENCE tag is refused');
SELECT is((SELECT private.partner_sig_der_rs('\x3006030101020102'::bytea)), NULL, 'der_rs: a wrong tag on r is refused');
SELECT is((SELECT private.partner_sig_der_rs('\x3006020101030102'::bytea)), NULL, 'der_rs: a wrong tag on s is refused');
SELECT is((SELECT private.partner_sig_der_rs('\x30060200020101'::bytea)), NULL, 'der_rs: an empty r (length 0) is refused');
SELECT is((SELECT private.partner_sig_der_rs('\x3006020101020001'::bytea)), NULL, 'der_rs: an empty s (length 0) is refused');
SELECT is((SELECT private.partner_sig_der_rs('\x3007020180020102'::bytea)), NULL, 'der_rs: a NEGATIVE r (0x80, no pad) is refused');
SELECT is((SELECT private.partner_sig_der_rs('\x3007020101020280'::bytea)), NULL, 'der_rs: a NEGATIVE s is refused');
SELECT is((SELECT private.partner_sig_der_rs('\x300702020001020102'::bytea)), NULL, 'der_rs: a non-minimal r (00 01) is refused');
SELECT is((SELECT private.partner_sig_der_rs('\x300702010102020002'::bytea)), NULL, 'der_rs: a non-minimal s (00 02) is refused');
SELECT is((SELECT private.partner_sig_der_rs('\x300702020080020102'::bytea)), ARRAY[128, 2]::numeric[], 'der_rs: r = 0x80 with its 0x00 pad (the required form) is accepted');
SELECT is((SELECT private.partner_sig_der_rs('\x308106020101020102'::bytea)), NULL, 'der_rs: a long-form SEQUENCE length is refused');
SELECT is((SELECT private.partner_sig_der_rs(NULL)), NULL, 'der_rs: NULL gives NULL');
SELECT is((SELECT private.partner_sig_der_rs('\x30050201010201'::bytea)), NULL, 'der_rs: a truncated s is refused');
SELECT is((SELECT array_length(private.partner_sig_der_rs(decode('3046' || '0221' || repeat('11', 33) || '0221' || repeat('22', 33), 'hex')), 1)), 2, 'der_rs: a 33-byte r that is positive without a pad parses (a 264-bit number): the RANGE is rs_ok''s check, not the parser''s');
SELECT is((SELECT array_length(private.partner_sig_der_rs(decode('3046' || '0221' || '00' || repeat('81', 32) || '0221' || '00' || repeat('82', 32), 'hex')), 1)), 2, 'der_rs: the longest valid form (33-byte r and s, each with its 0x00 pad) is accepted');
SELECT is((SELECT private.partner_sig_der_rs(decode('3047' || '0222' || '00' || repeat('81', 33) || '0221' || '00' || repeat('82', 32), 'hex'))), NULL, 'der_rs: a 34-byte r is refused');
-- 4e. partner_sig_rsa_key_ok and partner_sig_rsa_sig_ok
CREATE TEMP TABLE rsak AS SELECT h.k1 AS n, h.k2 AS e, h.sig AS sig FROM hb h WHERE h.label = 'rs.valid-2048';
SELECT is((SELECT private.partner_sig_rsa_key_ok(n, '\x010001') FROM rsak), true, 'rsa_key_ok: a genuine 2048-bit key');
SELECT is((SELECT private.partner_sig_rsa_key_ok(n, '\x03') FROM rsak), false, 'rsa_key_ok: e = 3 is refused');
SELECT is((SELECT private.partner_sig_rsa_key_ok(n, '\x00010001') FROM rsak), false, 'rsa_key_ok: e spelled in four bytes is refused');
SELECT is((SELECT private.partner_sig_rsa_key_ok(n, '\x010003') FROM rsak), false, 'rsa_key_ok: e = 65539 is refused');
SELECT is((SELECT private.partner_sig_rsa_key_ok(substring(n, 2), '\x010001') FROM rsak), false, 'rsa_key_ok: 255 bytes (under 2048 bits) is refused');
SELECT is((SELECT private.partner_sig_rsa_key_ok(n || '\x01', '\x010001') FROM rsak), true, 'rsa_key_ok: 257 bytes (a 2056-bit modulus, odd) is within 2048 to 4096 bits');
SELECT is((SELECT private.partner_sig_rsa_key_ok(decode(repeat('ab', 511) || 'ad', 'hex'), '\x010001')), true, 'rsa_key_ok: 512 bytes is the longest accepted modulus');
SELECT is((SELECT private.partner_sig_rsa_key_ok(decode(repeat('ab', 512) || 'ad', 'hex'), '\x010001')), false, 'rsa_key_ok: 513 bytes (over 4096 bits) is refused');
SELECT is((SELECT private.partner_sig_rsa_key_ok('\x00' || n, '\x010001') FROM rsak), false, 'rsa_key_ok: a leading 0x00 byte is refused');
SELECT is((SELECT private.partner_sig_rsa_key_ok(set_byte(n, 255, get_byte(n, 255) & 254), '\x010001') FROM rsak), false, 'rsa_key_ok: an even modulus is refused');
SELECT is((SELECT private.partner_sig_rsa_key_ok(NULL, '\x010001')), false, 'rsa_key_ok: NULL is refused');
SELECT is((SELECT private.partner_sig_rsa_sig_ok(sig, 256, private.partner_sig_os2ip(n)) FROM rsak), true, 'rsa_sig_ok: a genuine signature (length k, below n)');
SELECT is((SELECT private.partner_sig_rsa_sig_ok(substring(sig, 2), 256, private.partner_sig_os2ip(n)) FROM rsak), false, 'rsa_sig_ok: one byte short is refused: len = k');
SELECT is((SELECT private.partner_sig_rsa_sig_ok('\x00' || sig, 256, private.partner_sig_os2ip(n)) FROM rsak), false, 'rsa_sig_ok: one byte long is refused: len = k (a "length >= k" test would accept it)');
SELECT is((SELECT private.partner_sig_rsa_sig_ok(n, 256, private.partner_sig_os2ip(n)) FROM rsak), false, 'rsa_sig_ok: s = n is refused: s < n');
SELECT is((SELECT private.partner_sig_rsa_sig_ok(pg_temp.i2b(private.partner_sig_os2ip(n) - 1, 256), 256, private.partner_sig_os2ip(n)) FROM rsak), true, 'rsa_sig_ok: s = n - 1 is accepted (the boundary)');
SELECT is((SELECT private.partner_sig_rsa_sig_ok(pg_temp.i2b(private.partner_sig_os2ip(n) + 1, 256), 256, private.partner_sig_os2ip(n)) FROM rsak), false, 'rsa_sig_ok: s = n + 1 is refused');
SELECT is((SELECT private.partner_sig_rsa_sig_ok(NULL, 256, 5)), false, 'rsa_sig_ok: NULL is refused');

-- ----------------------------------------------------------------------------
-- 5. partner_cbor_head and the COSE_Key parser
-- ----------------------------------------------------------------------------
SELECT is((SELECT (o_major, o_arg, o_next)::text FROM private.partner_cbor_head('\xa5'::bytea, 0)), '(5,5,1)', 'cbor_head: a map of 5 pairs');
SELECT is((SELECT (o_major, o_arg, o_next)::text FROM private.partner_cbor_head('\x2f'::bytea, 0)), '(1,15,1)', 'cbor_head: a negative integer (-16)');
SELECT is((SELECT (o_major, o_arg, o_next)::text FROM private.partner_cbor_head('\x5820'::bytea, 0)), '(2,32,2)', 'cbor_head: a byte string of 32, one length byte');
SELECT is((SELECT (o_major, o_arg, o_next)::text FROM private.partner_cbor_head('\x590100'::bytea, 0)), '(2,256,3)', 'cbor_head: a byte string of 256, two length bytes');
SELECT is((SELECT (o_major, o_arg, o_next)::text FROM private.partner_cbor_head('\x5818'::bytea, 0)), '(2,24,2)', 'cbor_head: 24 is the first value that needs the one-byte form');
SELECT is((SELECT count(*)::int FROM private.partner_cbor_head('\x5817'::bytea, 0)), 0, 'cbor_head: 23 written in the one-byte form is non-minimal: refused');
SELECT is((SELECT count(*)::int FROM private.partner_cbor_head('\x5900ff'::bytea, 0)), 0, 'cbor_head: 255 written in the two-byte form is non-minimal: refused');
SELECT is((SELECT count(*)::int FROM private.partner_cbor_head('\x5a00010000'::bytea, 0)), 0, 'cbor_head: a four-byte argument is not used by a COSE_Key of this lane: refused');
SELECT is((SELECT count(*)::int FROM private.partner_cbor_head('\x5f'::bytea, 0)), 0, 'cbor_head: an indefinite length (additional information 31) is refused');
SELECT is((SELECT count(*)::int FROM private.partner_cbor_head('\x5c'::bytea, 0)), 0, 'cbor_head: reserved additional information 28 is refused');
SELECT is((SELECT count(*)::int FROM private.partner_cbor_head('\x58'::bytea, 0)), 0, 'cbor_head: a truncated one-byte argument is refused');
SELECT is((SELECT count(*)::int FROM private.partner_cbor_head('\x5901'::bytea, 0)), 0, 'cbor_head: a truncated two-byte argument is refused');
SELECT is((SELECT count(*)::int FROM private.partner_cbor_head('\x58'::bytea, 5)), 0, 'cbor_head: a position past the end gives nothing');

-- the two key shapes the lane accepts, as COSE hex (any helper that builds them is here, in the test, never in the migration)
CREATE FUNCTION pg_temp.cose_ec(p_x text, p_y text, p_head text DEFAULT 'a5', p_kty text DEFAULT '0102', p_alg text DEFAULT '0326', p_crv text DEFAULT '2001', p_xk text DEFAULT '215820', p_yk text DEFAULT '225820') RETURNS bytea LANGUAGE sql IMMUTABLE AS
  $f$ SELECT decode(p_head || p_kty || p_alg || p_crv || p_xk || p_x || p_yk || p_y, 'hex') $f$;
CREATE FUNCTION pg_temp.cose_rsa(p_n text, p_e text DEFAULT '2143010001', p_head text DEFAULT 'a4', p_kty text DEFAULT '0103', p_alg text DEFAULT '03390100', p_nk text DEFAULT '2059' || '0100') RETURNS bytea LANGUAGE sql IMMUTABLE AS
  $f$ SELECT decode(p_head || p_kty || p_alg || p_nk || p_n || p_e, 'hex') $f$;
CREATE TEMP TABLE keys AS SELECT encode(h.k1, 'hex') AS xh, encode(h.k2, 'hex') AS yh FROM hb h WHERE h.label = 'es.valid-baseline';
CREATE TEMP TABLE rsa_key_hex AS SELECT encode(k1, 'hex') AS nh FROM hb WHERE label = 'rs.valid-2048';
SELECT is((SELECT (o_alg, encode(o_a, 'hex') = xh, encode(o_b, 'hex') = yh)::text FROM keys, private.partner_cose_parse(pg_temp.cose_ec(xh, yh))), '(-7,t,t)', 'cose_parse: a canonical ES256 COSE_Key parses to (-7, x, y)');
SELECT is((SELECT (o_alg, encode(o_a, 'hex') = nh, encode(o_b, 'hex'))::text FROM rsa_key_hex, private.partner_cose_parse(pg_temp.cose_rsa(nh))), '(-257,t,010001)', 'cose_parse: a canonical RS256 COSE_Key parses to (-257, n, 010001)');
-- S0-L2, one field at a time (each is refused; the canonical key above is the control)
SELECT is((SELECT count(*)::int FROM keys, private.partner_cose_parse(pg_temp.cose_ec(xh, yh, p_crv => '2002'))), 0, 'cose_parse: crv 2 (P-384) with 32-byte coordinates, labelled -7: refused (P-256 only)');
SELECT is((SELECT count(*)::int FROM keys, private.partner_cose_parse(pg_temp.cose_ec(xh, yh, p_crv => '2003'))), 0, 'cose_parse: crv 3 (P-521) refused');
SELECT is((SELECT count(*)::int FROM keys, private.partner_cose_parse(pg_temp.cose_ec(xh, yh, p_crv => '2006'))), 0, 'cose_parse: crv 6 (Ed25519) on an EC2 key refused');
SELECT is((SELECT count(*)::int FROM keys, private.partner_cose_parse(pg_temp.cose_ec(xh, yh, p_crv => '20' || '5820'))), 0, 'cose_parse: a byte string where the curve id belongs is refused');
SELECT is((SELECT count(*)::int FROM keys, private.partner_cose_parse(pg_temp.cose_ec(substr(xh, 3), yh, p_xk => '215820'))), 0, 'cose_parse: a 31-byte x (the length byte still says 32) is refused: it does not fit');
SELECT is((SELECT count(*)::int FROM keys, private.partner_cose_parse(pg_temp.cose_ec(substr(xh, 3), yh, p_xk => '21581f'))), 0, 'cose_parse: a 31-byte x is refused: 32-byte coordinates only');
SELECT is((SELECT count(*)::int FROM keys, private.partner_cose_parse(pg_temp.cose_ec('00' || xh, yh, p_xk => '215821'))), 0, 'cose_parse: a 33-byte x is refused');
SELECT is((SELECT count(*)::int FROM keys, private.partner_cose_parse(pg_temp.cose_ec(xh, substr(yh, 3), p_yk => '22581f'))), 0, 'cose_parse: a 31-byte y is refused');
SELECT is((SELECT count(*)::int FROM keys, private.partner_cose_parse(pg_temp.cose_ec(xh, '00' || yh, p_yk => '225821'))), 0, 'cose_parse: a 33-byte y is refused');
SELECT is((SELECT count(*)::int FROM keys, private.partner_cose_parse(pg_temp.cose_ec(xh, yh, p_kty => '0101'))), 0, 'cose_parse: kty OKP with alg -7 is refused');
SELECT is((SELECT count(*)::int FROM keys, private.partner_cose_parse(pg_temp.cose_ec(xh, yh, p_kty => '0103'))), 0, 'cose_parse: kty RSA with alg -7 is refused');
SELECT is((SELECT count(*)::int FROM keys, private.partner_cose_parse(pg_temp.cose_ec(xh, yh, p_alg => '0327'))), 0, 'cose_parse: alg -8 (EdDSA) is refused');
SELECT is((SELECT count(*)::int FROM keys, private.partner_cose_parse(pg_temp.cose_ec(xh, yh, p_head => 'a4'))), 0, 'cose_parse: a map of 4 pairs holding EC2 fields is refused (EC2 needs all five)');
SELECT is((SELECT count(*)::int FROM keys, private.partner_cose_parse(pg_temp.cose_ec(xh, yh, p_head => 'a6'))), 0, 'cose_parse: a map of 6 pairs is refused');
SELECT is((SELECT count(*)::int FROM keys, private.partner_cose_parse(pg_temp.cose_ec(xh, yh) || '\x00'::bytea)), 0, 'cose_parse: a trailing byte is refused');
SELECT is((SELECT count(*)::int FROM keys, private.partner_cose_parse(substring(pg_temp.cose_ec(xh, yh), 1, 60))), 0, 'cose_parse: a truncated key is refused');
SELECT is((SELECT count(*)::int FROM keys, private.partner_cose_parse(pg_temp.cose_ec(xh, yh, p_kty => '011802'))), 0, 'cose_parse: a key written as 18 02 (a non-minimal head) is refused');
SELECT is((SELECT count(*)::int FROM keys, private.partner_cose_parse(pg_temp.cose_ec(xh, yh, p_xk => '215820', p_yk => '215820'))), 0, 'cose_parse: the same key (-2) twice is refused');
SELECT is((SELECT count(*)::int FROM keys, private.partner_cose_parse(pg_temp.cose_ec(xh, yh, p_xk => '235820'))), 0, 'cose_parse: an unknown key (-4) is refused');
-- a key, a value or a byte string written with the WRONG major type but the right argument: a parser that reads only the argument takes it for the right thing
SELECT is((SELECT count(*)::int FROM keys, private.partner_cose_parse(pg_temp.cose_ec(xh, yh, p_crv => '4001'))), 0, 'cose_parse: the key -1 written as a byte-string head (40) is refused: map keys are integers');
SELECT is((SELECT count(*)::int FROM keys, private.partner_cose_parse(pg_temp.cose_ec(xh, yh, p_alg => '0346'))), 0, 'cose_parse: alg written as a byte-string head (46), which a parser reading only the argument takes for -7, is refused');
SELECT is((SELECT count(*)::int FROM keys, private.partner_cose_parse(pg_temp.cose_ec(xh, yh, p_xk => '217820'))), 0, 'cose_parse: x written as a TEXT string of 32 bytes (78 20) is refused: a byte string only');
SELECT is((SELECT count(*)::int FROM keys, private.partner_cose_parse(pg_temp.cose_ec(xh, yh, p_crv => '204101'))), 0, 'cose_parse: the curve id as a one-byte byte string (20 41 01) instead of an integer is refused: no curve id at all');
SELECT is((SELECT count(*)::int FROM keys, private.partner_cose_parse(decode('a5' || '0326' || '0102' || '2001' || '215820' || xh || '225820' || yh, 'hex'))), 1, 'cose_parse: the pairs in ANOTHER order are fine (alg first)');
SELECT is((SELECT count(*)::int FROM keys, private.partner_cose_parse(decode('a5' || '0102' || '0326' || '2001' || '215820' || xh || '2258ff' || yh, 'hex'))), 0, 'cose_parse: a byte string longer than what is left is refused');
-- the ES256 verifier on its own refuses a coordinate that is not exactly 32 bytes (the COSE parser upstream already does; this is the second line)
SELECT is((SELECT private.partner_sig_es256_verify('\x00'::bytea || k1, k2, msg, sig) FROM hb WHERE label = 'es.valid-baseline'), false, 'es256_verify: a 33-byte x (the same value with a leading 0x00) is refused: 32-byte coordinates only');
SELECT is((SELECT private.partner_sig_es256_verify(k1, '\x00'::bytea || k2, msg, sig) FROM hb WHERE label = 'es.valid-baseline'), false, 'es256_verify: a 33-byte y is refused');
SELECT is((SELECT private.partner_sig_es256_verify(substring(k1, 2), k2, msg, sig) FROM hb WHERE label = 'es.valid-baseline'), false, 'es256_verify: a 31-byte x is refused');
-- RSA
SELECT is((SELECT count(*)::int FROM rsa_key_hex, private.partner_cose_parse(pg_temp.cose_rsa('00' || nh, p_nk => '20590101'))), 0, 'cose_parse: a modulus with a leading 0x00 byte (257 bytes) is refused');
SELECT is((SELECT count(*)::int FROM rsa_key_hex, private.partner_cose_parse(pg_temp.cose_rsa('00' || substr(nh, 3), p_nk => '20590100'))), 0, 'cose_parse: a 256-byte modulus whose first byte is 0x00 is refused');
SELECT is((SELECT count(*)::int FROM rsa_key_hex, private.partner_cose_parse(pg_temp.cose_rsa(substr(nh, 3), p_nk => '2058ff'))), 0, 'cose_parse: a 255-byte modulus (under 2048 bits) is refused');
SELECT is((SELECT count(*)::int FROM private.partner_cose_parse(pg_temp.cose_rsa(repeat('ab', 512), p_nk => '20590200'))), 1, 'cose_parse: a 512-byte modulus is the largest accepted');
SELECT is((SELECT count(*)::int FROM private.partner_cose_parse(pg_temp.cose_rsa(repeat('ab', 513), p_nk => '20590201'))), 0, 'cose_parse: a 513-byte modulus is refused');
SELECT is((SELECT count(*)::int FROM rsa_key_hex, private.partner_cose_parse(pg_temp.cose_rsa(nh, p_e => '2143030001'))), 0, 'cose_parse: e = 03 00 01 is refused');
SELECT is((SELECT count(*)::int FROM rsa_key_hex, private.partner_cose_parse(pg_temp.cose_rsa(nh, p_e => '2141' || '03'))), 0, 'cose_parse: e = 3 is refused');
SELECT is((SELECT count(*)::int FROM rsa_key_hex, private.partner_cose_parse(pg_temp.cose_rsa(nh, p_e => '214400010001'))), 0, 'cose_parse: e = 65537 spelled in four bytes is refused');
SELECT is((SELECT count(*)::int FROM rsa_key_hex, private.partner_cose_parse(pg_temp.cose_rsa(nh, p_kty => '0102'))), 0, 'cose_parse: kty EC2 with alg -257 is refused');
SELECT is((SELECT count(*)::int FROM rsa_key_hex, private.partner_cose_parse(pg_temp.cose_rsa(nh, p_alg => '03390101'))), 0, 'cose_parse: alg -258 (RS384) is refused');
SELECT is((SELECT count(*)::int FROM rsa_key_hex, private.partner_cose_parse(pg_temp.cose_rsa(nh, p_head => 'a5'))), 0, 'cose_parse: a map of 5 pairs holding RSA fields is refused');
SELECT is((SELECT count(*)::int FROM rsa_key_hex, private.partner_cose_parse(pg_temp.cose_rsa(nh, p_nk => '2059' || '0100') || '\x00'::bytea)), 0, 'cose_parse: a trailing byte after an RSA key is refused');
SELECT is((SELECT count(*)::int FROM rsa_key_hex, private.partner_cose_parse(pg_temp.cose_rsa(nh, p_nk => '2a59' || '0100'))), 0, 'cose_parse: an RSA key with an unknown key (-11) in place of the modulus is refused');
SELECT is((SELECT count(*)::int FROM rsa_key_hex, private.partner_cose_parse(pg_temp.cose_rsa(nh, p_head => 'a5') || '\x2143010001'::bytea)), 0, 'cose_parse: an RSA key whose exponent (-2) appears TWICE (five pairs, four distinct keys) is refused: each key once');
SELECT is((SELECT count(*)::int FROM rsa_key_hex, private.partner_cose_parse(pg_temp.cose_rsa(nh, p_head => 'a5') || '\x0441ff'::bytea)), 0, 'cose_parse: an RSA key with a FIFTH pair under an unknown key (4, with a byte-string value) is refused: exactly the four fields');
SELECT is((SELECT count(*)::int FROM rsa_key_hex, private.partner_cose_parse(pg_temp.cose_rsa(nh, p_head => 'a5') || '\x2241ff'::bytea)), 0, 'cose_parse: an RSA key with a fifth pair under a KNOWN EC key (-3) is refused: the key set must be exactly the RSA one');
SELECT is((SELECT count(*)::int FROM private.partner_cose_parse(NULL)), 0, 'cose_parse: NULL gives nothing');
SELECT is((SELECT count(*)::int FROM private.partner_cose_parse('\xa5'::bytea)), 0, 'cose_parse: a key that is too short gives nothing');

-- ----------------------------------------------------------------------------
-- 6. The entry point, end to end from COSE bytes
-- ----------------------------------------------------------------------------
CREATE TEMP TABLE e2e AS
SELECT pg_temp.cose_ec(encode(k1, 'hex'), encode(k2, 'hex')) AS cose_es, k1, k2, msg AS es_msg, sig AS es_sig FROM hb WHERE label = 'es.valid-baseline';
CREATE TEMP TABLE e2e_rs AS
SELECT pg_temp.cose_rsa(encode(k1, 'hex')) AS cose_rs, msg AS rs_msg, sig AS rs_sig FROM hb WHERE label = 'rs.valid-2048';
SELECT is((SELECT private.partner_sig_verify(-7::smallint, cose_es, es_msg, es_sig) FROM e2e), true, 'partner_sig_verify: a genuine ES256 signature under its COSE key verifies');
SELECT is((SELECT private.partner_sig_verify(-257::smallint, cose_rs, rs_msg, rs_sig) FROM e2e_rs), true, 'partner_sig_verify: a genuine RS256 signature under its COSE key verifies');
SELECT is((SELECT private.partner_sig_verify(-257::smallint, cose_es, es_msg, es_sig) FROM e2e), false, 'partner_sig_verify: the stored algorithm must be the key''s algorithm (an ES256 key presented as RS256)');
SELECT is((SELECT private.partner_sig_verify(-7::smallint, cose_rs, rs_msg, rs_sig) FROM e2e_rs), false, 'partner_sig_verify: ... and the other way round');
SELECT is((SELECT private.partner_sig_verify(-8::smallint, cose_es, es_msg, es_sig) FROM e2e), false, 'partner_sig_verify: an algorithm other than -7 / -257 is refused');
SELECT is((SELECT private.partner_sig_verify(-7::smallint, '\x0102030405060708'::bytea, es_msg, es_sig) FROM e2e), false, 'partner_sig_verify: a key that does not parse is false (fail closed), never an error');
SELECT is((SELECT private.partner_sig_verify(-7::smallint, cose_es, es_msg || '\x00', es_sig) FROM e2e), false, 'partner_sig_verify: a different message is refused');
SELECT is((SELECT private.partner_sig_verify(NULL, cose_es, es_msg, es_sig) FROM e2e), false, 'partner_sig_verify: a NULL algorithm is false');
SELECT is((SELECT private.partner_sig_verify(-7::smallint, NULL, es_msg, es_sig) FROM e2e), false, 'partner_sig_verify: a NULL key is false');
SELECT is((SELECT private.partner_sig_verify(-7::smallint, cose_es, NULL, es_sig) FROM e2e), false, 'partner_sig_verify: a NULL message is false');
SELECT is((SELECT private.partner_sig_verify(-7::smallint, cose_es, es_msg, NULL) FROM e2e), false, 'partner_sig_verify: a NULL signature is false');

-- ----------------------------------------------------------------------------
-- 7. Timing in THIS harness (the S0 criterion: under 200 ms for each algorithm; S0 measured ES256 35.5 ms and RS256 3.7 ms worst warm)
-- ----------------------------------------------------------------------------
CREATE TEMP TABLE timing (alg text, ms double precision);
DO $t$
DECLARE
  t0 timestamptz;
  i int;
  v record;
BEGIN
  SELECT * INTO v FROM e2e, e2e_rs;
  FOR i IN 1 .. 31 LOOP
    t0 := clock_timestamp();
    PERFORM private.partner_sig_verify(-7::smallint, v.cose_es, v.es_msg, v.es_sig);
    INSERT INTO timing VALUES ('ES256', extract(epoch FROM clock_timestamp() - t0) * 1000);
    t0 := clock_timestamp();
    PERFORM private.partner_sig_verify(-257::smallint, v.cose_rs, v.rs_msg, v.rs_sig);
    INSERT INTO timing VALUES ('RS256', extract(epoch FROM clock_timestamp() - t0) * 1000);
  END LOOP;
END
$t$;
SELECT diag(format('verifier timing in this harness (31 calls each, the first is cold): ES256 median %s ms, max %s ms; RS256 median %s ms, max %s ms',
  (SELECT round(percentile_cont(0.5) WITHIN GROUP (ORDER BY ms)::numeric, 1) FROM timing WHERE alg = 'ES256'), (SELECT round(max(ms)::numeric, 1) FROM timing WHERE alg = 'ES256'),
  (SELECT round(percentile_cont(0.5) WITHIN GROUP (ORDER BY ms)::numeric, 1) FROM timing WHERE alg = 'RS256'), (SELECT round(max(ms)::numeric, 1) FROM timing WHERE alg = 'RS256')));
SELECT ok((SELECT max(ms) FROM timing WHERE alg = 'ES256') < 500, 'ES256: the worst of 31 verifications is under 500 ms here (the S0 criterion is 200 ms on a quiet host; the margin is for a loaded CI runner; the median is in the diag line above)');
SELECT ok((SELECT max(ms) FROM timing WHERE alg = 'RS256') < 500, 'RS256: the worst of 31 verifications is under 500 ms here');

SELECT * FROM finish();
ROLLBACK;
