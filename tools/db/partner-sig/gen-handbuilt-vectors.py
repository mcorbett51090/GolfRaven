#!/usr/bin/env python3
"""
tools/db/partner-sig/gen-handbuilt-vectors.py

Generates supabase/tests/fixtures/partner-sig/handbuilt-vectors.json: the HAND-BUILT discriminating vectors of the SQL signature verifiers (partner-auth-design S0-L1; migration
0048_partner_signin_mint.sql). They complement the vendored Wycheproof corpora (supabase/tests/fixtures/partner-sig/wycheproof/): where Wycheproof has no vector that a given
weakening of the verifier would ACCEPT, one is built here, from first principles, and its expected verdict is the strict one.

Run:   python3 tools/db/partner-sig/gen-handbuilt-vectors.py > supabase/tests/fixtures/partner-sig/handbuilt-vectors.json
Needs: Python 3 only (no third-party package: P-256 and RSA are implemented here with plain integers, slowly and for test vectors only. Do not reuse this code for anything else).

Every key here is generated afresh when this script runs and its private half is never written anywhere: the fixture holds public keys, messages and signatures only. The output
is committed; re-running it changes it (new random keys), which is why it is committed rather than generated at test time (a pgTAP file cannot run Python).

THE CONSTRUCTIONS (each is a vector that a specific weakening of the strict verifier WOULD accept, so the strict refusal is evidence about that check):
  es.valid-*                a genuine signature, and the same with s -> n - s (valid: WebAuthn does not require low-s).
  es.s-plus-n / r-plus-n    the same signature with s (r) replaced by s + n (r + n), still valid DER (33-byte INTEGER). s + n reduces to s, so a verifier without `s < n` accepts it.
  es.xr-ge-n                a signature whose R has x(R) in [n, p): r = x(R) - n, so the verifier must take the `r + n` branch. Built from a chosen R (no discrete log needed):
                            pick s and the message hash e, set u1 = e/s, r = x(R) mod n, u2 = r/s and the PUBLIC KEY Q = u2^-1 (R - u1 G). The signature is valid for that Q.
  es.r-not-reduced          the same R with r = x(R) (not reduced mod n): a verifier without `r < n` accepts it, the strict one refuses it.
  es.off-curve-accepted     an OFF-curve public key under which a verifier WITHOUT the on-curve check ACCEPTS the signature. With u2 = 1 and u1 even the verifier's last step is the chord addition
                            M + Q, M = u1 G, whose formula involves neither a nor b: choose r, take M, pick x2 and solve the chord for y2 so that x(M + Q) = r. Q is then (almost surely) not on P-256.
  es.valid-key-is-G / -minus-G  genuine signatures under the two degenerate public keys G and -G (the add routine's P = Q and P = -Q branches, reached through the precomputed G + Q).
  es.trailing-*             a valid signature with one extra byte inside the SEQUENCE after s (its length counts it) and one after the SEQUENCE.
  es.neg-der / non-min-der  r (or s) with its top bit set written WITHOUT the 0x00 pad (a negative INTEGER), and a redundant leading 0x00 (non-minimal).
  rs.valid-*                genuine RS256 signatures at 2048, 3072 and 4096 bits.
  rs.s-plus-n               a 2048-bit key whose modulus is just above 2^2047 and s + n, which still fits the modulus length: a verifier without `s < n` accepts it.
  rs.len-minus-one          a signature whose leading byte is 0x00, presented WITHOUT it: the same integer, one byte short: a verifier that checks `len >= k` or only the integer accepts it.
  rs.len-plus-one           the signature with an extra leading 0x00.
  rs.e3 / even-n / lead0    key-shape refusals (e = 3, an even modulus, a leading zero byte).
The point on the curve with a SMALL coordinate (so that x + p still fits in 32 bytes), for the `coordinate < p` predicate cells, is emitted under "points".
"""
import hashlib
import json
import os
import sys

import random as _random
from math import isqrt

P = 115792089210356248762697446949407573530086143415290314195533631308867097853951
N = 115792089210356248762697446949407573529996955224135760342422259061068512044369
B = 41058363725152142129326129780047268409114441015993725554835256314039467401291
GX = 48439561293906451759052585252797914202762949526041747995844080717082404635286
GY = 36134250956749795798585127919587881956611106672985015071877198253568414405109
G = (GX, GY)


def inv(a, m):
    return pow(a % m, -1, m)


def padd(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if (y1 + y2) % P == 0:
            return None
        lam = (3 * x1 * x1 - 3) * inv(2 * y1, P) % P
    else:
        lam = (y2 - y1) * inv(x2 - x1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    return (x3, (lam * (x1 - x3) - y1) % P)


def pneg(p1):
    return None if p1 is None else (p1[0], (-p1[1]) % P)


def pmul(k, p1):
    k %= N
    r = None
    a = p1
    while k:
        if k & 1:
            r = padd(r, a)
        a = padd(a, a)
        k >>= 1
    return r


def on_curve(pt):
    x, y = pt
    return (y * y - (x * x * x - 3 * x + B)) % P == 0


def sqrt_mod_p(a):
    a %= P
    r = pow(a, (P + 1) // 4, P)  # p = 3 (mod 4)
    return r if (r * r) % P == a else None


def be(v, n):
    return v.to_bytes(n, "big")


def der_int(v, minimal=True, negative_ok=False, pad=False):
    """DER INTEGER body+header for v >= 0. minimal: shortest; negative_ok: omit the 0x00 even if the top bit is set; pad: add one redundant leading 0x00."""
    b = be(v, max(1, (v.bit_length() + 7) // 8))
    if (b[0] & 0x80) and not negative_ok:
        b = b"\x00" + b
    if pad:
        b = b"\x00" + b
    return bytes([2, len(b)]) + b


def der_sig(r_der, s_der):
    body = r_der + s_der
    return bytes([0x30, len(body)]) + body


def sig_rs(r, s):
    return der_sig(der_int(r), der_int(s))


def ecdsa_sign_with(d, msg):
    e = int.from_bytes(hashlib.sha256(msg).digest(), "big")
    while True:
        k = int.from_bytes(os.urandom(32), "big") % (N - 1) + 1
        r = pmul(k, G)[0] % N
        if r == 0:
            continue
        s = inv(k, N) * (e + r * d) % N
        if s != 0:
            return r, s


def is_probable_prime(v, rounds=24):
    if v < 2:
        return False
    for sp in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if v % sp == 0:
            return v == sp
    d, t = v - 1, 0
    while d % 2 == 0:
        d //= 2
        t += 1
    rng = _random.SystemRandom()
    for _ in range(rounds):
        a = rng.randrange(2, v - 1)
        x = pow(a, d, v)
        if x in (1, v - 1):
            continue
        for _ in range(t - 1):
            x = x * x % v
            if x == v - 1:
                break
        else:
            return False
    return True


def gen_prime(bits):
    while True:
        c = int.from_bytes(os.urandom(bits // 8), "big") | (1 << (bits - 1)) | (1 << (bits - 2)) | 1
        if c % 65537 != 1 and is_probable_prime(c):
            return c


def gen_prime_near_sqrt2(bits):
    """A prime in [sqrt(2) * 2^(bits-1), sqrt(2) * 2^(bits-1) * (1 + 2^-9)]: the product of two of them is just above 2^(2*bits - 1)."""
    lo = isqrt(2 << (2 * (bits - 1)))  # floor(sqrt(2) * 2^(bits-1))
    span = lo >> 9
    while True:
        c = lo + int.from_bytes(os.urandom(bits // 8), "big") % span
        if c % 2 == 1 and c % 65537 != 1 and is_probable_prime(c):
            return c


class RsaKey:
    def __init__(self, bits, near=False):
        while True:
            if near:
                p_, q_ = gen_prime_near_sqrt2(bits // 2), gen_prime_near_sqrt2(bits // 2)
            else:
                p_, q_ = gen_prime(bits // 2), gen_prime(bits // 2)
            if p_ == q_:
                continue
            n_ = p_ * q_
            if n_.bit_length() != bits:
                continue
            phi = (p_ - 1) * (q_ - 1)
            try:
                self.d = pow(65537, -1, phi)
            except ValueError:
                continue
            self.n = n_
            return

    def sign(self, msg):
        k = (self.n.bit_length() + 7) // 8
        prefix = bytes.fromhex("3031300d060960864801650304020105000420")
        em = b"\x00\x01" + b"\xff" * (k - 3 - len(prefix) - 32) + b"\x00" + prefix + hashlib.sha256(msg).digest()
        return be(pow(int.from_bytes(em, "big"), self.d, self.n), k)


def hx(b):
    return b.hex()


def es_vec(vectors, label, expect, q, msg, sig, note=""):
    vectors.append({"alg": "ES256", "label": label, "expect": expect, "k1": hx(be(q[0], 32)), "k2": hx(be(q[1], 32)), "msg": hx(msg), "sig": hx(sig), "note": note})


def rs_vec(vectors, label, expect, n_bytes, e_bytes, msg, sig, note=""):
    vectors.append({"alg": "RS256", "label": label, "expect": expect, "k1": hx(n_bytes), "k2": hx(e_bytes), "msg": hx(msg), "sig": hx(sig), "note": note})


def e_of(msg):
    return int.from_bytes(hashlib.sha256(msg).digest(), "big")


def verify_model(q, msg, r, s, check_curve=True):
    """An independent affine-arithmetic ECDSA verifier on P-256, optionally WITHOUT the on-curve check: used to prove each constructed vector means what it claims."""
    if check_curve and not on_curve(q):
        return False
    if not (1 <= r < N and 1 <= s < N):
        return False
    w = inv(s, N)
    u1 = e_of(msg) * w % N
    u2 = r * w % N
    rp = padd(pmul(u1, G), pmul(u2, q))
    if rp is None:
        return False
    return rp[0] % N == r


def main():
    vectors = []
    points = {}

    # ---------------- ES256 ----------------
    d = int.from_bytes(os.urandom(32), "big") % (N - 1) + 1
    q = pmul(d, G)
    msg = b"golfraven partner sign-in hand-built vector: baseline"
    r, s = ecdsa_sign_with(d, msg)
    assert verify_model(q, msg, r, s)
    es_vec(vectors, "es.valid-baseline", True, q, msg, sig_rs(r, s))
    es_vec(vectors, "es.valid-high-s", True, q, msg, sig_rs(r, N - s), "s -> n - s is also valid: low-s is not required")
    es_vec(vectors, "es.s-plus-n", False, q, msg, sig_rs(r, s + N), "s + n has the residue s: a verifier without s < n accepts it")
    es_vec(vectors, "es.r-plus-n", False, q, msg, sig_rs(r + N, s), "r + n: refused by r < n")
    es_vec(vectors, "es.r-and-s-plus-n", False, q, msg, sig_rs(r + N, s + N))
    es_vec(vectors, "es.s-equals-n", False, q, msg, sig_rs(r, N))
    es_vec(vectors, "es.r-equals-n", False, q, msg, sig_rs(N, s))
    es_vec(vectors, "es.s-zero", False, q, msg, sig_rs(r, 0))
    es_vec(vectors, "es.r-zero", False, q, msg, sig_rs(0, s))
    es_vec(vectors, "es.other-message", False, q, msg + b"!", sig_rs(r, s))
    # extra bytes AFTER the second INTEGER: inside the SEQUENCE (its length counts them) and outside it (the length does not)
    es_vec(vectors, "es.trailing-in-sequence", False, q, msg, der_sig(der_int(r), der_int(s) + b"\x00"), "a valid signature with one extra byte inside the SEQUENCE after s: a parser that stops reading at s accepts it")
    es_vec(vectors, "es.trailing-after-sequence", False, q, msg, sig_rs(r, s) + b"\x00", "a valid signature with one extra byte after the SEQUENCE")
    # the two degenerate public keys: Q = G (G + Q is a DOUBLING) and Q = -G (G + Q is the point at infinity, which the Shamir loop then adds to its accumulator)
    for label, dd, note in (("es.valid-key-is-G", 1, "the public key is G itself (d = 1): the precomputed G + Q is a doubling"),
                            ("es.valid-key-is-minus-G", N - 1, "the public key is -G (d = n - 1): the precomputed G + Q is the point at infinity, and adding it must leave the accumulator alone")):
        qd = pmul(dd, G)
        for i in range(64):
            md = (b"degenerate key %s %d" % (label.encode(), i))
            rd, sd = ecdsa_sign_with(dd, md)
            if verify_model(qd, md, rd, sd):
                es_vec(vectors, label, True, qd, md, sig_rs(rd, sd), note)
                break
    q2 = pmul(d + 1, G)
    es_vec(vectors, "es.other-key", False, q2, msg, sig_rs(r, s))
    # negative / non-minimal DER, from signatures whose r (or s) has the top bit set / clear
    found_hi = found_lo = found_s_hi = False
    for i in range(4000):
        m = b"der variants %d" % i
        rr, ss = ecdsa_sign_with(d, m)
        if rr >> 255 and not found_hi:
            es_vec(vectors, "es.valid-der-hi-r", True, q, m, sig_rs(rr, ss), "control: r with the top bit set, padded with 0x00 as DER requires")
            es_vec(vectors, "es.neg-der-r", False, q, m, der_sig(der_int(rr, negative_ok=True), der_int(ss)), "r written without its 0x00 pad: a negative INTEGER")
            found_hi = True
        if not (rr >> 255) and not found_lo:
            es_vec(vectors, "es.non-minimal-der-r", False, q, m, der_sig(der_int(rr, pad=True), der_int(ss)), "a redundant leading 0x00 on r")
            es_vec(vectors, "es.valid-der-lo-r", True, q, m, sig_rs(rr, ss), "control")
            found_lo = True
        if (ss >> 255) and not found_s_hi:
            es_vec(vectors, "es.neg-der-s", False, q, m, der_sig(der_int(rr), der_int(ss, negative_ok=True)), "s written without its 0x00 pad: a negative INTEGER")
            es_vec(vectors, "es.valid-der-hi-s", True, q, m, sig_rs(rr, ss), "control")
            found_s_hi = True
        if found_hi and found_lo and found_s_hi:
            break
    assert found_hi and found_lo and found_s_hi, "the DER variants need a signature of each shape"
    es_vec(vectors, "es.non-minimal-der-s", False, q, msg, der_sig(der_int(r), der_int(s, pad=True)) if not (s >> 255) else der_sig(der_int(r), der_int(s, pad=True)), "a redundant leading 0x00 (on a value that already has one when its top bit is set: non-minimal either way)")

    # x(R) in [n, p): the `r + n` branch (a real signature; the key is constructed from the signature)
    while True:
        x = N + int.from_bytes(os.urandom(4), "big") % 1000 + 1
        y = sqrt_mod_p(x * x * x - 3 * x + B)
        if y is not None and x < P:
            break
    R = (x, y)
    assert on_curve(R)
    mm = b"x(R) is at least n"
    s_ = int.from_bytes(os.urandom(32), "big") % (N - 1) + 1
    e = e_of(mm)
    u1 = e * inv(s_, N) % N
    r_red = x % N
    assert r_red == x - N
    u2 = r_red * inv(s_, N) % N
    Q = pmul(inv(u2, N), padd(R, pneg(pmul(u1, G))))
    assert on_curve(Q)
    assert verify_model(Q, mm, r_red, s_)
    es_vec(vectors, "es.xr-ge-n", True, Q, mm, sig_rs(r_red, s_), "x(R) = r + n: valid only through the r + n branch")
    # the same R with r NOT reduced (r = x(R) >= n): u2 uses r mod n, so the signature (x, s) is "valid" to a verifier that does not require r < n
    assert verify_model(Q, mm, r_red, s_)
    es_vec(vectors, "es.r-not-reduced", False, Q, mm, sig_rs(x, s_), "r = x(R), not reduced mod n: a verifier without r < n accepts it; the strict one refuses it")

    # off-curve public key that a verifier WITHOUT the on-curve check accepts
    mo = b"off-curve public key"
    eo = e_of(mo)
    for _ in range(10000):
        rr = int.from_bytes(os.urandom(32), "big") % (N - 1) + 1
        ss = rr
        u1o = eo * inv(rr, N) % N
        if u1o & 1:
            continue
        M = pmul(u1o, G)
        x1, y1 = M
        x2 = int.from_bytes(os.urandom(31), "big") % P
        if x2 == x1:
            continue
        lam2 = (rr + x1 + x2) % P
        lam = sqrt_mod_p(lam2)
        if lam is None:
            continue
        y2 = (y1 + lam * (x2 - x1)) % P
        Qo = (x2, y2)
        if on_curve(Qo):
            continue
        # the chord through M and Q has x3 = lam^2 - x1 - x2 = r
        assert (lam * lam - x1 - x2) % P == rr
        assert verify_model(Qo, mo, rr, ss, check_curve=False)
        assert not verify_model(Qo, mo, rr, ss, check_curve=True)
        es_vec(vectors, "es.off-curve-accepted-without-check", False, Qo, mo, sig_rs(rr, ss), "Q is not on P-256; without the on-curve check this signature verifies")
        break
    else:
        raise SystemExit("no off-curve vector found")

    # public keys: not on the curve at all
    es_vec(vectors, "es.key-y-plus-one", False, (q[0], (q[1] + 1) % P), msg, sig_rs(r, s))
    es_vec(vectors, "es.key-zero-zero", False, (0, 0), msg, sig_rs(r, s), "the encoding (0, 0) is not the point at infinity and is not on the curve")

    # points with a small coordinate (x + p, y + p still fit in 32 bytes), for the `coordinate < p` predicate cells
    for x in range(1, 200):
        yy = sqrt_mod_p(x * x * x - 3 * x + B)
        if yy is not None:
            points["small_x"] = {"x": hx(be(x, 32)), "y": hx(be(yy, 32)), "x_plus_p": hx(be(x + P, 32))}
            break
    assert "small_x" in points and on_curve((int(points["small_x"]["x"], 16), int(points["small_x"]["y"], 16)))
    # (a point with a small y is in the Wycheproof corpus, group 101; the test file builds y + p from it)

    # ---------------- RS256 ----------------
    def rsa_key(bits, near=False):
        return RsaKey(bits, near=near)

    def rsa_sign(key, m):
        return key.sign(m)

    for bits in (2048, 3072, 4096):
        key = rsa_key(bits)
        k = bits // 8
        nb = be(key.n, k)
        m = b"rsa baseline %d" % bits
        sg = rsa_sign(key, m)
        rs_vec(vectors, "rs.valid-%d" % bits, True, nb, b"\x01\x00\x01", m, sg)
        rs_vec(vectors, "rs.other-message-%d" % bits, False, nb, b"\x01\x00\x01", m + b"!", sg)
        rs_vec(vectors, "rs.bit-flip-%d" % bits, False, nb, b"\x01\x00\x01", m, sg[:-1] + bytes([sg[-1] ^ 1]))
    # s + n: the modulus just above 2^2047
    key = rsa_key(2048, near=True)
    nb = be(key.n, 256)
    m = b"rsa s plus n"
    sg = rsa_sign(key, m)
    s_int = int.from_bytes(sg, "big")
    assert s_int + key.n < (1 << 2048)
    rs_vec(vectors, "rs.valid-near-2^2047", True, nb, b"\x01\x00\x01", m, sg)
    rs_vec(vectors, "rs.s-plus-n", False, nb, b"\x01\x00\x01", m, be(s_int + key.n, 256), "s + n has the residue s and the same length: a verifier without s < n accepts it")
    rs_vec(vectors, "rs.s-equals-n", False, nb, b"\x01\x00\x01", m, nb)
    # length: a signature with a leading zero byte, presented without it / with another
    key = rsa_key(2048)
    nb = be(key.n, 256)
    for i in range(20000):
        m = b"rsa leading zero %d" % i
        sg = rsa_sign(key, m)
        if sg[0] == 0:
            rs_vec(vectors, "rs.valid-leading-zero", True, nb, b"\x01\x00\x01", m, sg, "control: a signature whose first byte is 0x00, full length")
            rs_vec(vectors, "rs.len-minus-one", False, nb, b"\x01\x00\x01", m, sg[1:], "the same integer, one byte short")
            rs_vec(vectors, "rs.len-plus-one", False, nb, b"\x01\x00\x01", m, b"\x00" + sg, "the same integer, one byte long")
            break
    else:
        raise SystemExit("no leading-zero signature found")
    # key-shape refusals
    rs_vec(vectors, "rs.e-3", False, nb, b"\x03", m, sg, "exponent 3")
    rs_vec(vectors, "rs.e-65537-four-bytes", False, nb, b"\x00\x01\x00\x01", m, sg, "65537 spelled in four bytes")
    rs_vec(vectors, "rs.even-n", False, nb[:-1] + bytes([nb[-1] & 0xFE]), b"\x01\x00\x01", m, sg)
    rs_vec(vectors, "rs.n-leading-zero", False, b"\x00" + nb, b"\x01\x00\x01", m, sg, "a leading zero byte on the modulus")
    rs_vec(vectors, "rs.n-too-short-2040", False, nb[1:], b"\x01\x00\x01", m, sg[1:], "255 bytes (under 2048 bits)")
    json.dump({"generator": "tools/db/partner-sig/gen-handbuilt-vectors.py", "vectors": vectors, "points": points}, sys.stdout, indent=1, sort_keys=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
