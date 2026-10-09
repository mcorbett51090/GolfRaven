/**
 * A minimal CBOR (RFC 8949) encoder and decoder for the WebAuthn bytes the tests build and read: unsigned and negative integers, byte strings, text
 * strings, arrays and maps. Enough for an attestation object (`{ fmt, attStmt, authData }`) and a COSE EC2 key; nothing else (no floats, tags, indefinite lengths).
 */

export type Cbor = number | Uint8Array | string | Cbor[] | Map<Cbor, Cbor>;

function head(major: number, n: number): number[] {
  if (n < 24) return [(major << 5) | n];
  if (n < 0x100) return [(major << 5) | 24, n];
  if (n < 0x10000) return [(major << 5) | 25, n >> 8, n & 0xff];
  throw new Error("cbor: length too large for this encoder");
}

export function cborEncode(v: Cbor): Uint8Array {
  if (typeof v === "number") return Uint8Array.from(v >= 0 ? head(0, v) : head(1, -1 - v));
  if (v instanceof Uint8Array) return Uint8Array.from([...head(2, v.length), ...v]);
  if (typeof v === "string") {
    const b = new TextEncoder().encode(v);
    return Uint8Array.from([...head(3, b.length), ...b]);
  }
  if (Array.isArray(v)) return Uint8Array.from([...head(4, v.length), ...v.flatMap((x) => [...cborEncode(x)])]);
  return Uint8Array.from([...head(5, v.size), ...[...v].flatMap(([k, x]) => [...cborEncode(k), ...cborEncode(x)])]);
}

export function cborDecode(bytes: Uint8Array): Cbor {
  let at = 0;
  const arg = (info: number): number => {
    if (info < 24) return info;
    if (info === 24) return bytes[at++]!;
    if (info === 25) {
      const n = (bytes[at]! << 8) | bytes[at + 1]!;
      at += 2;
      return n;
    }
    throw new Error("cbor: unsupported length");
  };
  const read = (): Cbor => {
    const b = bytes[at++]!;
    const major = b >> 5;
    const n = arg(b & 31);
    switch (major) {
      case 0:
        return n;
      case 1:
        return -1 - n;
      case 2: {
        const out = bytes.slice(at, at + n);
        at += n;
        return out;
      }
      case 3: {
        const out = new TextDecoder().decode(bytes.slice(at, at + n));
        at += n;
        return out;
      }
      case 4:
        return Array.from({ length: n }, read);
      case 5: {
        const m = new Map<Cbor, Cbor>();
        for (let i = 0; i < n; i += 1) {
          const k = read();
          m.set(k, read());
        }
        return m;
      }
      default:
        throw new Error("cbor: unsupported major type");
    }
  };
  return read();
}
