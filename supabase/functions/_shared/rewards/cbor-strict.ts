// supabase/functions/_shared/rewards/cbor-strict.ts
//
// A minimal, strict CBOR decoder for the one structure App Attest KEY REGISTRATION reads: the
// attestation object `{ "fmt": tstr, "attStmt": { "x5c": [bstr, bstr], "receipt": bstr }, "authData":
// bstr }` and the COSE_Key embedded in its authenticator data (a map with INTEGER keys, two of them
// negative). It is deliberately a separate, wider decoder than app-attest.ts's `decodeCbor` (which
// reads an ASSERTION and only knows text-keyed maps): the assertion path is left exactly as it was.
//
// Accepted: unsigned and negative integers (up to 32 bits), byte strings, text strings (valid UTF-8
// only), definite-length arrays and maps whose keys are integers or text strings.
// Refused (`CborError`): tags, floats, booleans/null/simple values, indefinite lengths, 64-bit
// arguments, duplicate map keys, a map key of any other type, nesting beyond `MAX_DEPTH`, more than
// `MAX_ITEMS` items in total, and any bytes after the one top-level item.
//
// Not required: the SHORTEST integer/length encoding. Nothing security-relevant hangs on it here —
// the attested bytes (authData, the certificates) are signed as opaque byte strings and read from
// those exact bytes, never re-encoded — and requiring it would add a way to refuse a real device's
// object for no gain `[unverified: Apple's encoder is believed canonical]`.

export class CborError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CborError";
  }
}

export type CborValue = number | Uint8Array | string | CborValue[] | Map<number | string, CborValue>;

const MAX_DEPTH = 6;
const MAX_ITEMS = 256;
const MAX_CONTAINER = 64;

interface Cursor {
  bytes: Uint8Array;
  pos: number;
  items: number;
}

function readArg(c: Cursor, info: number): number {
  if (info < 24) return info;
  const need = info === 24 ? 1 : info === 25 ? 2 : info === 26 ? 4 : 0;
  if (need === 0) throw new CborError(`unsupported additional information ${info} (64-bit and indefinite arguments are refused)`);
  if (c.pos + need > c.bytes.length) throw new CborError("truncated argument");
  let v = 0;
  for (const b of c.bytes.subarray(c.pos, c.pos + need)) v = v * 256 + b;
  c.pos += need;
  return v;
}

function readItem(c: Cursor, depth: number): CborValue {
  if (depth > MAX_DEPTH) throw new CborError("nesting too deep");
  if (++c.items > MAX_ITEMS) throw new CborError("too many items");
  if (c.pos >= c.bytes.length) throw new CborError("truncated");
  const head = c.bytes[c.pos++]!;
  const major = head >> 5;
  const info = head & 0x1f;
  switch (major) {
    case 0:
      return readArg(c, info);
    case 1:
      return -1 - readArg(c, info);
    case 2: {
      const n = readArg(c, info);
      if (c.pos + n > c.bytes.length) throw new CborError("truncated byte string");
      const out = c.bytes.slice(c.pos, c.pos + n);
      c.pos += n;
      return out;
    }
    case 3: {
      const n = readArg(c, info);
      if (c.pos + n > c.bytes.length) throw new CborError("truncated text string");
      const slice = c.bytes.slice(c.pos, c.pos + n);
      c.pos += n;
      try {
        return new TextDecoder("utf-8", { fatal: true }).decode(slice);
      } catch {
        throw new CborError("invalid utf-8 text string");
      }
    }
    case 4: {
      const n = readArg(c, info);
      if (n > MAX_CONTAINER) throw new CborError("array too large");
      const out: CborValue[] = [];
      for (let i = 0; i < n; i++) out.push(readItem(c, depth + 1));
      return out;
    }
    case 5: {
      const n = readArg(c, info);
      if (n > MAX_CONTAINER) throw new CborError("map too large");
      const map = new Map<number | string, CborValue>();
      for (let i = 0; i < n; i++) {
        const key = readItem(c, depth + 1);
        if (typeof key !== "string" && typeof key !== "number") throw new CborError("map key must be an integer or a text string");
        if (map.has(key)) throw new CborError("duplicate map key");
        map.set(key, readItem(c, depth + 1));
      }
      return map;
    }
    default:
      throw new CborError(`unsupported CBOR major type ${major} (tags, floats and simple values are refused)`);
  }
}

/** Decodes exactly one item and refuses trailing bytes. */
export function decodeCborStrict(bytes: Uint8Array): CborValue {
  const c: Cursor = { bytes, pos: 0, items: 0 };
  const v = readItem(c, 0);
  if (c.pos !== bytes.length) throw new CborError("trailing bytes after the CBOR item");
  return v;
}

/** Decodes ONE item from the front of `bytes` and reports how many bytes it used (for a COSE_Key that
 * sits inside authenticatorData). */
export function decodeCborPrefix(bytes: Uint8Array): { value: CborValue; length: number } {
  const c: Cursor = { bytes, pos: 0, items: 0 };
  const value = readItem(c, 0);
  return { value, length: c.pos };
}
