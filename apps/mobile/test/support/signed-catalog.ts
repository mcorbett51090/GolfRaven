/**
 * Test fixtures signed by the REAL `tools/catalog` signer: every artifact
 * here is produced by `emitCatalogArtifact` (the same emitter + `signManifest`
 * / `signVersions` + canonical JSON that publishes the real catalog), with a
 * throwaway Ed25519 key generated in-process — no key material is committed.
 */
import { createHash, createPrivateKey, generateKeyPairSync } from "node:crypto";
import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseCatalogBundle } from "@golfraven/catalog-tools/bundle";
import { emitCatalogArtifact } from "@golfraven/catalog-tools/emit-catalog";
import { canonicalStringify, type CatalogManifest } from "@golfraven/catalog-tools/manifest-core";
import { signManifest, signVersions } from "@golfraven/catalog-tools/sign";
import { base64UrlToBytes } from "../../src/catalog/bytes";
import type { FetchBytes, FetchOptions, FetchResult } from "../../src/catalog/manager";
import type { TrustedKey } from "../../src/catalog/keys";

export interface TestKey {
  kid: string;
  privateKeyPem: string;
  publicKeyPem: string;
  trusted: TrustedKey;
}

export function makeKey(kid: string): TestKey {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const jwk = publicKey.export({ format: "jwk" }) as { x: string };
  if (base64UrlToBytes(jwk.x).length !== 32) throw new Error("unexpected Ed25519 public key length");
  return {
    kid,
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
    trusted: { kid, publicKeyB64Url: jwk.x },
  };
}

export const IDS = {
  facTn: "fac_01M39GMFJZYF7W9HXMEC5V7FJ8",
  facQc: "fac_01M39GMFJZYF7W9HXMEC5V7FJ9",
  crsTn: "crs_01M39GMFJZ2P89V3ZZXPPH671T",
  crsQc: "crs_01M39GMFJZ2P89V3ZZXPPH671W",
  trail: "trl_01M39GMFJZQN74WV3R6HA63H0F",
  designer: "dsg_01M39GMFJZ21RFA7G11961JMQC",
} as const;

/** The same minimal-but-schema-valid bundle shape `tools/catalog`'s own emit
 * tests use (synthetic ids, `example.com` URLs), with the trail named so the
 * UI tests can assert on it. */
export function bundleRaw(trailName = "Test Trail"): unknown {
  const src = { url: "https://example.com/source", retrieved: "2026-01-01" };
  return {
    contractVersion: 0,
    facilities: [
      {
        id: IDS.facTn,
        slug: "test-facility-one",
        region: "US-TN",
        tz: "America/Chicago",
        verification: { status: "unverified" },
        seed: { origin: "osm", osmRef: "way/1001" },
        booking: [],
        courses: [{ id: IDS.crsTn, slug: "test-course-one" }],
      },
      {
        id: IDS.facQc,
        slug: "test-facility-two",
        region: "CA-QC",
        tz: "America/Toronto",
        verification: { status: "unverified" },
        seed: { origin: "manual" },
        booking: [],
        courses: [{ id: IDS.crsQc, slug: "test-course-two" }],
      },
    ],
    trails: [
      {
        id: IDS.trail,
        slug: "test-trail",
        name: trailName,
        countries: ["US"],
        regions: ["US-TN"],
        kind: "state-agency",
        status: "active",
        operator: { name: "Test Operator", url: "https://example.com/operator", type: "state-agency" },
        officialUrl: "https://example.com/trail",
        rosterStatus: "verified",
        rosterVersions: [
          {
            version: 1,
            effectiveFrom: "2026-01-01",
            source: src,
            verifiedAt: "2026-01-01",
            completionUnit: "course",
            markerUnit: "facility",
            completionRule: { kind: "all" },
            markerRule: { kind: "all" },
            members: [{ unit: "course", courseId: IDS.crsTn }],
          },
        ],
        lastReviewed: "2026-01-01",
        sources: [src],
      },
    ],
    designers: [{ id: IDS.designer, name: "Test Designer", sources: [src] }],
    idLedger: {
      entries: {
        [IDS.facTn]: { id: IDS.facTn, kind: "fac", slug: "test-facility-one", status: "stub", transitions: [] },
        [IDS.crsTn]: { id: IDS.crsTn, kind: "crs", status: "stub", facilityId: IDS.facTn, transitions: [] },
        [IDS.facQc]: { id: IDS.facQc, kind: "fac", slug: "test-facility-two", status: "stub", transitions: [] },
        [IDS.crsQc]: { id: IDS.crsQc, kind: "crs", status: "stub", facilityId: IDS.facQc, transitions: [] },
        [IDS.trail]: { id: IDS.trail, kind: "trl", slug: "test-trail", transitions: [] },
        [IDS.designer]: { id: IDS.designer, kind: "dsg", transitions: [] },
      },
    },
    osm: { "way/1001": { lat: 36.16, lng: -86.78, name: "Test Facility One (OSM)", holes: 18 } },
  };
}

export interface SignedCatalog {
  /** Files keyed by path relative to `catalog/v1/`. */
  files: Map<string, Uint8Array>;
  manifest: CatalogManifest;
}

export interface EmitSpec {
  version: string;
  generatedAt: string;
  key: TestKey;
  minAppVersion?: string;
  revokedKids?: string[];
  trailName?: string;
}

/** Emits successive catalog versions into ONE output tree so `versions.json`
 * appends exactly as the real publisher's does. */
export class CatalogPublisher {
  private dir: string | null = null;

  async emit(spec: EmitSpec): Promise<SignedCatalog> {
    const dir = (this.dir ??= await mkdtemp(join(tmpdir(), "gr-mobile-catalog-")));
    const parsed = parseCatalogBundle(bundleRaw(spec.trailName));
    if (!parsed.ok) throw new Error(`fixture bundle invalid: ${JSON.stringify(parsed.schemaIssues)}`);
    const result = await emitCatalogArtifact(parsed.bundle, {
      outDir: dir,
      catalogVersion: spec.version,
      minAppVersion: spec.minAppVersion ?? "0.0.0",
      kid: spec.key.kid,
      revokedKids: spec.revokedKids ?? [],
      privateKeyPem: spec.key.privateKeyPem,
      expectedPublicKeyPem: spec.key.publicKeyPem,
      generatedAt: spec.generatedAt,
    });
    const files = new Map<string, Uint8Array>();
    const walk = async (rel: string): Promise<void> => {
      for (const ent of await readdir(join(result.v1Dir, rel), { withFileTypes: true })) {
        const r = rel ? `${rel}/${ent.name}` : ent.name;
        if (ent.isDirectory()) await walk(r);
        else files.set(r, new Uint8Array(await readFile(join(result.v1Dir, r))));
      }
    };
    await walk("");
    return { files, manifest: result.manifest };
  }

  async dispose(): Promise<void> {
    if (this.dir) await rm(this.dir, { recursive: true, force: true });
  }
}

export interface RequestLogEntry {
  path: string;
  etag: string | null | undefined;
  status: number;
}

/** An in-memory CDN: serves a `SignedCatalog`'s files (with ETag/304 on the
 * manifest), lets a test tamper with or drop individual files, and records
 * every request. */
export class FakeCdn {
  readonly log: RequestLogEntry[] = [];
  private files = new Map<string, Uint8Array>();
  private failures = new Set<string>();
  offline = false;

  constructor(readonly base = "https://catalog.test") {}

  serve(catalog: SignedCatalog): void {
    this.files = new Map(catalog.files);
    this.failures.clear();
  }
  tamper(path: string, fn: (bytes: Uint8Array) => Uint8Array): void {
    const cur = this.files.get(path);
    if (!cur) throw new Error(`no such file ${path}`);
    this.files.set(path, fn(cur));
  }
  replace(path: string, bytes: Uint8Array): void {
    this.files.set(path, bytes);
  }
  fail(path: string): void {
    this.failures.add(path);
  }
  requested(path: string): boolean {
    return this.log.some((l) => l.path === path);
  }

  readonly fetchBytes: FetchBytes = (url: string, options: FetchOptions): Promise<FetchResult> => {
    const prefix = `${this.base}/catalog/v1/`;
    if (!url.startsWith(prefix)) return Promise.reject(new Error(`unexpected url ${url}`));
    const path = url.slice(prefix.length);
    const entry = (status: number): void => void this.log.push({ path, etag: options.etag, status });
    if (this.offline) {
      entry(0);
      return Promise.reject(new Error("network offline"));
    }
    const bytes = this.files.get(path);
    if (this.failures.has(path) || !bytes) {
      entry(404);
      return Promise.resolve({ status: 404, bytes: new Uint8Array(0), etag: null });
    }
    const etag = `"${createHash("sha256").update(bytes).digest("hex").slice(0, 16)}"`;
    if (path === "manifest.json" && options.etag === etag) {
      entry(304);
      return Promise.resolve({ status: 304, bytes: new Uint8Array(0), etag });
    }
    if (bytes.length > options.maxBytes) {
      entry(200);
      return Promise.reject(new Error(`${path}: body exceeds ${options.maxBytes}`));
    }
    entry(200);
    return Promise.resolve({ status: 200, bytes, etag: path === "manifest.json" ? etag : null });
  };
}

export function flipByte(bytes: Uint8Array, index = 0): Uint8Array {
  const out = Uint8Array.from(bytes);
  out[index] = out[index]! ^ 0x01;
  return out;
}

export function replaceText(bytes: Uint8Array, from: string, to: string): Uint8Array {
  const text = Buffer.from(bytes).toString("utf8");
  if (!text.includes(from)) throw new Error(`"${from}" not found in fixture`);
  return new Uint8Array(Buffer.from(text.replace(from, to), "utf8"));
}

/** A `versions.sig.json` over `versions.json`'s exact bytes, signed by `key`
 * (which need not be the key that signed the manifest — the verifier checks
 * each signature against its own `kid`). */
export function versionsSigBy(versionsBytes: Uint8Array, key: TestKey): Uint8Array {
  const sig = signVersions(Buffer.from(versionsBytes), key.kid, createPrivateKey(key.privateKeyPem));
  return new Uint8Array(Buffer.from(canonicalStringify(sig), "utf8"));
}

/** A `manifest.sig.json` that is genuinely signed by `key`, but whose
 * statement fields (`kid`, `catalogVersion`, `contractVersion`) are the ones
 * given — i.e. exactly one thing is wrong with it: it disagrees with the
 * manifest.json it sits next to. */
export function manifestSidecar(
  manifestBytes: Uint8Array,
  fields: { kid: string; catalogVersion: string; contractVersion: number },
  key: TestKey,
): Uint8Array {
  const sig = signManifest(fields, Buffer.from(manifestBytes), createPrivateKey(key.privateKeyPem));
  return new Uint8Array(Buffer.from(canonicalStringify(sig), "utf8"));
}

/** The same catalog with `versions.sig.json` re-signed by another key. */
export function withVersionsSignedBy(c: SignedCatalog, key: TestKey): SignedCatalog {
  const files = new Map(c.files);
  files.set("versions.sig.json", versionsSigBy(files.get("versions.json")!, key));
  return { files, manifest: c.manifest };
}
