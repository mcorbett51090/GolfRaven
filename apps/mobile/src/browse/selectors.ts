/**
 * Pure read-model helpers for the guest-browse screens (Trails, directory,
 * facility, course; P4 AT 13). No React, no I/O.
 */
import type { Course, Facility, RosterMember, RosterVersion, Trail } from "@golfraven/catalog";
import type { CatalogSnapshot } from "../catalog/snapshot";
import type { Locale } from "../i18n/locale";

export interface CourseEntry {
  course: Course;
  facility: Facility;
}

export interface CatalogIndex {
  trails: Map<string, Trail>;
  facilities: Map<string, Facility>;
  courses: Map<string, CourseEntry>;
}

export function buildIndex(snapshot: CatalogSnapshot): CatalogIndex {
  const facilities = new Map<string, Facility>();
  const courses = new Map<string, CourseEntry>();
  for (const f of snapshot.facilities) {
    facilities.set(f.id, f);
    for (const c of f.courses) courses.set(c.id, { course: c, facility: f });
  }
  return { trails: new Map(snapshot.trails.map((t) => [t.id, t] as const)), facilities, courses };
}

/** `west-nashville-golf` -> `West Nashville Golf`: a last-resort label for a
 * stub record that has no `name` yet (an unverified facility). */
export function titleFromSlug(slug: string): string {
  return slug
    .split("-")
    .filter(Boolean)
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");
}

export function trailName(trail: Trail, locale: Locale): string {
  return locale === "fr-CA" && trail.nameFr ? trail.nameFr : trail.name;
}
export function trailBlurb(trail: Trail, locale: Locale): string | undefined {
  return locale === "fr-CA" && trail.blurbFr ? trail.blurbFr : trail.blurb;
}
export function facilityName(f: Facility, locale: Locale): string {
  if (locale === "fr-CA" && f.nameFr) return f.nameFr;
  return f.name ?? titleFromSlug(f.slug);
}
export function facilityBlurb(f: Facility, locale: Locale): string | undefined {
  return locale === "fr-CA" && f.blurbFr ? f.blurbFr : f.blurb;
}
/** A single-course facility's course is named like the facility unless it
 * carries its own `name`. */
export function courseName(entry: CourseEntry, locale: Locale): string {
  if (entry.course.name) return entry.course.name;
  return entry.facility.courses.length === 1 ? facilityName(entry.facility, locale) : titleFromSlug(entry.course.slug);
}

/** The roster version the app shows: the highest `version`. (Older versions
 * stay in the catalog for scoring plays against the version in force when
 * they were played, §4.1; the checklist always shows the latest.) */
export function currentRoster(trail: Trail): RosterVersion {
  return trail.rosterVersions.reduce((a, b) => (b.version > a.version ? b : a));
}

export type StopKind = "course" | "facility" | "hole" | "any_of";
export interface RosterStop {
  key: string;
  kind: StopKind;
  label: string;
  /** Present when the stop resolves to one course/facility page. */
  courseId?: string;
  facilityId?: string;
  /** For `any_of`: how many alternatives. */
  alternatives?: number;
  stopOrder?: number;
}

/** Resolves a roster's members to labelled stops, in `stopOrder` (members
 * without one keep catalog order, after those that have one). A member whose
 * id is not in the loaded catalog still appears, with its id as the label,
 * so the stop count never silently shrinks. */
export function rosterStops(
  trail: Trail,
  index: CatalogIndex,
  locale: Locale,
  labels: { anyOf: (count: number) => string; hole: (course: string) => string },
): RosterStop[] {
  const roster = currentRoster(trail);
  const stops = roster.members.map((m, i): RosterStop => {
    const base = (key: string): Pick<RosterStop, "key" | "stopOrder"> => (m.stopOrder === undefined ? { key } : { key, stopOrder: m.stopOrder });
    return memberToStop(m, i, index, locale, labels, base);
  });
  return stops
    .map((s, i) => ({ s, i }))
    .sort((a, b) => {
      const ao = a.s.stopOrder ?? Number.POSITIVE_INFINITY;
      const bo = b.s.stopOrder ?? Number.POSITIVE_INFINITY;
      return ao === bo ? a.i - b.i : ao - bo;
    })
    .map((x) => x.s);
}

function memberToStop(
  m: RosterMember,
  i: number,
  index: CatalogIndex,
  locale: Locale,
  labels: { anyOf: (count: number) => string; hole: (course: string) => string },
  base: (key: string) => Pick<RosterStop, "key" | "stopOrder">,
): RosterStop {
  if ("anyOf" in m) {
    return { ...base(`anyof:${i}`), kind: "any_of", label: labels.anyOf(m.anyOf.length), alternatives: m.anyOf.length };
  }
  if (m.unit === "facility") {
    const f = index.facilities.get(m.facilityId);
    return { ...base(m.facilityId), kind: "facility", label: f ? facilityName(f, locale) : m.facilityId, facilityId: m.facilityId };
  }
  if (m.unit === "hole") {
    const c = index.courses.get(m.courseId);
    const name = c ? courseName(c, locale) : m.courseId;
    return { ...base(`${m.courseId}:${m.holeId}`), kind: "hole", label: labels.hole(name), courseId: m.courseId };
  }
  const c = index.courses.get(m.courseId);
  return {
    ...base(m.courseId),
    kind: "course",
    label: c ? courseName(c, locale) : m.courseId,
    courseId: m.courseId,
    ...(c ? { facilityId: c.facility.id } : {}),
  };
}

export interface RegionSummary {
  region: string;
  facilities: number;
  trails: number;
}

/** Every region that has a facility or a trail, sorted by code. */
export function regionSummaries(snapshot: CatalogSnapshot): RegionSummary[] {
  const m = new Map<string, RegionSummary>();
  const get = (region: string): RegionSummary => {
    let r = m.get(region);
    if (!r) {
      r = { region, facilities: 0, trails: 0 };
      m.set(region, r);
    }
    return r;
  };
  for (const f of snapshot.facilities) get(f.region).facilities += 1;
  for (const t of snapshot.trails) for (const region of t.regions) get(region).trails += 1;
  return [...m.values()].sort((a, b) => (a.region < b.region ? -1 : a.region > b.region ? 1 : 0));
}

export function trailsInRegion(snapshot: CatalogSnapshot, region: string | null): Trail[] {
  const list = region === null ? snapshot.trails : snapshot.trails.filter((t) => t.regions.includes(region));
  return [...list].sort((a, b) => a.name.localeCompare(b.name));
}

export function facilitiesInRegion(snapshot: CatalogSnapshot, region: string | null, locale: Locale): Facility[] {
  const list = region === null ? snapshot.facilities : snapshot.facilities.filter((f) => f.region === region);
  return [...list].sort((a, b) => facilityName(a, locale).localeCompare(facilityName(b, locale)));
}

const HTTPS_RE = /^https:\/\/[^\s/?#]+[^\s]*$/i;

/** The only URLs the app opens from catalog data: `https:` (the catalog
 * schema already enforces it, S7; this is the second, client-side check). */
export function isSafeHttpsUrl(url: string): boolean {
  return HTTPS_RE.test(url) && !/[\u0000-\u001f\u007f]/.test(url);
}

export interface BookingLink {
  provider: Facility["booking"][number]["provider"];
  url: string;
}
export function bookingLinks(f: Facility): BookingLink[] {
  return f.booking.filter((b) => isSafeHttpsUrl(b.url)).map((b) => ({ provider: b.provider, url: b.url }));
}
