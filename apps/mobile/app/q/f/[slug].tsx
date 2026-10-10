/**
 * Universal-link / App Link landing for printed facility QR (`/q/f/<slug>#kid.sig`).
 * Parks the full URL for MarkerCard; when the catalog has that slug, opens the
 * facility page so paste-scan (behind the same dual flag) is one tap away.
 */
import { useURL } from "expo-linking";
import { Redirect, Stack, useLocalSearchParams } from "expo-router";
import { useEffect, useMemo } from "react";
import { parseCourseQrLink } from "../../../src/marker/link";
import { parkCourseQrLink } from "../../../src/marker/pending-link";
import { useApp } from "../../../src/runtime/AppProvider";

export default function CourseQrPrintedLanding() {
  const url = useURL();
  const { slug } = useLocalSearchParams<{ slug: string }>();
  const { index } = useApp();

  useEffect(() => {
    if (url) parkCourseQrLink(url);
  }, [url]);

  const facilityId = useMemo(() => {
    if (!index || typeof slug !== "string" || slug.length === 0) return null;
    for (const f of index.facilities.values()) {
      if (f.slug === slug) return f.id;
    }
    // Fallback: parse from parked/open URL when the path param was decoded oddly.
    const parsed = url ? parseCourseQrLink(url) : null;
    if (parsed?.kind === "static_pin") {
      for (const f of index.facilities.values()) {
        if (f.slug === parsed.facilitySlug) return f.id;
      }
    }
    return null;
  }, [index, slug, url]);

  return (
    <>
      <Stack.Screen options={{ title: "GolfRaven", headerShown: false }} />
      <Redirect href={facilityId ? { pathname: "/facility/[id]", params: { id: facilityId } } : "/"} />
    </>
  );
}
