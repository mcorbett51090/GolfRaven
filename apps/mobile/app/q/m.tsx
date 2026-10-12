/**
 * Universal-link / App Link landing for rotating shop QR (`/q/m#<token>`).
 * Parks the full URL (fragment included) for MarkerCard paste-scan, then leaves
 * this route. Flags stay false — parking does not prompt for location.
 */
import { useURL } from "expo-linking";
import { Redirect, Stack } from "expo-router";
import { useEffect } from "react";
import { parkCourseQrLink } from "../../src/marker/pending-link";

export default function CourseQrRotatingLanding() {
  const url = useURL();
  useEffect(() => {
    if (url) parkCourseQrLink(url);
  }, [url]);
  return (
    <>
      <Stack.Screen options={{ title: "GolfRaven", headerShown: false }} />
      <Redirect href="/" />
    </>
  );
}
