import type { ReactNode } from "react";
import { Pressable, ScrollView, StyleSheet, Text, View, type StyleProp, type ViewStyle } from "react-native";
import { space, useTheme } from "./theme";

export function Screen({ children, scroll = true }: { children?: ReactNode; scroll?: boolean }) {
  const t = useTheme();
  const body = <View style={styles.screenBody}>{children}</View>;
  return scroll ? (
    <ScrollView style={{ backgroundColor: t.bg }} contentContainerStyle={styles.scrollContent}>
      {body}
    </ScrollView>
  ) : (
    <View style={[styles.flex, { backgroundColor: t.bg }]}>{body}</View>
  );
}

export function H1({ children }: { children: ReactNode }) {
  const t = useTheme();
  return <Text accessibilityRole="header" style={[styles.h1, { color: t.text }]}>{children}</Text>;
}

export function H2({ children }: { children: ReactNode }) {
  const t = useTheme();
  return <Text accessibilityRole="header" style={[styles.h2, { color: t.text }]}>{children}</Text>;
}

export function Body({ children, muted = false }: { children: ReactNode; muted?: boolean }) {
  const t = useTheme();
  return <Text style={[styles.body, { color: muted ? t.subtext : t.text }]}>{children}</Text>;
}

export function Card({ children, onPress, style }: { children: ReactNode; onPress?: () => void; style?: StyleProp<ViewStyle> }) {
  const t = useTheme();
  const base = [styles.card, { backgroundColor: t.card, borderColor: t.border }, style];
  return onPress ? (
    <Pressable accessibilityRole="button" onPress={onPress} style={({ pressed }) => [...base, pressed && styles.pressed]}>
      {children}
    </Pressable>
  ) : (
    <View style={base}>{children}</View>
  );
}

export function Button({
  title,
  onPress,
  variant = "primary",
  disabled = false,
  busy = false,
  accessibilityHint,
}: {
  title: string;
  onPress: () => void;
  variant?: "primary" | "secondary" | "danger";
  disabled?: boolean;
  /** An action is running: the button is disabled and says so to a screen reader. */
  busy?: boolean;
  accessibilityHint?: string;
}) {
  const t = useTheme();
  const bg = variant === "primary" ? t.accent : "transparent";
  const fg = variant === "primary" ? t.onAccent : variant === "danger" ? t.danger : t.accent;
  return (
    <Pressable
      accessibilityRole="button"
      accessibilityLabel={title}
      {...(accessibilityHint !== undefined ? { accessibilityHint } : {})}
      accessibilityState={{ disabled: disabled || busy, busy }}
      disabled={disabled || busy}
      onPress={onPress}
      style={({ pressed }) => [styles.button, { backgroundColor: bg, borderColor: variant === "primary" ? t.accent : t.border }, pressed && styles.pressed, (disabled || busy) && styles.disabled]}
    >
      <Text style={[styles.buttonText, { color: fg }]}>{title}</Text>
    </Pressable>
  );
}

export function Chip({ label, selected = false, onPress, tone = "neutral" }: { label: string; selected?: boolean; onPress?: () => void; tone?: "neutral" | "warn" | "danger" | "ok" }) {
  const t = useTheme();
  const bg = selected ? t.accent : tone === "warn" ? t.warnBg : t.chipBg;
  const fg = selected ? t.onAccent : tone === "warn" ? t.warn : tone === "danger" ? t.danger : t.text;
  const inner = (
    <View style={[styles.chip, { backgroundColor: bg }]}>
      <Text style={[styles.chipText, { color: fg }]}>{label}</Text>
    </View>
  );
  return onPress ? (
    <Pressable accessibilityRole="button" accessibilityState={{ selected }} onPress={onPress}>
      {inner}
    </Pressable>
  ) : (
    inner
  );
}

export function Banner({ text, actionLabel, onAction, tone = "warn" }: { text: string; actionLabel?: string; onAction?: () => void; tone?: "warn" | "info" }) {
  const t = useTheme();
  return (
    <View accessibilityRole="alert" style={[styles.banner, { backgroundColor: tone === "warn" ? t.warnBg : t.chipBg }]}>
      <Text style={[styles.bannerText, { color: tone === "warn" ? t.warn : t.text }]}>{text}</Text>
      {actionLabel && onAction ? (
        <Pressable accessibilityRole="button" onPress={onAction}>
          <Text style={[styles.bannerAction, { color: t.accent }]}>{actionLabel}</Text>
        </Pressable>
      ) : null}
    </View>
  );
}

export function EmptyState({ title, body, children }: { title: string; body?: string; children?: ReactNode }) {
  return (
    <View style={styles.empty}>
      <H2>{title}</H2>
      {body ? <Body muted>{body}</Body> : null}
      {children}
    </View>
  );
}

export function Row({ children, wrap = false }: { children: ReactNode; wrap?: boolean }) {
  return <View style={[styles.row, wrap && styles.wrap]}>{children}</View>;
}

const styles = StyleSheet.create({
  flex: { flex: 1 },
  scrollContent: { flexGrow: 1 },
  screenBody: { padding: space.lg, gap: space.md },
  h1: { fontSize: 24, fontWeight: "700" },
  h2: { fontSize: 18, fontWeight: "600" },
  body: { fontSize: 15, lineHeight: 21 },
  card: { borderWidth: StyleSheet.hairlineWidth, borderRadius: 10, padding: space.md, gap: space.xs },
  pressed: { opacity: 0.7 },
  disabled: { opacity: 0.45 },
  button: { borderWidth: 1, borderRadius: 10, paddingVertical: space.md, paddingHorizontal: space.lg, alignItems: "center" },
  buttonText: { fontSize: 16, fontWeight: "600" },
  chip: { borderRadius: 14, paddingVertical: 4, paddingHorizontal: 10 },
  chipText: { fontSize: 13, fontWeight: "500" },
  banner: { borderRadius: 8, padding: space.md, gap: space.xs },
  bannerText: { fontSize: 14 },
  bannerAction: { fontSize: 14, fontWeight: "600" },
  empty: { paddingVertical: space.xl, gap: space.sm },
  row: { flexDirection: "row", alignItems: "center", gap: space.sm },
  wrap: { flexWrap: "wrap" },
});
