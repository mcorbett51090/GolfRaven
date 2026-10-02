import { useColorScheme } from "react-native";

export interface Theme {
  bg: string;
  card: string;
  text: string;
  subtext: string;
  border: string;
  accent: string;
  onAccent: string;
  danger: string;
  warn: string;
  warnBg: string;
  chipBg: string;
}

const light: Theme = {
  bg: "#f4f7f5",
  card: "#ffffff",
  text: "#14231a",
  subtext: "#5b6b61",
  border: "#d8e2dc",
  accent: "#1f6f43",
  onAccent: "#ffffff",
  danger: "#b3261e",
  warn: "#7a4b00",
  warnBg: "#fff3d6",
  chipBg: "#e6efe9",
};

const dark: Theme = {
  bg: "#0f1612",
  card: "#18221c",
  text: "#e8f1ec",
  subtext: "#9db0a5",
  border: "#2a3a31",
  accent: "#52b788",
  onAccent: "#08140d",
  danger: "#f2b8b5",
  warn: "#f5d58a",
  warnBg: "#3a2f10",
  chipBg: "#223229",
};

export function useTheme(): Theme {
  return useColorScheme() === "dark" ? dark : light;
}

export const space = { xs: 4, sm: 8, md: 12, lg: 16, xl: 24 } as const;
