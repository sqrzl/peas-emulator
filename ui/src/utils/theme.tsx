import {
  createSignal,
  createEffect,
  useContext,
  createContext,
} from "solid-js";
import type { JSXElement } from "solid-js";

interface ThemeContextType {
  theme: () => "light" | "dark";
  toggleTheme: () => void;
}

export const ThemeContext = createContext<ThemeContextType>();

export function ThemeProvider(props: { children: JSXElement }) {
  const getInitialTheme = (): "light" | "dark" => {
    if (typeof window === "undefined") return "light";
    const stored = localStorage.getItem("theme");
    if (stored === "light" || stored === "dark") return stored;
    return window.matchMedia("(prefers-color-scheme: dark)").matches
      ? "dark"
      : "light";
  };

  const [theme, setTheme] = createSignal<"light" | "dark">(getInitialTheme());

  const toggleTheme = () => {
    setTheme((current) => (current === "light" ? "dark" : "light"));
  };

  createEffect(() => {
    localStorage.setItem("theme", theme());
    const html = document.documentElement;
    if (theme() === "dark") {
      html.classList.add("dark");
    } else {
      html.classList.remove("dark");
    }
  });

  return (
    <ThemeContext.Provider value={{ theme, toggleTheme }}>
      {props.children}
    </ThemeContext.Provider>
  );
}

export function useTheme() {
  const context = useContext(ThemeContext);
  if (!context) {
    throw new Error("useTheme must be used within a ThemeProvider");
  }
  return context;
}
