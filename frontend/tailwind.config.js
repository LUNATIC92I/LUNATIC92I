/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        // Lunatic-IT SOC identity — dark-first, high information density.
        // Swapped/extended as the design system matures in Phase 14.
        surface: {
          DEFAULT: "#0b0f14",
          raised: "#121826",
        },
        severity: {
          low: "#4b9fff",
          medium: "#f5c542",
          high: "#f57c42",
          critical: "#ef4444",
        },
        // Status colors (dataviz skill's fixed reference palette, validated
        // against a dark surface) — reserved for state, never reused as a
        // categorical series color. Used by the MITRE coverage matrix
        // (covered/partial/uncovered) and anywhere else "is this okay?" is
        // the question, as distinct from `severity` (how bad is this alert).
        status: {
          good: "#0ca30c",
          warning: "#fab219",
          serious: "#ec835a",
          critical: "#d03b3b",
        },
      },
    },
  },
  plugins: [],
};
