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
      },
    },
  },
  plugins: [],
};
