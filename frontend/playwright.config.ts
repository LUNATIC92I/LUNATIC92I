import { defineConfig, devices } from "@playwright/test";

/**
 * E2E tests here hit the real backend (spec §14's requirement: no mocked
 * data) — they expect `VITE_API_BASE_URL`'s server and a Vite dev server at
 * `baseURL` already running against a disposable test database, started by
 * `scripts/dev-services.sh` and the backend/frontend dev servers per
 * docs/DEVELOPMENT.md. Playwright does not start either for you.
 */
export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false,
  retries: 0,
  reporter: [["list"]],
  use: {
    baseURL: process.env.E2E_BASE_URL ?? "http://localhost:5173",
    trace: "retain-on-failure",
  },
  projects: [
    {
      name: "chromium",
      use: {
        ...devices["Desktop Chrome"],
        launchOptions: {
          executablePath: process.env.PLAYWRIGHT_CHROMIUM_PATH || "/opt/pw-browsers/chromium",
        },
      },
    },
  ],
});
