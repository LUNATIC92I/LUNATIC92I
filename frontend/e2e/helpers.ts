import type { Page } from "@playwright/test";

const API_BASE_URL = process.env.E2E_API_BASE_URL ?? "http://localhost:8000";
const PASSWORD = "Correct-Horse-Battery-Staple-1";

/**
 * Registers a fresh organization directly against the real backend (no UI
 * for this — spec §23 never lists an on-boarding screen, registration is an
 * out-of-band operation) so each test file gets an isolated tenant rather
 * than fighting others over shared seed data.
 */
export async function registerOrganization(slugPrefix: string): Promise<{ slug: string; email: string }> {
  const slug = `${slugPrefix}-${Date.now()}-${Math.floor(Math.random() * 10_000)}`;
  const email = `admin@${slug}.example.com`;
  const response = await fetch(`${API_BASE_URL}/auth/register-organization`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      organization_name: `E2E ${slug}`,
      organization_slug: slug,
      admin_email: email,
      admin_password: PASSWORD,
      admin_full_name: "E2E Admin",
    }),
  });
  if (!response.ok) {
    throw new Error(`register-organization failed: ${response.status} ${await response.text()}`);
  }
  return { slug, email };
}

export async function loginThroughUi(page: Page, slug: string, email: string): Promise<void> {
  await page.goto("/login");
  await page.fill('input[autocomplete="organization"]', slug);
  await page.fill('input[autocomplete="username"]', email);
  await page.fill('input[autocomplete="current-password"]', PASSWORD);
  await page.click('button[type="submit"]');
  await page.waitForURL("**/");
}

export { API_BASE_URL, PASSWORD };
