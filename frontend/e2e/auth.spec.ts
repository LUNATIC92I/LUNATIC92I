import { expect, test } from "@playwright/test";
import { loginThroughUi, registerOrganization } from "./helpers";

test("an unauthenticated visitor is redirected to login", async ({ page }) => {
  await page.goto("/alerts");
  await page.waitForURL("**/login");
});

test("a registered admin can log in and reaches SOC Overview", async ({ page }) => {
  const { slug, email } = await registerOrganization("auth");
  await loginThroughUi(page, slug, email);
  await expect(page.getByRole("heading", { name: "SOC Overview" })).toBeVisible();
  await expect(page.getByText("E2E Admin")).toBeVisible();
});

test("an invalid password is rejected with a real error from the API", async ({ page }) => {
  const { slug, email } = await registerOrganization("auth-bad");
  await page.goto("/login");
  await page.fill('input[autocomplete="organization"]', slug);
  await page.fill('input[autocomplete="username"]', email);
  await page.fill('input[autocomplete="current-password"]', "wrong-password-entirely");
  await page.click('button[type="submit"]');
  await expect(page.getByText(/invalid credentials/i)).toBeVisible();
  await expect(page).toHaveURL(/\/login/);
});

test("signing out returns to the login screen and blocks further navigation", async ({ page }) => {
  const { slug, email } = await registerOrganization("auth-logout");
  await loginThroughUi(page, slug, email);
  await page.click("text=Sign out");
  await page.waitForURL("**/login");
  await page.goto("/alerts");
  await page.waitForURL("**/login");
});
