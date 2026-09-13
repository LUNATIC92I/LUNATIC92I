import { expect, test } from "@playwright/test";
import { loginThroughUi, registerOrganization } from "./helpers";

test("creating a user and deactivating it through the real Administration API", async ({ page }) => {
  const { slug, email } = await registerOrganization("admin");
  await loginThroughUi(page, slug, email);

  await page.click("text=Administration");
  await expect(page.getByText(`/${slug}`)).toBeVisible();

  await page.getByLabel("Email").fill(`newhire@${slug}.example.com`);
  await page.getByLabel("Full name").fill("New Hire");
  await page.getByLabel("Temporary password").fill("Correct-Horse-Battery-Staple-9");
  await page.getByLabel("Role").selectOption("SOC_ANALYST_L1");
  await page.click('button:has-text("Create user")');

  await expect(page.getByText("New Hire")).toBeVisible();

  const row = page.locator("tr", { hasText: "New Hire" });
  await row.getByRole("button", { name: "Deactivate" }).click();
  await expect(row.getByRole("button", { name: "Reactivate" })).toBeVisible();
});
