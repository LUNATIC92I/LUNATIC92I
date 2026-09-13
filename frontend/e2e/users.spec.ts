import { expect, test } from "@playwright/test";
import { loginThroughUi, registerOrganization } from "./helpers";

test("Users lists the real registered admin from the tenant's own data", async ({ page }) => {
  const { slug, email } = await registerOrganization("users");
  await loginThroughUi(page, slug, email);

  await page.click("text=Users");
  await expect(page.getByRole("heading", { name: "Users" })).toBeVisible();
  const row = page.locator("tr", { hasText: email });
  await expect(row).toBeVisible();
  await expect(row.getByText("ORG_ADMIN")).toBeVisible();
});
