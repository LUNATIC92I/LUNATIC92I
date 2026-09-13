import { expect, test } from "@playwright/test";
import { loginThroughUi, registerOrganization } from "./helpers";

test("creating an asset and changing its criticality through the real assets API", async ({ page }) => {
  const { slug, email } = await registerOrganization("assets");
  await loginThroughUi(page, slug, email);

  await page.click("text=Assets");
  await page.click('button:has-text("New asset")');
  await page.getByLabel("Hostname").fill("e2e-host-01");
  await page.getByLabel("Criticality").selectOption("HIGH");
  await page.click('button:has-text("Create")');

  await expect(page.getByText("e2e-host-01")).toBeVisible();

  const row = page.locator("tr", { hasText: "e2e-host-01" });
  await row.getByRole("combobox").selectOption("CRITICAL");
  await page.reload();
  await expect(page.locator("tr", { hasText: "e2e-host-01" }).getByRole("combobox")).toHaveValue("CRITICAL");
});
