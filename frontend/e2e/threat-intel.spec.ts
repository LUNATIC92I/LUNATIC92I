import { expect, test } from "@playwright/test";
import { loginThroughUi, registerOrganization } from "./helpers";

test("adding and deleting an indicator through the real IOC API", async ({ page }) => {
  const { slug, email } = await registerOrganization("threat-intel");
  await loginThroughUi(page, slug, email);

  await page.click("text=Threat Intelligence");
  await page.click('button:has-text("Add indicator")');
  await page.getByLabel("Value").fill("203.0.113.77");
  await page.getByLabel("Classification").selectOption("malicious");
  await page.getByLabel("Source").fill("e2e-test");
  await page.getByRole("button", { name: "Add", exact: true }).click();

  await expect(page.getByText("203.0.113.77")).toBeVisible();
  await expect(page.getByRole("cell", { name: "malicious" })).toBeVisible();

  await page.click('button:has-text("Delete")');
  await expect(page.getByText("203.0.113.77")).toHaveCount(0);
});
