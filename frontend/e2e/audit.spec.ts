import { expect, test } from "@playwright/test";
import { loginThroughUi, registerOrganization } from "./helpers";

test("a real write elsewhere in the app shows up in the Audit screen", async ({ page }) => {
  const { slug, email } = await registerOrganization("audit");
  await loginThroughUi(page, slug, email);

  await page.click("text=Assets");
  await page.click('button:has-text("New asset")');
  await page.getByLabel("Hostname").fill("audited-host");
  await page.click('button:has-text("Create")');
  await expect(page.getByText("audited-host")).toBeVisible();

  await page.click("text=Audit");
  await expect(page.getByText("CREATE_ASSET")).toBeVisible();

  await page.getByPlaceholder(/Filter by action/).fill("CREATE_ASSET");
  await expect(page.getByText("CREATE_ASSET").first()).toBeVisible();
  await expect(page.getByText("LOGIN")).toHaveCount(0);
});
