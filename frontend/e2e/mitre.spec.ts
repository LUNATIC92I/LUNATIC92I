import { expect, test } from "@playwright/test";
import { loginThroughUi, registerOrganization } from "./helpers";

test("MITRE ATT&CK screen reports real (zero) coverage before any catalog import", async ({ page }) => {
  const { slug, email } = await registerOrganization("mitre");
  await loginThroughUi(page, slug, email);

  await page.click("text=MITRE ATT&CK");
  await expect(page.getByRole("heading", { name: "MITRE ATT&CK Coverage" })).toBeVisible();
  await expect(page.getByText("0.0%")).toBeVisible();
  await expect(page.getByText("Coverage rate")).toBeVisible();
});
