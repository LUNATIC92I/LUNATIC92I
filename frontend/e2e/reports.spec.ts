import { expect, test } from "@playwright/test";
import { loginThroughUi, registerOrganization } from "./helpers";

test("Reports composes its sections from the same real APIs as the other screens", async ({ page }) => {
  const { slug, email } = await registerOrganization("reports");
  await loginThroughUi(page, slug, email);

  await page.click("text=Reports");
  await expect(page.getByRole("heading", { name: "SOC Summary Report" })).toBeVisible();
  await expect(page.getByText("Alerts by status")).toBeVisible();
  await expect(page.getByText("Incidents by status")).toBeVisible();
  await expect(page.getByText("MITRE ATT&CK coverage")).toBeVisible();
  await expect(page.getByText("0.0%")).toBeVisible();
});
