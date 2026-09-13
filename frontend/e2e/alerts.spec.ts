import { expect, test } from "@playwright/test";
import { loginThroughUi, registerOrganization } from "./helpers";

test("the Alerts queue loads real (empty) data from the API and supports filtering", async ({ page }) => {
  const { slug, email } = await registerOrganization("alerts");
  await loginThroughUi(page, slug, email);

  await page.click("text=Alerts");
  await expect(page.getByRole("heading", { name: "Alerts" })).toBeVisible();
  await expect(page.getByText("No alerts match these filters.")).toBeVisible();

  const [statusSelect, severitySelect] = await page.getByRole("combobox").all();
  await statusSelect.selectOption("NEW");
  await severitySelect.selectOption("critical");
  // Filtering an empty queue still round-trips to the real API without error.
  await expect(page.getByText("No alerts match these filters.")).toBeVisible();
});
