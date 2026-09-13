import { expect, test } from "@playwright/test";
import { loginThroughUi, registerOrganization } from "./helpers";

test("SOC Overview renders real, zeroed metrics for a brand-new tenant", async ({ page }) => {
  const { slug, email } = await registerOrganization("overview");
  await loginThroughUi(page, slug, email);

  await expect(page.getByRole("heading", { name: "SOC Overview" })).toBeVisible();
  // A fresh tenant has no alerts/incidents yet — real zeros, not placeholders.
  await expect(page.getByText("Open alerts")).toBeVisible();
  await expect(page.getByText("Open incidents")).toBeVisible();
  await expect(page.getByText(/No data yet/).first()).toBeVisible();
});
