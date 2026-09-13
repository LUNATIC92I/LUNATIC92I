import { expect, test } from "@playwright/test";
import { loginThroughUi, registerOrganization } from "./helpers";

test("Detection Rules lists the real shipped rule pack installed at registration", async ({ page }) => {
  const { slug, email } = await registerOrganization("rules");
  await loginThroughUi(page, slug, email);

  await page.click("text=Detection Rules");
  await expect(page.getByText("AUTH-001")).toBeVisible();
  await expect(page.getByText("WIN-003")).toBeVisible();

  await page.click("text=Password spraying from a single source");
  await expect(page.getByText("AUTH-002", { exact: true })).toBeVisible();
  await expect(page.locator("pre")).toContainText("rule_id");
});

test("disabling a rule persists through the real rule status API", async ({ page }) => {
  const { slug, email } = await registerOrganization("rules-toggle");
  await loginThroughUi(page, slug, email);

  await page.click("text=Detection Rules");
  const row = page.locator("tr", { hasText: "AUTH-001" });
  await row.getByRole("combobox").selectOption("disabled");
  await page.reload();
  await expect(page.locator("tr", { hasText: "AUTH-001" }).getByRole("combobox")).toHaveValue("disabled");
});
