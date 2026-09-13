import { expect, test } from "@playwright/test";
import { loginThroughUi, registerOrganization } from "./helpers";

test("Playbooks honestly reports that the SOAR engine does not exist yet", async ({ page }) => {
  const { slug, email } = await registerOrganization("playbooks");
  await loginThroughUi(page, slug, email);

  await page.click("text=Playbooks");
  await expect(page.getByText("Playbook execution is not available yet.")).toBeVisible();
  await expect(page.getByText(/Phase 15/)).toBeVisible();
});
