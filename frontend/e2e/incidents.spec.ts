import { expect, test } from "@playwright/test";
import { loginThroughUi, registerOrganization } from "./helpers";

test("creating an incident through the UI, then driving it through its workflow", async ({ page }) => {
  const { slug, email } = await registerOrganization("incidents");
  await loginThroughUi(page, slug, email);

  await page.click("text=Incidents");
  await page.click('button:has-text("New incident")');
  await page.getByLabel("Title").fill("E2E: suspicious lateral movement");
  await page.click('button:has-text("Create")');

  await page.waitForURL(/\/incidents\/[0-9a-f-]+$/);
  await expect(page.getByText("E2E: suspicious lateral movement")).toBeVisible();
  await expect(page.getByText("NEW")).toBeVisible();

  await page.click('button:has-text("→ TRIAGE")');
  await expect(page.getByText("TRIAGE").first()).toBeVisible();

  // A note posted here should show up in both the notes list and the timeline.
  await page.fill('input[placeholder="Add a note…"]', "Confirmed with the asset owner.");
  await page.click('section:has-text("Notes") >> button:has-text("Add")');
  await expect(page.getByText("Confirmed with the asset owner.", { exact: true })).toBeVisible();
  await expect(page.getByText("[note]")).toBeVisible();

  await page.goBack();
  await expect(page.getByText("E2E: suspicious lateral movement")).toBeVisible();
});
