import { expect, test } from "@playwright/test";
import { loginThroughUi, registerOrganization } from "./helpers";

test("Event Explorer searches the real hunting API and shows an empty result honestly", async ({ page }) => {
  const { slug, email } = await registerOrganization("events");
  await loginThroughUi(page, slug, email);

  await page.click("text=Event Explorer");
  await page.getByPlaceholder("hostname, user, ip, hash…").fill("nothing-will-match-this");
  await page.click('button:has-text("Search")');
  await expect(page.getByText(/0 of 0 events/)).toBeVisible();
});
