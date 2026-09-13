import { expect, test } from "@playwright/test";
import { loginThroughUi, registerOrganization } from "./helpers";

test("Threat Hunting rejects an unknown field via the real validation path", async ({ page }) => {
  const { slug, email } = await registerOrganization("hunting");
  await loginThroughUi(page, slug, email);

  await page.click("text=Threat Hunting");
  await page.click('button:has-text("Add structured filter")');
  await page.getByPlaceholder("source_ip").fill("not_a_real_field");
  // "Value" is ambiguous: the structured-filter row and the pivot row below
  // it both have a field labeled "Value" — the filter row's is first in the
  // DOM since the Pivots section renders further down the page.
  await page.getByLabel("Value").first().fill("x");
  await page.click('button:has-text("Search")');
  await expect(page.getByText(/unknown field/i)).toBeVisible();
});

test("saving and running a hunt persists to the real saved-hunts API", async ({ page }) => {
  const { slug, email } = await registerOrganization("hunting-save");
  await loginThroughUi(page, slug, email);

  await page.click("text=Threat Hunting");
  await page.getByPlaceholder("hostname, user, ip, hash…").fill("nobody-matches-this-value");
  await page.getByPlaceholder("Save as…").fill("My saved hunt");
  await page.click('button:has-text("Save")');
  await expect(page.getByText("My saved hunt")).toBeVisible();

  await page.click('button:has-text("Run")');
  await expect(page.getByText(/Results \(0 of 0\)/)).toBeVisible();
});
