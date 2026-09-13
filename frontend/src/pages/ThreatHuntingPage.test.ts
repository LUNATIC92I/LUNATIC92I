import { describe, expect, it } from "vitest";
import { pivotLabel } from "./ThreatHuntingPage";
import { PIVOT_NAMES } from "@/types/hunting";

describe("pivotLabel", () => {
  it("renders exactly one arrow, not one per underscore", () => {
    // Regression test: an earlier version did `name.replace(/_/g, " → ")`,
    // which also turned the literal word "to" in "ip_to_events" into an
    // arrow, rendering "IP → to → events" in the pivot dropdown.
    expect(pivotLabel("ip_to_events")).toBe("IP → events");
    expect((pivotLabel("ip_to_events").match(/→/g) ?? []).length).toBe(1);
  });

  it("uppercases only the subject side, and keeps underscores in the target readable", () => {
    expect(pivotLabel("host_to_processes")).toBe("HOST → processes");
    expect(pivotLabel("user_to_timeline")).toBe("USER → timeline");
  });

  it("produces exactly one arrow for every real pivot name", () => {
    for (const name of PIVOT_NAMES) {
      expect((pivotLabel(name).match(/→/g) ?? []).length).toBe(1);
    }
  });
});
