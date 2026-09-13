import { describe, expect, it } from "vitest";
import { can } from "./auth";
import type { CurrentUser } from "./auth";

function user(permissions: string[]): CurrentUser {
  return {
    id: "u1",
    email: "a@example.com",
    full_name: "A",
    tenant_id: "t1",
    roles: ["SOC_ANALYST_L1"],
    permissions,
  };
}

describe("can", () => {
  it("is true when the resource:action pair is present", () => {
    expect(can(user(["alert:read", "alert:write"]), "alert", "write")).toBe(true);
  });

  it("is false when the pair is absent", () => {
    expect(can(user(["alert:read"]), "alert", "write")).toBe(false);
  });

  it("is false for a null user (not yet loaded / logged out)", () => {
    expect(can(null, "alert", "read")).toBe(false);
  });

  it("does not confuse a resource with a similarly-named one", () => {
    expect(can(user(["hunt:execute"]), "event", "execute")).toBe(false);
  });
});
