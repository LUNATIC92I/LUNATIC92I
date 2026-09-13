import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { RequirePermission } from "./RequirePermission";

const mockUseAuth = vi.fn();
vi.mock("@/hooks/useAuth", () => ({
  useAuth: () => mockUseAuth(),
}));

describe("RequirePermission", () => {
  it("renders children when the user holds the permission", () => {
    mockUseAuth.mockReturnValue({ user: { permissions: ["hunt:execute"] } });
    render(
      <RequirePermission resource="hunt" action="execute">
        <p>secret panel</p>
      </RequirePermission>,
    );
    expect(screen.getByText("secret panel")).toBeInTheDocument();
  });

  it("shows an access-restricted message instead of children when the permission is missing", () => {
    mockUseAuth.mockReturnValue({ user: { permissions: ["hunt:read"] } });
    render(
      <RequirePermission resource="hunt" action="execute">
        <p>secret panel</p>
      </RequirePermission>,
    );
    expect(screen.queryByText("secret panel")).not.toBeInTheDocument();
    expect(screen.getByText(/Access restricted/)).toBeInTheDocument();
  });

  it("treats a null user (not yet loaded) as having no permissions", () => {
    mockUseAuth.mockReturnValue({ user: null });
    render(
      <RequirePermission resource="hunt" action="execute">
        <p>secret panel</p>
      </RequirePermission>,
    );
    expect(screen.getByText(/Access restricted/)).toBeInTheDocument();
  });
});
