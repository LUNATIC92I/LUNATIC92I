import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { AppShell } from "./AppShell";

const mockUseAuth = vi.fn();
vi.mock("@/hooks/useAuth", () => ({
  useAuth: () => mockUseAuth(),
}));

function renderShell() {
  render(
    <MemoryRouter initialEntries={["/"]}>
      <Routes>
        <Route element={<AppShell />}>
          <Route index element={<div>overview page</div>} />
        </Route>
      </Routes>
    </MemoryRouter>,
  );
}

describe("AppShell navigation", () => {
  it("always shows SOC Overview and Reports, which need no permission", () => {
    mockUseAuth.mockReturnValue({ user: { permissions: [], full_name: "Nobody", roles: [] }, logout: vi.fn() });
    renderShell();
    expect(screen.getByText("SOC Overview")).toBeInTheDocument();
    expect(screen.getByText("Reports")).toBeInTheDocument();
  });

  it("hides screens the user's permissions don't cover", () => {
    mockUseAuth.mockReturnValue({ user: { permissions: [], full_name: "Nobody", roles: [] }, logout: vi.fn() });
    renderShell();
    expect(screen.queryByText("Alerts")).not.toBeInTheDocument();
    expect(screen.queryByText("Threat Hunting")).not.toBeInTheDocument();
    expect(screen.queryByText("Administration")).not.toBeInTheDocument();
  });

  it("shows a screen once the matching permission is present", () => {
    mockUseAuth.mockReturnValue({
      user: { permissions: ["alert:read"], full_name: "Analyst", roles: ["SOC_ANALYST_L1"] },
      logout: vi.fn(),
    });
    renderShell();
    expect(screen.getByText("Alerts")).toBeInTheDocument();
  });

  it("gates Event Explorer on hunt:execute, not event:read (no dedicated events API exists)", () => {
    // A READ_ONLY-shaped user: event:read but no hunt:execute.
    mockUseAuth.mockReturnValue({
      user: { permissions: ["event:read", "hunt:read"], full_name: "Viewer", roles: ["READ_ONLY"] },
      logout: vi.fn(),
    });
    renderShell();
    expect(screen.queryByText("Event Explorer")).not.toBeInTheDocument();
  });
});
