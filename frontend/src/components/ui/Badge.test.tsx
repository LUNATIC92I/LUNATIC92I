import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { SeverityBadge, StatusBadge } from "./Badge";

describe("SeverityBadge", () => {
  it("renders the severity text", () => {
    render(<SeverityBadge severity="critical" />);
    expect(screen.getByText("critical")).toBeInTheDocument();
  });

  it("is case-insensitive when picking a color class", () => {
    render(<SeverityBadge severity="CRITICAL" />);
    expect(screen.getByText("CRITICAL").className).toContain("severity-critical");
  });

  it("falls back to a neutral style for an unrecognized severity", () => {
    render(<SeverityBadge severity="mystery" />);
    expect(screen.getByText("mystery").className).toContain("slate");
  });
});

describe("StatusBadge", () => {
  it("renders underscores as spaces", () => {
    render(<StatusBadge status="IN_PROGRESS" />);
    expect(screen.getByText("IN PROGRESS")).toBeInTheDocument();
  });
});
