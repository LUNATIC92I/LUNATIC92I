import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { QueryState } from "./QueryState";
import { ApiError } from "@/services/apiClient";

describe("QueryState", () => {
  it("shows a loading message while loading", () => {
    render(
      <QueryState isLoading error={null}>
        <p>content</p>
      </QueryState>,
    );
    expect(screen.getByText(/Loading/)).toBeInTheDocument();
    expect(screen.queryByText("content")).not.toBeInTheDocument();
  });

  it("shows the ApiError's message on error", () => {
    render(
      <QueryState isLoading={false} error={new ApiError(403, "insufficient permissions")}>
        <p>content</p>
      </QueryState>,
    );
    expect(screen.getByText(/insufficient permissions/)).toBeInTheDocument();
  });

  it("shows a generic message for a non-ApiError failure", () => {
    render(
      <QueryState isLoading={false} error={new Error("boom")}>
        <p>content</p>
      </QueryState>,
    );
    expect(screen.getByText(/Something went wrong/)).toBeInTheDocument();
  });

  it("shows the empty label when isEmpty is true", () => {
    render(
      <QueryState isLoading={false} error={null} isEmpty emptyLabel="Nothing to see">
        <p>content</p>
      </QueryState>,
    );
    expect(screen.getByText("Nothing to see")).toBeInTheDocument();
  });

  it("renders children once loaded, without error, and not empty", () => {
    render(
      <QueryState isLoading={false} error={null} isEmpty={false}>
        <p>content</p>
      </QueryState>,
    );
    expect(screen.getByText("content")).toBeInTheDocument();
  });
});
