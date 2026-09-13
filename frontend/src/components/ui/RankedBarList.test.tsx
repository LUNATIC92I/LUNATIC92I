import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { RankedBarList } from "./RankedBarList";

describe("RankedBarList", () => {
  it("shows a fallback message for an empty list", () => {
    render(<RankedBarList items={[]} />);
    expect(screen.getByText(/No data yet/)).toBeInTheDocument();
  });

  it("renders every item's label and value", () => {
    render(
      <RankedBarList
        items={[
          { label: "dc01", value: 10 },
          { label: "ws-01", value: 3 },
        ]}
      />,
    );
    expect(screen.getByText("dc01")).toBeInTheDocument();
    expect(screen.getByText("10")).toBeInTheDocument();
    expect(screen.getByText("ws-01")).toBeInTheDocument();
    expect(screen.getByText("3")).toBeInTheDocument();
  });

  it("sizes the largest bar at 100% of the row width", () => {
    const { container } = render(
      <RankedBarList
        items={[
          { label: "a", value: 10 },
          { label: "b", value: 5 },
        ]}
      />,
    );
    const bars = container.querySelectorAll(".bg-blue-500");
    expect((bars[0] as HTMLElement).style.width).toBe("100%");
    expect((bars[1] as HTMLElement).style.width).toBe("50%");
  });
});
