import { render } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { CoverageBar } from "./CoverageBar";

describe("CoverageBar", () => {
  it("renders a flat neutral bar when total is zero", () => {
    const { container } = render(<CoverageBar covered={0} partial={0} total={0} />);
    expect(container.querySelectorAll(".bg-status-good, .bg-status-warning")).toHaveLength(0);
  });

  it("splits width proportionally across covered/partial/uncovered", () => {
    const { container } = render(<CoverageBar covered={5} partial={3} total={10} />);
    const good = container.querySelector(".bg-status-good") as HTMLElement;
    const warning = container.querySelector(".bg-status-warning") as HTMLElement;
    const uncovered = container.querySelector(".bg-slate-700") as HTMLElement;
    expect(good.style.width).toBe("50%");
    expect(warning.style.width).toBe("30%");
    expect(uncovered.style.width).toBe("20%");
  });

  it("omits a segment entirely when its share is zero", () => {
    const { container } = render(<CoverageBar covered={10} partial={0} total={10} />);
    expect(container.querySelector(".bg-status-warning")).toBeNull();
    expect(container.querySelector(".bg-slate-700")).toBeNull();
  });
});
