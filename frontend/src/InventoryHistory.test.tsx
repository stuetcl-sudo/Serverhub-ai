import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { InventoryHistory } from "./InventoryHistory";

describe("authenticated inventory history presentation", () => {
  it("explains missing observations without inventing removals", () => {
    render(
      <InventoryHistory
        entries={[
          {
            id: 1,
            collection_errors: 1,
            diff: { sections: { containers: { status: "unavailable" } } },
          },
        ]}
      />,
    );
    expect(
      screen.getByText("Unavailable — removals not inferred"),
    ).toBeInTheDocument();
    expect(screen.queryByText(/1 removed/)).not.toBeInTheDocument();
  });
  it("renders measured changes and first observation explicitly", () => {
    render(
      <InventoryHistory
        entries={[
          {
            id: 1,
            diff: {
              sections: {
                containers: {
                  status: "compared",
                  removed: ["old-container"],
                  counts: { removed: 1 },
                },
                services: { status: "first_observation", counts: { added: 2 } },
              },
            },
          },
        ]}
      />,
    );
    expect(
      screen.getByText("Compared: 0 added, 0 changed, 1 removed"),
    ).toBeInTheDocument();
    expect(screen.getByText("removed: old-container")).toBeInTheDocument();
    expect(
      screen.getByText("First observation: 2 added, 0 changed, 0 removed"),
    ).toBeInTheDocument();
  });
  it("has no synthetic inventory when the API returns no history", () => {
    render(<InventoryHistory entries={[]} />);
    expect(
      screen.getByText(/No inventory history recorded/),
    ).toBeInTheDocument();
  });
});
