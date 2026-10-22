import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { HostAuditReport } from "./HostAuditReport";

describe("read-only audit results", () => {
  it("distinguishes evidence, plans and missing verification", () => {
    render(<HostAuditReport report={{ summary: "Capacity needs review", total_findings: 1, baseline_comparison: { status: "historical_caller_report" }, coverage_gaps: ["gateway_policy"], exposure: { wan_exposure: "unverified" }, findings: [{ id: "capacity", priority: 0, title: "Data disk is 97% used", target: "/data", severity: "critical", confidence: "measured_capacity", action_plan: { steps: ["Verify restore before expansion"], verification: ["Check free bytes"], risk: "downtime" } }] }} />);
    expect(screen.getByText(/No changes executed/)).toBeInTheDocument();
    expect(screen.getByText(/Separate approval is required/)).toBeInTheDocument();
    expect(screen.getByText(/Historical measurements are unverified/)).toBeInTheDocument();
    expect(screen.getByText(/Listener configuration does not prove/)).toBeInTheDocument();
    expect(screen.getByText(/Data disk is 97% used/)).toBeInTheDocument();
  });
});
