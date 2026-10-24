import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { expect, it, vi } from "vitest";
import { FirstRunSetup, ModelSetup, ProfileSetup, DiagnosticsPanel } from "./Setup";

function backend(overrides: Record<string, unknown> = {}) {
  const payloads: Record<string, unknown> = { "/api/settings/models": { configured: false, routes: {} }, "/api/hosts": [{ id: "h1", name: "Linux" }], "/api/users": [{ id: "u1", username: "Dennis", role: "owner" }], "/api/diagnostics": { checks: [{ id: "worker", status: "error", message: "No heartbeat", remediation: "Inspect worker unit" }] }, ...overrides };
  const fetch = vi.fn(async (url: string, options?: RequestInit) => {
    let data = payloads[url];
    if (url.endsWith("/discover")) data = { models: [{ name: "tools:latest" }] };
    if (url.endsWith("/test")) data = { ready: true, message: "Harmless tool call verified" };
    if (options?.method === "PUT") data = { readiness: { message: "Saved" } };
    if (url.endsWith("/policies/profiles")) data = { message: "Scoped profile active" };
    return { ok: true, status: 200, json: async () => data } as Response;
  });
  vi.stubGlobal("fetch", fetch); return fetch;
}
it("discovers, tests and saves a model using owner API calls", async () => {
  const fetch = backend(); render(<ModelSetup />);
  await screen.findByText("Default route is not configured");
  fireEvent.change(screen.getByLabelText("Endpoint URL"), { target: { value: "http://192.168.68.20:11434" } });
  fireEvent.click(screen.getByLabelText(/I trust this exact/));
  fireEvent.click(screen.getByText("Discover models"));
  await screen.findByText(/1 models discovered/);
  fireEvent.change(screen.getByLabelText("Installed model"), { target: { value: "tools:latest" } });
  fireEvent.click(screen.getByText("Test connection & tools"));
  await screen.findByText("Harmless tool call verified");
  fireEvent.click(screen.getByText("Test & save route"));
  await waitFor(() => expect(fetch).toHaveBeenCalledWith("/api/settings/models/default", expect.objectContaining({ method: "PUT" })));
  const write = fetch.mock.calls.find(([url, options]) => url.endsWith("/default") && options?.method === "PUT")!;
  expect(JSON.parse(String(write[1]?.body))).toMatchObject({ allow_insecure_http: true, model: "tools:latest" });
});
it("walks first-run steps without editing YAML", async () => {
  backend(); render(<FirstRunSetup />);
  fireEvent.click(screen.getByText("Next step"));
  expect(screen.getByText("Enroll a Linux host")).toBeInTheDocument();
  fireEvent.click(screen.getByText("Next step"));
  expect(await screen.findByLabelText("Autonomy profile")).toBeInTheDocument();
  fireEvent.click(screen.getByText("Next step"));
  expect(await screen.findByText("No heartbeat")).toBeInTheDocument();
  expect(screen.getByText(/Inspect worker unit/)).toBeInTheDocument();
});
it("submits one expiring host and identity-scoped profile", async () => {
  const fetch = backend(); render(<ProfileSetup />);
  await screen.findByText("Linux");
  fireEvent.change(screen.getByLabelText("Authenticated account"), { target: { value: "u1" } });
  fireEvent.change(screen.getByLabelText("Target host"), { target: { value: "h1" } });
  fireEvent.click(screen.getByText("Grant expiring profile"));
  await screen.findByText("Scoped profile active");
  const write = fetch.mock.calls.find(([url]) => url.endsWith("/policies/profiles"))!;
  expect(JSON.parse(String(write[1]?.body))).toMatchObject({ profile: "read_only", subject_id: "u1", host_id: "h1", hours: 24 });
});
it("shows actionable diagnostics from the backend", async () => {
  backend(); render(<DiagnosticsPanel />);
  expect(await screen.findByText("No heartbeat")).toBeInTheDocument();
  expect(screen.getByText("Inspect worker unit")).toBeInTheDocument();
});
it("grants controller-only development without enrolling a host or enabling staging", async () => {
  const fetch = backend({ "/api/hosts": [] }); render(<ProfileSetup />);
  await screen.findByText("Dennis (owner)");
  fireEvent.change(screen.getByLabelText("Autonomy profile"), { target: { value: "development" } });
  fireEvent.change(screen.getByLabelText("Authenticated account"), { target: { value: "u1" } });
  fireEvent.change(screen.getByLabelText("Registered project"), { target: { value: "jarvis-os" } });
  expect(screen.queryByLabelText("Allowed service names")).not.toBeInTheDocument();
  fireEvent.click(screen.getByText("Grant expiring profile"));
  await screen.findByText("Scoped profile active");
  const write = fetch.mock.calls.find(([url]) => url.endsWith("/policies/profiles"))!;
  expect(JSON.parse(String(write[1]?.body))).toMatchObject({ profile: "development", project: "jarvis-os", host_id: null, allow_staging: false, hours: 24 });
});
it("removes a previously selected host when switching to controller-only development", async () => {
  const fetch = backend(); render(<ProfileSetup />);
  await screen.findByText("Linux");
  fireEvent.change(screen.getByLabelText("Authenticated account"), { target: { value: "u1" } });
  fireEvent.change(screen.getByLabelText("Target host"), { target: { value: "h1" } });
  fireEvent.change(screen.getByLabelText("Autonomy profile"), { target: { value: "development" } });
  expect(screen.getByLabelText("Target host")).toBeDisabled();
  expect(screen.getByLabelText("Target host")).not.toBeRequired();
  fireEvent.change(screen.getByLabelText("Registered project"), { target: { value: "jarvis-os" } });
  fireEvent.click(screen.getByText("Grant expiring profile"));
  await screen.findByText("Scoped profile active");
  const write = fetch.mock.calls.find(([url]) => url.endsWith("/policies/profiles"))!;
  expect(JSON.parse(String(write[1]?.body))).toMatchObject({ profile: "development", host_id: null, allow_staging: false });
});
