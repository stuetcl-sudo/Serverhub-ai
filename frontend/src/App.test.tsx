import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import App from "./App";
import type { Json } from "./api";

const owner = { id: "owner-1", username: "Dennis", role: "owner" };
const host = {
  id: "host-a",
  name: "Linux node A",
  group_name: "home",
  online: true,
  last_seen: new Date().toISOString(),
  inventory: {
    os: { distribution: { pretty_name: "Ubuntu 24.04 LTS" } },
    hardware: {
      cpu_count: 4,
      load_average: [2, 1, 1],
      memory: { percent: 47 },
      disks: [{ mountpoint: "/", percent: 31 }],
    },
    docker: { containers: [] },
    ports: [],
  },
};
class FakeEventSource {
  static instances: FakeEventSource[] = [];
  onopen: ((event: Event) => void) | null = null;
  onerror: ((event: Event) => void) | null = null;
  onmessage: ((event: Event) => void) | null = null;
  listeners = new Map<string, ((event: Event) => void)[]>();
  constructor(public url: string) {
    FakeEventSource.instances.push(this);
  }
  addEventListener(name: string, listener: (event: Event) => void) {
    this.listeners.set(name, [...(this.listeners.get(name) || []), listener]);
  }
  close() {}
  emit(name: string) {
    for (const listener of this.listeners.get(name) || [])
      listener(new Event(name));
  }
}
function mockBackend(
  overrides: Record<string, unknown> = {},
  user: unknown = owner,
) {
  const defaults: Record<string, unknown> = {
    "/api/auth/me": user,
    "/api/hosts": [host],
    "/api/jobs": [],
    "/api/findings": [],
    "/api/emergency-stop": { enabled: false },
    "/api/policies": [],
    "/api/users": [owner],
    "/api/backups": [],
    "/api/recovery/status": { available: false },
    "/api/integrations": [],
    "/api/catalog": [],
    "/api/projects": [],
    "/api/topology": { nodes: [], edges: [] },
  };
  const f = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input);
    const key =
      init?.method && init.method !== "GET" ? `${init.method} ${path}` : path;
    const value =
      key in overrides
        ? overrides[key]
        : path in overrides
          ? overrides[path]
          : defaults[path];
    if (value instanceof Response) return value.clone();
    return new Response(JSON.stringify(value ?? {}), {
      status: key === "POST /api/jobs" ? 202 : 200,
      headers: { "Content-Type": "application/json" },
    });
  });
  vi.stubGlobal("fetch", f);
  return f;
}
beforeEach(() => {
  FakeEventSource.instances = [];
  vi.stubGlobal("EventSource", FakeEventSource);
  window.location.hash = "";
});
describe("control center integration", () => {
  it("requires login and renders authentication errors without granting access", async () => {
    mockBackend({
      "/api/auth/me": new Response('{"detail":"Authentication required"}', {
        status: 401,
      }),
      "POST /api/auth/login": new Response(
        '{"detail":"Invalid credentials or account temporarily unavailable"}',
        { status: 401 },
      ),
    });
    render(<App />);
    await screen.findByRole("button", { name: "Sign in" });
    await userEvent.type(screen.getByLabelText("Username"), "unknown");
    await userEvent.type(screen.getByLabelText("Password"), "bad-password");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Invalid credentials",
    );
    expect(screen.queryByRole("navigation")).not.toBeInTheDocument();
  });
  it("shows controller data without a synthetic fleet or job fallback", async () => {
    mockBackend({ "/api/hosts": [] });
    render(<App />);
    expect(
      await screen.findByText("Your fleet starts here"),
    ).toBeInTheDocument();
    expect(
      await screen.findByText("No open findings returned"),
    ).toBeInTheDocument();
    expect(screen.queryByText("Linux node A")).not.toBeInTheDocument();
  });
  it("submits a host-bound persistent chat job and displays its result", async () => {
    window.location.hash = "#chat";
    const job = {
      id: "job-1",
      kind: "autonomous",
      state: "queued",
      spec: { prompt: "Find the DNS fault" },
      progress: 0,
      attempts: 0,
      max_attempts: 3,
      result: {},
    };
    const f = mockBackend({
      "POST /api/jobs": job,
      "/api/jobs/job-1": job,
      "/api/jobs/job-1/events": [],
    });
    render(<App />);
    await screen.findByLabelText("Describe your task");
    await within(screen.getByLabelText("Target host")).findByRole("option", { name: /Linux node A/ });
    await userEvent.selectOptions(
      screen.getByLabelText("Target host"),
      "host-a",
    );
    await userEvent.type(
      screen.getByLabelText("Describe your task"),
      "Find the DNS fault",
    );
    await userEvent.click(screen.getByRole("button", { name: "Submit task" }));
    await screen.findByText("Job execution");
    const call = f.mock.calls.find(
      ([path, options]) => path === "/api/jobs" && options?.method === "POST",
    );
    expect(JSON.parse(String(call?.[1]?.body))).toEqual({
      kind: "autonomous",
      host_id: "host-a",
      spec: { prompt: "Find the DNS fault" },
    });
    expect(localStorage.length).toBe(0);
  });
  it("shows a rejected chat request and retains the request text", async () => {
    window.location.hash = "#chat";
    mockBackend(
      {
        "POST /api/jobs": new Response(
          '{"detail":"Read-only role cannot submit jobs"}',
          { status: 403 },
        ),
      },
      { id: "reader", username: "Reader", role: "readonly" },
    );
    render(<App />);
    await screen.findByLabelText("Describe your task");
    await userEvent.type(
      screen.getByLabelText("Describe your task"),
      "Restart a service",
    );
    await userEvent.click(screen.getByRole("button", { name: "Submit task" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Read-only role cannot submit jobs",
    );
    expect(screen.getByLabelText("Describe your task")).toHaveValue(
      "Restart a service",
    );
    expect(
      screen.queryByRole("button", { name: "Emergency stop" }),
    ).not.toBeInTheDocument();
  });
  it("creates an expiring exact capability policy using the backend contract", async () => {
    window.location.hash = "#policies";
    const f = mockBackend({ "POST /api/policies": { id: "policy-1" } });
    render(<App />);
    await userEvent.click(
      await screen.findByRole("button", { name: "Create policy" }),
    );
    const dialog = screen.getByRole("dialog");
    await userEvent.type(
      within(dialog).getByLabelText("Policy name"),
      "Household DNS",
    );
    await userEvent.selectOptions(
      within(dialog).getByLabelText("Role"),
      "adult",
    );
    await within(within(dialog).getByLabelText("Host")).findByRole("option", { name: /Linux node A/ });
    await userEvent.selectOptions(
      within(dialog).getByLabelText("Host"),
      "host-a",
    );
    await userEvent.type(
      within(dialog).getByLabelText(/^Allowed operations/),
      "diagnostics.network",
    );
    fireEvent.change(within(dialog).getByLabelText("Expires at"), {
      target: {
        value: new Date(
          Date.now() + 3600000 - new Date().getTimezoneOffset() * 60000,
        )
          .toISOString()
          .slice(0, 16),
      },
    });
    await userEvent.click(
      within(dialog).getByRole("button", { name: "Create policy" }),
    );
    await waitFor(() =>
      expect(
        f.mock.calls.some(
          ([path, options]) =>
            path === "/api/policies" && options?.method === "POST",
        ),
      ).toBe(true),
    );
    const body = JSON.parse(
      String(
        f.mock.calls.find(
          ([path, options]) =>
            path === "/api/policies" && options?.method === "POST",
        )?.[1]?.body,
      ),
    );
    expect(body).toMatchObject({
      name: "Household DNS",
      role: "adult",
      host_id: "host-a",
      operations: ["diagnostics.network"],
      constraints: {},
      production: false,
    });
    expect(body).not.toHaveProperty("enabled");
  });
  it("revokes policy by PATCH rather than an unsupported action route", async () => {
    window.location.hash = "#policies";
    const f = mockBackend({
      "/api/policies": [
        {
          id: "p1",
          name: "Repair grant",
          role: "adult",
          enabled: true,
          operations: ["systemd.restart"],
          expires_at: "2030-10-23T14:00:00Z",
        },
      ],
    });
    render(<App />);
    await userEvent.click(
      await screen.findByRole("button", { name: "Inspect policy" }),
    );
    await userEvent.click(
      screen.getByRole("button", { name: "Revoke policy" }),
    );
    await waitFor(() =>
      expect(f).toHaveBeenCalledWith(
        "/api/policies/p1",
        expect.objectContaining({ method: "PATCH", body: '{"enabled":false}' }),
      ),
    );
  });
  it("requires a recorded reason before changing emergency-stop state", async () => {
    const f = mockBackend();
    render(<App />);
    await userEvent.click(
      await screen.findByRole("button", { name: "Emergency stop" }),
    );
    const dialog = screen.getByRole("dialog");
    const enable = within(dialog).getByRole("button", {
      name: "Enable emergency stop",
    });
    expect(enable).toBeDisabled();
    await userEvent.type(
      within(dialog).getByLabelText("Reason"),
      "Unexpected container restarts",
    );
    await userEvent.click(enable);
    await waitFor(() =>
      expect(f).toHaveBeenCalledWith(
        "/api/emergency-stop",
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify({
            enabled: true,
            reason: "Unexpected container restarts",
          }),
        }),
      ),
    );
  });
  it("logs out when the authenticated event stream reports expiry", async () => {
    mockBackend();
    render(<App />);
    await screen.findByRole("navigation");
    await waitFor(() => expect(FakeEventSource.instances[0]?.listeners.has("expired")).toBe(true));
    FakeEventSource.instances[0].emit("expired");
    expect(
      await screen.findByRole("button", { name: "Sign in" }),
    ).toBeInTheDocument();
  });
  it("shows API failure instead of reporting zero Docker containers as a successful inventory", async () => {
    window.location.hash = "#docker";
    mockBackend({
      "/api/hosts": new Response('{"detail":"Node inventory unavailable"}', {
        status: 503,
      }),
    });
    render(<App />);
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Node inventory unavailable",
    );
  });
  it("uses individual one-time node enrollment credentials", async () => {
    window.location.hash = "#hosts";
    const f = mockBackend({
      "POST /api/nodes/enrollment": {
        token: "one-time-test-credential",
        expires_at: "2030-10-23T14:00:00Z",
      },
    });
    render(<App />);
    await userEvent.click(
      await screen.findByRole("button", { name: "Enroll host" }),
    );
    await userEvent.type(screen.getByLabelText("Host name"), "raspberry-pi");
    await userEvent.click(
      screen.getByRole("button", { name: "Create enrollment token" }),
    );
    await screen.findByText(/one-time-test-credential/);
    expect(f).toHaveBeenCalledWith(
      "/api/nodes/enrollment",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({
          name: "raspberry-pi",
          group_name: "default",
          ttl_seconds: 3600,
        }),
      }),
    );
  });
  it("shows protected native backup publication independently of SQL records", async () => {
    window.location.hash = "#backups";
    mockBackend({
      "/api/recovery/status": {
        available: true,
        backups: {
          updated_at: "2030-10-22T14:00:00Z",
          backups: [
            {
              id: "native-copy",
              kind: "database",
              state: "complete",
              verified_at: "2030-10-22T14:00:00Z",
            },
          ],
        },
      },
    });
    render(<App />);
    expect(await screen.findByText("native-copy")).toBeInTheDocument();
    expect(screen.getByText("verified")).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Request backup" }),
    ).not.toBeInTheDocument();
  });
});

it("submits configured development workflow without arbitrary command arguments", async () => {
  window.location.hash = "#projects";
  const result = {
    id: "dev-job",
    kind: "development",
    state: "queued",
    attempts: 0,
    max_attempts: 3,
    result: {},
  };
  const f = mockBackend({
    "/api/projects": [
      {
        name: "jarvis",
        base_ref: "main",
        build_steps: 1,
        test_steps: 2,
        independent_checks: 1,
        staging_checks: 1,
        production_deployment: false,
      },
    ],
    "POST /api/jobs": result,
    "/api/jobs/dev-job": result,
    "/api/jobs/dev-job/events": [],
  });
  render(<App />);
  await userEvent.click(
    await screen.findByRole("button", { name: "Run project workflow" }),
  );
  await userEvent.selectOptions(screen.getByLabelText(/Enrolled staging host ID/), "host-a");
  await userEvent.click(
    screen.getByLabelText(/Deploy to enrolled isolated staging/),
  );
  await userEvent.click(
    screen.getByRole("button", { name: "Submit workflow" }),
  );
  await screen.findByText("Job execution");
  const call = f.mock.calls.find(
    ([path, options]) => path === "/api/jobs" && options?.method === "POST",
  );
  expect(JSON.parse(String(call?.[1]?.body))).toEqual({
    kind: "development",
    host_id: "host-a",
    project: "jarvis",
    spec: { project: "jarvis", stage: true },
  });
});
it("distinguishes load per core from CPU utilization and charts only recorded history", async () => {
  window.location.hash = "#monitoring";
  mockBackend({
    "/api/hosts/host-a/metrics?limit=60": [
      { created_at: "2026-10-22T14:01:00Z", metrics: { memory_percent: 47 } },
      { created_at: "2026-10-22T14:00:00Z", metrics: { memory_percent: 40 } },
    ],
  });
  render(<App />);
  expect(await screen.findByText("0.50×")).toBeInTheDocument();
  expect(screen.getByText("Load / core")).toBeInTheDocument();
  expect(
    await screen.findByRole("img", { name: /Memory usage history from/ }),
  ).toBeInTheDocument();
  expect(screen.getByText("2 samples")).toBeInTheDocument();
  expect(screen.queryByText("50%")).not.toBeInTheDocument();
});

it("renders persisted fractional job progress as a completed percentage", async () => {
  window.location.hash = "#jobs";
  mockBackend({
    "/api/jobs": [
      {
        id: "job-finished",
        kind: "workflow",
        state: "succeeded",
        progress: 1,
        attempts: 1,
        max_attempts: 3,
        created_at: "2026-10-22T12:00:00Z",
        spec: {},
      },
    ],
  });
  render(<App />);
  expect(await screen.findByText("100%")).toBeInTheDocument();
  expect(screen.queryByText("1%")).not.toBeInTheDocument();
});


it("loads scoped structural history when the host Changes tab is selected", async () => {
  window.location.hash = "#hosts";
  const fetch = mockBackend({
    "/api/hosts/host-a/inventory": host.inventory,
    "/api/hosts/host-a/inventory/history": [{ id: 1, collection_errors: 0, diff: { sections: {
      containers: { status: "compared", removed: ["retired-container"], counts: { removed: 1 } }
    } } }],
  });
  render(<App />);
  await userEvent.click(await screen.findByRole("button", { name: /Linux node A/ }));
  await userEvent.click(screen.getByRole("button", { name: "Changes" }));
  expect(await screen.findByText("removed: retired-container")).toBeInTheDocument();
  expect(fetch).toHaveBeenCalledWith("/api/hosts/host-a/inventory/history", expect.any(Object));
});

it("launches a persistent read-only host audit without a model budget", async () => {
  window.location.hash = "#hosts";
  const fetch = mockBackend({ "POST /api/jobs": { id: "audit-1", state: "queued" } });
  render(<App />);
  await userEvent.click(await screen.findByRole("button", { name: /Linux node A/ }));
  await userEvent.click(screen.getByRole("button", { name: "Run read-only audit" }));
  await waitFor(() => expect(fetch.mock.calls.some(([path, options]) => path === "/api/jobs" && options?.method === "POST")).toBe(true));
  const call = fetch.mock.calls.find(([path, options]) => path === "/api/jobs" && options?.method === "POST")!;
  expect(JSON.parse(String(call[1]?.body))).toEqual({ kind: "operation", host_id: "host-a", spec: { operation: "host.audit", arguments: {} }, token_budget: 0, cost_budget: 0 });
});

it("submits a scoped autonomous project task and staging host without executable arguments", async () => {
  window.location.hash = "#projects";
  const result = { id: "auto-dev", kind: "development_autonomous", state: "queued", attempts: 0, max_attempts: 3, result: {} };
  const f = mockBackend({
    "/api/projects": [{ name: "jarvis", base_ref: "main", build_steps: 1, test_steps: 1, independent_checks: 1, staging_checks: 0, production_deployment: false }],
    "POST /api/jobs": result,
    "/api/jobs/auto-dev": result,
    "/api/jobs/auto-dev/events": [],
  });
  render(<App />);
  await userEvent.click(await screen.findByRole("button", { name: "Run project workflow" }));
  await userEvent.type(screen.getByLabelText(/Autonomous development task/), "Repair the application version");
  await userEvent.type(screen.getByLabelText(/Token budget/), "85000");
  await userEvent.type(screen.getByLabelText(/API cost budget/), "2.5");
  await userEvent.selectOptions(screen.getByLabelText(/Enrolled staging host ID/), "host-a");
  await userEvent.click(screen.getByLabelText(/Deploy to enrolled isolated staging/));
  await userEvent.click(screen.getByRole("button", { name: "Submit workflow" }));
  await screen.findByText("Job execution");
  const call = f.mock.calls.find(([path, options]) => path === "/api/jobs" && options?.method === "POST");
  expect(JSON.parse(String(call?.[1]?.body))).toEqual({
    kind: "development_autonomous", host_id: "host-a", project: "jarvis", token_budget: 85000, cost_budget: 2.5,
    spec: { project: "jarvis", prompt: "Repair the application version", stage: true },
  });
});
