import { afterEach, describe, expect, it, vi } from "vitest";
import { api, ApiError, patch, post, rows } from "./api";
afterEach(() => vi.unstubAllGlobals());
describe("authenticated REST client", () => {
  it("sends same-origin cookies and serializes controlled write payloads", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValue(
        new Response(JSON.stringify({ id: "job" }), { status: 202 }),
      );
    vi.stubGlobal("fetch", fetchMock);
    await post("/jobs", {
      kind: "autonomous",
      host_id: "host-a",
      spec: { prompt: "Inspect DNS" },
    });
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/jobs",
      expect.objectContaining({
        method: "POST",
        credentials: "same-origin",
        body: JSON.stringify({
          kind: "autonomous",
          host_id: "host-a",
          spec: { prompt: "Inspect DNS" },
        }),
      }),
    );
    expect(fetchMock.mock.calls[0][1].headers).not.toHaveProperty(
      "Authorization",
    );
  });
  it("uses PATCH for authorization updates", async () => {
    const f = vi.fn().mockResolvedValue(new Response("{}"));
    vi.stubGlobal("fetch", f);
    await patch("/policies/p", { enabled: false });
    expect(f).toHaveBeenCalledWith(
      "/api/policies/p",
      expect.objectContaining({ method: "PATCH", body: '{"enabled":false}' }),
    );
  });
  it("preserves rejected authorization and validation evidence", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ detail: "Host scope denied" }), {
          status: 403,
        }),
      ),
    );
    await expect(api("/hosts/private")).rejects.toMatchObject({
      name: "ApiError",
      status: 403,
      message: "Host scope denied",
    });
  });
  it("does not turn a failed non-JSON response into successful empty data", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          new Response("<html>Gateway unavailable</html>", { status: 502 }),
        ),
    );
    await expect(api("/hosts")).rejects.toBeInstanceOf(ApiError);
  });
  it("extracts real list envelopes without fabricating entries", () => {
    expect(rows(null)).toEqual([]);
    expect(rows({ items: [{ id: "a" }] })).toEqual([{ id: "a" }]);
    expect(rows({ available: false })).toEqual([]);
  });
});

it("rejects a gateway HTML success response rather than presenting a fabricated empty result", async () => {
  vi.stubGlobal(
    "fetch",
    vi
      .fn()
      .mockResolvedValue(
        new Response("<html>Wrong upstream</html>", { status: 200 }),
      ),
  );
  await expect(api("/hosts")).rejects.toMatchObject({
    status: 502,
    message: "Controller returned an invalid JSON response",
  });
});
it("shows safe structured configuration remediation", async () => {
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({ detail: {
    code: "projects_configuration_invalid", message: "Registered project configuration is unavailable or invalid",
    remediation: "Ask an administrator to validate projects.yaml"
  }}), { status: 503 })));
  await expect(api("/projects")).rejects.toMatchObject({ status: 503,
    message: "Registered project configuration is unavailable or invalid. Ask an administrator to validate projects.yaml" });
});
