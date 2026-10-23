export type Json = Record<string, any>;
export type User = {
  id: string;
  username: string;
  role: string;
  enabled?: boolean;
};
export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}
export async function api<T = Json>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const response = await fetch(`/api${path}`, {
    ...options,
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", ...options.headers },
  });
  const data =
    response.status === 204 ? null : await response.json().catch(() => null);
  if (!response.ok) {
    const detail = data?.detail;
    const message =
      typeof detail === "string"
        ? detail
        : Array.isArray(detail)
          ? detail.map((d: Json) => d.msg).join("; ")
          : detail?.message ? `${detail.message}${detail.remediation ? `. ${detail.remediation}` : ""}` : "Request could not be completed";
    throw new ApiError(response.status, message);
  }
  if (data === null && response.status !== 204)
    throw new ApiError(502, "Controller returned an invalid JSON response");
  return data as T;
}
export const post = <T = Json>(path: string, data: Json = {}) =>
  api<T>(path, { method: "POST", body: JSON.stringify(data) });
export const patch = <T = Json>(path: string, data: Json = {}) =>
  api<T>(path, { method: "PATCH", body: JSON.stringify(data) });
export const put = <T = Json>(path: string, data: Json = {}) =>
  api<T>(path, { method: "PUT", body: JSON.stringify(data) });
export function rows(value: unknown): Json[] {
  if (Array.isArray(value)) return value;
  if (value && typeof value === "object") {
    const data = value as Json;
    for (const k of [
      "items",
      "results",
      "nodes",
      "hosts",
      "jobs",
      "findings",
      "events",
      "policies",
      "users",
      "backups",
    ])
      if (Array.isArray(data[k])) return data[k];
  }
  return [];
}
export const human = (value: unknown) =>
  value === null || value === undefined || value === "" ? "—" : String(value);
export const date = (value: unknown) => {
  if (!value) return "Not yet recorded";
  const d = new Date(
    String(value).match(/Z$|[+-]\d\d:\d\d$/) ? String(value) : `${value}Z`,
  );
  return Number.isNaN(d.valueOf())
    ? String(value)
    : d.toLocaleString(undefined, {
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      });
};
export const relative = (value: unknown) => {
  if (!value) return "Never connected";
  const elapsed =
    Date.now() -
    new Date(
      String(value).match(/Z$|[+-]\d\d:\d\d$/) ? String(value) : `${value}Z`,
    ).valueOf();
  if (Number.isNaN(elapsed)) return "Unknown";
  if (elapsed < 60_000) return "Just now";
  if (elapsed < 3_600_000) return `${Math.floor(elapsed / 60_000)}m ago`;
  return `${Math.floor(elapsed / 3_600_000)}h ago`;
};
