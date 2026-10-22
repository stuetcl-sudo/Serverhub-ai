import { InventoryHistory } from "./InventoryHistory";
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
} from "react";
import type { FormEvent, ReactNode } from "react";
import {
  Activity,
  AlertOctagon,
  ArrowDownLeft,
  ArrowRight,
  ArrowUpRight,
  Bell,
  Bot,
  Boxes,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Clock3,
  Code2,
  Database,
  Download,
  ExternalLink,
  FileText,
  Globe2,
  HardDrive,
  Layers3,
  LayoutDashboard,
  Loader2,
  LockKeyhole,
  LogOut,
  Menu,
  MessageSquare,
  Network,
  Pause,
  Play,
  Plus,
  Radio,
  RefreshCw,
  Search,
  Send,
  Server,
  Settings2,
  Shield,
  ShieldCheck,
  Sparkles,
  Square,
  Terminal,
  Users,
  Workflow,
  X,
  Zap,
} from "lucide-react";
import { api, date, human, patch, post, relative, rows } from "./api";
import type { Json, User } from "./api";
import { FirstRunSetup, ModelSetup, ProfileSetup } from "./Setup";

const RefreshContext = createContext(0);
const ToastContext = createContext<(message: string, error?: boolean) => void>(
  () => {},
);
const UserContext = createContext<User | null>(null);
const NAV = [
  {
    group: "Workspace",
    items: [
      ["overview", "Overview", LayoutDashboard],
      ["topology", "Topology", Network],
      ["hosts", "Managed hosts", Server],
      ["docker", "Docker", Boxes],
      ["integrations", "Integrations", Layers3],
      ["projects", "Development", Code2],
      ["network", "Network & ports", Globe2],
    ],
  },
  {
    group: "Autopilot",
    items: [
      ["chat", "AI assistant", Sparkles],
      ["jobs", "Jobs & activity", Workflow],
      ["security", "Security findings", ShieldCheck],
      ["monitoring", "Monitoring", Activity],
      ["incidents", "Incidents", AlertOctagon],
      ["memory", "Operational memory", Layers3],
    ],
  },
  {
    group: "Control plane",
    items: [
      ["policies", "Approval policies", LockKeyhole],
      ["backups", "Backup & recovery", HardDrive],
      ["setup", "Setup & diagnostics", Settings2],
      ["models", "AI providers", Bot],
      ["users", "Users & roles", Users],
      ["audit", "Audit trail", FileText],
    ],
  },
];
const TITLES: Record<string, [string, string]> = {
  setup: ["Set up reliable autonomy.", "Connect models, enroll hosts, delegate scoped permissions and diagnose readiness."],
  overview: [
    "Your infrastructure, in focus.",
    "A live view of your systems and the work happening around them.",
  ],
  topology: [
    "Connected by evidence.",
    "Explore managed hosts and their observed service relationships.",
  ],
  hosts: [
    "A home for every host.",
    "Inventory, health and individual agent identities across your fleet.",
  ],
  docker: [
    "Your container fleet.",
    "Real containers, deployment boundaries and service health.",
  ],
  integrations: [
    "Services, connected.",
    "Inspect configured integrations and a curated application catalog.",
  ],
  projects: [
    "Build with a clear boundary.",
    "Run configured project workflows in isolated workspaces.",
  ],
  network: [
    "Know what is listening.",
    "Addresses, network interfaces and observed TCP / UDP listeners.",
  ],
  chat: [
    "Put your infrastructure to work.",
    "Describe the outcome. The assistant works within your active policies.",
  ],
  jobs: [
    "Work that keeps moving.",
    "Persistent execution, live progress and a complete record of outcomes.",
  ],
  security: [
    "Evidence before action.",
    "Review findings, understand their scope and request authorized repairs.",
  ],
  monitoring: [
    "A pulse on your systems.",
    "Latest observed resource use and collection status from managed nodes.",
  ],
  incidents: [
    "From symptom to resolution.",
    "Track incidents and the evidence behind each remediation.",
  ],
  memory: [
    "Experience that stays useful.",
    "Verified operational knowledge and previous outcomes available to agents.",
  ],
  policies: [
    "Autonomy with boundaries.",
    "Grant specific operations to specific people, hosts and projects.",
  ],
  backups: [
    "Recovery you can account for.",
    "Registered checkpoints, verification status and protected recovery copies.",
  ],
  models: [
    "Intelligence, on your terms.",
    "Inspect model routing and configure providers through protected owner settings.",
  ],
  users: [
    "The right access for everyone.",
    "Manage household identities and administrative roles.",
  ],
  audit: [
    "Every change has a story.",
    "An ordered record of authorization, operations and control-plane changes.",
  ],
};

export function useResource<T = Json>(path: string | null) {
  const generation = useContext(RefreshContext);
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const seq = useRef(0);
  const previousGeneration = useRef(generation);
  const load = useCallback(async () => {
    if (!path) {
      setLoading(false);
      return;
    }
    const request = ++seq.current;
    try {
      const result = await api<T>(path);
      if (request === seq.current) {
        setData(result);
        setError("");
      }
    } catch (e) {
      if (request === seq.current)
        setError(e instanceof Error ? e.message : "Connection failed");
    } finally {
      if (request === seq.current) setLoading(false);
    }
  }, [path]);
  useEffect(() => {
    setData(null);
    setLoading(true);
    void load();
    return () => {
      seq.current++;
    };
  }, [load]);
  useEffect(() => {
    if (previousGeneration.current !== generation) {
      previousGeneration.current = generation;
      void load();
    }
  }, [generation, load]);
  return { data, loading, error, reload: load };
}

function IconButton({
  children,
  label,
  onClick,
  disabled = false,
  danger = false,
}: {
  children: ReactNode;
  label: string;
  onClick: () => void;
  disabled?: boolean;
  danger?: boolean;
}) {
  return (
    <button
      type="button"
      className={`icon-button ${danger ? "danger" : ""}`}
      title={label}
      aria-label={label}
      onClick={onClick}
      disabled={disabled}
    >
      {children}
    </button>
  );
}
export function Status({ value }: { value: unknown }) {
  const s = human(value).toLowerCase();
  const good = [
    "online",
    "healthy",
    "succeeded",
    "success",
    "completed",
    "active",
    "verified",
    "resolved",
    "enabled",
    "running",
  ].includes(s);
  const bad = [
    "failed",
    "critical",
    "high",
    "unhealthy",
    "revoked",
    "error",
    "offline",
  ].includes(s);
  const warn = [
    "medium",
    "pending",
    "paused",
    "waiting_approval",
    "approval_required",
    "degraded",
    "retrying",
    "leased",
    "pause_requested",
    "cancel_requested",
  ].includes(s);
  return (
    <span
      className={`status ${good ? "good" : bad ? "bad" : warn ? "warn" : ""}`}
    >
      <i />
      {s.replaceAll("_", " ")}
    </span>
  );
}
function Empty({
  icon: Icon = Layers3,
  title,
  text,
  action,
}: {
  icon?: typeof Server;
  title: string;
  text: string;
  action?: ReactNode;
}) {
  return (
    <div className="empty">
      <div className="empty-icon">
        <Icon size={25} />
      </div>
      <h3>{title}</h3>
      <p>{text}</p>
      {action}
    </div>
  );
}
function Issue({ error, onRetry }: { error: string; onRetry?: () => void }) {
  return (
    <div className="issue" role="alert">
      <AlertOctagon size={17} />
      <span>{error}</span>
      {onRetry && (
        <button type="button" onClick={onRetry}>
          Try again
        </button>
      )}
    </div>
  );
}
function Load({
  loading,
  error,
  children,
  onRetry,
}: {
  loading: boolean;
  error: string;
  children: ReactNode;
  onRetry?: () => void;
}) {
  if (error) return <Issue error={error} onRetry={onRetry} />;
  return (
    <>
      {loading ? (
        <div className="loading">
          <Loader2 className="spin" size={22} /> Loading live data…
        </div>
      ) : (
        children
      )}
    </>
  );
}
function Panel({
  title,
  eyebrow,
  action,
  children,
  className = "",
}: {
  title?: string;
  eyebrow?: string;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`panel ${className}`}>
      {(title || action) && (
        <div className="panel-heading">
          <div>
            {eyebrow && <div className="eyebrow">{eyebrow}</div>}
            <h2>{title}</h2>
          </div>
          {action}
        </div>
      )}
      {children}
    </section>
  );
}
function JsonView({ value }: { value: unknown }) {
  return <pre className="json-view">{JSON.stringify(value, null, 2)}</pre>;
}
function Modal({
  title,
  children,
  onClose,
  wide = false,
}: {
  title: string;
  children: ReactNode;
  onClose: () => void;
  wide?: boolean;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const titleId = useId();
  useEffect(() => {
    dialog.current?.showModal();
  }, []);
  return (
    <dialog
      ref={dialog}
      aria-labelledby={titleId}
      className={`modal ${wide ? "wide" : ""}`}
      onCancel={onClose}
      onClick={(e) => {
        if (e.target === dialog.current) onClose();
      }}
    >
      <div className="modal-head">
        <h2 id={titleId}>{title}</h2>
        <IconButton label="Close dialog" onClick={onClose}>
          <X size={18} />
        </IconButton>
      </div>
      {children}
    </dialog>
  );
}
function Metric({
  label,
  value,
  detail,
  icon: Icon,
  color = "blue",
}: {
  label: string;
  value: unknown;
  detail: string;
  icon: typeof Server;
  color?: string;
}) {
  return (
    <div className="metric">
      <div className="metric-top">
        <span>{label}</span>
        <div className={`metric-icon ${color}`}>
          <Icon size={18} />
        </div>
      </div>
      <strong>{human(value)}</strong>
      <small>{detail}</small>
    </div>
  );
}
function normalizedHosts(data: unknown) {
  return rows(data);
}
function inventory(host: Json): Json {
  return host.inventory || host.snapshot || {};
}
function hostOnline(host: Json) {
  if (host.revoked) return false;
  if (typeof host.online === "boolean") return host.online;
  if (host.status) return host.status === "online";
  if (!host.last_seen) return false;
  const d = String(host.last_seen);
  return (
    Date.now() - new Date(/Z$|[+-]\d\d:\d\d$/.test(d) ? d : `${d}Z`).valueOf() <
    180000
  );
}
function listField(inv: Json, key: string): Json[] {
  const val = inv[key];
  if (Array.isArray(val)) return val;
  return rows(val);
}
function containers(host: Json): Json[] {
  const d = inventory(host).docker;
  return Array.isArray(d) ? d : d?.containers || [];
}
function percent(value: unknown): string {
  const n = Number(value);
  return value !== null && value !== undefined && Number.isFinite(n)
    ? `${n.toFixed(1)}%`
    : "Not collected";
}
function resource(host: Json, name: "cpu" | "memory" | "disk"): number | null {
  const i = inventory(host),
    h = i.hardware || i.resources || {};
  const candidate =
    name === "cpu"
      ? (h.cpu?.percent ?? h.cpu_percent ?? i.cpu_percent)
      : name === "memory"
        ? (h.memory?.percent ?? h.memory_percent ?? i.memory?.percent)
        : (h.disk?.percent ??
          h.disks?.find((disk: Json) => disk.mountpoint === "/")?.percent ??
          i.disks?.find((disk: Json) => disk.mountpoint === "/")?.percent);
  return candidate === undefined ||
    candidate === null ||
    !Number.isFinite(Number(candidate))
    ? null
    : Number(candidate);
}
function loadPerCore(host: Json): number | null {
  const hardware = inventory(host).hardware || {};
  const value = hardware.load_average?.[0];
  return typeof value === "number" && hardware.cpu_count
    ? value / hardware.cpu_count
    : null;
}
function Progress({
  value,
  label,
  pressure = true,
}: {
  value: number | null;
  label?: string;
  pressure?: boolean;
}) {
  return (
    <div className="resource-line">
      {label && <span>{label}</span>}
      <div className="progress-track">
        <div
          style={{ width: `${Math.min(100, Math.max(0, value || 0))}%` }}
          className={pressure && value && value > 85 ? "danger-fill" : ""}
        />
      </div>
      <small>{value === null ? "—" : `${Math.round(value)}%`}</small>
    </div>
  );
}
function useSearch<T extends Json>(items: T[], fields: string[]) {
  const [query, setQuery] = useState("");
  const filtered = useMemo(
    () =>
      items.filter((item) =>
        fields.some((f) =>
          String(item[f] ?? "")
            .toLowerCase()
            .includes(query.toLowerCase()),
        ),
      ),
    [items, fields.join(","), query],
  );
  return { query, setQuery, filtered };
}
function SearchInput({
  value,
  onChange,
  placeholder = "Search…",
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
}) {
  return (
    <label className="search">
      <Search size={16} />
      <input
        aria-label={placeholder}
        placeholder={placeholder}
        value={value}
        onChange={(e) => onChange(e.target.value)}
      />
      <kbd>/</kbd>
    </label>
  );
}
function roleOwner(user: User | null) {
  return user?.role === "owner";
}

export default function App() {
  const [user, setUser] = useState<User | null>(null),
    [checking, setChecking] = useState(true);
  const [page, setPage] = useState(
    () => location.hash.slice(1).split("/")[0] || "overview",
  );
  const [refresh, setRefresh] = useState(0),
    [menu, setMenu] = useState(false),
    [stream, setStream] = useState(false);
  const [toast, setToast] = useState<{
    message: string;
    error?: boolean;
  } | null>(null);
  const [stopOpen, setStopOpen] = useState(false),
    [stopping, setStopping] = useState(false);
  const [stopEnabled, setStopEnabled] = useState(false),
    [stopReason, setStopReason] = useState("");
  const notice = useCallback(
    (message: string, error = false) => setToast({ message, error }),
    [],
  );
  useEffect(() => {
    void api<User>("/auth/me")
      .then((u) => setUser((u as Json).user || u))
      .catch(() => setUser(null))
      .finally(() => setChecking(false));
  }, []);
  useEffect(() => {
    const handler = () => {
      setPage(location.hash.slice(1).split("/")[0] || "overview");
      setMenu(false);
    };
    window.addEventListener("hashchange", handler);
    return () => window.removeEventListener("hashchange", handler);
  }, []);
  useEffect(() => {
    if (!toast) return;
    const timer = setTimeout(() => setToast(null), 6500);
    return () => clearTimeout(timer);
  }, [toast]);
  useEffect(() => {
    if (!user) return;
    const events = new EventSource("/api/events", { withCredentials: true });
    let debounce: ReturnType<typeof setTimeout> | undefined;
    events.onopen = () => setStream(true);
    const update = () => {
      if (!debounce)
        debounce = setTimeout(() => {
          setRefresh((x) => x + 1);
          debounce = undefined;
        }, 800);
    };
    events.addEventListener("update", update);
    events.addEventListener("expired", () => setUser(null));
    events.onmessage = update;
    events.onerror = () => setStream(false);
    const poll = setInterval(() => setRefresh((x) => x + 1), 15000);
    return () => {
      events.close();
      clearInterval(poll);
      clearTimeout(debounce);
    };
  }, [user]);
  useEffect(() => {
    if (user)
      void api("/emergency-stop")
        .then((v) => setStopEnabled(v.enabled === true))
        .catch(() => {});
  }, [user, refresh]);
  async function logout() {
    await post("/auth/logout").catch(() => {});
    setUser(null);
  }
  async function stop() {
    setStopping(true);
    try {
      await post("/emergency-stop", {
        enabled: !stopEnabled,
        reason: stopReason,
      });
      notice(
        stopEnabled
          ? "Emergency stop cleared. Policies still apply."
          : "Emergency stop enabled. New changes are blocked.",
      );
      setStopEnabled((v) => !v);
      setStopOpen(false);
      setRefresh((x) => x + 1);
    } catch (e) {
      notice((e as Error).message, true);
    } finally {
      setStopping(false);
    }
  }
  if (checking)
    return (
      <div className="boot">
        <div className="brand-mark">
          <Layers3 size={28} />
        </div>
        <h1>
          ServerHub<span> AI OS</span>
        </h1>
        <Loader2 className="spin" size={22} />
      </div>
    );
  if (!user) return <Login onLogin={setUser} />;
  const title = TITLES[page] || TITLES.overview;
  return (
    <UserContext.Provider value={user}>
      <ToastContext.Provider value={notice}>
        <RefreshContext.Provider value={refresh}>
          <div className="app-shell">
            {menu && (
              <button
                className="nav-scrim"
                aria-label="Close navigation"
                onClick={() => setMenu(false)}
              />
            )}
            <aside className={`sidebar ${menu ? "open" : ""}`}>
              <a className="brand" href="#overview">
                <span className="brand-mark">
                  <Layers3 size={23} />
                </span>
                <span>
                  serverhub<small>AI OPERATING SYSTEM</small>
                </span>
              </a>
              <div className="workspace">
                <div className="workspace-icon">
                  <Server size={18} />
                </div>
                <div>
                  <strong>Control center</strong>
                  <small>Native Linux platform</small>
                </div>
                <ChevronDown size={14} />
              </div>
              <nav aria-label="Main navigation">
                {NAV.map((group) => (
                  <div className="nav-group" key={group.group}>
                    <div className="nav-label">{group.group}</div>
                    {group.items.map(([key, label, Icon]) => (
                      <a
                        key={String(key)}
                        href={`#${key}`}
                        className={`nav-link ${page === key ? "selected" : ""}`}
                        aria-current={page === key ? "page" : undefined}
                      >
                        <Icon size={17} />
                        <span>{String(label)}</span>
                        {key === "chat" && <span className="nav-ai">AI</span>}
                      </a>
                    ))}
                  </div>
                ))}
              </nav>
              <div className="sidebar-footer">
                <div className="boundary">
                  <ShieldCheck size={16} />
                  <span>Policy enforced execution</span>
                </div>
                <button className="profile" onClick={logout} title="Sign out">
                  <div className="avatar">
                    {user.username.slice(0, 2).toUpperCase()}
                  </div>
                  <div>
                    <strong>{user.username}</strong>
                    <small>{user.role.replaceAll("_", " ")}</small>
                  </div>
                  <LogOut size={16} />
                </button>
              </div>
            </aside>
            <div className="main-shell">
              <header className="topbar">
                <div className="breadcrumbs">
                  <IconButton
                    label="Open navigation"
                    onClick={() => setMenu(true)}
                  >
                    <Menu size={20} />
                  </IconButton>
                  <span>Workspace</span>
                  <ChevronRight size={14} />
                  <strong>
                    {(NAV.flatMap((n) => n.items).find(
                      (n) => n[0] === page,
                    )?.[1] as string) || "Overview"}
                  </strong>
                </div>
                <div className="top-actions">
                  <span className={`connection ${stream ? "live" : ""}`}>
                    <i />
                    {stream ? "Live connection" : "15s refresh"}
                  </span>
                  <IconButton
                    label="Refresh all data"
                    onClick={() => setRefresh((x) => x + 1)}
                  >
                    <RefreshCw size={17} />
                  </IconButton>
                  {roleOwner(user) && (
                    <button
                      className="stop-button"
                      onClick={() => {
                        setStopReason("");
                        setStopOpen(true);
                      }}
                    >
                      <Square size={12} />
                      {stopEnabled ? "Changes stopped" : "Emergency stop"}
                    </button>
                  )}
                </div>
              </header>
              <main id="main">
                <div className="page-heading">
                  <div>
                    <div className="eyebrow">
                      <span className="eyebrow-dot" /> SERVERHUB CONTROL CENTER
                    </div>
                    <h1>{title[0]}</h1>
                    <p>{title[1]}</p>
                  </div>
                  <div className="heading-meta">
                    <span>
                      {new Date().toLocaleDateString(undefined, {
                        weekday: "long",
                        month: "short",
                        day: "numeric",
                      })}
                    </span>
                    <span>
                      <Shield size={13} /> Identity-bound access
                    </span>
                  </div>
                </div>
                {page === "overview" ? (
                  <Overview
                    navigate={(p) => {
                      location.hash = p;
                    }}
                  />
                ) : page === "hosts" ? (
                  <Hosts />
                ) : page === "topology" ? (
                  <Topology />
                ) : page === "docker" ? (
                  <Docker />
                ) : page === "integrations" ? (
                  <Integrations />
                ) : page === "projects" ? (
                  <Projects />
                ) : page === "network" ? (
                  <NetworkPage />
                ) : page === "chat" ? (
                  <Chat />
                ) : page === "jobs" ? (
                  <Jobs />
                ) : page === "security" ? (
                  <Security />
                ) : page === "monitoring" ? (
                  <Monitoring />
                ) : page === "policies" ? (
                  <Policies />
                ) : page === "users" ? (
                  <UserAdmin />
                ) : page === "setup" ? (
                  <FirstRunSetup />
                ) : page === "models" ? (
                  <Models />
                ) : page === "backups" ? (
                  <Backups />
                ) : page === "audit" ? (
                  <Records path="/audit" kind="audit" />
                ) : page === "incidents" ? (
                  <Records path="/incidents" kind="incidents" />
                ) : page === "memory" ? (
                  <Records path="/memory" kind="memory" />
                ) : (
                  <Overview
                    navigate={(p) => {
                      location.hash = p;
                    }}
                  />
                )}
                <footer className="page-footer">
                  <span>
                    <Layers3 size={13} /> ServerHub AI OS
                  </span>
                  <span>
                    Observed data. Authorized actions. Recorded outcomes.
                  </span>
                </footer>
              </main>
            </div>
          </div>
          {toast && (
            <div
              role={toast.error ? "alert" : "status"}
              className={`toast ${toast.error ? "error" : ""}`}
            >
              {toast.error ? (
                <AlertOctagon size={18} />
              ) : (
                <CheckCircle2 size={18} />
              )}
              <span>{toast.message}</span>
              <button
                onClick={() => setToast(null)}
                aria-label="Dismiss notification"
              >
                <X size={16} />
              </button>
            </div>
          )}
          {stopOpen && (
            <Modal
              title={
                stopEnabled ? "Clear emergency stop" : "Enable emergency stop"
              }
              onClose={() => setStopOpen(false)}
            >
              <div className="modal-content">
                <p>
                  {stopEnabled
                    ? "Clearing the stop permits authorized operations to continue. Existing policies and their expiry still apply."
                    : "This blocks new changing operations and signals active jobs to stop at their next safe boundary. An operation already running on a node may need to finish or roll back."}
                </p>
                <label className="reason-field">
                  Reason
                  <textarea
                    required
                    value={stopReason}
                    onChange={(e) => setStopReason(e.target.value)}
                    maxLength={1000}
                    rows={2}
                    placeholder="Record why the execution state is changing"
                  />
                </label>
                <div className="callout warning">
                  <AlertOctagon size={19} /> Protected rollback and watchdog
                  services remain independent.
                </div>
                <div className="form-actions">
                  <button
                    className="button secondary"
                    onClick={() => setStopOpen(false)}
                  >
                    Cancel
                  </button>
                  <button
                    className="button destructive"
                    disabled={stopping || !stopReason.trim()}
                    onClick={stop}
                  >
                    {stopping ? (
                      <Loader2 className="spin" size={16} />
                    ) : (
                      <Square size={14} />
                    )}{" "}
                    {stopEnabled
                      ? "Clear emergency stop"
                      : "Enable emergency stop"}
                  </button>
                </div>
              </div>
            </Modal>
          )}
        </RefreshContext.Provider>
      </ToastContext.Provider>
    </UserContext.Provider>
  );
}

function Login({ onLogin }: { onLogin: (user: User) => void }) {
  const [username, setUsername] = useState(""),
    [password, setPassword] = useState(""),
    [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      const result = await post<{ user: User }>("/auth/login", {
        username,
        password,
      });
      setPassword("");
      onLogin(result.user);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="login-layout">
      <div className="login-story">
        <a className="brand" href="#">
          <span className="brand-mark">
            <Layers3 size={25} />
          </span>
          <span>
            serverhub<small>AI OPERATING SYSTEM</small>
          </span>
        </a>
        <div className="login-copy">
          <div className="eyebrow">YOUR INFRASTRUCTURE. IN GOOD HANDS.</div>
          <h1>
            Less firefighting.
            <br />
            <span>More peace of mind.</span>
          </h1>
          <p>
            One workspace for your Linux systems, connected services and
            authorized AI operations.
          </p>
          <div className="login-orbit">
            <div className="orbit-node n1">
              <Server />
              <span>Linux hosts</span>
            </div>
            <div className="orbit-node n2">
              <Boxes />
              <span>Services</span>
            </div>
            <div className="orbit-center">
              <Layers3 size={44} />
            </div>
            <div className="orbit-node n3">
              <ShieldCheck />
              <span>Policy engine</span>
            </div>
          </div>
        </div>
        <small className="login-bottom">
          Native Linux · Persistent jobs · Individual identities
        </small>
      </div>
      <div className="login-panel">
        <form onSubmit={submit} className="login-form">
          <span className="form-badge">
            <LockKeyhole size={17} />
          </span>
          <h2>Welcome back.</h2>
          <p>Sign in to your ServerHub control center.</p>
          {error && <Issue error={error} />}
          <label>
            Username
            <input
              autoFocus
              required
              autoComplete="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
            />
          </label>
          <label>
            Password
            <input
              type="password"
              required
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </label>
          <button className="button primary" disabled={busy}>
            {busy ? (
              <Loader2 className="spin" size={17} />
            ) : (
              <>
                Sign in <ArrowRight size={17} />
              </>
            )}
          </button>
          <div className="login-help">
            <ShieldCheck size={16} />
            <p>
              Use the account created during native installation. Access is
              checked for every operation.
            </p>
          </div>
        </form>
      </div>
    </div>
  );
}

function Overview({ navigate }: { navigate: (p: string) => void }) {
  const h = useResource<Json[]>("/hosts"),
    j = useResource<Json[]>("/jobs"),
    f = useResource<Json[]>("/findings");
  const hosts = normalizedHosts(h.data),
    jobs = rows(j.data),
    findings = rows(f.data);
  const active = jobs.filter((x) =>
    ["queued", "running", "retrying", "leased"].includes(x.state),
  );
  const open = findings.filter(
    (x) => !["resolved", "dismissed"].includes(x.status),
  );
  return (
    <>
      <div className="autopilot-banner">
        <div className="banner-symbol">
          <Sparkles size={23} />
        </div>
        <div>
          <div className="eyebrow">YOUR OPERATIONS CO-PILOT</div>
          <h2>A little less admin. A lot more clarity.</h2>
          <p>
            Describe what needs to happen. Follow each decision, permission
            check and result.
          </p>
        </div>
        <button className="button primary" onClick={() => navigate("chat")}>
          Ask your AI <ArrowUpRight size={17} />
        </button>
      </div>
      <Load loading={h.loading} error={h.error} onRetry={h.reload}>
        <div className="metrics-grid">
          <Metric
            label="Managed hosts"
            value={hosts.length}
            detail={`${hosts.filter(hostOnline).length} reporting within 3 minutes`}
            icon={Server}
          />
          <Metric
            label="Running containers"
            value={hosts.reduce(
              (a, x) =>
                a +
                containers(x).filter(
                  (c) => (c.State || c.state || "").toLowerCase() === "running",
                ).length,
              0,
            )}
            detail="From latest Docker inventory"
            icon={Boxes}
            color="purple"
          />
          <Metric
            label="Active jobs"
            value={j.error ? null : active.length}
            detail="Durable tasks across your fleet"
            icon={Workflow}
            color="lime"
          />
          <Metric
            label="Security findings"
            value={f.error ? null : open.length}
            detail={`${open.filter((x) => ["high", "critical"].includes(x.severity)).length} high or critical · review evidence`}
            icon={ShieldCheck}
            color="amber"
          />
        </div>
      </Load>
      <div className="dashboard-grid">
        <Panel
          title="Infrastructure"
          eyebrow="YOUR MANAGED FLEET"
          action={
            <button className="text-button" onClick={() => navigate("hosts")}>
              View all hosts <ArrowRight size={14} />
            </button>
          }
        >
          {hosts.length ? (
            <div className="host-list">
              {hosts.slice(0, 5).map((host) => (
                <button
                  key={host.id}
                  className="host-row"
                  onClick={() => navigate("hosts")}
                >
                  <div
                    className={`host-symbol ${hostOnline(host) ? "online" : ""}`}
                  >
                    <Server size={20} />
                  </div>
                  <div className="host-info">
                    <strong>{host.name}</strong>
                    <small>
                      {inventory(host).os?.distribution?.pretty_name ||
                        inventory(host).os?.pretty_name ||
                        inventory(host).os?.name ||
                        "Awaiting inventory"}{" "}
                      <span>·</span> {host.group_name || "Ungrouped"}
                    </small>
                  </div>
                  <div className="host-resource">
                    <Progress label="CPU" value={resource(host, "cpu")} />
                    <Progress label="RAM" value={resource(host, "memory")} />
                  </div>
                  <Status
                    value={
                      host.revoked
                        ? "revoked"
                        : hostOnline(host)
                          ? "online"
                          : "offline"
                    }
                  />
                </button>
              ))}
            </div>
          ) : (
            <Empty
              icon={Server}
              title="Your fleet starts here"
              text="Enroll a native node agent to see real host health, services and network inventory."
              action={
                <button
                  className="button secondary"
                  onClick={() => navigate("hosts")}
                >
                  Connect a host <Plus size={15} />
                </button>
              }
            />
          )}
        </Panel>
        <Panel
          title="Recent execution"
          eyebrow="PERSISTENT OPERATIONS"
          action={
            <button className="text-button" onClick={() => navigate("jobs")}>
              All jobs <ArrowRight size={14} />
            </button>
          }
        >
          <Load loading={j.loading} error={j.error} onRetry={j.reload}>
            {jobs.length ? (
              <div className="activity-list">
                {jobs.slice(0, 5).map((job) => (
                  <button
                    className="activity-item"
                    key={job.id}
                    onClick={() => navigate("jobs")}
                  >
                    <div
                      className={`activity-icon ${job.state === "succeeded" ? "good" : ""}`}
                    >
                      {job.state === "succeeded" ? (
                        <Check size={16} />
                      ) : (
                        <Workflow size={16} />
                      )}
                    </div>
                    <div>
                      <strong>
                        {job.spec?.prompt || job.spec?.title || job.kind}
                      </strong>
                      <small>
                        {date(job.created_at)} · {job.kind}
                      </small>
                    </div>
                    <Status value={job.state} />
                  </button>
                ))}
              </div>
            ) : (
              <Empty
                icon={Workflow}
                title="Ready when you are"
                text="Jobs continue on the controller after your browser disconnects."
              />
            )}
          </Load>
        </Panel>
      </div>
      <div className="dashboard-bottom">
        <Panel
          title="Security posture"
          action={
            <button
              className="text-button"
              onClick={() => navigate("security")}
            >
              Review findings <ArrowRight size={14} />
            </button>
          }
        >
          <Load loading={f.loading} error={f.error} onRetry={f.reload}>
            {open.length ? (
              <div className="finding-summary">
                {["critical", "high", "medium", "low"].map((severity) => (
                  <div key={severity}>
                    <span className={`severity-dot ${severity}`} />
                    <span>{severity}</span>
                    <strong>
                      {open.filter((x) => x.severity === severity).length}
                    </strong>
                  </div>
                ))}
              </div>
            ) : (
              <div className="compact-empty">
                <Shield size={26} />
                <div>
                  <strong>No open findings returned</strong>
                  <p>
                    This reflects collected evidence, not a guarantee of
                    security.
                  </p>
                </div>
              </div>
            )}
          </Load>
        </Panel>
        <Panel title="A clear chain of trust">
          <div className="trust-grid">
            <div>
              <LockKeyhole size={18} />
              <strong>Scoped permissions</strong>
              <small>Host, project and expiry</small>
            </div>
            <div>
              <FileText size={18} />
              <strong>Recorded outcomes</strong>
              <small>Inspect the audit trail</small>
            </div>
            <div>
              <HardDrive size={18} />
              <strong>Recoverable changes</strong>
              <small>Policy-bound checkpoints</small>
            </div>
          </div>
        </Panel>
      </div>
    </>
  );
}

function Hosts() {
  const r = useResource<Json[]>("/hosts"),
    user = useContext(UserContext),
    notice = useContext(ToastContext);
  const list = normalizedHosts(r.data),
    { query, setQuery, filtered } = useSearch(list, [
      "name",
      "id",
      "group_name",
    ]);
  const [selected, setSelected] = useState<Json | null>(null),
    [enroll, setEnroll] = useState(false),
    [token, setToken] = useState<Json | null>(null),
    [busy, setBusy] = useState(false);
  async function createEnrollment(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    setBusy(true);
    try {
      setToken(
        await post("/nodes/enrollment", {
          name: f.get("name"),
          group_name: f.get("group_name") || "default",
          ttl_seconds: 3600,
        }),
      );
    } catch (e) {
      notice((e as Error).message, true);
    } finally {
      setBusy(false);
    }
  }
  return (
    <>
      <div className="toolbar">
        <SearchInput
          value={query}
          onChange={setQuery}
          placeholder="Find a host…"
        />
        <span className="count-label">{list.length} managed hosts</span>
        {roleOwner(user) && (
          <button
            className="button primary"
            onClick={() => {
              setToken(null);
              setEnroll(true);
            }}
          >
            <Plus size={16} /> Enroll host
          </button>
        )}
      </div>
      <Load loading={r.loading} error={r.error} onRetry={r.reload}>
        {filtered.length ? (
          <div className="host-cards">
            {filtered.map((host) => (
              <button
                key={host.id}
                className="host-card"
                onClick={() => setSelected(host)}
              >
                <div className="host-card-top">
                  <div className="host-symbol">
                    <Server size={24} />
                  </div>
                  <Status
                    value={
                      host.revoked
                        ? "revoked"
                        : hostOnline(host)
                          ? "online"
                          : "offline"
                    }
                  />
                </div>
                <h2>{host.name}</h2>
                <p>
                  {inventory(host).os?.distribution?.pretty_name ||
                    inventory(host).os?.pretty_name ||
                    inventory(host).os?.name ||
                    "No inventory collected"}
                </p>
                <div className="host-card-meta">
                  <span>
                    <Layers3 size={13} />
                    {host.group_name || "Ungrouped"}
                  </span>
                  <span>{relative(host.last_seen)}</span>
                </div>
                <div className="host-card-resources">
                  <Progress label="CPU" value={resource(host, "cpu")} />
                  <Progress label="Memory" value={resource(host, "memory")} />
                  <Progress label="Disk" value={resource(host, "disk")} />
                </div>
                <div className="card-footer">
                  <span>{containers(host).length} containers observed</span>
                  <ArrowUpRight size={16} />
                </div>
              </button>
            ))}
          </div>
        ) : (
          <Panel>
            <Empty
              icon={Server}
              title={query ? "No matching hosts" : "No hosts connected yet"}
              text="Native agents report inventory over authenticated HTTPS. Each host has an individual identity."
            />
          </Panel>
        )}
      </Load>
      {selected && (
        <Modal title={selected.name} wide onClose={() => setSelected(null)}>
          <HostDetail host={selected} />
        </Modal>
      )}
      {enroll && (
        <Modal
          title="Enroll a native Linux host"
          onClose={() => setEnroll(false)}
        >
          <div className="modal-content">
            {token ? (
              <>
                <div className="callout">
                  <ShieldCheck size={18} />
                  <span>
                    Enrollment token created. Copy it now and use it on the
                    intended node over trusted HTTPS. Do not share it in chat.
                  </span>
                </div>
                <JsonView value={token} />
                <p className="muted">
                  Use the node installation instructions in the repository.
                  Enrollment does not grant host-changing operations.
                </p>
              </>
            ) : (
              <form onSubmit={createEnrollment} className="form-grid">
                <label>
                  Host name
                  <input
                    name="name"
                    required
                    maxLength={120}
                    placeholder="e.g. serverhub"
                  />
                </label>
                <label>
                  Host group
                  <input name="group_name" placeholder="e.g. home" />
                </label>
                <p className="muted">
                  Creates a one-time enrollment credential valid for one hour.
                  Configure the agent with your trusted controller URL.
                </p>
                <div className="form-actions">
                  <button className="button primary" disabled={busy}>
                    {busy ? (
                      <Loader2 className="spin" size={16} />
                    ) : (
                      <Plus size={16} />
                    )}{" "}
                    Create enrollment token
                  </button>
                </div>
              </form>
            )}
          </div>
        </Modal>
      )}
    </>
  );
}
function HostDetail({ host }: { host: Json }) {
  const r = useResource<Json>(`/hosts/${host.id}/inventory`),
    notice = useContext(ToastContext),
    [tab, setTab] = useState("inventory");
  const history = useResource<Json[]>(`/hosts/${host.id}/inventory/history`);
  const data = r.data?.inventory || r.data || inventory(host);
  async function refresh() {
    try {
      await post("/jobs", {
        kind: "operation",
        host_id: host.id,
        spec: { operation: "inventory.refresh", arguments: {} },
      });
      notice("Inventory collection queued.");
    } catch (e) {
      notice((e as Error).message, true);
    }
  }
  return (
    <div className="modal-content">
      <div className="detail-meta">
        <Status value={hostOnline(host) ? "online" : "offline"} />
        <span>Last seen {date(host.last_seen)}</span>
        <span className="mono">{host.id}</span>
      </div>
      <div className="tabs">
        <button
          className={tab === "inventory" ? "active" : ""}
          onClick={() => setTab("inventory")}
        >
          Inventory
        </button>
        <button
          className={tab === "identity" ? "active" : ""}
          onClick={() => setTab("identity")}
        >
          Identity
        </button>
        <button
          className={tab === "changes" ? "active" : ""}
          onClick={() => setTab("changes")}
        >
          Changes
        </button>
        <button className="text-button" onClick={refresh}>
          <RefreshCw size={14} /> Refresh inventory
        </button>
      </div>
      {tab === "changes" ? (
        <Load
          loading={history.loading}
          error={history.error}
          onRetry={history.reload}
        >
          <InventoryHistory entries={history.data || []} />
        </Load>
      ) : (
        <Load loading={r.loading} error={r.error} onRetry={r.reload}>
          <JsonView
            value={
              tab === "inventory"
                ? data
                : {
                    id: host.id,
                    name: host.name,
                    group: host.group_name,
                    agent_version: host.agent_version,
                    revoked: host.revoked,
                    last_seen: host.last_seen,
                  }
            }
          />
        </Load>
      )}
    </div>
  );
}

function Topology() {
  const r = useResource<Json>("/topology"),
    h = useResource<Json[]>("/hosts"),
    [selected, setSelected] = useState<Json | null>(null);
  const hosts = normalizedHosts(h.data),
    graph = r.data || {},
    nodes = rows(graph.nodes),
    edges = rows(graph.edges || graph.relationships);
  return (
    <>
      <div className="topology-legend">
        <span>
          <i className="solid-line" /> Verified relationship
        </span>
        <span>
          <i className="dashed-line" /> Inferred relationship
        </span>
        <span className="muted">Select an item to inspect its evidence</span>
      </div>
      <Load
        loading={r.loading || h.loading}
        error={r.error || h.error}
        onRetry={() => {
          void r.reload();
          void h.reload();
        }}
      >
        <Panel className="topology-panel">
          <div className="topology-root">
            <div className="topology-controller">
              <Layers3 size={25} />
              <div>
                <strong>ServerHub controller</strong>
                <small>Authenticated agent reports</small>
              </div>
              <span className="tag">CONTROL PLANE</span>
            </div>
            {hosts.length > 0 && <div className="tree-stem" />}
          </div>
          {hosts.length ? (
            <div className="topology-hosts">
              {hosts.map((host) => (
                <div className="topology-branch" key={host.id}>
                  <button
                    className="topology-node"
                    onClick={() => setSelected(host)}
                  >
                    <div className="node-heading">
                      <Server size={23} />
                      <Status value={hostOnline(host) ? "online" : "offline"} />
                    </div>
                    <strong>{host.name}</strong>
                    <small>
                      {host.group_name || "Ungrouped"} ·{" "}
                      {relative(host.last_seen)}
                    </small>
                    <span className="node-services">
                      <Boxes size={13} />
                      {containers(host).length} containers{" "}
                      <ArrowUpRight size={14} />
                    </span>
                  </button>
                  {containers(host)
                    .slice(0, 4)
                    .map((c, i) => (
                      <button
                        key={c.Id || c.id || i}
                        className="topology-service"
                        onClick={() => setSelected(c)}
                      >
                        <Boxes size={15} />
                        <span>
                          {c.Names?.[0] ||
                            c.name ||
                            c.Name ||
                            c.Id?.slice(0, 12) ||
                            "Container"}
                        </span>
                        <i
                          className={`small-dot ${(c.State || c.state) === "running" ? "good" : ""}`}
                        />
                      </button>
                    ))}
                </div>
              ))}
            </div>
          ) : (
            <Empty
              icon={Network}
              title="No topology observed yet"
              text="Enroll a node to build a graph from real hosts, containers, ports and service dependencies."
            />
          )}
        </Panel>
        {(nodes.length > 0 || edges.length > 0) && (
          <Panel
            title="Knowledge graph relationships"
            action={
              <span className="tag">
                {nodes.length} nodes · {edges.length} edges
              </span>
            }
          >
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Source</th>
                    <th>Relationship</th>
                    <th>Target</th>
                    <th>Evidence class</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {edges.map((e, i) => (
                    <tr key={e.id || i}>
                      <td className="mono">
                        {human(e.source || e.from || e.source_id)}
                      </td>
                      <td>{human(e.type || e.relation || e.kind)}</td>
                      <td className="mono">
                        {human(e.target || e.to || e.target_id)}
                      </td>
                      <td>
                        <span className="tag">
                          {e.verified === true ? "verified" : "inferred"}
                        </span>
                      </td>
                      <td>
                        <button
                          className="text-button"
                          onClick={() => setSelected(e)}
                        >
                          Inspect <ArrowUpRight size={13} />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Panel>
        )}
      </Load>
      {selected && (
        <Modal
          title={selected.name || "Relationship evidence"}
          wide
          onClose={() => setSelected(null)}
        >
          <div className="modal-content">
            <JsonView value={selected} />
          </div>
        </Modal>
      )}
    </>
  );
}

function Docker() {
  const r = useResource<Json[]>("/hosts"),
    [selected, setSelected] = useState<Json | null>(null),
    [state, setState] = useState("all");
  const items: Json[] = normalizedHosts(r.data).flatMap((h) =>
    containers(h).map((c) => ({
      ...c,
      host_name: h.name,
      host_id: h.id,
      _name: c.Names?.join(", ") || c.name || c.Name || c.Id?.slice(0, 12),
      _image: c.Image || c.image,
      _state: c.State || c.state || "unknown",
    })),
  );
  const { query, setQuery, filtered } = useSearch(items, [
    "_name",
    "_image",
    "host_name",
  ]);
  return (
    <>
      <div className="toolbar">
        <SearchInput
          value={query}
          onChange={setQuery}
          placeholder="Search containers or images…"
        />
        <select
          aria-label="Container state"
          value={state}
          onChange={(e) => setState(e.target.value)}
        >
          <option value="all">All states</option>
          <option value="running">Running</option>
          <option value="exited">Exited</option>
        </select>
        <span className="count-label">{items.length} observed containers</span>
        <a className="button secondary" href="#chat">
          <Plus size={15} /> Request a service
        </a>
      </div>
      <Load loading={r.loading} error={r.error} onRetry={r.reload}>
        <Panel>
          {filtered.length ? (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Container</th>
                    <th>Image</th>
                    <th>Host</th>
                    <th>State</th>
                    <th>Health</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {filtered
                    .filter((c) => state === "all" || c._state === state)
                    .map((c, i) => (
                      <tr key={c.Id || c.id || i}>
                        <td>
                          <div className="cell-title">
                            <Boxes size={17} />
                            <strong>{c._name}</strong>
                          </div>
                          <small className="mono">
                            {(c.Id || c.id || "").slice(0, 16)}
                          </small>
                        </td>
                        <td className="mono small">{human(c._image)}</td>
                        <td>{c.host_name}</td>
                        <td>
                          <Status value={c._state} />
                        </td>
                        <td>
                          {human(c.health || c.Health?.Status || c.Status)}
                        </td>
                        <td>
                          <IconButton
                            label={`Inspect ${c._name}`}
                            onClick={() => setSelected(c)}
                          >
                            <ArrowUpRight size={16} />
                          </IconButton>
                        </td>
                      </tr>
                    ))}
                </tbody>
              </table>
            </div>
          ) : (
            <Empty
              icon={Boxes}
              title="No Docker inventory collected"
              text="Docker discovery requires a separately configured, restricted node broker. The AI worker never receives the Docker socket."
            />
          )}
        </Panel>
      </Load>
      {selected && (
        <Modal
          title={selected._name || "Container details"}
          wide
          onClose={() => setSelected(null)}
        >
          <div className="modal-content">
            <JsonView value={selected} />
          </div>
        </Modal>
      )}
    </>
  );
}

function NetworkPage() {
  const r = useResource<Json[]>("/hosts"),
    [tab, setTab] = useState("ports"),
    [hostId, setHostId] = useState("all"),
    [selected, setSelected] = useState<Json | null>(null);
  const hosts = normalizedHosts(r.data),
    chosen = hosts.filter((x) => hostId === "all" || x.id === hostId);
  const portItems: Json[] = chosen.flatMap((h) =>
      listField(inventory(h), "ports").map((p) => ({
        ...p,
        host_name: h.name,
      })),
    ),
    addressItems: Json[] = chosen.flatMap((h) =>
      listField(inventory(h), "addresses").map((p) => ({
        ...p,
        host_name: h.name,
      })),
    );
  const items = tab === "ports" ? portItems : addressItems;
  return (
    <>
      <div className="toolbar">
        <div className="segmented">
          <button
            className={tab === "ports" ? "active" : ""}
            onClick={() => setTab("ports")}
          >
            Listening ports <span>{portItems.length}</span>
          </button>
          <button
            className={tab === "addresses" ? "active" : ""}
            onClick={() => setTab("addresses")}
          >
            IP addresses <span>{addressItems.length}</span>
          </button>
        </div>
        <select
          value={hostId}
          aria-label="Filter network by host"
          onChange={(e) => setHostId(e.target.value)}
        >
          <option value="all">All hosts</option>
          {hosts.map((h) => (
            <option key={h.id} value={h.id}>
              {h.name}
            </option>
          ))}
        </select>
      </div>
      <div className="callout subtle">
        <Globe2 size={18} />
        <span>
          A wildcard listener shows a local bind address. LAN reachability and
          internet exposure require separate verification.
        </span>
      </div>
      <Load loading={r.loading} error={r.error} onRetry={r.reload}>
        <Panel>
          {items.length ? (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Host</th>
                    <th>{tab === "ports" ? "Protocol" : "Interface"}</th>
                    <th>Address</th>
                    <th>{tab === "ports" ? "Port" : "Family / scope"}</th>
                    <th>{tab === "ports" ? "Process / service" : "Prefix"}</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {items.map((p, i) => (
                    <tr key={i}>
                      <td>
                        <Server size={14} /> {p.host_name}
                      </td>
                      <td className="mono">
                        {human(
                          p.protocol || p.proto || p.interface || p.ifname,
                        )}
                      </td>
                      <td className="mono">
                        {human(
                          p.address || p.local_address || p.addr || p.local,
                        )}
                      </td>
                      <td className="mono">
                        {human(p.port || p.local_port || p.family || p.scope)}
                      </td>
                      <td>
                        {human(
                          p.process ||
                            p.service ||
                            p.process_name ||
                            p.prefixlen ||
                            p.prefix,
                        )}
                      </td>
                      <td>
                        <IconButton
                          label="Inspect network evidence"
                          onClick={() => setSelected(p)}
                        >
                          <ArrowUpRight size={15} />
                        </IconButton>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <Empty
              icon={Globe2}
              title={`No ${tab === "ports" ? "listener" : "address"} records available`}
              text="The node agent reports observed addresses and listeners. Collection errors are retained in each host inventory."
            />
          )}
        </Panel>
      </Load>
      {selected && (
        <Modal title="Network evidence" wide onClose={() => setSelected(null)}>
          <div className="modal-content">
            <JsonView value={selected} />
          </div>
        </Modal>
      )}
    </>
  );
}

function Jobs() {
  const r = useResource<Json[]>("/jobs"),
    [selected, setSelected] = useState<Json | null>(null),
    [filter, setFilter] = useState("all");
  const jobs = rows(r.data),
    { query, setQuery, filtered } = useSearch(jobs, [
      "id",
      "kind",
      "state",
      "host_id",
    ]);
  const states = [
    "all",
    "queued",
    "running",
    "succeeded",
    "partial",
    "waiting_approval",
    "retry",
    "failed",
    "paused",
    "cancelled",
  ];
  return (
    <>
      <div className="toolbar">
        <SearchInput
          value={query}
          onChange={setQuery}
          placeholder="Search jobs…"
        />
        <select
          value={filter}
          aria-label="Job state"
          onChange={(e) => setFilter(e.target.value)}
        >
          {states.map((s) => (
            <option key={s} value={s}>
              {s === "all" ? "All states" : s.replaceAll("_", " ")}
            </option>
          ))}
        </select>
        <span className="count-label">{jobs.length} recorded jobs</span>
        <a href="#chat" className="button primary">
          <Plus size={16} /> New AI job
        </a>
      </div>
      <Load loading={r.loading} error={r.error} onRetry={r.reload}>
        <Panel>
          {filtered.length ? (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Task</th>
                    <th>State</th>
                    <th>Progress</th>
                    <th>Attempts</th>
                    <th>Created</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {filtered
                    .filter((j) => filter === "all" || j.state === filter)
                    .map((job) => (
                      <tr
                        key={job.id}
                        className="clickable"
                        onClick={() => setSelected(job)}
                      >
                        <td>
                          <strong className="job-title">
                            {job.spec?.prompt || job.spec?.title || job.kind}
                          </strong>
                          <small className="mono">
                            {job.kind} · {job.id.slice(0, 12)}
                          </small>
                        </td>
                        <td>
                          <Status value={job.state} />
                        </td>
                        <td className="progress-cell">
                          <Progress
                            value={(Number(job.progress) || 0) * 100}
                            pressure={false}
                          />
                        </td>
                        <td>
                          {job.attempts || 0} / {job.max_attempts || 1}
                        </td>
                        <td>{date(job.created_at)}</td>
                        <td>
                          <IconButton
                            label={`Open job ${job.id}`}
                            onClick={() => setSelected(job)}
                          >
                            <ArrowUpRight size={16} />
                          </IconButton>
                        </td>
                      </tr>
                    ))}
                </tbody>
              </table>
            </div>
          ) : (
            <Empty
              icon={Workflow}
              title="No tasks recorded yet"
              text="Submit a request through the assistant. Jobs, events and results are persisted by the controller."
              action={
                <a href="#chat" className="button primary">
                  Start a task <ArrowRight size={15} />
                </a>
              }
            />
          )}
        </Panel>
      </Load>
      {selected && (
        <JobDetail id={selected.id} onClose={() => setSelected(null)} />
      )}
    </>
  );
}
function JobDetail({ id, onClose }: { id: string; onClose: () => void }) {
  const r = useResource<Json>(`/jobs/${id}`),
    events = useResource<Json[]>(`/jobs/${id}/events`),
    notice = useContext(ToastContext),
    [busy, setBusy] = useState(false);
  const job = r.data;
  async function action(name: string) {
    setBusy(true);
    try {
      await post(`/jobs/${id}/${name}`);
      notice(`Job ${name} requested.`);
      await r.reload();
      await events.reload();
    } catch (e) {
      notice((e as Error).message, true);
    } finally {
      setBusy(false);
    }
  }
  return (
    <Modal title="Job execution" wide onClose={onClose}>
      <div className="modal-content">
        <Load loading={r.loading} error={r.error} onRetry={r.reload}>
          {job && (
            <>
              <div className="job-detail-heading">
                <div>
                  <h3>{job.spec?.prompt || job.spec?.title || job.kind}</h3>
                  <small className="mono">{job.id}</small>
                </div>
                <Status value={job.state} />
              </div>
              <div className="job-meta-grid">
                <div>
                  <small>Created</small>
                  <span>{date(job.created_at)}</span>
                </div>
                <div>
                  <small>Attempts</small>
                  <span>
                    {job.attempts} / {job.max_attempts}
                  </span>
                </div>
                <div>
                  <small>Token usage</small>
                  <span>
                    {human(job.tokens_used)} / {human(job.token_budget)}
                  </span>
                </div>
                <div>
                  <small>Cost / budget</small>
                  <span>
                    {human(job.cost_used)} / {human(job.cost_budget)}
                  </span>
                </div>
              </div>
              <Progress
                value={(Number(job.progress) || 0) * 100}
                pressure={false}
              />
              <div className="job-controls">
                {["queued", "running", "retrying"].includes(job.state) && (
                  <button
                    className="button secondary"
                    disabled={busy}
                    onClick={() => action("pause")}
                  >
                    <Pause size={14} />
                    Pause
                  </button>
                )}
                {["paused", "waiting_approval"].includes(job.state) && (
                  <button
                    className="button secondary"
                    disabled={busy}
                    onClick={() => action("resume")}
                  >
                    <Play size={14} />
                    Resume
                  </button>
                )}
                {!["succeeded", "partial", "failed", "cancelled"].includes(job.state) && (
                  <button
                    className="button secondary danger"
                    disabled={busy}
                    onClick={() => action("cancel")}
                  >
                    <X size={14} />
                    Cancel
                  </button>
                )}
              </div>
              {job.error && (
                <Issue
                  error={
                    typeof job.error === "string"
                      ? job.error
                      : JSON.stringify(job.error)
                  }
                />
              )}
              {job.result?.denial && <section className="callout"><div><h4>Permission required</h4><p><strong>{job.result.denial.operation}</strong> · host {job.result.denial.host_id || "none"} · {job.result.denial.environment}</p><p>{job.result.denial.reason}</p><p>{job.result.denial.remediation}</p><a href="#policies" onClick={onClose}>Open scoped autonomy profiles</a></div></section>}
              <h4>Tool-call history</h4>
              {(job.checkpoint?.ai?.evidence || []).map((entry: Json, index: number) => <details key={index}><summary>{index + 1}. {entry.operation}</summary><JsonView value={entry.result} /></details>)}
              <h4>Execution events</h4>
              <Load
                loading={events.loading}
                error={events.error}
                onRetry={events.reload}
              >
                <div className="event-log">
                  {rows(events.data).length ? (
                    rows(events.data).map((e, i) => (
                      <div
                        key={e.id || i}
                        className={`event ${e.level === "error" ? "error" : ""}`}
                      >
                        <time>{date(e.created_at || e.at)}</time>
                        <span className="tag">{e.level || "info"}</span>
                        <div>
                          <p>{e.message}</p>
                          {e.data && Object.keys(e.data).length > 0 && (
                            <details>
                              <summary>Event details</summary>
                              <JsonView value={e.data} />
                            </details>
                          )}
                        </div>
                      </div>
                    ))
                  ) : (
                    <p className="muted">No execution events yet.</p>
                  )}
                </div>
              </Load>
              {job.result && (
                <>
                  <h4>Result</h4>
                  <JsonView value={job.result} />
                </>
              )}
              <details>
                <summary>Submitted job specification</summary>
                <JsonView value={job.spec} />
              </details>
            </>
          )}
        </Load>
      </div>
    </Modal>
  );
}

function Chat() {
  const h = useResource<Json[]>("/hosts"),
    j = useResource<Json[]>("/jobs"),
    notice = useContext(ToastContext),
    [prompt, setPrompt] = useState(""),
    [host, setHost] = useState(""),
    [busy, setBusy] = useState(false),
    [selected, setSelected] = useState<string | null>(null);
  const jobs = rows(j.data).filter(
      (x) => x.kind === "autonomous" && x.spec?.prompt,
    ),
    hosts = normalizedHosts(h.data);
  const suggestions = [
    [
      "Network diagnostics",
      "Investigate why the internet is slow. Start with read-only checks.",
    ],
    [
      "Service health",
      "Review service health and explain any observed failures.",
    ],
    [
      "Security review",
      "Review listening ports and security findings. Explain the evidence and allowed repairs.",
    ],
    [
      "Docker overview",
      "Review Docker health and identify containers that need attention.",
    ],
  ];
  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!prompt.trim()) return;
    setBusy(true);
    try {
      const result = await post("/jobs", {
        kind: "autonomous",
        host_id: host || null,
        spec: { prompt: prompt.trim() },
      });
      setPrompt("");
      await j.reload();
      notice("Task submitted. It continues independently of this browser.");
      if (result.id) setSelected(result.id);
    } catch (e) {
      notice((e as Error).message, true);
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="chat-layout">
      <section className="chat-main">
        <div className="chat-intro">
          <div className="assistant-orb">
            <Sparkles size={29} />
          </div>
          <div className="eyebrow">SERVERHUB ASSISTANT</div>
          <h2>What can I take off your plate?</h2>
          <p>
            Ask a question, investigate a problem or define a task.
            <br />
            Every operation is checked against your permissions.
          </p>
        </div>
        <div className="suggestion-grid">
          {suggestions.map(([title, text], i) => (
            <button key={title} onClick={() => setPrompt(text)}>
              <span>
                {i === 0 ? (
                  <Globe2 size={18} />
                ) : i === 1 ? (
                  <Activity size={18} />
                ) : i === 2 ? (
                  <Shield size={18} />
                ) : (
                  <Boxes size={18} />
                )}
              </span>
              <strong>{title}</strong>
              <small>{text}</small>
              <ArrowUpRight size={14} />
            </button>
          ))}
        </div>
        <form className="chat-composer" onSubmit={submit}>
          <label className="sr-only" htmlFor="chat-prompt">
            Describe your task
          </label>
          <textarea
            id="chat-prompt"
            placeholder="Ask ServerHub to investigate, explain or take action…"
            value={prompt}
            onChange={(e) => setPrompt(e.target.value)}
            maxLength={16000}
            required
            rows={4}
            onKeyDown={(e) => {
              if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
                e.preventDefault();
                e.currentTarget.form?.requestSubmit();
              }
            }}
          />
          <div className="composer-bottom">
            <label>
              <Server size={15} />
              <select
                aria-label="Target host"
                value={host}
                onChange={(e) => setHost(e.target.value)}
              >
                <option value="">Controller (no host selected)</option>
                {hosts.map((h) => (
                  <option key={h.id} value={h.id}>
                    {h.name}
                  </option>
                ))}
              </select>
            </label>
            <button
              className="button primary"
              disabled={busy || !prompt.trim()}
            >
              {busy ? (
                <Loader2 size={16} className="spin" />
              ) : (
                <Send size={16} />
              )}
              Submit task
            </button>
          </div>
        </form>
        <div className="chat-footnote">
          <LockKeyhole size={13} />
          <span>
            Identity-bound authorization · Credentials stay out of prompts ·
            Ctrl + Enter to submit
          </span>
        </div>
        {h.error && <Issue error={h.error} onRetry={h.reload} />}
      </section>
      <aside className="chat-history">
        <div className="panel-heading">
          <h2>Previous requests</h2>
          <span className="tag">{jobs.length}</span>
        </div>
        <Load loading={j.loading} error={j.error} onRetry={j.reload}>
          {jobs.length ? (
            <div className="request-list">
              {jobs.slice(0, 30).map((job) => (
                <button key={job.id} onClick={() => setSelected(job.id)}>
                  <MessageSquare size={15} />
                  <div>
                    <strong>{job.spec.prompt}</strong>
                    <small>{date(job.created_at)}</small>
                    <Status value={job.state} />
                  </div>
                  <ChevronRight size={14} />
                </button>
              ))}
            </div>
          ) : (
            <Empty
              icon={MessageSquare}
              title="A clean slate"
              text="Your persisted AI requests will appear here."
            />
          )}
        </Load>
      </aside>
      {selected && (
        <JobDetail id={selected} onClose={() => setSelected(null)} />
      )}
    </div>
  );
}

function Security() {
  const r = useResource<Json[]>("/findings"),
    [selected, setSelected] = useState<Json | null>(null),
    [severity, setSeverity] = useState("all"),
    notice = useContext(ToastContext),
    [busy, setBusy] = useState(false);
  const findings = rows(r.data),
    { query, setQuery, filtered } = useSearch(findings, [
      "title",
      "service",
      "host_id",
      "severity",
      "description",
    ]);
  async function investigate(finding: Json) {
    setBusy(true);
    try {
      await post("/jobs", {
        kind: "autonomous",
        host_id: finding.host_id,
        spec: {
          prompt: `Investigate security finding ${finding.id}: ${finding.title || finding.service || ""}. Verify the evidence and explain remediation options. Perform changes only when explicitly authorized by an active policy.`,
        },
      });
      notice("Security investigation queued.");
    } catch (e) {
      notice((e as Error).message, true);
    } finally {
      setBusy(false);
    }
  }
  return (
    <>
      <div className="toolbar">
        <SearchInput
          value={query}
          onChange={setQuery}
          placeholder="Search findings…"
        />
        <select
          aria-label="Finding severity"
          value={severity}
          onChange={(e) => setSeverity(e.target.value)}
        >
          <option value="all">All severities</option>
          {["critical", "high", "medium", "low", "info"].map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
        <span className="count-label">
          {findings.length} evidence-backed findings
        </span>
      </div>
      <Load loading={r.loading} error={r.error} onRetry={r.reload}>
        <Panel>
          {filtered.length ? (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Finding</th>
                    <th>Severity</th>
                    <th>Confidence</th>
                    <th>Service</th>
                    <th>Status</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {filtered
                    .filter(
                      (f) => severity === "all" || f.severity === severity,
                    )
                    .map((f) => (
                      <tr
                        key={f.id}
                        onClick={() => setSelected(f)}
                        className="clickable"
                      >
                        <td>
                          <strong>
                            {f.title || f.description || f.key || f.id}
                          </strong>
                          <small className="mono">{f.host_id}</small>
                        </td>
                        <td>
                          <Status value={f.severity} />
                        </td>
                        <td>
                          {typeof f.confidence === "number"
                            ? `${Math.round(f.confidence * 100)}%`
                            : human(f.confidence)}
                        </td>
                        <td>{human(f.service || f.affected_service)}</td>
                        <td>
                          <Status value={f.status || "open"} />
                        </td>
                        <td>
                          <IconButton
                            label="Inspect finding"
                            onClick={() => setSelected(f)}
                          >
                            <ArrowUpRight size={16} />
                          </IconButton>
                        </td>
                      </tr>
                    ))}
                </tbody>
              </table>
            </div>
          ) : (
            <Empty
              icon={ShieldCheck}
              title="No findings returned"
              text="Inspect host collection status before interpreting this as a clean scan. Automated analysis cannot identify every vulnerability."
            />
          )}
        </Panel>
      </Load>
      {selected && (
        <Modal
          title={selected.title || "Security finding"}
          wide
          onClose={() => setSelected(null)}
        >
          <div className="modal-content">
            <div className="detail-meta">
              <Status value={selected.severity} />
              <Status value={selected.status || "open"} />
              <span>Confidence: {human(selected.confidence)}</span>
            </div>
            <p>{selected.description}</p>
            <h4>Evidence and remediation options</h4>
            <JsonView value={selected} />
            <div className="form-actions">
              <button
                className="button primary"
                disabled={busy}
                onClick={() => investigate(selected)}
              >
                {busy ? (
                  <Loader2 size={16} className="spin" />
                ) : (
                  <Sparkles size={16} />
                )}
                Ask AI to investigate
              </button>
            </div>
          </div>
        </Modal>
      )}
    </>
  );
}

function Monitoring() {
  const r = useResource<Json[]>("/hosts"),
    hosts = normalizedHosts(r.data);
  return (
    <Load loading={r.loading} error={r.error} onRetry={r.reload}>
      {hosts.length ? (
        <>
          <div className="monitoring-grid">
            {hosts.map((host) => (
              <Panel
                key={host.id}
                title={host.name}
                action={
                  <Status value={hostOnline(host) ? "online" : "offline"} />
                }
              >
                <div className="monitoring-metrics">
                  {(["cpu", "memory", "disk"] as const).map((name, index) => {
                    const value =
                      name === "cpu" ? loadPerCore(host) : resource(host, name);
                    return (
                      <div key={name} className="monitoring-metric">
                        <div
                          className={`donut ${["blue", "purple", "lime"][index]}`}
                          style={
                            {
                              "--value": `${Math.min(100, Math.max(0, (value || 0) * (name === "cpu" ? 100 : 1)))}%`,
                            } as any
                          }
                        >
                          <span>
                            {value === null
                              ? "—"
                              : name === "cpu"
                                ? `${value.toFixed(2)}×`
                                : `${Math.round(value)}%`}
                          </span>
                        </div>
                        <strong>
                          {name === "cpu"
                            ? "Load / core"
                            : name === "memory"
                              ? "Memory"
                              : "Root disk"}
                        </strong>
                        <small>
                          {value === null
                            ? "Not collected"
                            : name === "cpu"
                              ? "1-minute load"
                              : "Latest sample"}
                        </small>
                      </div>
                    );
                  })}
                </div>
                <MetricHistory hostId={host.id} />
                <div className="monitoring-footer">
                  <Clock3 size={13} /> Reported {date(host.last_seen)}
                </div>
                {inventory(host).errors?.length > 0 && (
                  <div className="collection-warning">
                    <AlertOctagon size={14} />
                    {inventory(host).errors.length} collection warnings ·
                    inspect host inventory
                  </div>
                )}
              </Panel>
            ))}
          </div>
          <div className="callout subtle">
            <Activity size={17} />
            <span>
              Linux load includes runnable tasks and tasks waiting on I/O; load
              per core is not CPU utilization. History contains recorded reports
              only.
            </span>
          </div>
        </>
      ) : (
        <Panel>
          <Empty
            icon={Activity}
            title="Waiting for real measurements"
            text="Managed node reports populate load, memory, storage and collection health."
          />
        </Panel>
      )}
    </Load>
  );
}
function MetricHistory({ hostId }: { hostId: string }) {
  const r = useResource<Json[]>(`/hosts/${hostId}/metrics?limit=60`);
  const samples = rows(r.data).slice().reverse();
  const memory = samples
    .map((row) => ({ at: row.created_at, value: row.metrics?.memory_percent }))
    .filter(
      (row) => typeof row.value === "number" && Number.isFinite(row.value),
    );
  if (r.error)
    return (
      <div className="history">
        <Issue error={r.error} onRetry={r.reload} />
      </div>
    );
  if (r.loading)
    return <div className="history muted">Loading recorded history…</div>;
  if (memory.length < 2)
    return (
      <div className="history muted">
        Memory history needs at least two recorded samples.
      </div>
    );
  const points = memory
    .map(
      (row, index) =>
        `${(index / (memory.length - 1)) * 300},${60 - (row.value / 100) * 56}`,
    )
    .join(" ");
  return (
    <div className="history">
      <div className="history-label">
        <span>Memory history</span>
        <span>{memory.length} samples</span>
      </div>
      <svg
        viewBox="0 0 300 65"
        role="img"
        aria-label={`Memory usage history from ${date(memory[0].at)} to ${date(memory.at(-1)?.at)}`}
      >
        <line x1="0" x2="300" y1="60" y2="60" stroke="#35465f" />
        <polyline
          points={points}
          fill="none"
          stroke="#bdaceb"
          strokeWidth="2"
          vectorEffect="non-scaling-stroke"
        />
      </svg>
      <div className="history-label">
        <span>{date(memory[0].at)}</span>
        <span>{date(memory.at(-1)?.at)}</span>
      </div>
    </div>
  );
}

function Policies() {
  const r = useResource<Json[]>("/policies"),
    h = useResource<Json[]>("/hosts"),
    user = useContext(UserContext),
    notice = useContext(ToastContext),
    [add, setAdd] = useState(false),
    [selected, setSelected] = useState<Json | null>(null),
    [busy, setBusy] = useState(false);
  async function create(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setBusy(true);
    const f = new FormData(e.currentTarget);
    try {
      await post("/policies", {
        name: f.get("name"),
        role: f.get("role") || null,
        subject_id: f.get("subject_id") || null,
        host_id: f.get("host_id") || null,
        project: f.get("project") || null,
        operations: String(f.get("operations"))
          .split(/[,\n]/)
          .map((s) => s.trim())
          .filter(Boolean),
        constraints: JSON.parse(String(f.get("constraints") || "{}")),
        expires_at: new Date(String(f.get("expires_at"))).toISOString(),
        production: f.get("production") === "on",
      });
      notice("Policy created. Operations remain checked at execution.");
      setAdd(false);
      await r.reload();
    } catch (e) {
      notice((e as Error).message, true);
    } finally {
      setBusy(false);
    }
  }
  return (
    <>
      {roleOwner(user) && <ProfileSetup />}
      <div className="toolbar">
        <div className="scope-note">
          <Shield size={17} />
          Only an owner can grant or revoke execution permissions.
        </div>
        {roleOwner(user) && (
          <button className="button primary" onClick={() => setAdd(true)}>
            <Plus size={16} />
            Create policy
          </button>
        )}
      </div>
      <Load loading={r.loading} error={r.error} onRetry={r.reload}>
        <Panel>
          {rows(r.data).length ? (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Policy</th>
                    <th>Subject</th>
                    <th>Scope</th>
                    <th>Operations</th>
                    <th>Expires</th>
                    <th>Status</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {rows(r.data).map((p) => (
                    <tr key={p.id}>
                      <td>
                        <strong>{p.name}</strong>
                        {p.production && (
                          <small className="production-label">
                            Production release enabled
                          </small>
                        )}
                      </td>
                      <td>
                        {p.role || p.subject_id || p.user_id || "Unspecified"}
                      </td>
                      <td>
                        {p.host_id
                          ? `Host ${p.host_id.slice(0, 8)}`
                          : "All permitted hosts"}
                        {p.project && <small>{p.project}</small>}
                      </td>
                      <td>
                        <div className="tag-list">
                          {(p.operations || [])
                            .slice(0, 3)
                            .map((op: string) => (
                              <span key={op} className="tag mono">
                                {op}
                              </span>
                            ))}
                          {p.operations?.length > 3 && (
                            <span className="tag">
                              +{p.operations.length - 3}
                            </span>
                          )}
                        </div>
                      </td>
                      <td>{date(p.expires_at)}</td>
                      <td>
                        <Status value={p.enabled ? "enabled" : "disabled"} />
                      </td>
                      <td>
                        <IconButton
                          label="Inspect policy"
                          onClick={() => setSelected(p)}
                        >
                          <ArrowUpRight size={16} />
                        </IconButton>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <Empty
              icon={LockKeyhole}
              title="No execution grants configured"
              text="Grant narrowly scoped operations with an explicit expiry. Requests do not create permissions by themselves."
            />
          )}
        </Panel>
      </Load>
      {selected && (
        <Modal
          title={selected.name || "Policy"}
          wide
          onClose={() => setSelected(null)}
        >
          <div className="modal-content">
            <JsonView value={selected} />
            {roleOwner(user) && selected.enabled && (
              <div className="form-actions">
                <button
                  className="button destructive"
                  disabled={busy}
                  onClick={async () => {
                    setBusy(true);
                    try {
                      await patch(`/policies/${selected.id}`, {
                        enabled: false,
                      });
                      notice("Policy revoked.");
                      setSelected(null);
                      await r.reload();
                    } catch (e) {
                      notice((e as Error).message, true);
                    } finally {
                      setBusy(false);
                    }
                  }}
                >
                  Revoke policy
                </button>
              </div>
            )}
          </div>
        </Modal>
      )}
      {add && (
        <Modal
          title="Create an expiring execution policy"
          onClose={() => setAdd(false)}
        >
          <form className="modal-content form-grid" onSubmit={create}>
            <label>
              Policy name
              <input
                name="name"
                required
                placeholder="e.g. Household diagnostics"
              />
            </label>
            <div className="form-row">
              <label>
                Role
                <select name="role">
                  <option value="">Specific user only</option>
                  {["owner", "administrator", "adult", "user", "readonly"].map(
                    (x) => (
                      <option key={x} value={x}>
                        {x === "user" ? "standard user" : x}
                      </option>
                    ),
                  )}
                </select>
              </label>
              <label>
                User ID (optional)
                <input name="subject_id" placeholder="Identity UUID" />
              </label>
            </div>
            <div className="form-row">
              <label>
                Host
                <select name="host_id">
                  <option value="">All hosts in scope</option>
                  {rows(h.data).map((x) => (
                    <option value={x.id} key={x.id}>
                      {x.name}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                Project (optional)
                <input name="project" placeholder="jarvis" />
              </label>
            </div>
            <label>
              Allowed operations
              <textarea
                name="operations"
                required
                rows={3}
                placeholder={"inventory.refresh\nnetwork.diagnose"}
              />
              <small>
                Exact operation names, one per line or separated by commas.
                Avoid broad grants.
              </small>
            </label>
            <label>
              Argument constraints (JSON)
              <textarea
                className="mono"
                name="constraints"
                defaultValue="{}"
                rows={3}
              />
            </label>
            <label>
              Expires at
              <input
                name="expires_at"
                type="datetime-local"
                required
                min={new Date().toISOString().slice(0, 16)}
              />
            </label>
            <label className="checkbox-label">
              <input type="checkbox" name="production" />
              Explicitly allow production operations in this scope
            </label>
            <div className="form-actions">
              <button
                className="button secondary"
                type="button"
                onClick={() => setAdd(false)}
              >
                Cancel
              </button>
              <button className="button primary" disabled={busy}>
                {busy ? (
                  <Loader2 className="spin" size={16} />
                ) : (
                  <LockKeyhole size={16} />
                )}
                Create policy
              </button>
            </div>
          </form>
        </Modal>
      )}
    </>
  );
}

function UserAdmin() {
  const r = useResource<Json[]>("/users"),
    user = useContext(UserContext),
    notice = useContext(ToastContext),
    [add, setAdd] = useState(false),
    [busy, setBusy] = useState(false);
  async function create(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setBusy(true);
    const f = new FormData(e.currentTarget);
    try {
      await post("/users", {
        username: f.get("username"),
        password: f.get("password"),
        role: f.get("role"),
      });
      notice("User created.");
      setAdd(false);
      await r.reload();
    } catch (e) {
      notice((e as Error).message, true);
    } finally {
      setBusy(false);
    }
  }
  return (
    <>
      <div className="toolbar">
        <span className="scope-note">
          <Users size={17} />
          Authenticated identities determine access, including in AI chat.
        </span>
        {roleOwner(user) && (
          <button className="button primary" onClick={() => setAdd(true)}>
            <Plus size={16} />
            Add user
          </button>
        )}
      </div>
      <Load loading={r.loading} error={r.error} onRetry={r.reload}>
        <Panel>
          {rows(r.data).length ? (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>User</th>
                    <th>Role</th>
                    <th>Status</th>
                    <th>Created</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {rows(r.data).map((u) => (
                    <tr key={u.id}>
                      <td>
                        <div className="user-cell">
                          <div className="avatar">
                            {u.username.slice(0, 2).toUpperCase()}
                          </div>
                          <div>
                            <strong>
                              {u.username}
                              {u.id === user?.id && (
                                <span className="you-tag">YOU</span>
                              )}
                            </strong>
                            <small className="mono">{u.id}</small>
                          </div>
                        </div>
                      </td>
                      <td>
                        <span className="tag">
                          {u.role?.replaceAll("_", " ")}
                        </span>
                      </td>
                      <td>
                        <Status value={u.enabled ? "enabled" : "disabled"} />
                      </td>
                      <td>{date(u.created_at)}</td>
                      <td>
                        {roleOwner(user) && u.id !== user?.id && u.enabled && (
                          <button
                            className="text-button danger"
                            disabled={busy}
                            onClick={async () => {
                              if (
                                !window.confirm(
                                  `Disable access for ${u.username}?`,
                                )
                              )
                                return;
                              setBusy(true);
                              try {
                                await patch(`/users/${u.id}`, {
                                  enabled: false,
                                });
                                notice("User disabled.");
                                await r.reload();
                              } catch (e) {
                                notice((e as Error).message, true);
                              } finally {
                                setBusy(false);
                              }
                            }}
                          >
                            Disable access
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <Empty
              icon={Users}
              title="No user records available"
              text="Your identity may not have permission to list other accounts."
            />
          )}
        </Panel>
      </Load>
      <div className="roles-grid">
        {[
          ["owner", "Policies, accounts and control-plane administration"],
          ["administrator", "Operational administration within active grants"],
          ["adult", "Household problem reports and predefined repairs"],
          ["user", "Scoped requests and permitted service information"],
          ["readonly", "Read-only visibility within assigned scope"],
        ].map(([role, description]) => (
          <div key={role}>
            <LockKeyhole size={16} />
            <strong>{role.replaceAll("_", " ")}</strong>
            <p>{description}</p>
          </div>
        ))}
      </div>
      {add && (
        <Modal title="Create a user account" onClose={() => setAdd(false)}>
          <form className="modal-content form-grid" onSubmit={create}>
            <label>
              Username
              <input
                name="username"
                required
                autoComplete="off"
                minLength={3}
                maxLength={120}
              />
            </label>
            <label>
              Initial password
              <input
                name="password"
                type="password"
                required
                autoComplete="new-password"
                minLength={14}
              />
              <small>
                Use at least 14 characters. Share through a trusted private
                channel.
              </small>
            </label>
            <label>
              Role
              <select name="role" defaultValue="readonly">
                {["owner", "administrator", "adult", "user", "readonly"].map(
                  (x) => (
                    <option value={x} key={x}>
                      {x}
                    </option>
                  ),
                )}
              </select>
            </label>
            <div className="form-actions">
              <button
                type="button"
                className="button secondary"
                onClick={() => setAdd(false)}
              >
                Cancel
              </button>
              <button className="button primary" disabled={busy}>
                {busy ? (
                  <Loader2 size={16} className="spin" />
                ) : (
                  <Plus size={16} />
                )}
                Create user
              </button>
            </div>
          </form>
        </Modal>
      )}
    </>
  );
}

function Models() { return <ModelSetup />; }

function Backups() {
  const r = useResource<Json[]>("/backups"),
    recovery = useResource<Json>("/recovery/status"),
    [selected, setSelected] = useState<Json | null>(null);
  const copies: Json[] = [
    ...rows(r.data),
    ...rows(recovery.data?.backups?.backups).map((entry, index) => ({
      ...entry,
      id: entry.id || entry.backup_id || `protected-${index}`,
      kind: entry.kind || "Protected native backup",
      state: entry.state || entry.status || "recorded",
      created_at: entry.created_at || entry.completed_at,
      verification_status: entry.verified_at
        ? "verified"
        : "Inspect verification evidence",
    })),
  ];
  return (
    <>
      <div className="toolbar">
        <div className="scope-note">
          <Shield size={17} />
          Recovery copies are protected from the AI worker.
        </div>
        <span className="tag">Protected maintenance service</span>
      </div>
      {recovery.error && (
        <Issue error={recovery.error} onRetry={recovery.reload} />
      )}
      <Load
        loading={r.loading || recovery.loading}
        error={r.error}
        onRetry={r.reload}
      >
        <Panel>
          {copies.length ? (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Backup / checkpoint</th>
                    <th>Host / scope</th>
                    <th>Status</th>
                    <th>Verification</th>
                    <th>Created</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {copies.map((b) => (
                    <tr key={b.id}>
                      <td>
                        <div className="cell-title">
                          <HardDrive size={17} />
                          <strong>{b.name || b.kind || b.id}</strong>
                        </div>
                        <small className="mono">{b.id}</small>
                      </td>
                      <td>{b.host_id || b.scope || "Controller"}</td>
                      <td>
                        <Status value={b.status || b.state} />
                      </td>
                      <td>
                        <Status
                          value={
                            b.verified || b.verified_at
                              ? "verified"
                              : b.verification_status || "not verified"
                          }
                        />
                      </td>
                      <td>{date(b.created_at)}</td>
                      <td>
                        <IconButton
                          label="Inspect recovery record"
                          onClick={() => setSelected(b)}
                        >
                          <ArrowUpRight size={16} />
                        </IconButton>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <Empty
              icon={HardDrive}
              title="No recovery copies recorded"
              text="Configure a protected backup destination and verify restore procedures before authorizing production changes."
            />
          )}
        </Panel>
      </Load>
      <div className="callout subtle">
        <HardDrive size={18} />
        <span>
          A successful copy is not a successful restore. Inspect checksum and
          restore-test evidence separately. The protected maintenance service
          publishes native backup status when configured.
        </span>
      </div>
      {selected && (
        <Modal
          title="Backup and recovery evidence"
          wide
          onClose={() => setSelected(null)}
        >
          <div className="modal-content">
            <JsonView value={selected} />
            <p className="muted">
              Restores require the protected recovery procedure and an explicit
              operator action. No destructive restore is exposed through chat.
            </p>
          </div>
        </Modal>
      )}
    </>
  );
}

function Records({
  path,
  kind,
}: {
  path: string;
  kind: "audit" | "incidents" | "memory";
}) {
  const r = useResource<Json[]>(path),
    [selected, setSelected] = useState<Json | null>(null),
    { query, setQuery, filtered } = useSearch(rows(r.data), [
      "id",
      "action",
      "title",
      "summary",
      "content",
      "actor",
      "actor_id",
      "status",
      "kind",
      "target",
    ]);
  const isAudit = kind === "audit",
    isMemory = kind === "memory";
  return (
    <>
      <div className="toolbar">
        <SearchInput
          value={query}
          onChange={setQuery}
          placeholder={`Search ${kind === "memory" ? "operational memory" : kind}…`}
        />
        <span className="count-label">
          {rows(r.data).length} records returned
        </span>
        {isAudit && (
          <span className="scope-note">
            <FileText size={15} />
            Append-only operational history
          </span>
        )}
      </div>
      <Load loading={r.loading} error={r.error} onRetry={r.reload}>
        <Panel>
          {filtered.length ? (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>
                      {isAudit
                        ? "Action"
                        : isMemory
                          ? "Knowledge / outcome"
                          : "Incident"}
                    </th>
                    <th>
                      {isAudit ? "Actor" : isMemory ? "Kind" : "Severity"}
                    </th>
                    <th>
                      {isAudit
                        ? "Target"
                        : isMemory
                          ? "Verification"
                          : "Status"}
                    </th>
                    <th>Recorded</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((record, i) => (
                    <tr
                      key={record.id || i}
                      className="clickable"
                      onClick={() => setSelected(record)}
                    >
                      <td>
                        <strong className="record-title">
                          {record.action ||
                            record.title ||
                            record.summary ||
                            record.content ||
                            record.kind ||
                            record.id}
                        </strong>
                        {record.host_id && (
                          <small className="mono">Host {record.host_id}</small>
                        )}
                      </td>
                      <td>
                        {isAudit ? (
                          human(record.actor || record.actor_id)
                        ) : isMemory ? (
                          <span className="tag">
                            {human(record.kind || record.category)}
                          </span>
                        ) : (
                          <Status value={record.severity || "info"} />
                        )}
                      </td>
                      <td>
                        {isAudit ? (
                          <span className="mono small">
                            {human(record.target || record.target_id)}
                          </span>
                        ) : (
                          <Status
                            value={
                              isMemory
                                ? record.verified
                                  ? "verified"
                                  : record.status || "unverified"
                                : record.status || record.state || "open"
                            }
                          />
                        )}
                      </td>
                      <td>
                        {date(
                          record.created_at || record.at || record.observed_at,
                        )}
                      </td>
                      <td>
                        <IconButton
                          label="Inspect record"
                          onClick={() => setSelected(record)}
                        >
                          <ArrowUpRight size={16} />
                        </IconButton>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <Empty
              icon={isAudit ? FileText : isMemory ? Layers3 : AlertOctagon}
              title={
                isAudit
                  ? "No audit records returned"
                  : isMemory
                    ? "Operational knowledge starts with evidence"
                    : "No incidents returned"
              }
              text={
                isAudit
                  ? "Recorded operations appear here as the controller authorizes and executes work."
                  : isMemory
                    ? "Incident findings, verified fixes and failed attempts are stored for future retrieval."
                    : "Observed incidents and their remediation outcomes will be shown here."
              }
            />
          )}
        </Panel>
      </Load>
      {selected && (
        <Modal
          title={selected.action || selected.title || "Record evidence"}
          wide
          onClose={() => setSelected(null)}
        >
          <div className="modal-content">
            <JsonView value={selected} />
          </div>
        </Modal>
      )}
    </>
  );
}

function Integrations() {
  const r = useResource<Json[]>("/integrations"),
    catalog = useResource<Json[]>("/catalog");
  const [selected, setSelected] = useState<Json | null>(null);
  return (
    <>
      <Panel
        title="Configured connections"
        eyebrow="OWNER-REGISTERED ENDPOINTS"
      >
        <Load loading={r.loading} error={r.error} onRetry={r.reload}>
          {rows(r.data).length ? (
            <div className="integration-grid">
              {rows(r.data).map((item, index) => (
                <button
                  className="integration-card"
                  key={item.id || item.name || index}
                  onClick={() => setSelected(item)}
                >
                  <div className="integration-icon">
                    <Layers3 size={22} />
                  </div>
                  <div>
                    <h3>{item.name || item.id || item.kind}</h3>
                    <p>{item.kind || item.type || "Configured adapter"}</p>
                  </div>
                  <ArrowUpRight size={17} />
                  <div className="tag-list">
                    {(item.allowed_operations || item.operations || [])
                      .slice(0, 4)
                      .map((op: string) => (
                        <span className="tag mono" key={op}>
                          {op}
                        </span>
                      ))}
                  </div>
                </button>
              ))}
            </div>
          ) : (
            <Empty
              title="No connections configured"
              text="Register endpoints and environment-based credentials in the protected integration settings. Configuration alone does not verify live connectivity."
            />
          )}
        </Load>
      </Panel>
      <Panel title="Application catalog" eyebrow="PLANS YOU CAN INSPECT">
        <Load
          loading={catalog.loading}
          error={catalog.error}
          onRetry={catalog.reload}
        >
          {rows(catalog.data).length ? (
            <div className="catalog-grid">
              {rows(catalog.data).map((app, index) => (
                <article className="catalog-card" key={app.id || index}>
                  <div className="catalog-symbol">
                    <Boxes size={24} />
                  </div>
                  <h3>{app.name}</h3>
                  <p>{app.description}</p>
                  <div className="tag-list">
                    {(app.capabilities || []).map((capability: string) => (
                      <span className="tag" key={capability}>
                        {capability}
                      </span>
                    ))}
                  </div>
                  <p className="catalog-reason">{app.reason}</p>
                  <button
                    className="text-button"
                    onClick={() => setSelected(app)}
                  >
                    Selection details <ArrowUpRight size={14} />
                  </button>
                </article>
              ))}
            </div>
          ) : (
            <Empty
              icon={Boxes}
              title="No catalog entries returned"
              text="The controller supplies application metadata and deployment limitations."
            />
          )}
        </Load>
      </Panel>
      <div className="callout subtle">
        <Shield size={18} />
        <span>
          Deployments require a reviewed, pinned service definition, a
          configured broker and an active policy. Catalog entries do not
          indicate an installed service.
        </span>
      </div>
      {selected && (
        <Modal
          title={selected.name || selected.id || "Integration details"}
          wide
          onClose={() => setSelected(null)}
        >
          <div className="modal-content">
            <JsonView value={selected} />
          </div>
        </Modal>
      )}
    </>
  );
}
function Projects() {
  const r = useResource<Json[]>("/projects"),
    notice = useContext(ToastContext);
  const [project, setProject] = useState<Json | null>(null),
    [patchText, setPatchText] = useState(""),
    [stage, setStage] = useState(false),
    [busy, setBusy] = useState(false),
    [job, setJob] = useState<string | null>(null);
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!project) return;
    setBusy(true);
    try {
      const result = await post("/jobs", {
        kind: "development",
        project: project.name,
        spec: {
          project: project.name,
          ...(patchText.trim() ? { patch: patchText } : {}),
          stage,
        },
      });
      notice(
        "Development workflow queued. Follow its checks and artifact results.",
      );
      setProject(null);
      setPatchText("");
      setJob(result.id);
    } catch (error) {
      notice((error as Error).message, true);
    } finally {
      setBusy(false);
    }
  }
  return (
    <>
      <div className="callout subtle">
        <Code2 size={18} />
        <span>
          Project repositories, commands and independent checks are configured
          on the controller. A task cannot supply a different executable or
          production target.
        </span>
      </div>
      <Load loading={r.loading} error={r.error} onRetry={r.reload}>
        {rows(r.data).length ? (
          <div className="provider-grid">
            {rows(r.data).map((item) => (
              <Panel
                key={item.name}
                title={item.name}
                action={
                  <span className="tag mono">
                    {item.base_ref || "Configured ref"}
                  </span>
                }
              >
                <dl className="provider-details">
                  <dt>Build steps</dt>
                  <dd>{human(item.build_steps)}</dd>
                  <dt>Test steps</dt>
                  <dd>{human(item.test_steps)}</dd>
                  <dt>Independent checks</dt>
                  <dd>{human(item.independent_checks)}</dd>
                  <dt>Staging checks</dt>
                  <dd>{human(item.staging_checks)}</dd>
                  <dt>Production adapter</dt>
                  <dd>
                    {item.production_deployment
                      ? "Registered"
                      : "Not available"}
                  </dd>
                </dl>
                <button
                  className="button secondary"
                  onClick={() => {
                    setProject(item);
                    setStage(false);
                    setPatchText("");
                  }}
                >
                  <Play size={15} />
                  Run project workflow
                </button>
              </Panel>
            ))}
          </div>
        ) : (
          <Panel>
            <Empty
              icon={Code2}
              title="No development projects registered"
              text="Register a protected project definition with its repository, sandboxed commands and independent checks before submitting a job."
            />
          </Panel>
        )}
      </Load>
      {project && (
        <Modal
          title={`Run ${project.name}`}
          wide
          onClose={() => setProject(null)}
        >
          <form className="modal-content form-grid" onSubmit={submit}>
            <label>
              Proposed patch (optional)
              <textarea
                className="mono"
                value={patchText}
                onChange={(event) => setPatchText(event.target.value)}
                rows={10}
                maxLength={150000}
                placeholder="Paste a unified Git patch, or leave empty to validate the configured source."
              />
            </label>
            <label className="checkbox-label">
              <input
                type="checkbox"
                checked={stage}
                onChange={(event) => setStage(event.target.checked)}
              />
              Include configured staging checks
            </label>
            <p className="muted">
              The worker creates an isolated Git workspace and checks the active
              project policy. Production deployment is a separate release
              operation.
            </p>
            <div className="form-actions">
              <button
                className="button secondary"
                type="button"
                onClick={() => setProject(null)}
              >
                Cancel
              </button>
              <button className="button primary" disabled={busy}>
                {busy ? (
                  <Loader2 className="spin" size={16} />
                ) : (
                  <Play size={16} />
                )}
                Submit workflow
              </button>
            </div>
          </form>
        </Modal>
      )}
      {job && <JobDetail id={job} onClose={() => setJob(null)} />}
    </>
  );
}
