import { useEffect, useState } from "react";
import { api, post, put, date } from "./api";
import type { Json } from "./api";

export function ModelSetup() {
  const [config, setConfig] = useState<Json>({ kind: "ollama", base_url: "http://127.0.0.1:11434", model: "", allow_insecure_http: false, timeout_seconds: 90 });
  const [models, setModels] = useState<Json[]>([]);
  const [saved, setSaved] = useState<Json>({});
  const [route, setRoute] = useState("default");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  async function reload() {
    const data = await api("/settings/models"); setSaved(data);
    if (data.routes?.default) setConfig(data.routes.default);
  }
  useEffect(() => { reload().catch(e => setError(e.message)); }, []);
  function change(key: string, value: unknown) { setConfig(c => ({ ...c, [key]: value })); setMessage(""); }
  async function run(action: string) {
    setBusy(true); setError(""); setMessage("");
    try {
      const body = { ...config, model: config.model || "__discovery__" };
      if (action !== "discover" && !config.model) throw new Error("Select or enter an installed model first");
      const result = action === "save" ? await put(`/settings/models/${encodeURIComponent(route)}`, body) : await post(`/settings/models/${action}`, body);
      if (action === "discover") { setModels(result.models || []); setMessage(`${result.models?.length || 0} models discovered. Select one, then test it.`); }
      else if (action === "test" && result.ready === false) setError(result.message);
      else setMessage(result.message || result.readiness?.message || "Model route saved; new jobs use it without restarting services.");
      if (action === "save") setSaved(await api("/settings/models"));
    } catch (e) { setError((e as Error).message); } finally { setBusy(false); }
  }
  return <section className="panel setup-panel" aria-label="AI provider setup">
    <h2>Connect an AI provider</h2>
    <p>Use the controller-to-Ollama address, discover installed models, and verify a harmless structured tool call. No model is downloaded and no infrastructure tool runs during this test.</p>
    {error && <p role="alert" className="error-box">{error}</p>}
    {message && <p role="status">{message}</p>}
    <div className="form-grid">
      <label>Provider<select value={config.kind} onChange={e => change("kind", e.target.value)}><option value="ollama">Ollama</option><option value="openai">OpenAI-compatible</option></select></label>
      <label>Endpoint URL<input value={config.base_url} onChange={e => change("base_url", e.target.value)} placeholder="http://192.168.68.20:11434" /></label>
      <label className="check-label"><input type="checkbox" checked={config.allow_insecure_http} onChange={e => change("allow_insecure_http", e.target.checked)} />I trust this exact private HTTP endpoint (literal RFC1918/ULA IP only)</label>
      <label>Installed model<input list="discovered-models" value={config.model} onChange={e => change("model", e.target.value)} /><datalist id="discovered-models">{models.map(m => <option key={m.name} value={m.name} />)}</datalist></label>
      <label>Route name<input value={route} onChange={e => setRoute(e.target.value)} /></label>
      <label>Timeout (seconds)<input type="number" min="1" max="300" value={config.timeout_seconds} onChange={e => change("timeout_seconds", Number(e.target.value))} /></label>
      {config.kind === "openai" && <>
        <label>Credential environment reference<input value={config.api_key_env || ""} onChange={e => change("api_key_env", e.target.value || null)} placeholder="OPENAI_API_KEY" /></label>
        <label>Input price per million tokens<input type="number" min="0" value={config.input_cost_per_million ?? ""} onChange={e => change("input_cost_per_million", Number(e.target.value))} /></label>
        <label>Output price per million tokens<input type="number" min="0" value={config.output_cost_per_million ?? ""} onChange={e => change("output_cost_per_million", Number(e.target.value))} /></label>
      </>}
    </div>
    <p className="muted">Keep Ollama on your trusted network. HTTPS is required for public endpoints and DNS names. API credentials are provisioned separately for both API and worker; never paste keys into chat. A connection test can use up to 128 output tokens and $0.10.</p>
    <div className="toolbar"><button disabled={busy} className="button secondary" onClick={() => run("discover")}>Discover models</button><button disabled={busy} className="button secondary" onClick={() => run("test")}>Test connection & tools</button><button disabled={busy} className="button primary" onClick={() => run("save")}>{busy ? "Checking…" : "Test & save route"}</button></div>
    <p>{saved.configured ? "Default route configured" : "Default route is not configured"}</p>
    {Object.entries(saved.routes || {}).map(([name, value]) => <p key={name}><strong>{name}</strong> · {(value as Json).model} · {(value as Json).base_url} · checked {date(saved.readiness?.[name]?.checked_at)}</p>)}
  </section>;
}

export function ProfileSetup() {
  const [hosts, setHosts] = useState<Json[]>([]), [users, setUsers] = useState<Json[]>([]);
  const [profile, setProfile] = useState("read_only"), [message, setMessage] = useState(""), [error, setError] = useState(""), [busy, setBusy] = useState(false);
  useEffect(() => { Promise.all([api<Json[]>("/hosts"), api<Json[]>("/users")]).then(([h,u]) => { setHosts(h); setUsers(u); }).catch(e => setError(e.message)); }, []);
  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault(); const form = new FormData(event.currentTarget); setBusy(true); setError("");
    const names = (key: string) => String(form.get(key) || "").split(",").map(v => v.trim()).filter(Boolean);
    try {
      const result = await post("/policies/profiles", { profile, subject_id: form.get("subject_id"), host_id: form.get("host_id"), hours: Number(form.get("hours")), project: form.get("project") || null, services: names("services"), containers: names("containers"), network_targets: names("network_targets"), storage_targets: names("storage_targets"), backup_targets: names("backup_targets"), package_targets: names("package_targets"), configuration_targets: names("configuration_targets"), compose_targets: names("compose_targets"), allow_dependency_network: form.get("allow_dependency_network") === "on" });
      setMessage(result.message);
    } catch (e) { setError((e as Error).message); } finally { setBusy(false); }
  }
  return <section className="panel setup-panel"><h2>Delegate an autonomy profile</h2><p>Grant once for a named account and host until expiry. Service/container targets must also be allowed by the node's root-owned broker configuration. These profiles exclude production releases and destructive operations.</p>
    {error && <p role="alert">{error}</p>}{message && <p role="status">{message}</p>}
    <form onSubmit={submit}><div className="form-grid">
      <label>Autonomy profile<select value={profile} onChange={e => setProfile(e.target.value)}><option value="read_only">Read-only autonomy</option><option value="maintenance">Maintenance autonomy</option><option value="development">Development autonomy</option></select></label>
      <label>Authenticated account<select name="subject_id" required><option value="">Select account</option>{users.filter(u => u.enabled !== false).map(u => <option key={u.id} value={u.id}>{u.username} ({u.role})</option>)}</select></label>
      <label>Target host<select name="host_id" required><option value="">Select enrolled host</option>{hosts.filter(h => !h.revoked).map(h => <option key={h.id} value={h.id}>{h.name}</option>)}</select></label>
      <label>Expires after (hours)<input name="hours" type="number" min="1" max="8784" defaultValue="24" required /></label>
      <label>Allowed service names<input name="services" placeholder="example.service, other.service" /></label>
      <label>Approved storage target names<input name="storage_targets" placeholder="data (broker allowlist required)" /></label>
      <label>Allowed fixed network target names<input name="network_targets" placeholder="internet, gateway" /></label>
      {profile === "maintenance" && <><label>Allowed container names<input name="containers" placeholder="homepage, uptime-kuma" /></label><label>Enrolled backup plans<input name="backup_targets" /></label><label>Enrolled package plans<input name="package_targets" /></label><label>Enrolled configuration plans<input name="configuration_targets" /></label><label>Enrolled Compose update plans<input name="compose_targets" /></label></>}
      {profile === "development" && <><label>Registered project<input name="project" required /></label><label className="check-label"><input name="allow_dependency_network" type="checkbox" />Allow dependency installation network in its isolated workspace</label></>}
    </div><button className="button primary" disabled={busy || !hosts.length}>Grant expiring profile</button></form>
    <p className="muted">If a job is already approval-blocked, grant only its intended scope here, then resume that same job. Saved steps are retained.</p>
  </section>;
}

export function DiagnosticsPanel() {
  const [report, setReport] = useState<Json | null>(null), [error, setError] = useState("");
  const reload = () => api("/diagnostics").then(setReport).catch(e => setError(e.message));
  useEffect(() => { reload(); const timer = setInterval(reload, 15000); return () => clearInterval(timer); }, []);
  return <section className="panel setup-panel"><div className="toolbar"><h2>System diagnostics</h2><button className="button secondary" onClick={reload}>Refresh diagnostics</button></div>
    {error && <p role="alert">{error}</p>}
    {!report && !error && <p>Checking controller configuration…</p>}
    {report?.checks?.map((check: Json) => <article className="diagnostic-check" key={check.id}><h3><span className={`tag ${check.status}`}>{check.status}</span> {check.id}</h3><p>{check.message}</p>{check.status !== "ok" && <p><strong>Next step:</strong> {check.remediation}</p>}<details><summary>Evidence and scope</summary><pre>{JSON.stringify(check.evidence, null, 2)}</pre></details></article>)}
  </section>;
}

export function FirstRunSetup() {
  const [step, setStep] = useState(0);
  const titles = ["AI provider", "Host enrollment", "Autonomy", "Health & first job"];
  return <><section className="panel setup-panel"><h2>First-run setup</h2><p>Complete these checks once. Model configuration, hosts and delegated policies persist in PostgreSQL.</p><nav className="toolbar" aria-label="Setup steps">{titles.map((title,index) => <button key={title} className={`button ${index === step ? "primary" : "secondary"}`} aria-current={index === step ? "step" : undefined} onClick={() => setStep(index)}>{index + 1}. {title}</button>)}</nav></section>
    {step === 0 ? <ModelSetup /> : step === 1 ? <section className="panel setup-panel"><h2>Enroll a Linux host</h2><p>Create a one-time enrollment token in Managed hosts. Install the native node, provide its token locally and start serverhub-node. Tokens are consumed once; no shared root SSH identity is used.</p><a className="button primary" href="#hosts">Open host enrollment</a></section> : step === 2 ? <ProfileSetup /> : <><DiagnosticsPanel /><section className="panel setup-panel"><h2>Run the first scoped job</h2><p>Select an enrolled host in AI assistant and request: “Read CPU, memory and disk usage, verify inventory freshness, then explain the measured result.” Keep the host selected; the worker continues after you close the browser.</p><a className="button primary" href="#chat">Open AI assistant</a></section></>}
    <div className="toolbar"><button className="button secondary" disabled={step === 0} onClick={() => setStep(s => s - 1)}>Previous step</button><button className="button primary" disabled={step === 3} onClick={() => setStep(s => s + 1)}>Next step</button></div>
  </>;
}
