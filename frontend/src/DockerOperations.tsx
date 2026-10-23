import { useEffect, useState } from "react";
import { api, post } from "./api";
import type { Json } from "./api";

export function DockerOperations() {
  const [hosts, setHosts] = useState<Json[]>([]), [host, setHost] = useState("");
  const [target, setTarget] = useState(""), [backup, setBackup] = useState("");
  const [operation, setOperation] = useState("docker.backup.create");
  const [job, setJob] = useState<Json | null>(null), [error, setError] = useState("");
  const [interval, setIntervalHours] = useState(24), [capabilities, setCapabilities] = useState<Json>({});
  useEffect(() => { if (host) api<Json>(`/hosts/${host}/inventory`).then(data => setCapabilities(data.administration || {})).catch(e => setError(e.message)); }, [host]);
  useEffect(() => { api<Json[]>("/hosts").then(setHosts).catch(e => setError(e.message)); }, []);
  useEffect(() => {
    if (!job?.id || ["succeeded", "partial", "failed", "cancelled", "waiting_approval", "paused"].includes(job.state)) return;
    const timer = window.setInterval(() => api<Json>(`/jobs/${job.id}`).then(setJob).catch(e => setError(e.message)), 2000);
    return () => window.clearInterval(timer);
  }, [job?.id, job?.state]);
  async function submit(scheduled = false) {
    setError("");
    try {
      if (!host || !target) throw new Error("Select a host and exact enrolled plan name");
      const arguments_: Json = { target };
      if (["docker.backup.verify", "docker.restore.plan", "docker.restore.apply"].includes(operation)) arguments_.backup_id = backup;
      const payload = { kind: "operation", host_id: host, spec: { operation, arguments: arguments_ } };
      if (scheduled) {
        await post("/schedules", { ...payload, name: `${target} encrypted Docker backup`, interval_seconds: interval * 3600 });
        setJob({ state: "scheduled", target, interval_hours: interval });
      } else setJob(await post("/jobs", { ...payload, time_limit: 7200 }));
    } catch (e) { setError((e as Error).message); }
  }
  return <section className="panel setup-panel" aria-label="Authorized host operations">
    <h2>Docker backups and authorized maintenance</h2>
    <p>Uses real queued node operations and expiring policies. Plans must first be enrolled locally by root. Restores create isolated resources and never overwrite source volumes.</p>
    {error && <p role="alert">{error}</p>}
    <div className="form-grid">
      <label>Host<select value={host} onChange={e => setHost(e.target.value)}><option value="">Select host</option>{hosts.map(h => <option key={h.id} value={h.id}>{h.name}</option>)}</select></label>
      <label>Enrolled plan<input list="root-enrolled-plans" value={target} onChange={e => setTarget(e.target.value)} placeholder="Exact root-enrolled name" /><datalist id="root-enrolled-plans">{[...(capabilities.docker_backup_plans || []), ...(capabilities.package_plans || []), ...(capabilities.configuration_plans || []), ...(capabilities.compose_updates || [])].map((name, index) => <option key={`${name}-${index}`} value={name} />)}</datalist></label>
      <label>Operation<select value={operation} onChange={e => setOperation(e.target.value)}>
        {["docker.backup.create", "docker.backup.list", "docker.backup.verify", "docker.restore.plan", "docker.restore.apply", "package.plan", "package.apply", "configuration.plan", "configuration.apply", "docker.compose.update"].map(name => <option key={name}>{name}</option>)}
      </select></label>
      {["docker.backup.verify", "docker.restore.plan", "docker.restore.apply"].includes(operation) && <label>Backup ID<input value={backup} onChange={e => setBackup(e.target.value)} /></label>}
      <label>Backup interval (hours)<input type="number" min="1" max="744" value={interval} onChange={e => setIntervalHours(Number(e.target.value))} /></label>
    </div>
    <div className="toolbar"><button className="button primary" onClick={() => submit()}>Queue authorized operation</button>
      <button className="button secondary" disabled={operation !== "docker.backup.create"} onClick={() => submit(true)}>Schedule backup</button></div>
    {(capabilities.transactions || []).length > 0 && <><h3>Recorded operation and rollback history</h3><ul>{capabilities.transactions.map((entry: Json) => <li key={entry.id}>{entry.kind} · {entry.target_name || entry.id} · {entry.state}</li>)}</ul></>}
    {job && <><p role="status">{job.state}{job.id && ` · ${job.id}`}{job.progress !== undefined && ` · ${Math.round(job.progress * 100)}%`}</p>
      {job.error && <p role="alert">{job.error}</p>}<pre>{JSON.stringify(job.result || job, null, 2)}</pre></>}
  </section>;
}
