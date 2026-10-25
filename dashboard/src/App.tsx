import { useCallback, useEffect, useState } from "react";
import { api, liveSocket, type Scan, type Stats } from "./api";
import { HBars } from "./components/HBars";
import { ScanDetail } from "./components/ScanDetail";
import { ScanFeed } from "./components/ScanFeed";
import { StatTile } from "./components/StatTile";
import { Timeline } from "./components/Timeline";
import { LAYER_LABEL } from "./tokens";

const WINDOWS = [7, 14, 30];
// One-click demo for presentations: a mix of benign and phishing-style URLs.
const DEMO_URLS = [
  "https://www.google.com/",
  "https://en.wikipedia.org/wiki/Phishing",
  "http://paypa1-secure-login.xyz/verify/account",
  "https://xn--pypal-4ve.com/signin",
  "https://netflix-billing-update.com/account",
  "http://192.168.13.37/chase/login.php?cmd=verify",
  "https://amazonn.com/",
  "https://login-portal-77.web.app/microsoft/outlook",
  "https://github.com/",
  "https://www.bankofamerica.com.session-77.top/signin",
];

export default function App() {
  const [days, setDays] = useState(14);
  const [stats, setStats] = useState<Stats | null>(null);
  const [scans, setScans] = useState<Scan[]>([]);
  const [verdict, setVerdict] = useState("");
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<Scan | null>(null);
  const [url, setUrl] = useState("");
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [models, setModels] = useState<Awaited<ReturnType<typeof api.models>> | null>(null);

  const refresh = useCallback(async () => {
    try {
      const [s, list] = await Promise.all([api.stats(days), api.scans(verdict, query)]);
      setStats(s);
      setScans(list);
      setError(null);
    } catch (e) {
      setError(`Cannot reach the PhishNetra API (${(e as Error).message}). Is the backend running on :8000?`);
    }
  }, [days, verdict, query]);

  useEffect(() => { refresh(); }, [refresh]);
  useEffect(() => { api.models().then(setModels).catch(() => {}); }, []);
  useEffect(() => {
    let timer: number | undefined;
    const stop = liveSocket(() => {
      window.clearTimeout(timer);
      timer = window.setTimeout(refresh, 300); // coalesce bursts of scans
    });
    return () => { stop(); window.clearTimeout(timer); };
  }, [refresh]);

  const runDemo = async () => {
    setScanning(true);
    try {
      for (const u of DEMO_URLS) await api.scan(u);
      refresh();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setScanning(false);
    }
  };

  const runScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url.trim()) return;
    setScanning(true);
    try {
      setSelected(await api.scan(url.trim()));
      refresh();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setScanning(false);
    }
  };

  const layerData = Object.entries(stats?.layer_avg ?? {}).map(([k, v]) => ({ label: LAYER_LABEL[k] ?? k, value: v }));
  const urlMeta = models?.url_model as { dataset?: string; test_metrics?: { f1?: number; roc_auc?: number } } | null;

  return (
    <div className="mx-auto max-w-7xl px-4 py-6 sm:px-6">
      <header className="mb-6 flex flex-wrap items-center gap-3">
        <img src="/dashboard/logo.png" alt="" className="h-9 w-9" />
        <div className="mr-auto">
          <h1 className="text-xl font-semibold text-ink">PhishNetra Console</h1>
          <p className="text-xs text-ink2">Multi-layered AI-driven zero-trust phishing defence</p>
        </div>
        <div className="flex rounded-lg border border-line p-0.5 text-xs" role="group" aria-label="Time window">
          {WINDOWS.map((w) => (
            <button key={w} onClick={() => setDays(w)}
              className={`rounded-md px-3 py-1 font-medium ${days === w ? "bg-[var(--line)] text-ink" : "text-ink2"}`}>
              {w}d
            </button>
          ))}
        </div>
      </header>

      {error && <div className="card mb-4 border-block/40 p-3 text-sm text-ink">⚠ {error}</div>}

      <form onSubmit={runScan} className="card mb-6 flex flex-col gap-2 p-3 sm:flex-row">
        <input value={url} onChange={(e) => setUrl(e.target.value)} placeholder="Scan any URL, e.g. http://paypa1-secure-login.xyz/verify"
          className="flex-1 rounded-md border border-line bg-transparent px-3 py-2 font-mono text-sm text-ink placeholder:text-muted" />
        <button disabled={scanning} className="rounded-md bg-accent px-4 py-2 text-sm font-semibold text-white disabled:opacity-60">
          {scanning ? "Scanning…" : "Scan URL"}
        </button>
        <button type="button" onClick={runDemo} disabled={scanning}
          className="rounded-md border border-line px-4 py-2 text-sm font-semibold text-ink disabled:opacity-60">
          Run demo scans
        </button>
      </form>

      <section className="mb-6 grid grid-cols-2 gap-3 md:grid-cols-3 lg:grid-cols-6">
        <StatTile label="Scans" value={stats?.total_scans ?? "—"} sub={`last ${days} days`} />
        <StatTile label="Threats mitigated" value={stats?.threats_mitigated ?? "—"} sub="blocked + restricted" />
        <StatTile label="Warnings" value={stats?.verdicts.WARN ?? "—"} />
        <StatTile label="Unique domains" value={stats?.unique_domains ?? "—"} />
        <StatTile label="Avg. decision time" value={stats ? `${stats.avg_latency_ms} ms` : "—"} />
        <StatTile label="User overrides" value={stats?.overrides ?? "—"} sub={`blocklist: ${stats?.blocklist_size ?? 0}`} />
      </section>

      <section className="mb-6 grid gap-4 lg:grid-cols-3">
        <div className="card min-w-0 p-4 lg:col-span-2">
          <h3 className="mb-2 text-sm font-semibold text-ink">Verdicts per day</h3>
          {stats && <Timeline data={stats.timeline} />}
        </div>
        <div className="card min-w-0 p-4">
          <h3 className="mb-1 text-sm font-semibold text-ink">Average layer risk score</h3>
          <p className="mb-2 text-xs text-muted">0–100, across all scans in window</p>
          <HBars data={layerData} valueName="Avg score" max={100} empty="No layer data yet" />
        </div>
      </section>

      <section className="mb-6 grid gap-4 lg:grid-cols-3">
        <div className="min-w-0 lg:col-span-2">
          <ScanFeed scans={scans} verdict={verdict} setVerdict={setVerdict} query={query} setQuery={setQuery}
            onSelect={setSelected} selected={selected?.scan_id} />
        </div>
        <div className="min-w-0 space-y-4">
          {selected ? <ScanDetail scan={selected} onClose={() => setSelected(null)} /> : (
            <div className="card p-5 text-sm text-muted">Select a scan to see its layer-by-layer explanation.</div>
          )}
          <div className="card p-4">
            <h3 className="mb-2 text-sm font-semibold text-ink">Most impersonated brands</h3>
            <HBars data={(stats?.top_brands ?? []).map((b) => ({ label: b.brand, value: b.count }))}
              valueName="Scans" empty="No impersonation attempts seen" />
          </div>
          <div className="card p-4 text-xs text-ink2">
            <h3 className="mb-2 text-sm font-semibold text-ink">Models</h3>
            <p>URL ensemble: {urlMeta ? `${urlMeta.dataset} · F1 ${urlMeta.test_metrics?.f1} · AUC ${urlMeta.test_metrics?.roc_auc}` : "rule fallback"}</p>
            <p>DOM model: {models?.dom_model ? String((models.dom_model as { dataset?: string }).dataset) : "rule fallback"}</p>
          </div>
        </div>
      </section>
    </div>
  );
}
