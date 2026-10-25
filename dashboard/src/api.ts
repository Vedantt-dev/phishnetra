export type Verdict = "ALLOW" | "WARN" | "RESTRICT" | "BLOCK";

export interface Layer {
  name: string;
  score: number | null;
  weight: number;
  contribution: number;
  available: boolean;
  reasons: string[];
  details: Record<string, unknown>;
}

export interface Scan {
  scan_id: number;
  url: string;
  domain: string;
  stage: string;
  risk: number;
  verdict: Verdict;
  trust: string;
  impersonated_brand: string | null;
  reasons: string[];
  layers: Layer[];
  latency_ms: number;
  created_at: string;
  overridden?: boolean;
  source?: string;
}

export interface Stats {
  window_days: number;
  total_scans: number;
  unique_domains: number;
  verdicts: Record<Verdict, number>;
  threats_mitigated: number;
  overrides: number;
  avg_latency_ms: number;
  avg_risk: number;
  timeline: ({ date: string } & Record<Verdict, number>)[];
  top_brands: { brand: string; count: number }[];
  top_threat_domains: { domain: string; count: number }[];
  layer_avg: Record<string, number>;
  feedback: Record<string, number>;
  blocklist_size: number;
}

async function req<T>(path: string, body?: unknown): Promise<T> {
  const res = await fetch(path, {
    method: body ? "POST" : "GET",
    headers: { "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) throw new Error(`${res.status} ${await res.text()}`);
  return res.json();
}

export const api = {
  stats: (days: number) => req<Stats>(`/api/v1/stats?days=${days}`),
  scans: (verdict?: string, q?: string) =>
    req<Scan[]>(`/api/v1/scans?limit=200${verdict ? `&verdict=${verdict}` : ""}${q ? `&q=${encodeURIComponent(q)}` : ""}`),
  scan: (url: string) => req<Scan>("/api/v1/scan", { url, source: "dashboard" }),
  feedback: (url: string, label: "phishing" | "legitimate", scan_id?: number) =>
    req("/api/v1/feedback", { url, label, scan_id }),
  models: () => req<{ url_model: Record<string, unknown> | null; dom_model: Record<string, unknown> | null }>("/api/v1/models"),
  health: () => req<{ status: string; url_model: boolean; dom_model: boolean }>("/health"),
};

/**
 * Live updates: WebSocket when the server supports it (local uvicorn), otherwise polling
 * (serverless hosts such as Vercel cannot hold WebSocket connections open).
 */
export function liveSocket(onScan: (s: Scan | null) => void, pollMs = 5000): () => void {
  let ws: WebSocket | null = null;
  let closed = false;
  let poll: number | undefined;
  const startPolling = () => {
    if (poll === undefined) poll = window.setInterval(() => onScan(null), pollMs);
  };
  const connect = () => {
    const proto = location.protocol === "https:" ? "wss" : "ws";
    let opened = false;
    try {
      ws = new WebSocket(`${proto}://${location.host}/api/v1/ws/live`);
    } catch {
      return startPolling();
    }
    ws.onopen = () => { opened = true; };
    ws.onmessage = (e) => {
      const msg = JSON.parse(e.data);
      if (msg.type === "scan") onScan(msg.scan);
    };
    ws.onclose = () => {
      if (closed) return;
      if (opened) setTimeout(connect, 2000);
      else startPolling();
    };
  };
  connect();
  return () => { closed = true; ws?.close(); window.clearInterval(poll); };
}
