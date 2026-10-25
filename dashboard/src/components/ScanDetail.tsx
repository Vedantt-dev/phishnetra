import { useState } from "react";
import { api, type Scan } from "../api";
import { LAYER_LABEL, useTokens } from "../tokens";
import { VerdictBadge } from "./VerdictBadge";

/** Explainability view: how each layer contributed to the fused zero-trust risk score. */
export function ScanDetail({ scan, onClose }: { scan: Scan; onClose?: () => void }) {
  const t = useTokens();
  const [sent, setSent] = useState<string | null>(null);
  const send = async (label: "phishing" | "legitimate") => {
    await api.feedback(scan.url, label, scan.scan_id);
    setSent(label);
  };
  return (
    <div className="card p-5">
      <div className="flex items-start gap-3">
        <div className="min-w-0 flex-1">
          <div className="break-all font-mono text-xs text-ink2">{scan.url}</div>
          <div className="mt-2 flex flex-wrap items-center gap-3">
            <VerdictBadge verdict={scan.verdict} />
            <span className="text-sm text-ink2">risk <b className="text-ink tnum">{scan.risk.toFixed(1)}</b>/100</span>
            <span className="text-xs text-muted">trust: {scan.trust} · {scan.stage} stage · {scan.latency_ms} ms</span>
            {scan.impersonated_brand && <span className="text-xs text-ink2">impersonates <b>{scan.impersonated_brand}</b></span>}
          </div>
        </div>
        {onClose && <button onClick={onClose} className="text-muted hover:text-ink" aria-label="Close">✕</button>}
      </div>

      <h4 className="mt-5 text-xs font-semibold uppercase tracking-wide text-muted">Layer contributions</h4>
      <div className="mt-2 space-y-2">
        {scan.layers.map((l) => (
          <div key={l.name} className="grid grid-cols-[84px_1fr_64px] items-center gap-3 text-sm">
            <span className="text-ink2">{LAYER_LABEL[l.name] ?? l.name}</span>
            <div className="h-2 rounded bg-[var(--line)]" title={l.available ? `score ${l.score}` : "not evaluated"}>
              {l.available && (
                <div className="h-2 rounded" style={{ width: `${l.score}%`, background: t["series-1"] }} />
              )}
            </div>
            <span className="text-right text-xs text-muted tnum">
              {l.available ? `${Math.round(l.score!)} × ${l.weight.toFixed(2)}` : "n/a"}
            </span>
          </div>
        ))}
      </div>

      <h4 className="mt-5 text-xs font-semibold uppercase tracking-wide text-muted">Evidence</h4>
      <ul className="mt-2 list-disc space-y-1 pl-5 text-sm text-ink">
        {scan.reasons.map((r) => <li key={r}>{r}</li>)}
      </ul>

      <div className="mt-5 flex flex-wrap gap-2">
        <button onClick={() => send("phishing")} className="rounded-md border border-line px-3 py-1.5 text-xs font-semibold text-ink hover:bg-[var(--line)]">
          {sent === "phishing" ? "Added to blocklist ✓" : "Confirm phishing"}
        </button>
        <button onClick={() => send("legitimate")} className="rounded-md border border-line px-3 py-1.5 text-xs font-semibold text-ink hover:bg-[var(--line)]">
          {sent === "legitimate" ? "Marked legitimate ✓" : "False positive"}
        </button>
      </div>
    </div>
  );
}
