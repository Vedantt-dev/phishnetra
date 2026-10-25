import type { Scan, Verdict } from "../api";
import { VERDICT_LABEL, VERDICTS } from "../tokens";
import { VerdictBadge } from "./VerdictBadge";

export function ScanFeed({ scans, verdict, setVerdict, query, setQuery, onSelect, selected }: {
  scans: Scan[]; verdict: string; setVerdict: (v: string) => void; query: string; setQuery: (q: string) => void;
  onSelect: (s: Scan) => void; selected?: number;
}) {
  return (
    <div className="card overflow-hidden">
      <div className="flex flex-wrap items-center gap-2 border-b border-line p-3">
        <h3 className="mr-auto text-sm font-semibold text-ink">Live scan feed</h3>
        <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Filter URL…"
          className="w-40 rounded-md border border-line bg-transparent px-2 py-1 text-xs text-ink placeholder:text-muted" />
        <select value={verdict} onChange={(e) => setVerdict(e.target.value)} aria-label="Verdict filter"
          className="rounded-md border border-line bg-[var(--surface)] px-2 py-1 text-xs text-ink">
          <option value="">All verdicts</option>
          {VERDICTS.map((v: Verdict) => <option key={v} value={v}>{VERDICT_LABEL[v]}</option>)}
        </select>
      </div>
      <div className="max-h-[460px] overflow-auto">
        <table className="w-full text-left text-sm">
          <thead className="sticky top-0 bg-[var(--surface)] text-xs text-muted">
            <tr>
              <th className="px-3 py-2 font-medium">Time</th>
              <th className="px-3 py-2 font-medium">URL</th>
              <th className="px-3 py-2 font-medium">Verdict</th>
              <th className="px-3 py-2 text-right font-medium">Risk</th>
              <th className="hidden px-3 py-2 text-right font-medium sm:table-cell">ms</th>
            </tr>
          </thead>
          <tbody>
            {scans.map((s) => (
              <tr key={s.scan_id} onClick={() => onSelect(s)}
                className={`cursor-pointer border-t border-line hover:bg-[var(--line)]/40 ${selected === s.scan_id ? "bg-[var(--line)]/60" : ""}`}>
                <td className="whitespace-nowrap px-3 py-2 text-xs text-muted tnum">
                  {new Date(s.created_at + (s.created_at.endsWith("Z") ? "" : "Z")).toLocaleTimeString()}
                </td>
                <td className="max-w-[160px] truncate sm:max-w-[280px] px-3 py-2 font-mono text-xs text-ink" title={s.url}>
                  {s.url}{s.overridden && <span className="ml-1 text-muted" title="User overrode the warning">(overridden)</span>}
                </td>
                <td className="px-3 py-2"><VerdictBadge verdict={s.verdict} /></td>
                <td className="px-3 py-2 text-right text-ink tnum">{Math.round(s.risk)}</td>
                <td className="hidden px-3 py-2 text-right text-xs text-muted tnum sm:table-cell">{Math.round(s.latency_ms)}</td>
              </tr>
            ))}
            {!scans.length && (
              <tr><td colSpan={5} className="px-3 py-10 text-center text-sm text-muted">
                No scans yet. Browse with the extension or scan a URL above.
              </td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
