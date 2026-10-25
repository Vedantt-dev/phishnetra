import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { Stats } from "../api";
import { useTokens, VERDICT_LABEL, VERDICT_TOKEN, VERDICTS } from "../tokens";
import { ChartTooltip } from "./ChartTooltip";

export function Timeline({ data }: { data: Stats["timeline"] }) {
  const t = useTokens();
  const rows = data.map((d) => ({ ...d, label: d.date.slice(5) }));
  return (
    <div>
      <div className="mb-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-ink2" role="list" aria-label="Legend">
        {VERDICTS.map((v) => (
          <span key={v} role="listitem" className="inline-flex items-center gap-1.5">
            <span className="h-2.5 w-2.5 rounded-sm" style={{ background: t[VERDICT_TOKEN[v]] }} />
            {VERDICT_LABEL[v]}
          </span>
        ))}
      </div>
      <ResponsiveContainer width="100%" height={220}>
        <BarChart data={rows} margin={{ top: 4, right: 4, bottom: 0, left: -20 }} barCategoryGap="22%">
          <CartesianGrid vertical={false} stroke={t.line} />
          <XAxis dataKey="label" tick={{ fill: t.muted, fontSize: 11 }} tickLine={false} axisLine={{ stroke: t.axis }} />
          <YAxis allowDecimals={false} tick={{ fill: t.muted, fontSize: 11 }} tickLine={false} axisLine={false} />
          <Tooltip content={<ChartTooltip />} cursor={{ fill: t.line, opacity: 0.5 }} />
          {VERDICTS.map((v, i) => (
            <Bar key={v} dataKey={v} name={VERDICT_LABEL[v]} stackId="v" fill={t[VERDICT_TOKEN[v]]}
              stroke={t.surface} strokeWidth={1} radius={i === VERDICTS.length - 1 ? [4, 4, 0, 0] : 0}
              isAnimationActive={false} />
          ))}
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
