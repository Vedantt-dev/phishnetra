import { Bar, BarChart, LabelList, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { useTokens } from "../tokens";
import { ChartTooltip } from "./ChartTooltip";

/** Single-series horizontal bars (magnitude by category), direct-labelled. */
export function HBars({ data, valueName, max, empty }: {
  data: { label: string; value: number }[]; valueName: string; max?: number; empty: string;
}) {
  const t = useTokens();
  if (!data.length) return <p className="py-8 text-center text-sm text-muted">{empty}</p>;
  return (
    <ResponsiveContainer width="100%" height={Math.max(120, data.length * 34)}>
      <BarChart data={data} layout="vertical" margin={{ top: 0, right: 36, bottom: 0, left: 0 }} barCategoryGap={8}>
        <XAxis type="number" hide domain={[0, max ?? "auto"]} />
        <YAxis type="category" dataKey="label" width={92} tick={{ fill: t["ink-2"], fontSize: 12 }}
          tickLine={false} axisLine={{ stroke: t.axis }} />
        <Tooltip content={<ChartTooltip />} cursor={{ fill: t.line, opacity: 0.5 }} />
        <Bar dataKey="value" name={valueName} fill={t["series-1"]} radius={[0, 4, 4, 0]} isAnimationActive={false}>
          <LabelList dataKey="value" position="right" fill={t["ink-2"]} fontSize={12} />
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}
