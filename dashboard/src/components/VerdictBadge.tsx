import type { Verdict } from "../api";
import { VERDICT_LABEL } from "../tokens";

const ICON: Record<Verdict, string> = { ALLOW: "✓", WARN: "!", RESTRICT: "⊘", BLOCK: "✕" };
const BG: Record<Verdict, string> = { ALLOW: "bg-allow", WARN: "bg-warn", RESTRICT: "bg-restrict", BLOCK: "bg-block" };

/** Status is never colour-alone: icon + label + colour. */
export function VerdictBadge({ verdict }: { verdict: Verdict }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-ink whitespace-nowrap">
      <span className={`${BG[verdict]} inline-flex h-4 w-4 items-center justify-center rounded-full text-[10px] font-bold text-white`}
        aria-hidden>{ICON[verdict]}</span>
      {VERDICT_LABEL[verdict]}
    </span>
  );
}
