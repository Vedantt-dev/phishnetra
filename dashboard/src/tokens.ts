import { useEffect, useState } from "react";
import type { Verdict } from "./api";

const NAMES = ["surface", "ink", "ink-2", "muted", "line", "axis", "series-1",
  "st-allow", "st-warn", "st-restrict", "st-block"] as const;
export type Tokens = Record<(typeof NAMES)[number], string>;

function read(): Tokens {
  const css = getComputedStyle(document.documentElement);
  return Object.fromEntries(NAMES.map((n) => [n, css.getPropertyValue(`--${n}`).trim()])) as Tokens;
}

/** Resolved colour tokens for SVG charts; re-read when the OS colour scheme changes. */
export function useTokens(): Tokens {
  const [tokens, setTokens] = useState(read);
  useEffect(() => {
    const mq = matchMedia("(prefers-color-scheme: dark)");
    const update = () => setTokens(read());
    mq.addEventListener("change", update);
    return () => mq.removeEventListener("change", update);
  }, []);
  return tokens;
}

export const VERDICTS: Verdict[] = ["ALLOW", "WARN", "RESTRICT", "BLOCK"];
export const VERDICT_TOKEN: Record<Verdict, keyof Tokens> = {
  ALLOW: "st-allow", WARN: "st-warn", RESTRICT: "st-restrict", BLOCK: "st-block",
};
export const VERDICT_LABEL: Record<Verdict, string> = {
  ALLOW: "Allowed", WARN: "Warned", RESTRICT: "Restricted", BLOCK: "Blocked",
};
export const LAYER_LABEL: Record<string, string> = {
  reputation: "Reputation", url_model: "URL model", dom_model: "DOM model", brand: "Brand",
};
