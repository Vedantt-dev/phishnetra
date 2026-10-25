// Small rendering helpers shared by the popup and the blocked page.
export const LAYER_LABELS = { reputation: "Reputation", url_model: "URL model", dom_model: "Page model", brand: "Brand" };

export function esc(s) {
  return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}

export function riskColor(score) {
  return score >= 75 ? "var(--block)" : score >= 45 ? "var(--restrict)" : score >= 30 ? "var(--warn)" : "var(--allow)";
}

export function renderLayers(layers) {
  return (layers || []).map((l) => {
    const score = l.available ? Math.round(l.score) : null;
    return `<div class="layer"><span>${esc(LAYER_LABELS[l.name] || l.name)}</span>
      <div class="bar"><i style="width:${score ?? 0}%;background:${riskColor(score ?? 0)}"></i></div>
      <span class="muted" style="text-align:right">${score ?? "—"}</span></div>`;
  }).join("");
}

export function renderReasons(reasons, n = 5) {
  return `<ul class="reasons">${(reasons || []).slice(0, n).map((r) => `<li>${esc(r)}</li>`).join("")}</ul>`;
}
