import { renderLayers, renderReasons } from "../lib/render.js";

const $ = (id) => document.getElementById(id);
const params = new URLSearchParams(location.search);
let result = null;

if (params.get("t")) {
  result = await chrome.runtime.sendMessage({ type: "get-blocked", token: params.get("t") });
} else if (params.get("domain")) {
  // Redirected by a declarativeNetRequest blocklist rule (zero-latency path).
  result = { url: `https://${params.get("domain")}/`, risk: 100, verdict: "BLOCK",
    reasons: ["Domain is on the PhishNetra threat-intelligence blocklist"], layers: [] };
}

if (result) {
  $("url").textContent = result.url;
  $("risk").textContent = `${Math.round(result.risk)}/100`;
  if (result.impersonated_brand) $("brand").textContent = `Impersonating ${result.impersonated_brand}`;
  $("layers").innerHTML = renderLayers(result.layers);
  $("reasons").innerHTML = renderReasons(result.reasons, 6);
} else {
  $("url").textContent = "(unknown — scan details expired)";
}

$("safety").onclick = async () => {
  const tab = await chrome.tabs.getCurrent();
  chrome.tabs.update(tab.id, { url: "chrome://newtab" });
};
$("report").onclick = async () => {
  await chrome.runtime.sendMessage({ type: "feedback", payload: { url: result?.url, label: "phishing", scan_id: result?.scan_id } });
  $("report").textContent = "Reported ✓";
};
$("ack").onchange = (e) => { $("proceed").disabled = !e.target.checked; };
$("proceed").onclick = () => {
  if (result?.url) chrome.runtime.sendMessage({ type: "proceed", url: result.url, scanId: result.scan_id });
};
