import { esc, renderLayers, renderReasons, riskColor } from "../lib/render.js";

const $ = (id) => document.getElementById(id);
const send = (msg) => chrome.runtime.sendMessage(msg);
const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

function render(r) {
  if (!r) {
    $("main").innerHTML = `<p class="muted">No scan for this tab yet. Only http(s) pages are scanned.</p>`;
    return;
  }
  let host = r.domain;
  try { host = host || new URL(r.url).hostname; } catch { /* keep */ }
  $("main").innerHTML = `
    <div class="summary">
      <div class="gauge" style="color:${riskColor(r.risk)}">${Math.round(r.risk)}</div>
      <div><div class="host">${esc(host)}</div>
        <span class="chip ${r.verdict}">${r.verdict}</span>
        <span class="muted"> ${esc(r.trust || "")}${r.offline ? " · offline heuristics" : ""}${r.stage ? " · " + esc(r.stage) + " stage" : ""}</span>
        ${r.impersonated_brand ? `<div class="muted">Impersonates <b>${esc(r.impersonated_brand)}</b></div>` : ""}
      </div>
    </div>
    ${renderLayers(r.layers)}
    ${renderReasons(r.reasons)}`;
}

const { consented } = await chrome.storage.local.get("consented");
if (!consented) {
  $("main").innerHTML = `<p>PhishNetra is not active yet.</p>
    <button class="primary" id="setup">Finish setup</button>`;
  $("setup").onclick = () => chrome.tabs.create({ url: chrome.runtime.getURL("welcome/welcome.html") });
} else {
  render(await send({ type: "get-tab-result", tabId: tab.id }));
}

const health = await send({ type: "health" });
$("api").className = "dot " + (health ? "up" : "down");
$("api").title = health ? "API connected" : "API unreachable — using offline heuristics";

$("rescan").onclick = async () => render(await send({ type: "rescan", url: tab.url, tabId: tab.id }));
for (const [id, label] of [["report", "phishing"], ["safe", "legitimate"]]) {
  $(id).onclick = async () => {
    const res = await send({ type: "feedback", payload: { url: tab.url, label } });
    $(id).textContent = res?.ok ? "Thanks ✓" : "Failed";
  };
}

const s = await chrome.storage.local.get(["apiBase", "enabled", "mode"]);
$("apiBase").value = s.apiBase;
$("enabled").checked = s.enabled !== false;
$("enforce").checked = (s.mode || "enforce") === "enforce";
$("dash").href = ($("apiBase").value || "").replace(/\/$/, "") + "/dashboard/";
$("save").onclick = async () => {
  await chrome.storage.local.set({
    apiBase: $("apiBase").value.replace(/\/$/, ""),
    enabled: $("enabled").checked,
    mode: $("enforce").checked ? "enforce" : "monitor",
  });
  $("settingsMsg").textContent = "Saved.";
};
$("sync").onclick = async () => {
  const r = await send({ type: "sync-blocklist" });
  $("settingsMsg").textContent = r?.ok ? `Blocklist synced: ${r.size} domains` : `Sync failed: ${r?.error}`;
};
