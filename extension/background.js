// PhishNetra background service worker — the browser-side enforcement point of the
// zero-trust policy. Every top-level navigation is verified before it is trusted.
import { scoreUrl } from "./lib/offline_heuristics.js";

// mode: enforce | monitor. Nothing is scanned until the user accepts the data disclosure (welcome page).
const DEFAULTS = { apiBase: "https://phishnetra-seven.vercel.app", enabled: true, mode: "enforce", consented: false };
const CACHE_TTL_MS = 10 * 60 * 1000;
const API_TIMEOUT_MS = 2500;
const BYPASS_TTL_MS = 30 * 60 * 1000;
const BADGE = {
  ALLOW: ["✓", "#16a34a"], WARN: ["!", "#d97706"], RESTRICT: ["🔒", "#ea580c"], BLOCK: ["✕", "#dc2626"],
};

const cache = new Map(); // url -> {result, expires}

async function settings() {
  return { ...DEFAULTS, ...(await chrome.storage.local.get(Object.keys(DEFAULTS))) };
}

async function api(path, body) {
  const { apiBase } = await settings();
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), API_TIMEOUT_MS);
  try {
    const res = await fetch(apiBase + path, {
      method: body ? "POST" : "GET",
      headers: { "Content-Type": "application/json" },
      body: body ? JSON.stringify(body) : undefined,
      signal: ctrl.signal,
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } finally {
    clearTimeout(timer);
  }
}

function isScannable(url) {
  return /^https?:\/\//i.test(url);
}

async function isApiUrl(url) {
  const { apiBase } = await settings();
  try { return new URL(url).origin === new URL(apiBase).origin && !new URL(url).pathname.startsWith("/demo"); }
  catch { return false; }
}

async function bypassed(url) {
  const host = new URL(url).hostname;
  const { bypass = {} } = await chrome.storage.session.get("bypass");
  return (bypass[host] || 0) > Date.now();
}

async function addBypass(url) {
  const host = new URL(url).hostname;
  const { bypass = {} } = await chrome.storage.session.get("bypass");
  bypass[host] = Date.now() + BYPASS_TTL_MS;
  await chrome.storage.session.set({ bypass });
  // Also lift any blocklist redirect rule for this host for the rest of the session.
  await chrome.declarativeNetRequest.updateSessionRules({
    removeRuleIds: [hashId(host)],
    addRules: [{ id: hashId(host), priority: 10, action: { type: "allow" },
      condition: { requestDomains: [host], resourceTypes: ["main_frame"] } }],
  });
}

function hashId(s) {
  let h = 0;
  for (const c of s) h = (h * 31 + c.charCodeAt(0)) | 0;
  return (Math.abs(h) % 900000) + 100000;
}

async function scanUrl(url) {
  const hit = cache.get(url);
  if (hit && hit.expires > Date.now()) return hit.result;
  let result;
  try {
    result = await api("/api/v1/scan", { url, source: "extension" });
  } catch (err) {
    result = { ...scoreUrl(url), url, layers: [], stage: "offline" };
  }
  cache.set(url, { result, expires: Date.now() + CACHE_TTL_MS });
  return result;
}

async function setTabResult(tabId, result) {
  await chrome.storage.session.set({ [`tab:${tabId}`]: result });
  const [text, color] = BADGE[result.verdict] || ["", "#64748b"];
  chrome.action.setBadgeText({ tabId, text }).catch(() => {});
  chrome.action.setBadgeBackgroundColor({ tabId, color }).catch(() => {});
}

async function redirectToBlocked(tabId, result) {
  const token = crypto.randomUUID();
  await chrome.storage.session.set({ [`blocked:${token}`]: result });
  await chrome.tabs.update(tabId, { url: chrome.runtime.getURL(`blocked/blocked.html?t=${token}`) });
}

async function enforce(tabId, url, result) {
  await setTabResult(tabId, result);
  const { mode } = await settings();
  if (result.verdict === "BLOCK" && mode === "enforce" && !(await bypassed(url))) {
    await redirectToBlocked(tabId, result);
  }
}

// Stage 1: pre-navigation URL verification.
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0 || !isScannable(details.url)) return;
  const { enabled, consented } = await settings();
  if (!enabled || !consented || (await isApiUrl(details.url))) return;
  const result = await scanUrl(details.url);
  await enforce(details.tabId, details.url, result);
});

// Stage 2: post-load DOM verification, plus messages from popup / blocked page.
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    switch (msg.type) {
      case "page-features": {
        const { enabled, consented, mode } = await settings();
        if (!enabled || !consented || (await isApiUrl(msg.payload.url))) return sendResponse({ verdict: "ALLOW", skip: true });
        let result;
        try {
          result = await api("/api/v1/scan/dom", { ...msg.payload, source: "extension" });
        } catch {
          result = (await chrome.storage.session.get(`tab:${sender.tab.id}`))[`tab:${sender.tab.id}`]
            || { ...scoreUrl(msg.payload.url), stage: "offline", layers: [] };
        }
        const bypass = await bypassed(msg.payload.url);
        await enforce(sender.tab.id, msg.payload.url, result);
        return sendResponse({ ...result, mode, bypassed: bypass });
      }
      case "get-tab-result": {
        const key = `tab:${msg.tabId}`;
        return sendResponse((await chrome.storage.session.get(key))[key] || null);
      }
      case "get-blocked": {
        const key = `blocked:${msg.token}`;
        return sendResponse((await chrome.storage.session.get(key))[key] || null);
      }
      case "proceed": {
        await addBypass(msg.url);
        if (msg.scanId) api("/api/v1/override", { scan_id: msg.scanId }).catch(() => {});
        const tabId = sender.tab ? sender.tab.id : msg.tabId;
        await chrome.tabs.update(tabId, { url: msg.url });
        return sendResponse({ ok: true });
      }
      case "override": {
        if (msg.scanId) await api("/api/v1/override", { scan_id: msg.scanId }).catch(() => {});
        return sendResponse({ ok: true });
      }
      case "feedback": {
        cache.clear();
        try { await api("/api/v1/feedback", msg.payload); return sendResponse({ ok: true }); }
        catch (e) { return sendResponse({ ok: false, error: String(e) }); }
      }
      case "rescan": {
        cache.delete(msg.url);
        const result = await scanUrl(msg.url);
        await setTabResult(msg.tabId, result);
        return sendResponse(result);
      }
      case "health": {
        try { return sendResponse(await api("/health")); }
        catch { return sendResponse(null); }
      }
      case "sync-blocklist": {
        return sendResponse(await syncBlocklist());
      }
      default:
        return sendResponse(null);
    }
  })();
  return true; // async response
});

// Zero-latency layer: known-bad domains from the backend blocklist become
// declarativeNetRequest redirect rules, enforced by Chrome before any request is sent.
async function syncBlocklist() {
  try {
    const { domains } = await api("/api/v1/blocklist");
    const existing = await chrome.declarativeNetRequest.getDynamicRules();
    const rules = domains.slice(0, 4500).map((domain, i) => ({
      id: i + 1,
      priority: 1,
      action: { type: "redirect", redirect: { extensionPath: `/blocked/blocked.html?domain=${encodeURIComponent(domain)}` } },
      condition: { requestDomains: [domain], resourceTypes: ["main_frame"] },
    }));
    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: existing.map((r) => r.id),
      addRules: rules,
    });
    await chrome.storage.local.set({ blocklistSyncedAt: Date.now(), blocklistSize: rules.length });
    return { ok: true, size: rules.length };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
}

chrome.runtime.onInstalled.addListener(async ({ reason }) => {
  await chrome.storage.local.set({ ...DEFAULTS, ...(await chrome.storage.local.get(Object.keys(DEFAULTS))) });
  if (reason === "install") chrome.tabs.create({ url: chrome.runtime.getURL("welcome/welcome.html") });
  chrome.alarms.create("sync-blocklist", { periodInMinutes: 30 });
  syncBlocklist();
});
chrome.runtime.onStartup.addListener(syncBlocklist);
chrome.alarms.onAlarm.addListener((a) => a.name === "sync-blocklist" && syncBlocklist());
chrome.tabs.onRemoved.addListener((tabId) => chrome.storage.session.remove(`tab:${tabId}`));
