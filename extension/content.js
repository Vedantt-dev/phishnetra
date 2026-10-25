// PhishNetra content script: extracts PhiUSIIL-aligned DOM features for the Layer-3 model,
// then applies the policy verdict in-page (WARN banner, RESTRICT credential guard).
(() => {
  if (window.__phishnetra) return;
  window.__phishnetra = true;

  const SOCIAL = /(facebook|twitter|x|linkedin|instagram|youtube|tiktok|pinterest)\.com/i;
  let verdict = null;
  let credentialsUnlocked = false;
  let rescanned = false;

  function sameSite(a, b) {
    const tail = (h) => h.split(".").slice(-2).join(".");
    return a === b || tail(a) === tail(b);
  }

  function extractFeatures() {
    const html = document.documentElement.outerHTML;
    const lines = html.split("\n");
    const host = location.hostname;
    const text = document.body ? document.body.innerText : "";
    const lower = text.toLowerCase();
    let self = 0, empty = 0, external = 0, social = false;
    for (const a of document.querySelectorAll("a[href]")) {
      const raw = a.getAttribute("href").trim();
      if (!raw || raw === "#" || raw.startsWith("#") || /^javascript:/i.test(raw)) { empty++; continue; }
      try {
        const u = new URL(raw, location.href);
        if (SOCIAL.test(u.hostname)) social = true;
        if (sameSite(u.hostname, host)) self++; else external++;
      } catch { empty++; }
    }
    let externalForm = false;
    for (const f of document.forms) {
      const action = f.getAttribute("action");
      if (!action) continue;
      try {
        const u = new URL(action, location.href);
        if (/^https?:$/.test(u.protocol) && !sameSite(u.hostname, host)) externalForm = true;
      } catch { /* ignore malformed action */ }
    }
    const inlineJs = [...document.scripts].filter((s) => !s.src).map((s) => s.textContent).join("\n");
    const favicon = document.querySelector("link[rel~='icon']");
    return {
      url: location.href,
      title: document.title || "",
      text: text.slice(0, 5000),
      favicon_url: favicon ? favicon.href : null,
      features: {
        LineOfCode: lines.length,
        LargestLineLength: Math.max(...lines.map((l) => l.length)),
        HasFavicon: favicon ? 1 : 0,
        IsResponsive: document.querySelector("meta[name='viewport']") ? 1 : 0,
        HasDescription: document.querySelector("meta[name='description']") ? 1 : 0,
        NoOfPopup: (inlineJs.match(/window\.open\s*\(/g) || []).length,
        NoOfiFrame: document.querySelectorAll("iframe").length,
        HasExternalFormSubmit: externalForm ? 1 : 0,
        HasSocialNet: social ? 1 : 0,
        HasSubmitButton: document.querySelector("input[type=submit], button[type=submit], form button") ? 1 : 0,
        HasHiddenFields: document.querySelector("input[type=hidden]") ? 1 : 0,
        HasPasswordField: document.querySelector("input[type=password]") ? 1 : 0,
        Bank: /\bbank/.test(lower) ? 1 : 0,
        Pay: /\bpay/.test(lower) ? 1 : 0,
        Crypto: /crypto|bitcoin|wallet|seed phrase/.test(lower) ? 1 : 0,
        HasCopyrightInfo: /©|copyright/i.test(text) ? 1 : 0,
        NoOfImage: document.images.length,
        NoOfCSS: document.querySelectorAll("link[rel='stylesheet'], style").length,
        NoOfJS: document.scripts.length,
        NoOfSelfRef: self,
        NoOfEmptyRef: empty,
        NoOfExternalRef: external,
      },
    };
  }

  // ---- UI (isolated in a shadow root so page CSS cannot restyle or hide it) ----
  const host = document.createElement("phishnetra-ui");
  const root = host.attachShadow({ mode: "closed" });
  root.innerHTML = `<style>
    :host { all: initial; }
    .banner { position: fixed; top: 0; left: 0; right: 0; z-index: 2147483647; display: flex; gap: 12px;
      align-items: flex-start; padding: 12px 16px; font: 14px/1.4 -apple-system, system-ui, sans-serif;
      color: #1c1917; background: #fef3c7; border-bottom: 2px solid #d97706; box-shadow: 0 4px 16px #0002; }
    .banner.restrict { background: #ffedd5; border-color: #ea580c; }
    .banner b { display: block; margin-bottom: 2px; }
    .banner ul { margin: 4px 0 0; padding-left: 18px; font-size: 13px; }
    .banner .grow { flex: 1; }
    button { font: 600 13px system-ui, sans-serif; border-radius: 6px; padding: 6px 10px; cursor: pointer;
      border: 1px solid #0003; background: #fff; color: #1c1917; }
    button.primary { background: #1c1917; color: #fff; border-color: #1c1917; }
    .overlay { position: fixed; inset: 0; z-index: 2147483647; background: #0009; display: flex;
      align-items: center; justify-content: center; font: 14px/1.5 -apple-system, system-ui, sans-serif; }
    .modal { background: #fff; color: #1c1917; max-width: 440px; margin: 16px; padding: 22px; border-radius: 12px;
      box-shadow: 0 20px 50px #0006; }
    .modal h2 { margin: 0 0 8px; font-size: 18px; color: #c2410c; }
    .modal .actions { display: flex; gap: 8px; justify-content: flex-end; margin-top: 16px; flex-wrap: wrap; }
    .risk { font-variant-numeric: tabular-nums; font-weight: 700; }
  </style><div id="slot"></div>`;
  const slot = root.getElementById("slot");
  const mount = () => document.documentElement.appendChild(host);

  function esc(s) {
    return String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  }

  function showBanner(r, restrict) {
    mount();
    const reasons = (r.reasons || []).slice(0, 3).map((x) => `<li>${esc(x)}</li>`).join("");
    slot.innerHTML = `<div class="banner ${restrict ? "restrict" : ""}">
      <div class="grow"><b>PhishNetra: ${restrict ? "credential entry restricted" : "this site looks suspicious"}
        — risk <span class="risk">${Math.round(r.risk)}</span>/100</b>
        ${restrict ? "This unverified site asks for a password. Inputs are locked until you confirm." : "Be careful entering any personal information."}
        <ul>${reasons}</ul></div>
      <button id="report">Report phishing</button>
      <button id="safe">It's safe</button>
      <button id="close" class="primary">Dismiss</button></div>`;
    root.getElementById("close").onclick = () => (slot.innerHTML = "");
    root.getElementById("report").onclick = () => feedback("phishing");
    root.getElementById("safe").onclick = () => { feedback("legitimate"); unlock(); slot.innerHTML = ""; };
  }

  function feedback(label) {
    chrome.runtime.sendMessage({ type: "feedback", payload: { url: location.href, label, scan_id: verdict?.scan_id } });
  }

  function unlock() {
    credentialsUnlocked = true;
    document.querySelectorAll("input[data-phishnetra-locked]").forEach((el) => {
      el.readOnly = false;
      el.removeAttribute("data-phishnetra-locked");
    });
  }

  function confirmCredentials() {
    mount();
    const prev = slot.innerHTML;
    slot.innerHTML = `<div class="overlay"><div class="modal">
      <h2>Stop — is this really who you think it is?</h2>
      <p>You are about to type a password on <b>${esc(location.hostname)}</b>, which PhishNetra could not verify
      (risk <span class="risk">${Math.round(verdict.risk)}</span>/100${verdict.impersonated_brand ? `, resembles <b>${esc(verdict.impersonated_brand)}</b>` : ""}).</p>
      <p>Zero-trust policy: credentials are only released to verified sites.</p>
      <div class="actions"><button id="leave" class="primary">Leave this site</button>
      <button id="allow">I trust this site</button></div></div></div>`;
    root.getElementById("leave").onclick = () => { location.href = "about:blank"; };
    root.getElementById("allow").onclick = () => {
      unlock();
      chrome.runtime.sendMessage({ type: "override", scanId: verdict.scan_id });
      slot.innerHTML = prev;
    };
  }

  function lockCredentials() {
    document.querySelectorAll("input[type=password]:not([data-phishnetra-locked])").forEach((el) => {
      el.readOnly = true;
      el.setAttribute("data-phishnetra-locked", "1");
    });
  }

  // Capture-phase guards run before page scripts can read or submit credentials.
  document.addEventListener("focusin", (e) => {
    if (verdict?.verdict === "RESTRICT" && !credentialsUnlocked && e.target.matches?.("input[type=password]")) {
      e.target.blur();
      confirmCredentials();
    }
  }, true);
  document.addEventListener("submit", (e) => {
    if (verdict?.verdict === "RESTRICT" && !credentialsUnlocked && e.target.querySelector?.("input[type=password]")) {
      e.preventDefault();
      e.stopImmediatePropagation();
      confirmCredentials();
    }
  }, true);

  function apply(r) {
    verdict = r;
    if (!r || r.skip || r.bypassed || r.mode === "monitor") return;
    if (r.verdict === "RESTRICT") {
      lockCredentials();
      showBanner(r, true);
    } else if (r.verdict === "WARN") {
      showBanner(r, false);
    }
  }

  function scan() {
    chrome.runtime.sendMessage({ type: "page-features", payload: extractFeatures() }, (r) => {
      if (chrome.runtime.lastError) return;
      apply(r);
    });
  }

  scan();
  // Single-page apps often render the login form after load: rescan once when a password field appears.
  const observer = new MutationObserver(() => {
    if (!rescanned && document.querySelector("input[type=password]") && !verdict?.layers?.find(
      (l) => l.name === "dom_model" && l.details?.features?.HasPasswordField)) {
      rescanned = true;
      observer.disconnect();
      scan();
    }
    if (verdict?.verdict === "RESTRICT" && !credentialsUnlocked) lockCredentials();
  });
  observer.observe(document.documentElement, { childList: true, subtree: true });
  setTimeout(() => { if (verdict?.verdict !== "RESTRICT") observer.disconnect(); }, 30000);
})();
