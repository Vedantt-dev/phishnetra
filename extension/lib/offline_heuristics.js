// Offline fallback: a JavaScript port of the backend's lexical rule score and brand
// typosquat check. Used when the PhishNetra API is unreachable, so protection degrades
// gracefully instead of failing open.

const SUSPICIOUS_TLDS = new Set(["zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "link",
  "work", "rest", "fit", "country", "kim", "support", "review", "cam", "icu", "buzz", "live", "monster",
  "quest", "sbs", "cfd"]);
const KEYWORDS = ["login", "log-in", "signin", "sign-in", "verify", "verification", "account", "update",
  "secure", "security", "banking", "confirm", "password", "credential", "wallet", "unlock", "suspend",
  "billing", "invoice", "support", "webscr", "authenticate", "recovery", "limited"];
const FREE_HOSTING = ["000webhostapp.com", "weebly.com", "wixsite.com", "firebaseapp.com", "web.app",
  "github.io", "glitch.me", "netlify.app", "vercel.app", "pages.dev", "blogspot.com", "herokuapp.com",
  "ngrok.io", "ngrok-free.app", "workers.dev"];
// Brand → official registrable domains (subset of backend/data/brands.json).
const BRANDS = {
  paypal: ["paypal.com"], google: ["google.com", "gmail.com", "youtube.com"], microsoft: ["microsoft.com",
  "live.com", "office.com", "microsoftonline.com"], outlook: ["outlook.com", "live.com"], apple: ["apple.com"],
  icloud: ["icloud.com"], amazon: ["amazon.com", "amazon.in"], facebook: ["facebook.com"],
  instagram: ["instagram.com"], netflix: ["netflix.com"], linkedin: ["linkedin.com"], chase: ["chase.com"],
  wellsfargo: ["wellsfargo.com"], coinbase: ["coinbase.com"], binance: ["binance.com"],
  metamask: ["metamask.io"], dropbox: ["dropbox.com"], docusign: ["docusign.com"], paytm: ["paytm.com"],
  hdfcbank: ["hdfcbank.com"], icicibank: ["icicibank.com"], onlinesbi: ["onlinesbi.sbi", "sbi.co.in"],
};
const TRUSTED = new Set(["google.com", "youtube.com", "facebook.com", "wikipedia.org", "github.com",
  "microsoft.com", "apple.com", "amazon.com", "linkedin.com", "paypal.com", "netflix.com", "x.com",
  "twitter.com", "instagram.com", "reddit.com", "stackoverflow.com", "live.com", "office.com"]);
const LEET = { 0: "o", 1: "l", 3: "e", 4: "a", 5: "s", 7: "t", 8: "b", 9: "g" };

function registrable(host) {
  const parts = host.split(".");
  const twoPart = /\.(co|com|org|net|gov|ac|edu)\.[a-z]{2}$/.test(host);
  return parts.slice(twoPart ? -3 : -2).join(".");
}

function skeleton(s) {
  return s.replace(/[0-9]/g, (d) => LEET[d] || d).replace(/rn/g, "m").replace(/vv/g, "w");
}

function levenshtein(a, b) {
  const dp = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    let prev = dp[0];
    dp[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const tmp = dp[j];
      dp[j] = Math.min(dp[j] + 1, dp[j - 1] + 1, prev + (a[i - 1] === b[j - 1] ? 0 : 1));
      prev = tmp;
    }
  }
  return dp[b.length];
}

export function scoreUrl(rawUrl) {
  let u;
  try { u = new URL(rawUrl); } catch { return null; }
  const host = u.hostname.toLowerCase();
  const reg = registrable(host);
  const full = u.href.toLowerCase();
  const reasons = [];
  if (TRUSTED.has(reg)) {
    return { risk: 5, verdict: "ALLOW", trust: "verified", reasons: ["Trusted domain (offline list)"], offline: true };
  }
  let score = 15;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) { score += 30; reasons.push("Host is a raw IP address"); }
  if (u.username || full.split("://")[1].includes("@")) { score += 25; reasons.push("URL contains '@' obfuscation"); }
  if (host.includes("xn--")) { score += 25; reasons.push("Punycode (possible homoglyph) host"); }
  const tld = host.split(".").pop();
  if (SUSPICIOUS_TLDS.has(tld)) { score += 20; reasons.push(`.${tld} has poor TLD reputation`); }
  const hits = KEYWORDS.filter((k) => full.includes(k)).length;
  if (hits) { score += Math.min(hits, 4) * 8; if (hits >= 2) reasons.push(`${hits} credential-lure keywords in URL`); }
  if (/\.(com|net|org)[/.-]/.test(host.slice(0, -reg.length) + u.pathname)) { score += 15; reasons.push("Domain name embedded in subdomain/path"); }
  if (FREE_HOSTING.some((h) => host === h || host.endsWith("." + h))) { score += 10; reasons.push("Free hosting platform"); }
  if (host.split(".").length - reg.split(".").length >= 3) { score += 10; reasons.push("Deeply nested subdomains"); }
  if (u.href.length > 100) score += 10;
  if (u.protocol === "http:") { score += 10; reasons.push("Unencrypted HTTP"); }

  const sld = reg.split(".")[0];
  const tokens = host.split(/[.-]/);
  for (const [kw, domains] of Object.entries(BRANDS)) {
    if (domains.some((d) => reg === d || host.endsWith("." + d))) continue;
    if (skeleton(sld) === kw && sld !== kw) { score = Math.max(score, 95); reasons.unshift(`Spoof of ${kw}`); break; }
    if (kw.length >= 5 && levenshtein(sld, kw) === 1) { score = Math.max(score, 85); reasons.unshift(`Typosquat of ${kw}`); break; }
    if (tokens.some((t) => t === kw || skeleton(t) === kw)) { score = Math.max(score, 75); reasons.unshift(`Uses '${kw}' on a domain it does not own`); break; }
  }
  const risk = Math.min(100, score);
  const verdict = risk >= 75 ? "BLOCK" : risk >= 30 ? "WARN" : "ALLOW";
  const trust = { ALLOW: "unverified", WARN: "suspicious", BLOCK: "malicious" }[verdict];
  return { risk, verdict, trust, reasons, offline: true };
}
