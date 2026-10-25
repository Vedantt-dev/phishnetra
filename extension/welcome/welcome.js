const $ = (id) => document.getElementById(id);
const { apiBase } = await chrome.storage.local.get("apiBase");
$("api").textContent = apiBase;
$("privacy").href = `${apiBase}/privacy.html`;

$("accept").onclick = async () => {
  await chrome.storage.local.set({ consented: true, enabled: true });
  chrome.runtime.sendMessage({ type: "sync-blocklist" });
  $("done").style.display = "inline";
  $("accept").disabled = true;
};
$("decline").onclick = async () => {
  await chrome.storage.local.set({ consented: false });
  window.close();
};
