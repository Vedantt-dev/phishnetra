# Publishing the PhishNetra extension

Three ways to get the extension to people, from fastest to most public.

| Option | Who can install | Cost | Time |
|---|---|---|---|
| **A. Load unpacked** (zip download) | Anyone with Developer mode on | Free | Instant |
| **B. Chrome Web Store — Unlisted** | Anyone with the link | $5 one-time | Review: ~1–3 days |
| **C. Chrome Web Store — Public** | Everyone, searchable | $5 one-time | Review: ~1–3 days (longer for broad permissions) |

Microsoft Edge Add-ons accepts the same zip for free (option D).

---

## A. Load unpacked (judges / testers, no review)

1. Download `https://phishnetra-seven.vercel.app/phishnetra-extension.zip` (built on every deploy) and unzip it.
2. Open `chrome://extensions`, turn on **Developer mode** (top right).
3. Click **Load unpacked** and pick the unzipped folder.
4. Accept the data disclosure on the welcome tab that opens.

Good for a demo; Chrome shows a "developer mode extensions" notice and it won't auto-update.

---

## B / C. Chrome Web Store

### 1. One-time setup
1. Go to the [Chrome Web Store Developer Dashboard](https://chrome.google.com/webstore/devconsole) and sign in
   with the Google account that should own the listing.
2. Pay the **US $5 registration fee** (one-time).
3. In **Account**, verify your contact email (required before publishing).

### 2. Build the upload package
```bash
./scripts/package_extension.sh        # → dist/phishnetra-extension-1.0.0.zip
```
The script refuses to build if the API URL placeholder is still present. Bump `"version"` in
`extension/manifest.json` for every new upload (the store rejects a version it has seen before).

### 3. Prepare listing assets
| Asset | Spec | Where to get it |
|---|---|---|
| Icon | 128×128 PNG | `extension/icons/icon128.png` |
| Screenshots | 1–5 images, **1280×800** or 640×400 | Block page, warning banner, popup, dashboard |
| Small promo tile | 440×280 PNG | Logo + "Zero-trust phishing protection" |
| Description | ≤ 16,000 chars | Use the text below |

Short description (≤ 132 chars):
> Real-time AI phishing protection: blocks fake login pages, typosquats and brand impersonation with zero-trust checks.

### 4. Create the item
1. Dashboard → **New item** → upload the zip.
2. **Store listing**: description, category *Productivity* (or *Developer Tools*), language, screenshots, promo tile.
3. **Privacy** tab — this is where most rejections happen. Fill it exactly:

   **Single purpose**
   > Detect phishing websites in real time and protect the user from them by blocking, warning, or restricting
   > password entry on suspicious pages.

   **Permission justifications**
   | Permission | Justification |
   |---|---|
   | `webNavigation` | Check each page's URL before it loads so phishing pages can be blocked before they render. |
   | `tabs` | Redirect a tab to the warning page when a site is blocked and read the active tab's URL for the popup. |
   | `storage` | Save the user's settings (on/off, enforce vs monitor, server URL) and short-lived per-tab verdicts. |
   | `alarms` | Refresh the phishing blocklist every 30 minutes. |
   | `declarativeNetRequest` | Block known phishing domains from the blocklist before any request is sent. |
   | Host permission `<all_urls>` | Phishing can appear on any website; the content script must analyse page structure (forms, password fields, links) on every site the user visits. |
   | Remote code | **No**, the extension does not execute remote code. |

   **Data usage**: tick **Web history** (page URLs) and **Website content** (title, text, page structure).
   Do not tick anything else. Then certify all three statements (not sold, not used for unrelated purposes,
   not used for creditworthiness).

   **Privacy policy URL**: `https://phishnetra-seven.vercel.app/privacy.html`

4. **Distribution**: choose **Unlisted** (link-only, great for judges) or **Public**.
5. **Submit for review**.

### 5. Review tips
- Broad host permissions (`<all_urls>`) trigger an in-depth review; the clear single purpose and the welcome-page
  consent (`extension/welcome/`) are what reviewers look for. Do not remove the consent step.
- Reviewers test the extension: make sure the deployed API is up when you submit.
- If rejected, the email names the policy; fix, bump the version, re-upload.
- Updates: bump version → `./scripts/package_extension.sh` → Dashboard → *Package* → *Upload new package* → submit.
  Installed users update automatically within a few hours.

---

## D. Microsoft Edge Add-ons (free)
1. Register at [Partner Center](https://partner.microsoft.com/dashboard/microsoftedge) (no fee).
2. **Create new extension** → upload the same zip.
3. Reuse the description, screenshots, privacy policy URL and permission justifications above.
