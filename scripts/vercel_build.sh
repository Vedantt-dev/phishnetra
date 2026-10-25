#!/usr/bin/env bash
# Vercel build: assemble the static site (dashboard, demo pages, privacy policy) into public/.
set -euo pipefail
cd "$(dirname "$0")/.."
(cd dashboard && npm ci --no-audit --no-fund && npm run build)
rm -rf public && mkdir -p public
cp -R dashboard/dist public/dashboard
cp -R demo public/demo
cp -R site/. public/
# Downloadable copy of the extension for judges / testers (Load unpacked).
if command -v python3 >/dev/null; then
  (cd extension && python3 -m zipfile -c ../public/phishnetra-extension.zip .) || true
fi
