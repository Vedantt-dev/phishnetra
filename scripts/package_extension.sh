#!/usr/bin/env bash
# Build the Chrome Web Store upload: dist/phishnetra-extension-<version>.zip
set -euo pipefail
cd "$(dirname "$0")/.."
version=$(python3 -c "import json; print(json.load(open('extension/manifest.json'))['version'])")
if grep -rq "__API_BASE__" extension; then
  echo "error: extension still contains the __API_BASE__ placeholder" >&2; exit 1
fi
mkdir -p dist
out="dist/phishnetra-extension-$version.zip"
rm -f "$out"
(cd extension && zip -qr "../$out" . -x '.*' -x '__MACOSX/*')
echo "wrote $out ($(du -h "$out" | cut -f1))"
