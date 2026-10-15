#!/usr/bin/env bash
# Build the root-origin copy of the app for Cloudflare Pages (tonychen-vault.pages.dev).
# Source of truth stays docs/app/ (GitHub Pages at /vault/app/); this rewrites paths to '/'.
set -euo pipefail
cd "$(dirname "$0")/.."
rm -rf dist && mkdir -p dist && cp -R docs/app/. dist/
sed -i 's#/vault/app/#/#g; s#"/vault/app"#"/"#g' dist/index.html dist/app.js dist/sw.js dist/vault-app.webmanifest
# Root build: the app is the whole origin.
sed -i 's#location.pathname === "/" || location.pathname.startsWith("/")#true#' dist/app.js
sed -i 's#^const CACHE = .*#const CACHE = "vault-app-v1";#' dist/sw.js
grep -q 'key.startsWith("vault-")' dist/sw.js || { echo "sw.js must only delete vault-* caches" >&2; exit 1; }
if grep -rn '/vault/' dist; then echo "leftover /vault/ paths" >&2; exit 1; fi
echo "Built dist/"
