#!/usr/bin/env bash
# Push Hardened v2 as the single canonical GitHub repository.
# Usage:
#   export GITHUB_TOKEN=ghp_...   # classic PAT with repo scope, or fine-grained with Contents+Admin
#   export GITHUB_USER=your-username
#   bash scripts/push_to_github.sh [repo-name]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

REPO_NAME="${1:-atl-edge-smarttoken-hardened}"
USER="${GITHUB_USER:-}"
TOKEN="${GITHUB_TOKEN:-${GH_TOKEN:-}}"

if [[ -z "$USER" || -z "$TOKEN" ]]; then
  echo "Set GITHUB_USER and GITHUB_TOKEN (PAT with repo scope) before running."
  echo "  export GITHUB_USER=your-username"
  echo "  export GITHUB_TOKEN=ghp_xxxxxxxx"
  echo "  bash scripts/push_to_github.sh"
  exit 1
fi

# Clean binaries
find . -name "*.so" -delete 2>/dev/null || true
find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

if [[ ! -d .git ]]; then
  git init -b main
fi

git config user.email "${GIT_EMAIL:-dev@atl-edge.local}"
git config user.name "${GIT_NAME:-ATL Edge}"

git add -A
git status --short | head -50
if git rev-parse --verify HEAD >/dev/null 2>&1; then
  git commit -m "chore: sync Hardened v2" || true
else
  git commit -m "Initial commit: ATL Edge SmartToken Integrated Hardened v2

- ATLP data plane + MORPH-8 gate
- SmartTokenProd (ML-KEM + master_secret binding + header_mac)
- Adversarial testbench 14/14
- Docker, sidecar HTTP, CI/CD workflows
- Data room evidence package"
fi

# Create repo if missing (idempotent)
HTTP_CODE=$(curl -s -o /tmp/gh_create.json -w "%{http_code}" \
  -X POST "https://api.github.com/user/repos" \
  -H "Authorization: token ${TOKEN}" \
  -H "Accept: application/vnd.github+json" \
  -d "{\"name\":\"${REPO_NAME}\",\"description\":\"ATL Edge + SmartTokenProd Hardened v2 (single canonical trunk)\",\"private\":true,\"auto_init\":false}")

if [[ "$HTTP_CODE" == "201" ]]; then
  echo "Created private repo: ${USER}/${REPO_NAME}"
elif [[ "$HTTP_CODE" == "422" ]]; then
  echo "Repo already exists (or validation error); continuing push."
  cat /tmp/gh_create.json
else
  echo "GitHub API response HTTP ${HTTP_CODE}:"
  cat /tmp/gh_create.json
  exit 1
fi

git remote remove origin 2>/dev/null || true
git remote add origin "https://${USER}:${TOKEN}@github.com/${USER}/${REPO_NAME}.git"
git push -u origin main

echo ""
echo "Published: https://github.com/${USER}/${REPO_NAME}"
echo "Enable Actions in the repo settings if not already on."
