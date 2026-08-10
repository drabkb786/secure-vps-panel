#!/usr/bin/env bash
set -Eeuo pipefail

visibility="${1:-private}"
case "$visibility" in
  private|public) ;;
  *) echo "Usage: $0 [private|public]" >&2; exit 2 ;;
esac

repo="drabkb786/secure-vps-panel"
remote_url="https://github.com/${repo}.git"

command -v git >/dev/null || { echo "Git is required." >&2; exit 1; }
command -v gh >/dev/null || { echo "GitHub CLI (gh) is required." >&2; exit 1; }

gh auth status >/dev/null 2>&1 || gh auth login --web
git rev-parse --is-inside-work-tree >/dev/null

if gh repo view "$repo" --json nameWithOwner >/dev/null 2>&1; then
  if git remote get-url origin >/dev/null 2>&1; then
    git remote set-url origin "$remote_url"
  else
    git remote add origin "$remote_url"
  fi
  git branch -M main
  git push --set-upstream origin main
else
  gh repo create "$repo" "--$visibility" --source=. --remote=origin --push
fi

echo "Published: https://github.com/$repo"

