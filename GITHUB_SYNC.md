# GitHub Sync — Abdul Basit

Canonical target:

```text
https://github.com/drabkb786/secure-vps-panel
```

## First push to a new empty repository

Create a repository named `secure-vps-panel` under the `drabkb786` account, then run from this project directory:

```bash
git remote remove origin 2>/dev/null || true
git remote add origin https://github.com/drabkb786/secure-vps-panel.git
git branch -M main
git push -u origin main
```

GitHub will ask for authentication. With HTTPS, use a fine-grained Personal Access Token rather than the account password. The token needs repository Contents write access.

## Push with GitHub CLI

```bash
gh auth login
gh repo create drabkb786/secure-vps-panel --private --source=. --remote=origin --push
```

For an existing repository:

```bash
git remote set-url origin https://github.com/drabkb786/secure-vps-panel.git
git push -u origin main
```

## Important secret rule

Never commit a Telegram bot token, VPS password, SSH private key, certificate private key, or files copied from `/etc/abdulbasit`. Rotate any secret that appeared in old Git history.
