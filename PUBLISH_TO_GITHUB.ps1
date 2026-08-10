[CmdletBinding()]
param(
    [ValidateSet("private", "public")]
    [string]$Visibility = "private"
)

$ErrorActionPreference = "Stop"
$Repository = "drabkb786/secure-vps-panel"
$RemoteUrl = "https://github.com/$Repository.git"

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    throw "Git is not installed. Install Git for Windows first."
}
if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
    throw "GitHub CLI (gh) is not installed. Install it, then run this script again."
}

try {
    gh auth status | Out-Host
} catch {
    gh auth login --web
}

$insideRepo = git rev-parse --is-inside-work-tree 2>$null
if ($insideRepo -ne "true") {
    throw "Run this script from the extracted Abdul Basit Secure VPS Panel folder."
}

$repoExists = $true
try {
    gh repo view $Repository --json nameWithOwner | Out-Null
} catch {
    $repoExists = $false
}

if (-not $repoExists) {
    $visibilityFlag = "--$Visibility"
    gh repo create $Repository $visibilityFlag --source=. --remote=origin --push
} else {
    $hasOrigin = $true
    try { git remote get-url origin | Out-Null } catch { $hasOrigin = $false }
    if ($hasOrigin) {
        git remote set-url origin $RemoteUrl
    } else {
        git remote add origin $RemoteUrl
    }
    git branch -M main
    git push --set-upstream origin main
}

Write-Host "Published: https://github.com/$Repository"
