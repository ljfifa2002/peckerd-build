<# ::
@echo off
REM ===========================================================================
REM Single-file peckerd release launcher (batch/PowerShell polyglot).
REM Double-click -> commit/push pending main changes + bump and push the v1.0.x
REM   tag, which triggers the CI to build peckerd + libncore.so (x2 ABI) and
REM   publish them as artifacts.
REM
REM cmd runs this batch header, then relaunches PowerShell on THIS file via
REM -Command iex (PowerShell -File rejects a .cmd extension). The PS body lives
REM below the closing marker and is invisible to cmd. ASCII-ONLY (Windows
REM PowerShell 5.1 mis-parses non-ASCII under the GBK codepage).
REM ===========================================================================
cd /d "%~dp0"
powershell -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "iex (Get-Content -Raw -LiteralPath '%~f0')"
echo.
pause
exit /b
#>

# ===== PowerShell body (CWD is the peckerd repo root, set by 'cd /d %~dp0') =====
$ErrorActionPreference = 'Stop'

# Guard: fail loud if this is not the repo root.
if (-not (Test-Path -LiteralPath '.git')) {
    Write-Error "Not a git repo: no .git in the current directory"; exit 1
}

# 1) Push main first if it is ahead of origin/main.
$ahead = git rev-list --count "origin/main..HEAD" 2>$null
if ($ahead -gt 0) {
    Write-Host "WARNING: $ahead unpushed commit(s) on main. Pushing main first..."
    git push origin main
    if ($LASTEXITCODE -ne 0) { Write-Error "git push main failed"; exit 1 }
    Write-Host "main pushed."; Write-Host ""
}

# 2) Commit pending changes if any.
$status = git status --porcelain 2>$null
if ($status) {
    Write-Host "WARNING: uncommitted changes detected:"
    Write-Host $status
    Write-Host ""
    $commitConfirm = Read-Host "Commit all changes before tagging? (Y/N)"
    if ($commitConfirm -match '^[Yy]$') {
        $msg = Read-Host "Commit message"
        git add -A
        git commit -m $msg
        if ($LASTEXITCODE -ne 0) { Write-Error "git commit failed"; exit 1 }
        git push origin main
        if ($LASTEXITCODE -ne 0) { Write-Error "git push main failed"; exit 1 }
        Write-Host "main pushed."; Write-Host ""
    } else {
        Write-Host "Proceeding without committing (tag will point to current HEAD)."; Write-Host ""
    }
}

# 3) Find the latest v1.0.x tag and bump the patch.
$lastTag = git tag --sort=v:refname | Where-Object { $_ -match '^v1\.0\.(\d+)$' } | Select-Object -Last 1
if ($lastTag) {
    $patch = [int]($lastTag -replace '^v1\.0\.', '')
    $nextTag = "v1.0.$($patch + 1)"
} else {
    $nextTag = "v1.0.1"
}
Write-Host "Last tag : $(if ($lastTag) { $lastTag } else { '(none)' })"
Write-Host "Next tag : $nextTag"
Write-Host ""

$confirm = Read-Host "Push tag $nextTag ? (Y/N)"
if ($confirm -notmatch '^[Yy]$') { Write-Host "Cancelled."; exit 0 }

git tag $nextTag
if ($LASTEXITCODE -ne 0) { Write-Error "git tag failed"; exit 1 }

git push origin $nextTag
if ($LASTEXITCODE -ne 0) {
    Write-Warning "git push tag failed, removing local tag..."
    git tag -d $nextTag
    exit 1
}

Write-Host ""
Write-Host "Done. CI will build peckerd with PECKERD_VERSION=$nextTag"
Write-Host "(peckerd + libncore.so, x2 ABI). After it finishes: run"
Write-Host "tools\update-peckerd.ps1 in pecker-agent to pull the artifacts."
