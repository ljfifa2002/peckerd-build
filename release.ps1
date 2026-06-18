<# ::
@echo off
powershell -NoLogo -ExecutionPolicy Bypass -File "%~f0"
pause
exit /b
#>
# release.ps1 - auto-increment the v1.0.x tag and push it to trigger the CI build.
# Commits and pushes any pending main changes first.

$ErrorActionPreference = 'Stop'

# Run from the script's own directory. Launched as a .ps1 ("Run with PowerShell")
# the working dir is System32 / the user profile, not the repo root, which made the
# git checks below silently no-op. Set-Location fixes it regardless of how it starts.
Set-Location -LiteralPath $PSScriptRoot

# Guard: fail loud if this is not the repo root (.git missing). Uses Test-Path,
# not git rev-parse, which is unreliable with LASTEXITCODE under Windows PowerShell 5.1.
if (-not (Test-Path -LiteralPath (Join-Path $PSScriptRoot '.git'))) {
    Write-Error "Not a git repo: no .git found at $PSScriptRoot"; exit 1
}

# Check whether main is ahead of origin/main (unpushed commits).
$ahead = git rev-list --count "origin/main..HEAD" 2>$null
if ($ahead -gt 0) {
    Write-Host "WARNING: $ahead unpushed commit(s) on main. Pushing main first..."
    git push origin main
    if ($LASTEXITCODE -ne 0) { Write-Error "git push main failed"; exit 1 }
    Write-Host "main pushed."
    Write-Host ""
}

# Check the working tree for uncommitted changes.
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
        Write-Host "main pushed."
        Write-Host ""
    } else {
        Write-Host "Proceeding without committing (tag will point to current HEAD)."
        Write-Host ""
    }
}

# Find the latest v1.0.x tag.
$lastTag = git tag --sort=v:refname |
    Where-Object { $_ -match '^v1\.0\.(\d+)$' } |
    Select-Object -Last 1

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
if ($confirm -notmatch '^[Yy]$') {
    Write-Host "Cancelled."
    exit 0
}

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
