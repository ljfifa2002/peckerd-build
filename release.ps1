<# ::
@echo off
powershell -NoLogo -ExecutionPolicy Bypass -File "%~f0"
pause
exit /b
#>
# release.ps1 — 自动递增 v1.0.x tag 并推送，触发 CI 构建
# 推送前先确保 master 上有未推送的改动时一并提交推送

$ErrorActionPreference = 'Stop'

# 检查 master 是否领先 origin/master（有未推送提交）
$ahead = git rev-list --count "origin/master..HEAD" 2>$null
if ($ahead -gt 0) {
    Write-Host "WARNING: $ahead unpushed commit(s) on master. Pushing master first..."
    git push origin master
    if ($LASTEXITCODE -ne 0) { Write-Error "git push master failed"; exit 1 }
    Write-Host "master pushed."
    Write-Host ""
}

# 检查工作区是否有未提交的改动
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
        git push origin master
        if ($LASTEXITCODE -ne 0) { Write-Error "git push master failed"; exit 1 }
        Write-Host "master pushed."
        Write-Host ""
    } else {
        Write-Host "Proceeding without committing (tag will point to current HEAD)."
        Write-Host ""
    }
}

# 找最新 v1.0.x tag
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
Write-Host "Done. CI will build Ninjector with NINJECTOR_VERSION=$nextTag"
