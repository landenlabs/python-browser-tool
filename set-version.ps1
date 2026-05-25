#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Bump the project version, commit pending changes, then push commits and tag
    to trigger the release workflow.

.DESCRIPTION
    Updates the version in:
      1. brow-tool.py           (the VERSION = "..."  line)
      2. README.md              (<!-- VERSION --> and <!-- DATE --> markers)
      3. VERSION                (project version file)

    Then stages everything, commits with the supplied message, pushes the
    commit, creates an annotated tag, and pushes the tag. The tag push is
    intentionally last so the commit is already on the remote when the
    tag-triggered GitHub Action starts building.

.PARAMETER Version
    Release version, e.g. v0.07.00 (the leading 'v' is optional).

.PARAMETER Message
    Git commit message (also used as the annotated tag message). Can be passed
    as a single quoted string or as multiple unquoted words — all remaining
    arguments after the version are joined with single spaces.

.EXAMPLE
    .\set-version.ps1 v0.07.00 "Add Firefox support"

.EXAMPLE
    .\set-version.ps1 v0.07.00 'Fix Windows ACL crash'

.EXAMPLE
    .\set-version.ps1 v0.07.00 Add Firefox support
#>

param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$Version,

    [Parameter(Mandatory=$true, Position=1, ValueFromRemainingArguments=$true)]
    [string[]]$MessageParts
)

# Accept the commit message as either a single quoted string or as multiple
# unquoted tokens. ValueFromRemainingArguments collects whatever's left into
# an array; joining with a single space reconstructs the intended sentence
# (collapsing any incidental multiple whitespace at the shell level).
$Message = ($MessageParts -join ' ').Trim()
if ([string]::IsNullOrWhiteSpace($Message)) {
    Write-Host "ERROR: Commit message is required." -ForegroundColor Red
    exit 1
}

$ErrorActionPreference = 'Stop'

function Fail([string]$msg) {
    Write-Host "ERROR: $msg" -ForegroundColor Red
    exit 1
}

# ---------------------------------------------------------------------------
# Validate and normalize version
# ---------------------------------------------------------------------------

if ($Version -notmatch '^v') { $Version = "v$Version" }
if ($Version -notmatch '^v\d+\.\d+\.\d+$') {
    Fail "Version must look like v0.07.00 (got: $Version)"
}

$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ProjectRoot

# Verify we're in a git repo
git rev-parse --git-dir 2>$null | Out-Null
if ($LASTEXITCODE -ne 0) { Fail "Not in a git repository." }

# Make sure the tag doesn't already exist locally
$existing = git tag --list $Version
if ($existing) { Fail "Tag $Version already exists locally." }

# Make sure the tag doesn't already exist on the remote
$remoteTag = git ls-remote --tags origin "refs/tags/$Version" 2>$null
if ($remoteTag) { Fail "Tag $Version already exists on origin." }

# ---------------------------------------------------------------------------
# Date components
# ---------------------------------------------------------------------------

$now             = Get-Date
$monthShort      = $now.ToString('MMM')              # May
$year            = $now.ToString('yyyy')             # 2026
$dateForReadme   = $now.ToString('dd-MMM-yyyy')      # 25-May-2026
$versionWithDate = "$Version ($monthShort-$year)"    # v0.07.00 (May-2026)

Write-Host ""
Write-Host "Setting project version to $Version" -ForegroundColor Cyan
Write-Host "  build date string : $versionWithDate"
Write-Host "  README date       : $dateForReadme"
Write-Host ""

# ---------------------------------------------------------------------------
# Helpers for byte-faithful file rewrites (preserves line endings, no BOM)
# ---------------------------------------------------------------------------

$utf8NoBom = [System.Text.UTF8Encoding]::new($false)

function Read-File([string]$path) {
    return [System.IO.File]::ReadAllText($path)
}

function Write-File([string]$path, [string]$content) {
    [System.IO.File]::WriteAllText($path, $content, $utf8NoBom)
}

# ---------------------------------------------------------------------------
# 1. brow-tool.py
# ---------------------------------------------------------------------------

$pyFile = Join-Path $ProjectRoot 'brow-tool.py'
if (-not (Test-Path $pyFile)) { Fail "Python file not found: $pyFile" }

$pyContent = Read-File $pyFile
$pyPattern = 'VERSION\s*=\s*"v\d+\.\d+\.\d+\s*\([^)]+\)"'
if (-not [regex]::IsMatch($pyContent, $pyPattern)) {
    Fail "No VERSION line matching $pyPattern found in $pyFile"
}
$pyNew = [regex]::Replace($pyContent, $pyPattern, "VERSION = `"$versionWithDate`"")
if ($pyNew -eq $pyContent) {
    Write-Host "  brow-tool.py already at VERSION = `"$versionWithDate`" (no change)" -ForegroundColor DarkGray
} else {
    Write-File $pyFile $pyNew
    Write-Host "  updated brow-tool.py    -> VERSION = `"$versionWithDate`""
}

# ---------------------------------------------------------------------------
# 2. README.md
# ---------------------------------------------------------------------------

$readme = Join-Path $ProjectRoot 'README.md'
if (Test-Path $readme) {
    $rmContent  = Read-File $readme
    $verMarker  = '(<!-- VERSION -->)v?\d+\.\d+\.\d+'
    $dateMarker = '(<!-- DATE -->)[\w\-]+'

    $hasVerMarker  = [regex]::IsMatch($rmContent, $verMarker)
    $hasDateMarker = [regex]::IsMatch($rmContent, $dateMarker)
    if (-not ($hasVerMarker -or $hasDateMarker)) {
        Write-Host "  WARNING: No <!-- VERSION --> / <!-- DATE --> markers found in README.md" -ForegroundColor Yellow
    } else {
        $rmNew = $rmContent
        $rmNew = [regex]::Replace($rmNew, $verMarker,  "`${1}$Version")
        $rmNew = [regex]::Replace($rmNew, $dateMarker, "`${1}$dateForReadme")
        if ($rmNew -eq $rmContent) {
            Write-Host "  README.md already at $Version, $dateForReadme (no change)" -ForegroundColor DarkGray
        } else {
            Write-File $readme $rmNew
            Write-Host "  updated README.md       -> $Version, $dateForReadme"
        }
    }
}

# ---------------------------------------------------------------------------
# 3. VERSION file
# ---------------------------------------------------------------------------

$versionFile = Join-Path $ProjectRoot 'VERSION'
Write-File $versionFile "$Version`n"
Write-Host "  updated VERSION         -> $Version"

# ---------------------------------------------------------------------------
# Git: stage, commit
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "Staging and committing..." -ForegroundColor Cyan

git add -A
if ($LASTEXITCODE -ne 0) { Fail "git add failed." }

git diff --cached --quiet
if ($LASTEXITCODE -eq 0) {
    Fail "Nothing to commit. (Did the version files already match?)"
}

git commit -m $Message
if ($LASTEXITCODE -ne 0) { Fail "git commit failed." }

# ---------------------------------------------------------------------------
# Push commits FIRST, then tag.
# This order matters: the GitHub Action is triggered by the tag push, and we
# want the commit to already be on the remote when the action checks out.
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "Pushing commits..." -ForegroundColor Cyan
git push
if ($LASTEXITCODE -ne 0) { Fail "git push failed." }

Write-Host ""
Write-Host "Creating annotated tag $Version..." -ForegroundColor Cyan
git tag -a $Version -m $Message
if ($LASTEXITCODE -ne 0) { Fail "git tag failed." }

Write-Host "Pushing tag $Version (this triggers the release workflow)..."
git push origin $Version
if ($LASTEXITCODE -ne 0) { Fail "git push origin $Version failed." }

Write-Host ""
Write-Host "Done. Tag $Version pushed." -ForegroundColor Green
Write-Host "The GitHub Action should now be building macOS + Windows binaries."
Write-Host "Watch progress at: https://github.com/landenlabs/browser-tools/actions"
