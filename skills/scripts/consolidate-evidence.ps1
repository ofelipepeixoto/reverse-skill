#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $CaseRoot,
    [Parameter(Mandatory = $true)][string] $EvidenceIds,
    [Parameter(Mandatory = $true)][string] $FindingId,
    [Parameter(Mandatory = $true)][string] $Title,
    [Parameter(Mandatory = $true)][string] $Description,
    [string] $Severity = 'medium',
    [string] $Status = 'candidate',
    [string] $Confidence = 'medium',
    [string] $Location = 'see evidence_ids'
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $CaseRoot)) { Write-Error "CaseRoot not found: $CaseRoot" }

$evidenceDir = Join-Path $CaseRoot "evidence"
$reportDir = Join-Path $CaseRoot "report"


$idList = @($EvidenceIds -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
if ($idList.Count -eq 0) { Write-Error "No Evidence IDs provided." }
if (($idList | Select-Object -Unique).Count -ne $idList.Count) { throw "Duplicate Evidence IDs" }
foreach ($id in $idList) {
    if ($id -cnotmatch '\AE-[A-Za-z0-9][A-Za-z0-9_-]*\z') { throw "Invalid Evidence ID" }
}
if ($FindingId -cnotmatch '\AF-[A-Za-z0-9][A-Za-z0-9_-]*\z') { throw "Invalid Finding ID" }
foreach ($value in @($Title, $Severity, $Status, $Confidence, $Location)) {
    if ($value -match '[\x00-\x1f\x7f]') { throw "Metadata fields must be single-line text" }
}
if ($Status -cnotin @('candidate','validated','false_positive','accepted_risk','superseded')) {
    throw "Unsupported Finding status"
}
# Reject links/junctions in all input/output paths below the chosen case root.
# This preflight does not prevent concurrent path replacement (TOCTOU).
$paths = @($evidenceDir, $reportDir, (Join-Path $reportDir 'report.md'))
$paths += @($idList | ForEach-Object { Join-Path $evidenceDir "$_.md" })
foreach ($candidate in $paths) {
    $item = Get-Item -LiteralPath $candidate -Force -ErrorAction SilentlyContinue
    if ($null -ne $item -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Case paths must not contain links or junctions"
    }
}


foreach ($id in $idList) {
    $evidenceFile = Join-Path $evidenceDir "$id.md"
    if (-not (Test-Path -LiteralPath $evidenceFile)) { Write-Error "Evidence file not found: $evidenceFile" }
}

if (-not (Test-Path -LiteralPath $reportDir)) { New-Item -ItemType Directory -Path $reportDir | Out-Null }

foreach ($id in $idList) {
    $evidenceFile = Join-Path $evidenceDir "$id.md"
    $content = Get-Content -LiteralPath $evidenceFile -Raw -Encoding UTF8
    if ($content -match "(?m)^-\s*status:\s*.*$") {
        $content = [regex]::Replace($content, "(?m)^-\s*status:\s*.*$", "- status: superseded by $FindingId")
    } elseif ($content -match "(?m)^---\s*$") {
        $content = [regex]::Replace($content, "(?m)^---\s*$", "---`r`n- status: superseded by $FindingId", 1)
    } else {
        $content = $content.TrimEnd() + "`r`n- status: superseded by $FindingId`r`n"
    }
    Set-Content -LiteralPath $evidenceFile -Value $content -Encoding UTF8 -NoNewline
}

$timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$joined = ($idList -join ', ')
$findingBlock = @"
### $FindingId
- title: $Title
- severity: $Severity
- status: $Status
- confidence: $Confidence
- location: $Location
- evidence_ids: $joined
- consolidated_at: $timestamp

$Description
"@

$reportFile = Join-Path $reportDir "report.md"
if (Test-Path -LiteralPath $reportFile) {
    $reportContent = Get-Content -LiteralPath $reportFile -Raw -Encoding UTF8
    if ($reportContent -notmatch "(?m)^## Findings") {
        $reportContent = $reportContent.TrimEnd() + "`r`n`r`n## Findings`r`n"
    }
    Set-Content -LiteralPath $reportFile -Value ($reportContent.TrimEnd() + "`r`n`r`n" + $findingBlock + "`r`n") -Encoding UTF8 -NoNewline
} else {
    $initialReport = @"
# Case Report

## Findings

$findingBlock
"@
    Set-Content -LiteralPath $reportFile -Value $initialReport -Encoding UTF8
}