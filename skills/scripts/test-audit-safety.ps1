#Requires -Version 5.1
# Synthetic local fixtures only. Does not bootstrap tools or contact any target.
$ErrorActionPreference = 'Stop'
$scratch = Join-Path ([IO.Path]::GetTempPath()) ('reverse-safety-' + [guid]::NewGuid().ToString('N'))
$case = Join-Path $scratch 'case'
$evidence = Join-Path $case 'evidence'
$report = Join-Path $case 'report'
$script = Join-Path $PSScriptRoot 'consolidate-evidence.ps1'
New-Item -ItemType Directory -Path $evidence -Force | Out-Null
try {
    $original = "### E-001`n- status: observed`n"
    Set-Content -LiteralPath (Join-Path $evidence 'E-001.md') -Value $original -Encoding UTF8
    Set-Content -LiteralPath (Join-Path $case 'outside.md') -Value 'synthetic outside fixture' -Encoding UTF8
    $outsideBefore = [IO.File]::ReadAllBytes((Join-Path $case 'outside.md'))
    foreach ($bad in @('../outside', '..\outside', 'E-001,E-001', 'E-001/../../outside')) {
        $denied = $false
        try { & $script -CaseRoot $case -EvidenceIds $bad -FindingId 'F-001' -Title 'synthetic' -Description 'synthetic' }
        catch { $denied = $true }
        if (-not $denied) { throw 'Invalid Evidence ID accepted' }
        if (Test-Path -LiteralPath $report) { throw 'Rejected input created report directory' }
        $after = [IO.File]::ReadAllBytes((Join-Path $case 'outside.md'))
        if ([Convert]::ToBase64String($after) -ne [Convert]::ToBase64String($outsideBefore)) { throw 'Outside fixture changed' }
    }
    foreach ($field in @('FindingId', 'Title')) {
        $argsMap = @{CaseRoot=$case; EvidenceIds='E-001'; FindingId='F-001'; Title='synthetic'; Description='synthetic'}
        $argsMap[$field] = "F-001`n## synthetic"
        $denied = $false
        try { & $script @argsMap } catch { $denied = $true }
        if (-not $denied -or (Test-Path -LiteralPath $report)) { throw 'Metadata injection accepted or wrote output' }
    }
    & $script -CaseRoot $case -EvidenceIds 'E-001' -FindingId 'F-001' -Title 'synthetic' -Description 'synthetic'
    if ((Get-Content -LiteralPath (Join-Path $report 'report.md') -Raw) -notmatch '(?m)^- status: candidate\r?$') {
        throw 'Consolidation silently promoted a candidate'
    }
    # Scanner must identify a synthetic match without printing its value.
    $fixture = Join-Path $scratch 'synthetic-leak.txt'
    $marker = 'sk-' + ('A' * 24)
    Set-Content -LiteralPath $fixture -Value $marker -Encoding ASCII
    $output = & (Join-Path $PSScriptRoot 'scan-leaks.ps1') -Path $fixture -ReportOnly 6>&1 | Out-String
    if ($output.Contains($marker) -or -not $output.Contains('[REDACTED]')) { throw 'Leak scanner output is not redacted' }
    Write-Host 'AUDIT_SAFETY_PS_OK synthetic paths, metadata, candidate default and redaction'
} finally {
    Remove-Item -LiteralPath $scratch -Recurse -Force
}
