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
    # Native child processes let us assert exit codes without terminating this test.
    # Use the same engine as the parent (pwsh or Windows PowerShell 5.1).
    $engine = (Get-Process -Id $PID).Path
    $scanner = Join-Path $PSScriptRoot 'scan-leaks.ps1'
    $marker = 'sk-' + ('A' * 24)
    $cases = @(
        @{ Name='empty'; Text=''; Lines=@() }
        @{ Name='one-clean'; Text='synthetic clean text'; Lines=@() }
        @{ Name='one-match'; Text=$marker; Lines=@(1) }
        @{ Name='one-match-newline'; Text=($marker + "`n"); Lines=@(1) }
        @{ Name='multi-clean'; Text="first clean line`nsecond clean line`n"; Lines=@() }
        @{ Name='multi-match'; Text=("clean first`n" + $marker + "`nclean third`n" + $marker + "`n"); Lines=@(2,4) }
    )
    $scannerChecks = 0
    foreach ($testCase in $cases) {
        $fixture = Join-Path $scratch ($testCase.Name + '.txt')
        [IO.File]::WriteAllText($fixture, $testCase.Text, (New-Object Text.UTF8Encoding($false)))
        if ($testCase.Name -eq 'one-match') {
            $rawLines = Get-Content -LiteralPath $fixture -Encoding UTF8
            Write-Host ("SCANNER_INPUT_SHAPE type={0} indexed_type={1}" -f $rawLines.GetType().FullName, $rawLines[0].GetType().FullName)
        }
        foreach ($reportOnly in @($false, $true)) {
            $arguments = @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $scanner, '-Path', $fixture)
            if ($reportOnly) { $arguments += '-ReportOnly' }
            # Exit 1 is expected for findings in gate mode, not an unhandled native error.
            $PSNativeCommandUseErrorActionPreference = $false
            $output = (& $engine @arguments 2>&1 | Out-String)
            $actualExit = $LASTEXITCODE
            $expectedCount = $testCase.Lines.Count
            $expectedExit = if ($expectedCount -gt 0 -and -not $reportOnly) { 1 } else { 0 }
            if ($output.Contains($marker)) { throw "Scanner leaked synthetic match: $($testCase.Name)" }
            $summary = 'scan-leaks: scanned 1 files, ' + $expectedCount + ' finding(s)'
            if (-not $output.Contains($summary)) {
                throw "Scanner detection mismatch: case=$($testCase.Name), reportOnly=$reportOnly, expectedFindings=$expectedCount"
            }
            if ($actualExit -ne $expectedExit) {
                throw "Scanner exit mismatch: case=$($testCase.Name), reportOnly=$reportOnly, expected=$expectedExit, actual=$actualExit"
            }
            $annotations = @([regex]::Matches($output, '(?m)^::(error|warning) file=.+,line=([0-9]+)::[^\r\n]+: \[REDACTED\]\r?$'))
            if ($annotations.Count -ne $expectedCount) { throw "Scanner redaction/count mismatch: $($testCase.Name)" }
            $kind = if ($reportOnly) { 'warning' } else { 'error' }
            for ($i = 0; $i -lt $annotations.Count; $i++) {
                if ($annotations[$i].Groups[1].Value -ne $kind -or
                    [int]$annotations[$i].Groups[2].Value -ne $testCase.Lines[$i]) {
                    throw "Scanner annotation kind/line mismatch: $($testCase.Name)"
                }
            }
            $scannerChecks++
        }
    }
    Write-Host "SCANNER_REGRESSION_OK cases=$scannerChecks empty/single/multiple lines; detection/redaction/exit codes"
    Write-Host 'AUDIT_SAFETY_PS_OK synthetic paths, metadata, candidate default and redaction'
} finally {
    Remove-Item -LiteralPath $scratch -Recurse -Force
}
