<#
Invoke-Tests.ps1 - offline lint + test run for DX-CF-DDNS.
  * PSScriptAnalyzer (default rules + PS 5.1 / 7 compatibility rules for the shipped scripts) on all .ps1 files
  * Pester tests in tests/ (Cloudflare API, IP providers, scheduled task and ACL cmdlets are mocked)
Exit codes: 0 = all passed, 1 = lint findings or test failures.
#>
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$settings = @{
    Rules = @{
        PSUseCompatibleSyntax   = @{ Enable = $true; TargetVersions = @('5.1', '7.0') }
        PSUseCompatibleCommands = @{ Enable = $true; TargetProfiles = @(
                'win-8_x64_10.0.17763.0_5.1.17763.316_x64_4.0.30319.42000_framework',   # Server 2019, PS 5.1
                'win-8_x64_10.0.14393.0_5.1.14393.2791_x64_4.0.30319.42000_framework',  # Server 2016, PS 5.1
                'win-8_x64_10.0.17763.0_7.0.0_x64_3.1.2_core') }                          # PS 7
        PSUseCompatibleTypes    = @{ Enable = $true; TargetProfiles = @(
                'win-8_x64_10.0.14393.0_5.1.14393.2791_x64_4.0.30319.42000_framework',
                'win-8_x64_10.0.17763.0_7.0.0_x64_3.1.2_core') }
    }
}
$files = Get-ChildItem -Path $root -Recurse -Filter *.ps1 | Where-Object { $_.FullName -notmatch '[\\/]\.git[\\/]' }
$findings = @()
foreach ($f in $files) {
    if ($f.FullName -notmatch '[\\/]tests[\\/]|[\\/]tools[\\/]') {
        $findings += Invoke-ScriptAnalyzer -Path $f.FullName -Settings $settings -ExcludeRule PSAvoidUsingWriteHost
    }
    $findings += Invoke-ScriptAnalyzer -Path $f.FullName -IncludeDefaultRules -ExcludeRule PSAvoidUsingWriteHost
}
$findings = $findings | Sort-Object ScriptName, Line, RuleName -Unique
if ($findings) { $findings | Format-Table ScriptName, Line, Severity, RuleName, Message -AutoSize -Wrap | Out-String -Width 220 | Write-Output }
Write-Output ("PSScriptAnalyzer: {0} finding(s) in {1} file(s)" -f @($findings).Count, $files.Count)
$cfg = New-PesterConfiguration
$cfg.Run.Path = Join-Path $root 'tests'
$cfg.Run.PassThru = $true
$cfg.Output.Verbosity = 'Detailed'
$res = Invoke-Pester -Configuration $cfg
Write-Output ("Pester: {0} passed, {1} failed, {2} skipped" -f $res.PassedCount, $res.FailedCount, $res.SkippedCount)
if (@($findings).Count -gt 0 -or $res.FailedCount -gt 0) { exit 1 }
exit 0
