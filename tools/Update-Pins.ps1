<#
Update-Pins.ps1 - writes the SHA256 of src/DX-CF-DDNS.ps1 into the BEGIN-PINS block of install.ps1.
Run it before every commit that changes src/DX-CF-DDNS.ps1 (the tests fail if the pin is stale).
Hashes are over the exact bytes in the repo (LF line endings, see .gitattributes). Exit codes: 0 = updated, 1 = error.
#>
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$installer = Join-Path $root 'install.ps1'
$text = [IO.File]::ReadAllText($installer)
foreach ($rel in @('src/DX-CF-DDNS.ps1')) {
    $hash = (Get-FileHash -LiteralPath (Join-Path $root $rel) -Algorithm SHA256).Hash
    $pattern = "('" + [regex]::Escape($rel) + "'\s*=\s*)'[0-9A-Fa-f]*'"
    if ($text -notmatch $pattern) { Write-Error "pin line for $rel not found in install.ps1"; exit 1 }
    $text = [regex]::Replace($text, $pattern, ('${1}' + "'$hash'"))
    Write-Output "$rel $hash"
}
[IO.File]::WriteAllText($installer, $text, (New-Object Text.UTF8Encoding($false)))
exit 0
