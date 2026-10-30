# Shared test helpers: a fake Cloudflare API (+ ntfy) behind a mocked Invoke-RestMethod, and HTTP error records shaped
# like the ones Invoke-RestMethod throws in pwsh 7.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidGlobalVars', '', Justification = 'Test state shared with mocks')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Test helpers')]
param()

$global:TestTok = 'CfTok_' + ('k' * 34)
$global:TestNtfyTok = 'tk_' + ('n' * 29)
$global:TestZone = '0123456789abcdef0123456789abcdef'

function New-HttpError([int]$Status, [string]$Body = '') {
    $resp = New-Object System.Net.Http.HttpResponseMessage ([System.Net.HttpStatusCode]$Status)
    $ex = New-Object Microsoft.PowerShell.Commands.HttpResponseException ("Response status code does not indicate success: $Status", $resp)
    $er = New-Object Management.Automation.ErrorRecord ($ex, 'WebCmdletWebResponseException', 'InvalidOperation', $null)
    if ($Body) { $er.ErrorDetails = New-Object Management.Automation.ErrorDetails $Body }
    return $er
}

function Reset-FakeCf {
    $global:CfRecords = New-Object System.Collections.ArrayList
    $global:CfCalls = New-Object System.Collections.ArrayList
    $global:CfBodies = New-Object System.Collections.ArrayList
    $global:Ntfy = New-Object System.Collections.ArrayList
    $global:CfFail = $null          # @{ Match = 'regex on "METHOD uri"'; Status = 403; Body = '...' }
    $global:CfVerify = 'active'     # token verify result status, or an int HTTP status to fail with
}

function Add-FakeRecord([string]$Name, [string]$Content, [string]$Type = 'A', [bool]$Proxied = $false, [int]$Ttl = 1) {
    [void]$global:CfRecords.Add([pscustomobject]@{ id = [guid]::NewGuid().ToString('N'); type = $Type; name = $Name
            content = $Content; proxied = $Proxied; ttl = $Ttl })
}

function Invoke-FakeCf($Uri, $Method, $Body, $Headers) {
    $m = ([string]$Method).ToUpperInvariant()
    if (-not $m) { $m = 'GET' }
    $u = [string]$Uri
    if ($u -match '/ntfy') {
        [void]$global:Ntfy.Add([pscustomobject]@{ Title = $Headers.Title; Priority = $Headers.Priority; Auth = $Headers.Authorization
                Body = [Text.Encoding]::UTF8.GetString([byte[]]$Body) })
        return ''
    }
    [void]$global:CfCalls.Add("$m $u")
    if ($Headers.Authorization -ne "Bearer $global:TestTok") { throw (New-HttpError 401 '{"success":false,"errors":[{"code":1000,"message":"Invalid API Token"}]}') }
    if ($global:CfFail -and "$m $u" -match $global:CfFail.Match) { throw (New-HttpError $global:CfFail.Status $global:CfFail.Body) }
    $ok = { param($r) [pscustomobject]@{ success = $true; errors = @(); result = $r } }
    if ($u -match '/user/tokens/verify$') {
        if ($global:CfVerify -is [int]) { throw (New-HttpError $global:CfVerify '{"success":false,"errors":[{"code":1000,"message":"Invalid API Token"}]}') }
        return (& $ok ([pscustomobject]@{ id = 'x'; status = $global:CfVerify }))
    }
    if ($u -notmatch "/zones/$global:TestZone/dns_records") {
        throw (New-HttpError 400 '{"success":false,"errors":[{"code":7003,"message":"Could not route to /zones/x, perhaps your object identifier is invalid?"}]}')
    }
    if ($m -eq 'GET') {
        $q = @{}
        if ($u -match '\?(.*)$') { foreach ($kv in $Matches[1] -split '&') { $k, $v = $kv -split '=', 2; $q[$k] = [uri]::UnescapeDataString($v) } }
        $r = @($global:CfRecords | Where-Object { (-not $q.type -or $_.type -eq $q.type) -and (-not $q.name -or $_.name -eq $q.name) })
        if ($q.per_page) { $r = @($r | Select-Object -First ([int]$q.per_page)) }
        return (& $ok $r)
    }
    $b = $null
    if ($Body) { $b = $Body | ConvertFrom-Json; [void]$global:CfBodies.Add("$m $Body") }
    if ($m -eq 'POST') {
        Add-FakeRecord -Name $b.name -Content $b.content -Type $b.type -Proxied ([bool]$b.proxied) -Ttl ([int]$b.ttl)
        return (& $ok $global:CfRecords[-1])
    }
    if ($m -eq 'PATCH' -and $u -match '/dns_records/([0-9a-f]+)$') {
        $rec = $global:CfRecords | Where-Object id -eq $Matches[1]
        foreach ($p in $b.PSObject.Properties) { $rec.($p.Name) = $p.Value }
        return (& $ok $rec)
    }
    throw "fake CF: unhandled $m $u"
}
