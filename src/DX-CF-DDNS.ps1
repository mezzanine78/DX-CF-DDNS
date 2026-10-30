<#
DX-CF-DDNS.ps1 - DX Cloudflare dynamic DNS updater (client side). Marker: DX Cloudflare DDNS updater

Runs as SYSTEM every few minutes (scheduled task \DX\DX-CF-DDNS, registered by install.ps1) and keeps one or more
Cloudflare DNS records (A, and optionally AAAA) pointing at this site's public IP.

  1. Public IPv4 from https://1.1.1.1/cdn-cgi/trace, https://api.ipify.org, https://ipv4.icanhazip.com (in that order).
     Each answer must be one globally routable address (private, CGNAT, loopback, documentation, reserved ... rejected).
     Agreement rule: providers are asked in order until two agree. If only one gives a valid answer it is used (WARN);
     if they disagree (dual WAN / load balancing) nothing is changed this run (exit 2).
  2. The Cloudflare API is called only when the IP differs from the State cache, the config changed, the last run
     failed, every -VerifyHours (default 6) to re-check the records, or with -Force.
  3. Per record: GET it; PATCH when the content (or the configured proxied / TTL) differs; POST to create it when
     missing and Create is on. Nothing is written when the record already matches.

Windows PowerShell 5.1 and pwsh 7. The API token is read from the ACL'd config file and never logged.
  powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\Windows\Scripts\DX\Scripts\DX-CF-DDNS.ps1

Exit codes:
  0 = OK (records match / updated / created, or nothing due)
  1 = configuration error (missing/invalid config file, zone ID, record names or token)
  2 = no public IP (all providers failed, or providers disagree)
  3 = Cloudflare API / network / TLS error (incl. 429 and 5xx)
  4 = Cloudflare rejected the token (HTTP 401/403: invalid, expired, or no DNS edit access to this zone)
  5 = record missing and Create is off
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Console output for RMM / technician')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Script parameters are read inside the functions')]
[CmdletBinding()]
param(
    [string]$ConfigPath = '',         # default <root>\Config\DX-CF-DDNS.json
    [string]$StateDir = '',           # default <root>\State
    [string]$LogDir = '',             # default <root>\Logs     (<root> = C:\Windows\Scripts\DX)
    [switch]$Force,                   # check the records now even if nothing changed
    [int]$VerifyHours = 6,            # re-check the records at least this often
    [string[]]$IpProviders = @(),
    [string[]]$Ip6Providers = @(),
    [int]$TimeoutSec = 10,
    [string]$ApiBase = 'https://api.cloudflare.com/client/v4'
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$ScriptVersion = '1.0.0'
$DefaultIpProviders = @('https://1.1.1.1/cdn-cgi/trace', 'https://api.ipify.org', 'https://ipv4.icanhazip.com')
$DefaultIp6Providers = @('https://[2606:4700:4700::1111]/cdn-cgi/trace', 'https://api6.ipify.org', 'https://ipv6.icanhazip.com')
$script:LogFile = $null
$script:Secrets = @()
$script:TlsDiagDone = $false

function Get-DXDefaultRoot {
    $sr = [string]$env:SystemRoot
    if (-not $sr) { $sr = 'C:\Windows' }
    return ($sr.TrimEnd('\', '/') + '\Scripts\DX')
}

function Protect-DXText([string]$Text) {
    # Masks every secret we hold (API token, ntfy token) in a log line.
    foreach ($s in $script:Secrets) { if ($s -and $s.Length -ge 6) { $Text = $Text.Replace($s, '***') } }
    return $Text
}

function Write-DXLog([string]$Msg, [string]$Level = 'INFO') {
    # DEBUG lines go to the console only (keeps the log quiet while nothing changes).
    $line = '{0} DX cf-ddns {1,-5} {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, (Protect-DXText $Msg)
    Write-Host $line
    if ($script:LogFile -and $Level -ne 'DEBUG') {
        try {
            if ((Test-Path -LiteralPath $script:LogFile) -and (Get-Item -LiteralPath $script:LogFile).Length -gt 1MB) {
                Move-Item -LiteralPath $script:LogFile -Destination ($script:LogFile + '.1') -Force
            }
            Add-Content -LiteralPath $script:LogFile -Value $line -Encoding UTF8
        }
        catch { $null = $_ }  # a locked/full log must never stop the update
    }
}

# ------------------------------------------------------------------------------------------------ TLS
function Get-DXTlsProtocolSet([int]$Current, [int]$Build, [bool]$IsWin, [string[]]$Names) {
    # Existing flags -bor Tls12 (3072); Tls13 (12288) only if the enum exists AND Windows can do it (build 20348+),
    # because forcing Tls13 on older Windows makes .NET Framework fail every handshake.
    $p = $Current -bor 3072
    if ($Names -contains 'Tls13' -and (-not $IsWin -or $Build -ge 20348)) { $p = $p -bor 12288 }
    return $p
}

function Enable-DXTlsProtocol {
    try {
        $build = 0
        $isWinOs = ($env:OS -eq 'Windows_NT')
        if ($isWinOs) { $build = [Environment]::OSVersion.Version.Build }
        $p = Get-DXTlsProtocolSet -Current ([int][Net.ServicePointManager]::SecurityProtocol) -Build $build -IsWin $isWinOs `
            -Names ([enum]::GetNames([Net.SecurityProtocolType]))
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]$p
        Write-DXLog "TLS protocols: $([Net.ServicePointManager]::SecurityProtocol)" 'DEBUG'
    }
    catch { Write-DXLog "could not set TLS protocols: $($_.Exception.Message)" 'WARN' }
}

function Test-DXTlsFailure($Exception) {
    $e = $Exception
    $n = 0
    while ($null -ne $e -and $n -lt 10) {
        if ($e -is [Net.WebException] -and $e.Status -eq [Net.WebExceptionStatus]::SecureChannelFailure) { return $true }
        if ($e -is [Security.Authentication.AuthenticationException]) { return $true }
        if ([string]$e.Message -match 'SSL/TLS|secure channel|SSL connection could not be established|TLS handshake') { return $true }
        $e = $e.InnerException
        $n++
    }
    return $false
}

function ConvertTo-DXNetFxVersion([int]$Release) {
    $map = @(@(533320, '4.8.1'), @(528040, '4.8'), @(461808, '4.7.2'), @(461308, '4.7.1'), @(460798, '4.7'),
        @(394802, '4.6.2'), @(394254, '4.6.1'), @(393295, '4.6'), @(379893, '4.5.2'), @(378675, '4.5.1'), @(378389, '4.5'))
    foreach ($m in $map) { if ($Release -ge $m[0]) { return $m[1] } }
    if ($Release -gt 0) { return 'older than 4.5' }
    return 'not found'
}

function Get-DXPlatformInfo {
    $i = [ordered]@{ Caption = ''; Build = 0; PSVersion = [string]$PSVersionTable.PSVersion; NetRelease = 0 }
    if ($env:OS -eq 'Windows_NT') {
        try {
            $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
            $i.Caption = [string]$os.Caption; $i.Build = [int]$os.BuildNumber
        }
        catch {
            try {
                $k = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
                $i.Caption = [string]$k.ProductName; $i.Build = [int]$k.CurrentBuildNumber
            }
            catch { $null = $_ }
        }
        try { $i.NetRelease = [int](Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -Name Release -ErrorAction Stop).Release }
        catch { $null = $_ }
    }
    if (-not $i.Build) { $i.Build = [Environment]::OSVersion.Version.Build }
    if (-not $i.Caption) { $i.Caption = [Environment]::OSVersion.VersionString }
    return [pscustomobject]$i
}

function Get-DXTlsAdvice($Info) {
    $lines = @(
        "TLS handshake failed on $($Info.Caption) (build $($Info.Build)), PowerShell $($Info.PSVersion), .NET Framework $(ConvertTo-DXNetFxVersion $Info.NetRelease) (release $($Info.NetRelease))",
        'TLS hint: let .NET use strong crypto / the OS TLS defaults: set DWORD SchUseStrongCrypto=1 and SystemDefaultTlsVersions=1 under HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319 and HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319, then let the task run again')
    if ($Info.Build -eq 9600) {
        $lines += 'TLS hint (Windows 8.1 / Server 2012 R2, build 9600): install the latest rollup updates (the KB3140245-era TLS 1.2 updates and later); Cloudflare requires TLS 1.2 with ECDHE-GCM cipher suites, which an unpatched 2012 R2 does not offer'
    }
    return $lines
}

function Write-DXTlsDiagnostic {
    if ($script:TlsDiagDone) { return }
    $script:TlsDiagDone = $true
    try { foreach ($l in (Get-DXTlsAdvice (Get-DXPlatformInfo))) { Write-DXLog $l 'WARN' } }
    catch { Write-DXLog "TLS diagnostics failed: $($_.Exception.Message)" 'WARN' }
}

# ------------------------------------------------------------------------------------------------ public IP
function Test-DXPublicIPv4([string]$Value) {
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $v = $Value.Trim()
    # Strict dotted quad: [IPAddress]::TryParse would also accept '1' or '1.2.3' (as 0.0.0.1 / 1.2.0.3).
    if ($v -notmatch '^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$') { return $false }
    $o = [int[]]($v.Split('.'))
    $n = ([uint32]$o[0] -shl 24) -bor ([uint32]$o[1] -shl 16) -bor ([uint32]$o[2] -shl 8) -bor [uint32]$o[3]
    $blocked = @(  # non-global IPv4 (RFC 6890 / IANA special-purpose registry)
        @('0.0.0.0', 8), @('10.0.0.0', 8), @('100.64.0.0', 10), @('127.0.0.0', 8), @('169.254.0.0', 16),
        @('172.16.0.0', 12), @('192.0.0.0', 24), @('192.0.2.0', 24), @('192.88.99.0', 24), @('192.168.0.0', 16),
        @('198.18.0.0', 15), @('198.51.100.0', 24), @('203.0.113.0', 24), @('224.0.0.0', 4), @('240.0.0.0', 4))
    foreach ($b in $blocked) {
        $bo = [int[]]($b[0].Split('.'))
        $bn = ([uint32]$bo[0] -shl 24) -bor ([uint32]$bo[1] -shl 16) -bor ([uint32]$bo[2] -shl 8) -bor [uint32]$bo[3]
        $mask = [uint32]([math]::Pow(2, 32) - [math]::Pow(2, 32 - $b[1]))
        if (($n -band $mask) -eq $bn) { return $false }
    }
    return $true
}

function Test-DXPublicIPv6([string]$Value) {
    # Global unicast 2000::/3 only, excluding documentation 2001:db8::/32. No zone IDs, no embedded IPv4 forms.
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $v = $Value.Trim()
    if ($v -notmatch '^[0-9A-Fa-f:]{2,39}$' -or $v -notmatch ':') { return $false }
    $a = $null
    if (-not [Net.IPAddress]::TryParse($v, [ref]$a)) { return $false }
    if ($a.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetworkV6) { return $false }
    $b = $a.GetAddressBytes()
    if (($b[0] -band 0xE0) -ne 0x20) { return $false }
    if ($b[0] -eq 0x20 -and $b[1] -eq 0x01 -and $b[2] -eq 0x0D -and $b[3] -eq 0xB8) { return $false }
    return $true
}

function ConvertFrom-DXIpResponse($Content) {
    # Plain text ('203.0.113.5\n') or Cloudflare trace ('...\nip=203.0.113.5\n...'). Returns the trimmed candidate.
    if ($Content -is [byte[]]) { $Content = [Text.Encoding]::ASCII.GetString($Content) }
    $t = [string]$Content
    if ($t -match '(?m)^ip=([^\r\n]+)') { return $Matches[1].Trim() }
    return $t.Trim()
}

function Get-DXPublicIp([string[]]$Providers, [string]$Family, [int]$Timeout) {
    # Returns the address two providers agree on; a single valid answer if only one provider answered; else $null
    # (with $script:IpProblem = 'none' or 'disagree').
    $votes = [ordered]@{}
    $script:IpProblem = 'none'
    foreach ($u in $Providers) {
        try {
            $r = Invoke-WebRequest -Uri $u -UseBasicParsing -TimeoutSec $Timeout -Headers @{ 'User-Agent' = "dx-cf-ddns/$ScriptVersion" }
            $ip = ConvertFrom-DXIpResponse $r.Content
            $ok = $false
            if ($Family -eq 'v6') { $ok = Test-DXPublicIPv6 $ip } else { $ok = Test-DXPublicIPv4 $ip }
            if (-not $ok) {
                $shown = $ip
                if ($shown.Length -gt 40) { $shown = $shown.Substring(0, 40) + '...' }
                Write-DXLog "IP provider $u returned an invalid/non-public value '$shown'" 'WARN'
                continue
            }
            if ($Family -eq 'v6') { $ip = ([Net.IPAddress]::Parse($ip)).ToString() }  # canonical form for comparisons
            if ($votes.Contains($ip)) { $votes[$ip]++ } else { $votes[$ip] = 1 }
            if ($votes[$ip] -ge 2) { return $ip }
        }
        catch {
            Write-DXLog "IP provider $u failed: $($_.Exception.Message)" 'WARN'
            if (Test-DXTlsFailure $_.Exception) { Write-DXTlsDiagnostic }
        }
    }
    if ($votes.Count -eq 1) {
        $only = @($votes.Keys)[0]
        Write-DXLog "only one provider gave a valid public $Family address ($only); using it" 'WARN'
        return $only
    }
    if ($votes.Count -gt 1) {
        $script:IpProblem = 'disagree'
        Write-DXLog ("IP providers disagree (" + (@($votes.Keys) -join ', ') + "): dual WAN / load balancing? Nothing changed") 'ERROR'
    }
    return $null
}

# ------------------------------------------------------------------------------------------------ Cloudflare
function Get-DXHttpStatus($ErrorRecord) {
    try {
        $resp = $ErrorRecord.Exception.Response
        if ($null -ne $resp -and $null -ne $resp.StatusCode) { return [int]$resp.StatusCode }
    }
    catch { $null = $_ }
    return 0
}

function Invoke-DXCfApi([string]$Method, [string]$Path, $Body = $null) {
    # Never throws. Returns Ok / Status / Result / Message / Kind ('ok','auth','error').
    $p = @{ Uri = $script:Api + $Path; Method = $Method; TimeoutSec = ($TimeoutSec * 2); UseBasicParsing = $true
        Headers = @{ Authorization = "Bearer $($script:Token)"; 'User-Agent' = "dx-cf-ddns/$ScriptVersion" }
    }
    if ($null -ne $Body) { $p.Body = ($Body | ConvertTo-Json -Compress); $p.ContentType = 'application/json' }
    try {
        $r = Invoke-RestMethod @p
        if ($r.success -eq $false) {
            $m = (@($r.errors) | ForEach-Object { "$($_.code): $($_.message)" }) -join '; '
            return [pscustomobject]@{ Ok = $false; Status = 200; Result = $null; Message = "success=false $m"; Kind = 'error' }
        }
        return [pscustomobject]@{ Ok = $true; Status = 200; Result = $r.result; Message = ''; Kind = 'ok' }
    }
    catch {
        $status = Get-DXHttpStatus $_
        $detail = $_.Exception.Message
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
            try {
                $j = $_.ErrorDetails.Message | ConvertFrom-Json
                $detail = (@($j.errors) | ForEach-Object { "$($_.code): $($_.message)" }) -join '; '
            }
            catch { $detail = [string]$_.ErrorDetails.Message }
        }
        $kind = 'error'
        if ($status -eq 401 -or $status -eq 403) { $kind = 'auth' }
        elseif (-not $status -and (Test-DXTlsFailure $_.Exception)) { Write-DXTlsDiagnostic }
        $s = ''
        if ($status) { $s = "HTTP $status " }
        return [pscustomobject]@{ Ok = $false; Status = $status; Result = $null; Message = "$s$detail".Trim(); Kind = $kind }
    }
}

function Sync-DXRecord([string]$Name, [string]$Type, [string]$Ip, $Cfg) {
    # Returns 'unchanged' | 'updated' | 'created' | 'missing' | 'auth' | 'error'
    $zone = [uri]::EscapeDataString($Cfg.ZoneId)
    $q = "/zones/$zone/dns_records?type=$Type&name=$([uri]::EscapeDataString($Name))"
    $g = Invoke-DXCfApi -Method GET -Path $q
    if (-not $g.Ok) {
        Write-DXLog "$Type $Name lookup failed: $($g.Message)" 'ERROR'
        if ($g.Kind -eq 'auth') { Write-DXLog 'the token was rejected (401/403): invalid, expired, or no DNS edit access to this zone' 'ERROR' }
        return $g.Kind
    }
    $recs = @($g.Result | Where-Object { $_ })
    $proxied = $null
    if ($null -ne $Cfg.Proxied -and "$($Cfg.Proxied)" -ne '') { $proxied = [bool]$Cfg.Proxied }
    $ttl = $null
    if ($null -ne $Cfg.Ttl -and "$($Cfg.Ttl)" -ne '') { $ttl = [int]$Cfg.Ttl }
    if ($recs.Count -eq 0) {
        if (-not $Cfg.Create) { Write-DXLog "$Type $Name not found in the zone (create it, or set CF_DDNS_CREATE=1)" 'ERROR'; return 'missing' }
        $body = [ordered]@{ type = $Type; name = $Name; content = $Ip; ttl = 1; proxied = $false; comment = 'managed by DX-CF-DDNS' }
        if ($null -ne $proxied) { $body.proxied = $proxied }
        if ($null -ne $ttl -and -not $body.proxied) { $body.ttl = $ttl }
        $c = Invoke-DXCfApi -Method POST -Path "/zones/$zone/dns_records" -Body $body
        if (-not $c.Ok) { Write-DXLog "$Type $Name create failed: $($c.Message)" 'ERROR'; return $c.Kind }
        Write-DXLog "CREATED $Type $Name -> $Ip (proxied=$($body.proxied), ttl=$($body.ttl))"
        return 'created'
    }
    if ($recs.Count -gt 1) {
        Write-DXLog "$($recs.Count) $Type records named ${Name}: updating only the first ($($recs[0].id)); delete the duplicates" 'WARN'
    }
    $rec = $recs[0]
    $was = [string]$rec.content
    $patch = [ordered]@{}
    if ([string]$rec.content -ne $Ip) { $patch.content = $Ip }
    $effProxied = [bool]$rec.proxied
    if ($null -ne $proxied -and [bool]$rec.proxied -ne $proxied) { $patch.proxied = $proxied; $effProxied = $proxied }
    if ($null -ne $ttl -and -not $effProxied -and [int]$rec.ttl -ne $ttl) { $patch.ttl = $ttl }
    if ($patch.Count -eq 0) { Write-DXLog "$Type $Name already $Ip" 'DEBUG'; return 'unchanged' }
    $u = Invoke-DXCfApi -Method PATCH -Path "/zones/$zone/dns_records/$([uri]::EscapeDataString([string]$rec.id))" -Body $patch
    if (-not $u.Ok) { Write-DXLog "$Type $Name update failed: $($u.Message)" 'ERROR'; return $u.Kind }
    $what = @($patch.Keys | ForEach-Object { "$_=$($patch[$_])" }) -join ', '
    Write-DXLog "UPDATED $Type $Name $was -> $Ip ($what)"
    return 'updated'
}

# ------------------------------------------------------------------------------------------------ ntfy
function Send-DXNtfy([string]$Title, [string]$Message, [int]$Priority) {
    if (-not $script:NtfyUrl) { return }
    $h = @{ Title = "DX CF-DDNS: $Title"; Priority = [string]$Priority; Tags = 'globe_with_meridians' }
    if ($script:NtfyToken) { $h.Authorization = "Bearer $($script:NtfyToken)" }
    try {
        Invoke-RestMethod -Uri $script:NtfyUrl -Method Post -Headers $h -Body ([Text.Encoding]::UTF8.GetBytes($Message)) `
            -ContentType 'text/plain; charset=utf-8' -TimeoutSec 15 -UseBasicParsing | Out-Null
    }
    catch {
        $st = Get-DXHttpStatus $_
        $why = $_.Exception.Message
        if ($st -eq 401 -or $st -eq 403) { $why = "HTTP $st - CF_DDNS_NTFY_TOKEN invalid/expired or no write access to the topic" }
        elseif ($st) { $why = "HTTP $st" }
        Write-DXLog "ntfy send failed: $why" 'WARN'
    }
}

# ------------------------------------------------------------------------------------------------ main
function Get-DXConfigHash($Cfg) {
    $s = '{0}|{1}|{2}|{3}|{4}|{5}' -f $Cfg.ZoneId, (@($Cfg.Records) -join ','), $Cfg.Proxied, $Cfg.Ttl, $Cfg.IPv6, $Cfg.Create
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($s)))).Replace('-', '').Substring(0, 16) }
    finally { $sha.Dispose() }
}

function Read-DXConfig([string]$Path) {
    # Returns the normalised config or throws with a readable message.
    if (-not (Test-Path -LiteralPath $Path)) { throw "config file $Path not found (re-run the installer)" }
    try { $c = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json } catch { throw "config file $Path is not valid JSON" }
    $zone = ([string]$c.ZoneId).Trim().ToLowerInvariant()
    if ($zone -notmatch '^[0-9a-f]{32}$') { throw 'ZoneId must be the 32-hex zone ID (zone Overview > API > Zone ID)' }
    $names = @(@($c.Records) | ForEach-Object { [string]$_ -split '[,;\s]+' } | Where-Object { $_ } |
            ForEach-Object { $_.Trim().TrimEnd('.').ToLowerInvariant() } | Select-Object -Unique)
    if ($names.Count -eq 0) { throw 'no record names in the config (CF_DDNS_RECORD)' }
    foreach ($n in $names) {
        if ($n -notmatch '^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$') { throw "record name '$n' is not a valid FQDN" }
    }
    $tok = [string]$c.Token
    if ($tok -notmatch '^[A-Za-z0-9_-]{20,200}$') { throw 'API token missing or malformed in the config' }
    $ttl = $null
    if ($null -ne $c.Ttl -and "$($c.Ttl)" -ne '') {
        $ttl = [int]$c.Ttl
        if ($ttl -ne 1 -and ($ttl -lt 60 -or $ttl -gt 86400)) { throw 'Ttl must be 1 (auto) or 60-86400 seconds' }
    }
    $prox = $null
    if ($null -ne $c.Proxied -and "$($c.Proxied)" -ne '') { $prox = [bool]$c.Proxied }
    $ntfy = [string]$c.NtfyUrl
    if ($ntfy -and $ntfy -notmatch '^https?://[^\s/]+') { throw 'NtfyUrl must be an http(s) URL' }
    return [pscustomobject]@{ ZoneId = $zone; Records = $names; Token = $tok; Proxied = $prox; Ttl = $ttl
        Create = [bool]$c.Create; IPv6 = [bool]$c.IPv6; NtfyUrl = $ntfy; NtfyToken = [string]$c.NtfyToken
    }
}

function Invoke-DXDnsUpdate {
    $root = Get-DXDefaultRoot
    if (-not $ConfigPath) { $ConfigPath = Join-Path $root 'Config\DX-CF-DDNS.json' }
    if (-not $StateDir) { $StateDir = Join-Path $root 'State' }
    if (-not $LogDir) { $LogDir = Join-Path $root 'Logs' }
    try {
        if (-not (Test-Path -LiteralPath $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
        $script:LogFile = Join-Path $LogDir 'DX-CF-DDNS.log'
    }
    catch { $script:LogFile = $null }
    Write-DXLog "start v$ScriptVersion on $([Environment]::MachineName) (PS $($PSVersionTable.PSVersion))" 'DEBUG'

    try { $cfg = Read-DXConfig $ConfigPath }
    catch { Write-DXLog "config error: $($_.Exception.Message) (exit 1)" 'ERROR'; return 1 }
    $script:Token = $cfg.Token
    $script:NtfyUrl = $cfg.NtfyUrl
    $script:NtfyToken = $cfg.NtfyToken
    $script:Secrets = @($cfg.Token, $cfg.NtfyToken)
    $script:Api = $ApiBase.TrimEnd('/')
    $v4Providers = @($IpProviders | ForEach-Object { $_ -split '[,;\s]+' } | Where-Object { $_ })
    if ($v4Providers.Count -eq 0) { $v4Providers = $DefaultIpProviders }
    $v6Providers = @($Ip6Providers | ForEach-Object { $_ -split '[,;\s]+' } | Where-Object { $_ })
    if ($v6Providers.Count -eq 0) { $v6Providers = $DefaultIp6Providers }

    if (-not (Test-Path -LiteralPath $StateDir)) { New-Item -ItemType Directory -Path $StateDir -Force | Out-Null }
    $statePath = Join-Path $StateDir 'DX-CF-DDNS-state.json'
    $state = $null
    if (Test-Path -LiteralPath $statePath) { try { $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json } catch { $state = $null } }
    $st = [ordered]@{ Ipv4 = ''; Ipv6 = ''; ConfigHash = ''; LastVerifyUtc = ''; Pending = $false; FailKey = ''; FailNotifiedUtc = ''; ChangeNotifiedUtc = '' }
    if ($state) { foreach ($k in @($st.Keys)) { if ($null -ne $state.$k) { $st[$k] = $state.$k } } }
    $save = { $st | ConvertTo-Json | Set-Content -LiteralPath $statePath -Encoding UTF8 }
    $nowUtc = (Get-Date).ToUniversalTime()

    Enable-DXTlsProtocol   # before any web call: the task is a fresh process, the installer's TLS setting does not carry over
    $ip4 = Get-DXPublicIp -Providers $v4Providers -Family 'v4' -Timeout $TimeoutSec
    $fail = { param($Key, [int]$Code, [string]$Msg)
        # One ntfy per failure kind per 6 h; state.Pending forces a retry next run.
        $st.Pending = $true
        $last = [datetime]::MinValue
        [void][datetime]::TryParse([string]$st.FailNotifiedUtc, [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$last)
        if ($st.FailKey -ne $Key -or ($nowUtc - $last).TotalHours -ge 6) {
            Send-DXNtfy -Title "FAILED on $([Environment]::MachineName)" -Message "$Msg (exit $Code)" -Priority 5
            $st.FailKey = $Key; $st.FailNotifiedUtc = $nowUtc.ToString('o')
        }
        & $save
        Write-DXLog "$Msg (exit $Code)" 'ERROR'
        return $Code
    }
    if (-not $ip4) {
        if ($script:IpProblem -eq 'disagree') { return (& $fail 'ip-disagree' 2 'public IP providers disagree; records left unchanged') }
        return (& $fail 'ip-none' 2 'no public IPv4 could be determined')
    }
    $ip6 = $null
    if ($cfg.IPv6) {
        $ip6 = Get-DXPublicIp -Providers $v6Providers -Family 'v6' -Timeout $TimeoutSec
        if (-not $ip6) { Write-DXLog 'IPv6 is on but no public IPv6 was found; AAAA records skipped this run' 'WARN' }
    }

    $hash = Get-DXConfigHash $cfg
    $last = [datetime]::MinValue
    $parsed = [datetime]::TryParse([string]$st.LastVerifyUtc, [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$last)
    $reason = ''
    if ($Force) { $reason = 'forced' }
    elseif (-not $state) { $reason = 'first run' }
    elseif ($st.ConfigHash -ne $hash) { $reason = 'config changed' }
    elseif ($st.Pending) { $reason = 'retry after a failure' }
    elseif ($st.Ipv4 -ne $ip4) { $reason = "IPv4 changed $($st.Ipv4) -> $ip4" }
    elseif ($ip6 -and $st.Ipv6 -ne $ip6) { $reason = "IPv6 changed $($st.Ipv6) -> $ip6" }
    elseif (-not $parsed -or ($nowUtc - $last).TotalHours -ge $VerifyHours) { $reason = "periodic check (${VerifyHours}h)" }
    if (-not $reason) { Write-DXLog "IP $ip4 unchanged, records checked $($st.LastVerifyUtc) UTC; nothing to do" 'DEBUG'; return 0 }
    Write-DXLog "checking $(@($cfg.Records).Count) record(s) for $ip4$(if ($ip6) { " / $ip6" }) ($reason)"

    $results = @()
    $changes = @()
    foreach ($name in $cfg.Records) {
        $pairs = @([pscustomobject]@{ Type = 'A'; Ip = $ip4 })
        if ($ip6) { $pairs += [pscustomobject]@{ Type = 'AAAA'; Ip = $ip6 } }
        foreach ($pr in $pairs) {
            $r = Sync-DXRecord -Name $name -Type $pr.Type -Ip $pr.Ip -Cfg $cfg
            $results += $r
            if ($r -eq 'updated' -or $r -eq 'created') { $changes += "$r $($pr.Type) $name -> $($pr.Ip)" }
        }
    }
    if ($changes.Count) {
        Send-DXNtfy -Title "IP change on $([Environment]::MachineName)" -Message ($changes -join "`n") -Priority 3
        $st.ChangeNotifiedUtc = $nowUtc.ToString('o')
    }
    $code = 0
    if ($results -contains 'auth') { $code = 4 } elseif ($results -contains 'error') { $code = 3 } elseif ($results -contains 'missing') { $code = 5 }
    if ($code) {
        $st.ConfigHash = $hash
        $msgs = @{ 4 = 'Cloudflare rejected the token (401/403)'; 3 = 'Cloudflare API / network error'; 5 = 'DNS record missing (create it or set CF_DDNS_CREATE=1)' }
        return (& $fail "cf-$code" $code $msgs[$code])
    }
    if ($st.FailKey) { Send-DXNtfy -Title "recovered on $([Environment]::MachineName)" -Message "records OK at $ip4" -Priority 3; $st.FailKey = ''; $st.FailNotifiedUtc = '' }
    $st.Ipv4 = $ip4; $st.Ipv6 = [string]$ip6; $st.ConfigHash = $hash; $st.LastVerifyUtc = $nowUtc.ToString('o'); $st.Pending = $false
    & $save
    Write-DXLog "OK: $(@($results | Where-Object { $_ -eq 'unchanged' }).Count) unchanged, $($changes.Count) changed" 'DEBUG'
    return 0
}

$rc = Invoke-DXDnsUpdate
exit $rc
