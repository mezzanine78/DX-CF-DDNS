# Tests for src/DX-CF-DDNS.ps1, run in-process with Invoke-WebRequest (IP providers) and Invoke-RestMethod
# (Cloudflare API + ntfy) mocked. Pure functions are lifted from the script's AST for unit tests.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidGlobalVars', '', Justification = 'Test state shared with mocks')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '', Justification = 'Loads functions from the script AST')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'Pester scopes')]
param()
BeforeAll {
    . (Join-Path $PSScriptRoot 'Common.ps1')
    $script:Script = Join-Path (Split-Path -Parent $PSScriptRoot) 'src/DX-CF-DDNS.ps1'
    $ast = [Management.Automation.Language.Parser]::ParseFile($Script, [ref]$null, [ref]$null)
    foreach ($f in $ast.FindAll({ param($a) $a -is [Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
        if ($f.Name -in 'Test-DXPublicIPv4', 'Test-DXPublicIPv6', 'ConvertFrom-DXIpResponse', 'Get-DXTlsProtocolSet', 'Test-DXTlsFailure', 'Get-DXTlsAdvice', 'ConvertTo-DXNetFxVersion') {
            Invoke-Expression ($f.Extent.Text -replace "^function $($f.Name)", "function script:$($f.Name)")
        }
    }
    $script:P = @('https://p1.example/', 'https://p2.example/', 'https://p3.example/')
    $script:P6 = @('https://q1.example/', 'https://q2.example/')

    function script:New-Site([hashtable]$Cfg = @{}) {
        $d = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory $d | Out-Null
        $c = [ordered]@{ ZoneId = $global:TestZone; Records = @('site1.example.com'); Token = $global:TestTok; Proxied = $null; Ttl = $null
            Create = $false; IPv6 = $false; IntervalMinutes = 5; NtfyUrl = 'https://ntfy.example/ntfy/topic'; NtfyToken = $global:TestNtfyTok }
        foreach ($k in $Cfg.Keys) { $c[$k] = $Cfg[$k] }
        $c | ConvertTo-Json | Set-Content (Join-Path $d 'cfg.json')
        return $d
    }
    function script:Invoke-DdnsRun([string]$Site, [hashtable]$Extra = @{}) {
        $a = @{ ConfigPath = (Join-Path $Site 'cfg.json'); StateDir = (Join-Path $Site 'State'); LogDir = (Join-Path $Site 'Logs')
            IpProviders = $P; Ip6Providers = $P6; TimeoutSec = 1 }
        foreach ($k in $Extra.Keys) { $a[$k] = $Extra[$k] }
        $global:LASTEXITCODE = -1
        $out = & $Script @a 6>&1 | Out-String
        $log = ''
        $lf = Join-Path $Site 'Logs/DX-CF-DDNS.log'
        if (Test-Path $lf) { $log = Get-Content $lf -Raw }
        return [pscustomobject]@{ Rc = $LASTEXITCODE; Out = $out; Log = $log }
    }
    function script:Get-State([string]$Site) { Get-Content (Join-Path $Site 'State/DX-CF-DDNS-state.json') -Raw | ConvertFrom-Json }
}

Describe 'DX-CF-DDNS.ps1' {
    BeforeEach {
        Reset-FakeCf
        $global:Prov = @{ 'https://p1.example/' = "fl=1\nip=9.9.9.9\nts=1"; 'https://p2.example/' = '9.9.9.9'; 'https://p3.example/' = "9.9.9.9`n"
            'https://q1.example/' = '2606:4700:4700::1111'; 'https://q2.example/' = '2606:4700:4700:0::1111'
        }
        Mock Invoke-WebRequest {
            $v = $global:Prov[[string]$Uri]
            if ($v -is [scriptblock]) { & $v }
            if ($null -eq $v) { throw (New-HttpError 404) }
            [pscustomobject]@{ StatusCode = 200; Content = ($v -replace '\\n', "`n") }
        }
        Mock Invoke-RestMethod { Invoke-FakeCf -Uri $Uri -Method $Method -Body $Body -Headers $Headers }
    }

    Context 'IP parsing and selection' {
        It 'accepts only a strict, public dotted quad: <v> -> <ok>' -ForEach @(
            @{ v = '9.9.9.9'; ok = $true }, @{ v = ' 1.1.1.1 '; ok = $true }, @{ v = '1'; ok = $false }, @{ v = '1.2.3'; ok = $false },
            @{ v = '10.0.0.1'; ok = $false }, @{ v = '100.64.1.1'; ok = $false }, @{ v = '192.168.1.1'; ok = $false }, @{ v = '203.0.113.5'; ok = $false },
            @{ v = '09.9.9.9'; ok = $false }, @{ v = '256.1.1.1'; ok = $false }, @{ v = '<html>'; ok = $false }, @{ v = '9.9.9.9 1.1.1.1'; ok = $false }) {
            Test-DXPublicIPv4 $v | Should -Be $ok
        }
        It 'IPv6 global unicast only: <v> -> <ok>' -ForEach @(
            @{ v = '2606:4700:4700::1111'; ok = $true }, @{ v = '2001:db8::1'; ok = $false }, @{ v = 'fe80::1'; ok = $false },
            @{ v = '::1'; ok = $false }, @{ v = 'fd00::1'; ok = $false }, @{ v = '9.9.9.9'; ok = $false }, @{ v = '::ffff:9.9.9.9'; ok = $false }) {
            Test-DXPublicIPv6 $v | Should -Be $ok
        }
        It 'reads the Cloudflare trace format and plain text' {
            ConvertFrom-DXIpResponse "fl=12\nh=1.1.1.1\nip=9.9.9.9\nts=1".Replace('\n', "`n") | Should -Be '9.9.9.9'
            ConvertFrom-DXIpResponse "8.8.8.8`n" | Should -Be '8.8.8.8'
        }
        It 'stops after two providers agree' {
            $s = New-Site
            Add-FakeRecord 'site1.example.com' '9.9.9.9'
            (Invoke-DdnsRun $s).Rc | Should -Be 0
            Should -Invoke Invoke-WebRequest -Times 2 -Exactly
        }
        It 'skips an invalid answer and still needs agreement' {
            $global:Prov['https://p1.example/'] = '10.1.2.3'
            $s = New-Site
            Add-FakeRecord 'site1.example.com' '9.9.9.9'
            $r = Invoke-DdnsRun $s
            $r.Rc | Should -Be 0
            $r.Out | Should -Match 'invalid/non-public'
            Should -Invoke Invoke-WebRequest -Times 3 -Exactly
        }
        It 'uses a single valid answer with a warning' {
            $global:Prov['https://p1.example/'] = { throw 'timeout' }; $global:Prov['https://p2.example/'] = 'garbage'
            $s = New-Site
            Add-FakeRecord 'site1.example.com' '9.9.9.9'
            $r = Invoke-DdnsRun $s
            $r.Rc | Should -Be 0
            $r.Log | Should -Match 'only one provider'
        }
        It 'changes nothing (exit 2) when providers disagree' {
            $global:Prov['https://p2.example/'] = '1.1.1.1'; $global:Prov['https://p3.example/'] = '8.8.8.8'
            $s = New-Site
            Add-FakeRecord 'site1.example.com' '5.5.5.5'
            $r = Invoke-DdnsRun $s
            $r.Rc | Should -Be 2
            $r.Log | Should -Match 'disagree'
            $global:CfCalls.Count | Should -Be 0
        }
        It 'exits 2 when no provider works' {
            foreach ($k in @($global:Prov.Keys)) { $global:Prov[$k] = { throw 'no route' } }
            (Invoke-DdnsRun (New-Site)).Rc | Should -Be 2
            $global:CfCalls.Count | Should -Be 0
        }
    }

    Context 'record updates' {
        It 'PATCHes the content when the IP differs, and logs UPDATED' {
            $s = New-Site
            Add-FakeRecord 'site1.example.com' '5.5.5.5' -Proxied $true -Ttl 300
            $r = Invoke-DdnsRun $s
            $r.Rc | Should -Be 0
            $r.Log | Should -Match 'UPDATED A site1\.example\.com 5\.5\.5\.5 -> 9\.9\.9\.9'
            $global:CfRecords[0].content | Should -Be '9.9.9.9'
            $global:CfRecords[0].proxied | Should -BeTrue     # not configured -> left alone
            $global:CfBodies | Should -Be @('PATCH {"content":"9.9.9.9"}')
        }
        It 'no-op when the record matches; the next run makes no API call at all (state cache)' {
            $s = New-Site
            Add-FakeRecord 'site1.example.com' '9.9.9.9'
            $first = Invoke-DdnsRun $s
            $first.Rc | Should -Be 0
            @($global:CfCalls | Where-Object { $_ -notmatch '^GET' }).Count | Should -Be 0
            $global:CfCalls.Clear()
            $r = Invoke-DdnsRun $s
            $r.Rc | Should -Be 0
            $global:CfCalls.Count | Should -Be 0
            $r.Log | Should -Be $first.Log   # nothing written to the log while nothing changes
        }
        It 're-checks the records after VerifyHours and when the IP changes' {
            $s = New-Site
            Add-FakeRecord 'site1.example.com' '9.9.9.9'
            Invoke-DdnsRun $s | Out-Null
            $st = Get-State $s; $st.LastVerifyUtc = (Get-Date).ToUniversalTime().AddHours(-7).ToString('o')
            $st | ConvertTo-Json | Set-Content (Join-Path $s 'State/DX-CF-DDNS-state.json')
            $global:CfCalls.Clear()
            (Invoke-DdnsRun $s).Log | Should -Match 'periodic check'
            $global:CfCalls.Count | Should -Be 1
            $global:CfCalls.Clear()
            foreach ($k in 'https://p1.example/', 'https://p2.example/') { $global:Prov[$k] = '1.1.1.1' }
            $r = Invoke-DdnsRun $s
            $r.Log | Should -Match 'IPv4 changed 9\.9\.9\.9 -> 1\.1\.1\.1'
            $global:CfRecords[0].content | Should -Be '1.1.1.1'
        }
        It '-Force checks even when nothing changed' {
            $s = New-Site
            Add-FakeRecord 'site1.example.com' '9.9.9.9'
            Invoke-DdnsRun $s | Out-Null
            $global:CfCalls.Clear()
            (Invoke-DdnsRun $s @{ Force = $true }).Log | Should -Match 'forced'
            $global:CfCalls.Count | Should -Be 1
        }
        It 'creates a missing record when Create is on (DNS only, TTL auto by default)' {
            $s = New-Site @{ Create = $true }
            $r = Invoke-DdnsRun $s
            $r.Rc | Should -Be 0
            $r.Log | Should -Match 'CREATED A site1\.example\.com -> 9\.9\.9\.9'
            $global:CfRecords.Count | Should -Be 1
            $global:CfRecords[0].proxied | Should -BeFalse
            $global:CfRecords[0].ttl | Should -Be 1
        }
        It 'does not create (exit 5) when Create is off, and retries next run' {
            $s = New-Site
            $r = Invoke-DdnsRun $s
            $r.Rc | Should -Be 5
            $r.Log | Should -Match 'not found in the zone'
            @($global:CfCalls | Where-Object { $_ -match '^POST' }).Count | Should -Be 0
            (Get-State $s).Pending | Should -BeTrue
            $global:CfCalls.Clear()
            (Invoke-DdnsRun $s).Rc | Should -Be 5
            $global:CfCalls.Count | Should -Be 1
        }
        It 'handles several records in one run' {
            $s = New-Site @{ Records = @('a.example.com', 'b.example.com', 'c.example.com') }
            Add-FakeRecord 'a.example.com' '9.9.9.9'; Add-FakeRecord 'b.example.com' '5.5.5.5'; Add-FakeRecord 'c.example.com' '6.6.6.6'
            $r = Invoke-DdnsRun $s
            $r.Rc | Should -Be 0
            @($global:CfCalls | Where-Object { $_ -match '^GET' }).Count | Should -Be 3
            @($global:CfCalls | Where-Object { $_ -match '^PATCH' }).Count | Should -Be 2
            @($global:CfRecords | Where-Object content -eq '9.9.9.9').Count | Should -Be 3
        }
        It 'warns about duplicate records and updates only the first' {
            $s = New-Site
            Add-FakeRecord 'site1.example.com' '5.5.5.5'; Add-FakeRecord 'site1.example.com' '6.6.6.6'
            $r = Invoke-DdnsRun $s
            $r.Log | Should -Match '2 A records named site1\.example\.com'
            $global:CfRecords[0].content | Should -Be '9.9.9.9'
            $global:CfRecords[1].content | Should -Be '6.6.6.6'
        }
        It 'enforces a configured proxied flag (and leaves TTL to Cloudflare when proxied)' {
            $s = New-Site @{ Proxied = $true; Ttl = 300 }
            Add-FakeRecord 'site1.example.com' '9.9.9.9' -Proxied $false -Ttl 120
            (Invoke-DdnsRun $s).Rc | Should -Be 0
            $global:CfBodies | Should -Be @('PATCH {"proxied":true}')
        }
        It 'enforces a configured TTL on a DNS-only record' {
            $s = New-Site @{ Proxied = $false; Ttl = 60 }
            Add-FakeRecord 'site1.example.com' '9.9.9.9' -Ttl 1
            Invoke-DdnsRun $s | Out-Null
            $global:CfBodies | Should -Be @('PATCH {"ttl":60}')
        }
        It 'keeps AAAA records on the public IPv6 when IPv6 is on' {
            $s = New-Site @{ IPv6 = $true }
            Add-FakeRecord 'site1.example.com' '9.9.9.9'; Add-FakeRecord 'site1.example.com' '2606:4700::1' -Type 'AAAA'
            $r = Invoke-DdnsRun $s
            $r.Rc | Should -Be 0
            ($global:CfRecords | Where-Object type -eq 'AAAA').content | Should -Be '2606:4700:4700::1111'
        }
        It 'skips AAAA (still exit 0) when no public IPv6 is found' {
            $global:Prov['https://q1.example/'] = { throw 'no v6' }; $global:Prov['https://q2.example/'] = 'fe80::1'
            $s = New-Site @{ IPv6 = $true }
            Add-FakeRecord 'site1.example.com' '9.9.9.9'
            $r = Invoke-DdnsRun $s
            $r.Rc | Should -Be 0
            $r.Log | Should -Match 'AAAA records skipped'
        }
    }

    Context 'errors, ntfy and secrets' {
        It 'exits 4 on 401/403 and says why' {
            $global:CfFail = @{ Match = '^GET'; Status = 403; Body = '{"success":false,"errors":[{"code":10000,"message":"Authentication error"}]}' }
            $s = New-Site
            $r = Invoke-DdnsRun $s
            $r.Rc | Should -Be 4
            $r.Log | Should -Match 'HTTP 403 10000: Authentication error'
            $r.Log | Should -Match 'no DNS edit access'
        }
        It 'exits 3 on a 5xx / network error' {
            $global:CfFail = @{ Match = '^PATCH'; Status = 502; Body = '' }
            $s = New-Site
            Add-FakeRecord 'site1.example.com' '5.5.5.5'
            (Invoke-DdnsRun $s).Rc | Should -Be 3
        }
        It 'exits 1 on a bad config' -ForEach @(
            @{ c = @{ ZoneId = 'nothex' } }, @{ c = @{ Records = @('not a host') } }, @{ c = @{ Token = 'short' } }, @{ c = @{ Ttl = 30 } }) {
            (Invoke-DdnsRun (New-Site $c)).Rc | Should -Be 1
            $global:CfCalls.Count | Should -Be 0
        }
        It 'sends one ntfy on an IP change' {
            $s = New-Site
            Add-FakeRecord 'site1.example.com' '5.5.5.5'
            Invoke-DdnsRun $s | Out-Null
            $global:Ntfy.Count | Should -Be 1
            $global:Ntfy[0].Title | Should -Match 'IP change'
            $global:Ntfy[0].Body | Should -Match 'updated A site1\.example\.com -> 9\.9\.9\.9'
            $global:Ntfy[0].Auth | Should -Be "Bearer $global:TestNtfyTok"
        }
        It 'throttles failure alerts (one per failure kind per 6 h) and sends one recovery' {
            $global:CfFail = @{ Match = '^GET'; Status = 500; Body = '' }
            $s = New-Site
            Add-FakeRecord 'site1.example.com' '9.9.9.9'
            Invoke-DdnsRun $s | Out-Null; Invoke-DdnsRun $s | Out-Null; Invoke-DdnsRun $s | Out-Null
            @($global:Ntfy | Where-Object Title -match 'FAILED').Count | Should -Be 1
            $global:CfFail = $null
            (Invoke-DdnsRun $s).Rc | Should -Be 0
            @($global:Ntfy | Where-Object Title -match 'recovered').Count | Should -Be 1
        }
        It 'never logs the API or ntfy token, even if an error message echoes it' {
            $global:CfFail = @{ Match = '^GET'; Status = 400; Body = ('{"success":false,"errors":[{"code":6003,"message":"bad header Bearer ' + $global:TestTok + ' / ' + $global:TestNtfyTok + '"}]}') }
            $s = New-Site
            $r = Invoke-DdnsRun $s
            $r.Rc | Should -Be 3
            $r.Log | Should -Match '\*\*\*'
            foreach ($t in $global:TestTok, $global:TestNtfyTok) {
                $r.Out.Contains($t) | Should -BeFalse
                $r.Log.Contains($t) | Should -BeFalse
            }
        }
        It 'rotates the log at 1 MB' {
            $s = New-Site
            New-Item -ItemType Directory (Join-Path $s 'Logs') | Out-Null
            [IO.File]::WriteAllText((Join-Path $s 'Logs/DX-CF-DDNS.log'), ('x' * 1100000))
            Add-FakeRecord 'site1.example.com' '5.5.5.5'
            Invoke-DdnsRun $s | Out-Null
            Test-Path (Join-Path $s 'Logs/DX-CF-DDNS.log.1') | Should -BeTrue
            (Get-Item (Join-Path $s 'Logs/DX-CF-DDNS.log')).Length | Should -BeLessThan 10000
        }
    }

    Context 'TLS' {
        It 'adds Tls12 always and Tls13 only on build 20348+ / where the enum exists' {
            ((Get-DXTlsProtocolSet 0 9600 $true @('Tls12', 'Tls13')) -band 15360) | Should -Be 3072
            ((Get-DXTlsProtocolSet 0 20348 $true @('Tls12', 'Tls13')) -band 15360) | Should -Be 15360
            ((Get-DXTlsProtocolSet 0 26100 $true @('Tls12')) -band 15360) | Should -Be 3072
            ((Get-DXTlsProtocolSet 192 17763 $true @('Tls12')) -band 192) | Should -Be 192
        }
        It 'sets TLS 1.2 in the process before the first web call' {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::SystemDefault
            $global:TlsAtFirstCall = $null
            $global:Prov['https://p1.example/'] = { if ($null -eq $global:TlsAtFirstCall) { $global:TlsAtFirstCall = [int][Net.ServicePointManager]::SecurityProtocol } }
            $global:Prov['https://p3.example/'] = '9.9.9.9'
            $s = New-Site
            Add-FakeRecord 'site1.example.com' '9.9.9.9'
            Invoke-DdnsRun $s | Out-Null
            ($global:TlsAtFirstCall -band 3072) | Should -Be 3072
        }
        It 'detects TLS failures, not other errors' {
            Test-DXTlsFailure (New-Object Net.WebException('Could not create SSL/TLS secure channel.', [Net.WebExceptionStatus]::SecureChannelFailure)) | Should -BeTrue
            Test-DXTlsFailure (New-Object Net.Http.HttpRequestException('outer', (New-Object Security.Authentication.AuthenticationException('x')))) | Should -BeTrue
            Test-DXTlsFailure (New-Object Net.WebException('Unable to connect', [Net.WebExceptionStatus]::ConnectFailure)) | Should -BeFalse
        }
        It 'logs platform info and the registry hint on a TLS failure (build 9600 advice included)' {
            (Get-DXTlsAdvice ([pscustomobject]@{ Caption = 'Windows Server 2012 R2'; Build = 9600; PSVersion = '5.1'; NetRelease = 528040 })) -join "`n" |
                Should -Match '(?s)build 9600.*\.NET Framework 4\.8.*SchUseStrongCrypto=1.*WOW6432Node.*KB3140245.*ECDHE-GCM'
            (Get-DXTlsAdvice ([pscustomobject]@{ Caption = 'Windows Server 2019'; Build = 17763; PSVersion = '5.1'; NetRelease = 528040 })) -join "`n" | Should -Not -Match 'ECDHE'
            foreach ($k in @($global:Prov.Keys)) { $global:Prov[$k] = { throw (New-Object Net.Http.HttpRequestException('The SSL connection could not be established', (New-Object Security.Authentication.AuthenticationException('frame')))) } }
            $r = Invoke-DdnsRun (New-Site)
            $r.Rc | Should -Be 2
            $r.Log | Should -Match 'TLS handshake failed on'
            $r.Log | Should -Match 'TLS hint'
        }
        It 'a non-TLS failure gets no TLS hint' {
            $global:CfFail = @{ Match = '^GET'; Status = 500; Body = '' }
            $r = Invoke-DdnsRun (New-Site)
            $r.Rc | Should -Be 3
            $r.Log | Should -Not -Match 'TLS hint'
        }
    }
}
