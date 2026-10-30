# Tests for install.ps1, run in-process exactly as `irm | iex` would (the file text as one scriptblock), with the
# download (Invoke-WebRequest), the Cloudflare API (Invoke-RestMethod) and every OS action ($global:CfDdnsOpsOverride)
# faked. The real ACL and task scriptblocks are lifted from the AST and run against mocked cmdlets.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidGlobalVars', '', Justification = 'Test state shared with mocks')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'Pester scopes')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Stubs for Windows-only cmdlets so Pester can mock them')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Test stubs')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Test stubs')]
param()
BeforeAll {
    . (Join-Path $PSScriptRoot 'Common.ps1')
    $script:Repo = Split-Path -Parent $PSScriptRoot
    $script:InstallPath = Join-Path $Repo 'install.ps1'
    $script:InstallText = Get-Content $InstallPath -Raw
    $script:Src = Join-Path $Repo 'src/DX-CF-DDNS.ps1'
    $script:AllVars = 'CF_DDNS_TOKEN', 'CF_ZONE_ID', 'CF_DDNS_RECORD', 'CF_DDNS_INTERVAL', 'CF_DDNS_PROXIED', 'CF_DDNS_CREATE', 'CF_DDNS_IPV6',
    'CF_DDNS_TTL', 'CF_DDNS_NTFY_URL', 'CF_DDNS_NTFY_TOKEN', 'CF_DDNS_UNINSTALL', 'CF_DDNS_NORUNNOW', 'CF_DDNS_SKIPVERIFY', 'CF_DDNS_ROOTDIR', 'CF_DDNS_REPOURL'

    # Scriptblocks of the real $Ops table, by key
    $ast = [Management.Automation.Language.Parser]::ParseInput($InstallText, [ref]$null, [ref]$null)
    $script:RealOps = @{}
    foreach ($h in $ast.FindAll({ param($a) $a -is [Management.Automation.Language.HashtableAst] }, $true)) {
        foreach ($kv in $h.KeyValuePairs) {
            $sb = $kv.Item2.PipelineElements[0].Expression
            if ($sb -is [Management.Automation.Language.ScriptBlockExpressionAst]) { $RealOps[[string]$kv.Item1.Value] = $sb.ScriptBlock.GetScriptBlock() }
        }
    }

    function script:New-Root { Join-Path $TestDrive ([guid]::NewGuid().ToString('N') + '/Windows/Scripts/DX') }
    function script:Invoke-Install([hashtable]$Env, [string]$Root) {
        foreach ($v in $AllVars) { Remove-Item "Env:$v" -ErrorAction SilentlyContinue }
        $e = @{ CF_DDNS_ROOTDIR = $Root }
        foreach ($k in $Env.Keys) { $e[$k] = $Env[$k] }
        foreach ($k in $e.Keys) { Set-Item "Env:$k" $e[$k] }
        $global:LASTEXITCODE = -1
        $out = & ([scriptblock]::Create($InstallText)) 6>&1 | Out-String
        $rc = $global:LASTEXITCODE
        $cfgFile = Join-Path $Root 'Config/DX-CF-DDNS.json'
        $cfg = $null
        if (Test-Path $cfgFile) { $cfg = Get-Content $cfgFile -Raw | ConvertFrom-Json }
        $tokEnv = [string]$env:CF_DDNS_TOKEN
        foreach ($v in $AllVars) { Remove-Item "Env:$v" -ErrorAction SilentlyContinue }
        return [pscustomobject]@{ Rc = $rc; Out = $out; Config = $cfg; Fake = @($global:Fake); TokenEnv = $tokEnv }
    }
    function script:Join-Env([hashtable]$A, [hashtable]$B) { $o = @{}; foreach ($k in $A.Keys) { $o[$k] = $A[$k] }; foreach ($k in $B.Keys) { $o[$k] = $B[$k] }; $o }
    $script:Good = @{ CF_DDNS_TOKEN = $global:TestTok; CF_ZONE_ID = $global:TestZone; CF_DDNS_RECORD = 'site1.example.com' }
}

Describe 'install.ps1' {
    BeforeEach {
        Reset-FakeCf
        Add-FakeRecord 'site1.example.com' '9.9.9.9'
        $global:Fake = New-Object System.Collections.ArrayList
        $global:ServeFile = $Src
        $global:CanPrompt = $false; $global:RunRc = 0; $global:Elevated = $true
        $global:PromptTok = $global:TestTok
        $global:CfDdnsOpsOverride = @{
            IsWindows      = { $true }; IsElevated = { $global:Elevated }; CanPrompt = { $global:CanPrompt }
            ReadToken      = { $s = New-Object Security.SecureString; foreach ($c in $global:PromptTok.ToCharArray()) { $s.AppendChar($c) }; $s }
            ProtectPath    = { param($Path, $Directory) [void]$global:Fake.Add("acl:$Path|$Directory") }
            RegisterTask   = { param($Arguments, $Minutes) [void]$global:Fake.Add("register:$Minutes|$Arguments") }
            UnregisterTask = { [void]$global:Fake.Add('unregister'); $true }
            RunScript      = { param($Arguments) [void]$global:Fake.Add("run:$Arguments"); $global:RunRc }
            Exit           = { param($Code) [void]$global:Fake.Add("exit:$Code") }
        }
        Mock Invoke-WebRequest { Copy-Item -LiteralPath $global:ServeFile -Destination $OutFile -Force }
        Mock Invoke-RestMethod { Invoke-FakeCf -Uri $Uri -Method $Method -Body $Body -Headers $Headers }
    }
    AfterAll { Remove-Variable -Scope Global -Name CfDdnsOpsOverride -ErrorAction SilentlyContinue }

    Context 'fresh install' {
        It 'installs from env vars: files, config, ACLs, task, first run; token cleared and never printed' {
            $root = New-Root
            $r = Invoke-Install (Join-Env $Good @{ CF_DDNS_RECORD = 'Site1.Example.com; site2.example.com'; CF_DDNS_INTERVAL = '3'; CF_DDNS_NTFY_URL = 'https://ntfy.example/t'; CF_DDNS_NTFY_TOKEN = $global:TestNtfyTok }) $root
            $r.Rc | Should -Be 0
            $r.Fake | Should -Contain 'exit:0'
            $r.Config.ZoneId | Should -Be $global:TestZone
            $r.Config.Records | Should -Be @('site1.example.com', 'site2.example.com')
            $r.Config.Token | Should -Be $global:TestTok
            $r.Config.IntervalMinutes | Should -Be 3
            $r.Config.Proxied | Should -BeNullOrEmpty
            $r.Config.Create | Should -BeFalse
            $r.Config.NtfyToken | Should -Be $global:TestNtfyTok
            (Get-FileHash (Join-Path $root 'Scripts/DX-CF-DDNS.ps1')).Hash | Should -Be (Get-FileHash $Src).Hash
            foreach ($d in @($root) + @('Scripts', 'Config', 'State', 'Logs' | ForEach-Object { Join-Path $root $_ })) { $r.Fake | Should -Contain "acl:$d|True" }
            $r.Fake | Should -Contain "acl:$(Join-Path $root 'Config/DX-CF-DDNS.json')|False"
            $r.Fake | Should -Contain "acl:$(Join-Path $root 'Scripts/DX-CF-DDNS.ps1')|False"
            ($r.Fake -match '^register:') | Should -Match ('^register:3\|.*-File ".*DX-CF-DDNS\.ps1" -ConfigPath ".*DX-CF-DDNS\.json" -StateDir ".*State" -LogDir ".*Logs"')
            ($r.Fake -match '^run:') | Should -Not -BeNullOrEmpty
            $r.Out | Should -Match 'SHA256 OK'
            $r.Out | Should -Match 'API token verified'
            $r.Out.Contains($global:TestTok) | Should -BeFalse
            $r.Out.Contains($global:TestNtfyTok) | Should -BeFalse
            ($r.Fake -join "`n").Contains($global:TestTok) | Should -BeFalse
            $r.TokenEnv | Should -Be ''
        }
        It 'leaves the ACL of existing shared folders alone and never touches the other tool''s files' {
            $root = New-Root
            New-Item -ItemType Directory (Join-Path $root 'Config'), (Join-Path $root 'Logs'), (Join-Path $root 'Scripts') -Force | Out-Null
            Set-Content (Join-Path $root 'Config/cfip-collector.json') '{"Token":"other"}'
            Set-Content (Join-Path $root 'Scripts/Invoke-DXCfipCollector.ps1') '# other tool'
            $r = Invoke-Install $Good $root
            $r.Rc | Should -Be 0
            foreach ($d in $root, (Join-Path $root 'Config'), (Join-Path $root 'Logs'), (Join-Path $root 'Scripts')) { $r.Fake | Should -Not -Contain "acl:$d|True" }
            $r.Fake | Should -Contain "acl:$(Join-Path $root 'State')|True"     # created by us
            $r.Fake | Should -Contain "acl:$(Join-Path $root 'Config/DX-CF-DDNS.json')|False"
            Get-Content (Join-Path $root 'Config/cfip-collector.json') -Raw | Should -Match 'other'
            Get-Content (Join-Path $root 'Scripts/Invoke-DXCfipCollector.ps1') -Raw | Should -Match 'other tool'
        }
        It 'stores proxied / ttl / create / ipv6 when given' {
            $r = Invoke-Install (Join-Env $Good @{ CF_DDNS_PROXIED = 'false'; CF_DDNS_TTL = '120'; CF_DDNS_CREATE = '1'; CF_DDNS_IPV6 = 'yes' }) (New-Root)
            $r.Rc | Should -Be 0
            $r.Config.Proxied | Should -BeFalse
            $r.Config.Ttl | Should -Be 120
            $r.Config.Create | Should -BeTrue
            $r.Config.IPv6 | Should -BeTrue
        }
        It 'returns 4 (task kept) when the first run fails, and skips the run with CF_DDNS_NORUNNOW=1' {
            $global:RunRc = 5
            $r = Invoke-Install $Good (New-Root)
            $r.Rc | Should -Be 4
            ($r.Fake -match '^register:') | Should -Not -BeNullOrEmpty
            $global:RunRc = 0; $global:Fake.Clear()
            $r = Invoke-Install (Join-Env $Good @{ CF_DDNS_NORUNNOW = '1' }) (New-Root)
            $r.Rc | Should -Be 0
            ($r.Fake -match '^run:') | Should -BeNullOrEmpty
        }
    }

    Context 'idempotent re-run' {
        It 'keeps the stored token (and other values) when not given, and updates what is given' {
            $root = New-Root
            (Invoke-Install (Join-Env $Good @{ CF_DDNS_NTFY_URL = 'https://ntfy.example/t'; CF_DDNS_PROXIED = 'false' }) $root).Rc | Should -Be 0
            $global:Fake.Clear()
            $r = Invoke-Install @{ CF_DDNS_INTERVAL = '10'; CF_DDNS_RECORD = 'site1.example.com,site3.example.com' } $root
            $r.Rc | Should -Be 0
            $r.Out | Should -Match 'keeping the token from the existing config'
            $r.Config.Token | Should -Be $global:TestTok
            $r.Config.ZoneId | Should -Be $global:TestZone
            $r.Config.IntervalMinutes | Should -Be 10
            $r.Config.Records | Should -Be @('site1.example.com', 'site3.example.com')
            $r.Config.NtfyUrl | Should -Be 'https://ntfy.example/t'
            $r.Config.Proxied | Should -BeFalse
            ($r.Fake -match '^register:') | Should -Match '^register:10\|'
            $r.Fake | Should -Not -Contain "acl:$root|True"     # folders exist now: not re-ACL'd
            $r.Fake | Should -Contain "acl:$(Join-Path $root 'Config/DX-CF-DDNS.json')|False"
        }
        It '''none'' clears the ntfy settings' {
            $root = New-Root
            Invoke-Install (Join-Env $Good @{ CF_DDNS_NTFY_URL = 'https://ntfy.example/t'; CF_DDNS_NTFY_TOKEN = $global:TestNtfyTok }) $root | Out-Null
            $r = Invoke-Install @{ CF_DDNS_NTFY_URL = 'none'; CF_DDNS_NTFY_TOKEN = 'none' } $root
            $r.Config.NtfyUrl | Should -Be ''
            $r.Config.NtfyToken | Should -Be ''
        }
    }

    Context 'token input' {
        It 'fails clearly (1) with no token in a non-interactive session' {
            $r = Invoke-Install @{ CF_ZONE_ID = $global:TestZone; CF_DDNS_RECORD = 'site1.example.com' } (New-Root)
            $r.Rc | Should -Be 1
            $r.Out | Should -Match 'cannot prompt'
            $r.Config | Should -BeNullOrEmpty
        }
        It 'prompts (hidden) when interactive' {
            $global:CanPrompt = $true
            $r = Invoke-Install @{ CF_ZONE_ID = $global:TestZone; CF_DDNS_RECORD = 'site1.example.com' } (New-Root)
            $r.Rc | Should -Be 0
            $r.Config.Token | Should -Be $global:TestTok
            $r.Out.Contains($global:TestTok) | Should -BeFalse
        }
        It 'rejects bad input with 1 and writes nothing: <name>' -ForEach @(
            @{ name = 'zone'; e = @{ CF_ZONE_ID = 'abc' }; pat = 'CF_ZONE_ID' },
            @{ name = 'record'; e = @{ CF_DDNS_RECORD = 'bad_host!' }; pat = 'CF_DDNS_RECORD' },
            @{ name = 'interval 0'; e = @{ CF_DDNS_INTERVAL = '0' }; pat = 'CF_DDNS_INTERVAL' },
            @{ name = 'ttl 30'; e = @{ CF_DDNS_TTL = '30' }; pat = 'CF_DDNS_TTL' },
            @{ name = 'proxied maybe'; e = @{ CF_DDNS_PROXIED = 'maybe' }; pat = 'CF_DDNS_PROXIED' },
            @{ name = 'http ntfy'; e = @{ CF_DDNS_NTFY_URL = 'http://ntfy.example/t' }; pat = 'CF_DDNS_NTFY_URL' },
            @{ name = 'token'; e = @{ CF_DDNS_TOKEN = 'has spaces in it ok' }; pat = 'CF_DDNS_TOKEN' }) {
            $root = New-Root
            $r = Invoke-Install (Join-Env $Good $e) $root
            $r.Rc | Should -Be 1
            $r.Out | Should -Match $pat
            Test-Path $root | Should -BeFalse
        }
    }

    Context 'Cloudflare token / zone verification' {
        It '<name> -> exit 5, nothing installed' -ForEach @(
            @{ name = 'invalid token (401)'; setup = { $global:TestTokSave = $global:TestTok }; e = @{ CF_DDNS_TOKEN = ('Wrong_' + ('w' * 34)) }; pat = 'rejected the API token' },
            @{ name = 'token not active'; setup = { $global:CfVerify = 'disabled' }; e = @{}; pat = 'not active' },
            @{ name = 'no access to the zone (403)'; setup = { $global:CfFail = @{ Match = 'dns_records\?per_page'; Status = 403; Body = '{"success":false,"errors":[{"code":10000,"message":"Authentication error"}]}' } }; e = @{}; pat = 'no DNS access to zone' },
            @{ name = 'wrong zone ID'; setup = {}; e = @{ CF_ZONE_ID = ('f' * 32) }; pat = 'was not found' }) {
            & $setup
            $root = New-Root
            $r = Invoke-Install (Join-Env $Good $e) $root
            $r.Rc | Should -Be 5
            $r.Out | Should -Match $pat
            Test-Path (Join-Path $root 'Config/DX-CF-DDNS.json') | Should -BeFalse
            ($r.Fake -match '^register:') | Should -BeNullOrEmpty
        }
        It 'accepts an account-owned token (verify endpoint 401) that can read the zone' {
            $global:CfVerify = 401
            $r = Invoke-Install $Good (New-Root)
            $r.Rc | Should -Be 0
            $r.Out | Should -Match 'account-owned token'
        }
        It 'warns about a missing record unless CF_DDNS_CREATE=1' {
            (Invoke-Install (Join-Env $Good @{ CF_DDNS_RECORD = 'new.example.com' }) (New-Root)).Out | Should -Match 'new\.example\.com does not exist: create it'
            (Invoke-Install (Join-Env $Good @{ CF_DDNS_RECORD = 'new.example.com'; CF_DDNS_CREATE = '1' }) (New-Root)).Out | Should -Match 'will be created'
        }
        It 'CF_DDNS_SKIPVERIFY=1 skips the API check' {
            $r = Invoke-Install (Join-Env $Good @{ CF_DDNS_SKIPVERIFY = '1' }) (New-Root)
            $r.Rc | Should -Be 0
            Should -Invoke Invoke-RestMethod -Times 0 -Exactly
        }
    }

    Context 'download, pin and TLS' {
        It 'fails with 3 and installs nothing on a SHA256 mismatch' {
            $bad = Join-Path $TestDrive 'tampered.ps1'
            (Get-Content $Src -Raw) + "`n# tampered" | Set-Content $bad -NoNewline
            $global:ServeFile = $bad
            $root = New-Root
            $r = Invoke-Install $Good $root
            $r.Rc | Should -Be 3
            $r.Out | Should -Match 'SHA256 mismatch'
            Test-Path $root | Should -BeFalse
        }
        It 'the pin in install.ps1 matches src/DX-CF-DDNS.ps1 (run tools/Update-Pins.ps1)' {
            $InstallText | Should -Match ("'src/DX-CF-DDNS.ps1'\s*=\s*'" + (Get-FileHash $Src).Hash + "'")
        }
        It 'downloads from CF_DDNS_REPOURL and refuses a non-https one' {
            Invoke-Install (Join-Env $Good @{ CF_DDNS_REPOURL = 'https://raw.example/x/abc123' }) (New-Root) | Out-Null
            Should -Invoke Invoke-WebRequest -ParameterFilter { $Uri -eq 'https://raw.example/x/abc123/src/DX-CF-DDNS.ps1' }
            (Invoke-Install (Join-Env $Good @{ CF_DDNS_REPOURL = 'http://evil.example' }) (New-Root)).Rc | Should -Be 1
        }
        It 'forces TLS 1.2 before downloading' {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::SystemDefault
            $global:TlsAtDownload = $null
            Mock Invoke-WebRequest { $global:TlsAtDownload = [int][Net.ServicePointManager]::SecurityProtocol; Copy-Item -LiteralPath $global:ServeFile -Destination $OutFile -Force }
            Invoke-Install $Good (New-Root) | Out-Null
            ($global:TlsAtDownload -band 3072) | Should -Be 3072
        }
        It 'gives the TLS hint when the download fails the handshake' {
            Mock Invoke-WebRequest { throw (New-Object Net.Http.HttpRequestException('The SSL connection could not be established', (New-Object Security.Authentication.AuthenticationException('x')))) }
            $r = Invoke-Install $Good (New-Root)
            $r.Rc | Should -Be 3
            $r.Out | Should -Match 'TLS handshake failed'
            $r.Out | Should -Match 'SchUseStrongCrypto=1'
        }
        It 'install.ps1 is ASCII-only with no param() block (safe for irm | iex on 5.1)' {
            @([IO.File]::ReadAllBytes($InstallPath) | Where-Object { $_ -gt 127 }).Count | Should -Be 0
            [Management.Automation.Language.Parser]::ParseFile($InstallPath, [ref]$null, [ref]$null).ParamBlock | Should -BeNullOrEmpty
        }
    }

    Context 'environment checks and uninstall' {
        It 'not elevated -> 2, nothing written' {
            $global:Elevated = $false
            $root = New-Root
            (Invoke-Install $Good $root).Rc | Should -Be 2
            Test-Path $root | Should -BeFalse
        }
        It 'uninstall removes the task and only our files, keeps logs and the other tool''s files, removes empty folders' {
            $root = New-Root
            Invoke-Install $Good $root | Out-Null
            Set-Content (Join-Path $root 'State/DX-CF-DDNS-state.json') '{}'
            Set-Content (Join-Path $root 'Logs/DX-CF-DDNS.log') 'log'
            Set-Content (Join-Path $root 'Config/cfip-collector.json') '{}'
            $global:Fake.Clear()
            $r = Invoke-Install @{ CF_DDNS_UNINSTALL = '1' } $root
            $r.Rc | Should -Be 0
            $r.Fake | Should -Contain 'unregister'
            foreach ($f in 'Scripts/DX-CF-DDNS.ps1', 'Config/DX-CF-DDNS.json', 'State/DX-CF-DDNS-state.json') { Test-Path (Join-Path $root $f) | Should -BeFalse }
            Test-Path (Join-Path $root 'Scripts') | Should -BeFalse
            Test-Path (Join-Path $root 'State') | Should -BeFalse
            Test-Path (Join-Path $root 'Config/cfip-collector.json') | Should -BeTrue
            Test-Path (Join-Path $root 'Logs/DX-CF-DDNS.log') | Should -BeTrue
        }
    }

    Context 'real ACL and task code (cmdlets mocked)' {
        BeforeAll {
            function Get-Acl { param([string]$LiteralPath) $LiteralPath }
            function Set-Acl { param([string]$LiteralPath, $AclObject) $null = $AclObject }
            function New-ScheduledTaskAction { param($Execute, $Argument) [pscustomobject]@{ Execute = $Execute; Argument = $Argument } }
            function New-ScheduledTaskTrigger { param([switch]$Once, $At, $RepetitionInterval, $RepetitionDuration, [switch]$AtStartup) [pscustomobject]@{ Delay = $null } }
            function New-ScheduledTaskPrincipal { param($UserId, $LogonType, $RunLevel) [pscustomobject]@{ UserId = $UserId } }
            function New-ScheduledTaskSettingsSet { param([switch]$StartWhenAvailable, [switch]$AllowStartIfOnBatteries, [switch]$DontStopIfGoingOnBatteries, $ExecutionTimeLimit, $MultipleInstances) [pscustomobject]@{} }
            function Register-ScheduledTask { param($TaskPath, $TaskName, $Action, $Trigger, $Principal, $Settings, [switch]$Force, $Description) }
        }
        It 'ProtectPath grants FullControl to S-1-5-18 and S-1-5-32-544 only, protected (<kind>)' -ForEach @(
            @{ kind = 'directory'; dir = $true; inherit = 'ContainerInherit, ObjectInherit' }, @{ kind = 'file'; dir = $false; inherit = 'None' }) {
            $acl = [pscustomobject]@{ Access = @('usersRead', 'trustedInstaller'); Protected = $null; Removed = 0; Added = (New-Object System.Collections.ArrayList) }
            $acl | Add-Member ScriptMethod SetAccessRuleProtection { param($a, $b) $this.Protected = "$a,$b" }
            $acl | Add-Member ScriptMethod RemoveAccessRule { param($x) $null = $x; $this.Removed++; $true }
            $acl | Add-Member ScriptMethod AddAccessRule { param($x) [void]$this.Added.Add($x) }
            Mock Get-Acl { $acl }
            Mock Set-Acl {}
            Mock New-Object -ParameterFilter { $TypeName -like '*SecurityIdentifier' } { [pscustomobject]@{ Sid = $ArgumentList[0] } }
            Mock New-Object -ParameterFilter { $TypeName -like '*FileSystemAccessRule' } {
                [pscustomobject]@{ Id = $ArgumentList[0].Sid; Rights = $ArgumentList[1]; Inherit = [string]$ArgumentList[2] } }
            & $RealOps.ProtectPath 'X:\p' $dir
            $acl.Protected | Should -Be 'True,False'
            $acl.Removed | Should -Be 2
            @($acl.Added | ForEach-Object Id) | Should -Be @('S-1-5-18', 'S-1-5-32-544')
            @($acl.Added | ForEach-Object Rights | Select-Object -Unique) | Should -Be 'FullControl'
            @($acl.Added | ForEach-Object Inherit | Select-Object -Unique) | Should -Be $inherit
            Should -Invoke Set-Acl -Times 1 -ParameterFilter { $LiteralPath -eq 'X:\p' }
        }
        It 'RegisterTask: \DX\DX-CF-DDNS as SYSTEM (by SID), every N minutes + at startup, no overlap, 10 min limit' {
            Mock New-ScheduledTaskTrigger { [pscustomobject]@{ Delay = $null } }
            Mock New-ScheduledTaskPrincipal { [pscustomobject]@{ UserId = $UserId } }
            Mock New-ScheduledTaskSettingsSet { [pscustomobject]@{} }
            Mock Register-ScheduledTask {}
            $TaskPath = '\DX\'; $TaskName = 'DX-CF-DDNS'
            $keep = $env:SystemRoot
            try { $env:SystemRoot = $TestDrive; & $RealOps.RegisterTask '-File x' 7 } finally { $env:SystemRoot = $keep }
            Should -Invoke New-ScheduledTaskTrigger -Times 1 -ParameterFilter { $Once -and $RepetitionInterval -eq (New-TimeSpan -Minutes 7) }
            Should -Invoke New-ScheduledTaskTrigger -Times 1 -ParameterFilter { $AtStartup }
            Should -Invoke New-ScheduledTaskPrincipal -Times 1 -ParameterFilter { $UserId -eq 'S-1-5-18' }
            Should -Invoke New-ScheduledTaskSettingsSet -Times 1 -ParameterFilter { $MultipleInstances -eq 'IgnoreNew' -and $ExecutionTimeLimit -eq (New-TimeSpan -Minutes 10) }
            Should -Invoke Register-ScheduledTask -Times 1 -ParameterFilter { $TaskPath -eq '\DX\' -and $TaskName -eq 'DX-CF-DDNS' -and $Force }
        }
    }
}
