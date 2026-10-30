# DX-CF-DDNS

A Cloudflare dynamic DNS updater for Windows client sites. A scheduled task running as SYSTEM keeps one or more
Cloudflare DNS records (A, and AAAA if you turn it on) pointing at the site's current public IP. It is installed and
updated from N-central or another RMM with a single line, `irm | iex`, and gets its per-client values from RMM
variables.

It shares the `C:\Windows\Scripts\DX` layout with [DX-CFTrustedIPs](https://github.com/mezzanine78/DX-CFTrustedIPs).
Every file it owns starts with `DX-CF-DDNS`, and it never touches the other tool's files or folder ACLs.

## How it works

1. `install.ps1` takes its values from environment variables and forces TLS 1.2, or TLS 1.3 on build 20348 and later.
   It downloads `src/DX-CF-DDNS.ps1` and checks it against the **SHA256 pin** stored in `install.ps1`. If the hash
   doesn't match, the install fails. It also confirms that the script parses.
2. It **checks the token** with `GET /user/tokens/verify`, then checks DNS access with
   `GET /zones/<zone>/dns_records`. A wrong token, missing permission or wrong zone ID stops the install with a clear
   message and exit code 5.
3. It writes the config. The file is created empty and locked down to SYSTEM and Administrators before the token is
   written into it.
4. It registers the task `\DX\DX-CF-DDNS` (as SYSTEM, every N minutes and at startup), then runs the updater once.
5. On each run, `DX-CF-DDNS.ps1`:
   - Gets the public IP from several providers: `1.1.1.1/cdn-cgi/trace`, `api.ipify.org` and `ipv4.icanhazip.com`.
     For IPv6 it uses the matching v6 endpoints.
   - **Validates each answer.** An IPv4 address must be a strict dotted quad in public space, so private, CGNAT,
     loopback, link-local, multicast and documentation ranges are rejected. An IPv6 address must be global unicast
     (2000::/3) and not documentation space.
   - **Agreement rule:** providers are asked in order until two of them return the same address. If only one valid
     answer comes back, it is used and a WARN is logged. If the providers disagree, nothing is changed and the run
     exits 2.
   - **Only calls Cloudflare when needed:** when the IP has changed since the last good run, when the config has
     changed, after a failed or pending run, and every 6 hours as a safety check in case someone edited the record by
     hand. Otherwise it logs `no change` and exits 0 without making an API call.
   - For each record it does a `GET`, then a `PATCH` only if the content, proxied setting or TTL differs. If the record
     is missing it does a `POST`, but only when `CF_DDNS_CREATE=1`.
   - It can optionally send ntfy alerts: one when the IP changes, one per failure type every 6 hours, and one when
     things recover.

## Cloudflare API token (scope)

Create the token under My Profile > API Tokens > Create Token, using the "Edit zone DNS" template:

| Setting | Value |
|---|---|
| Permissions | **Zone > DNS > Edit** (Zone > Zone > Read isn't needed) |
| Zone Resources | **Include > Specific zone > the client's zone** (not "All zones") |
| Client IP filtering | Optional. Leave it off if the site's IP is dynamic, which is the reason for this tool |
| TTL | Optional end date, but set a reminder to rotate it |

Use a separate token for each client or zone. Account-owned tokens (Manage Account > API Tokens) also work. The
installer accepts them as long as the token can read the zone's DNS records.

## RMM one-liner (N-central)

In N-central, set up a **Custom Property / script parameter** for each value. Make `CF_DDNS_TOKEN` (and
`CF_DDNS_NTFY_TOKEN`, if you use it) a **secure / password** type. Then run this as a PowerShell script on the
device, as LocalSystem:

```powershell
$env:CF_DDNS_TOKEN  = '<secure var: Cloudflare token>'
$env:CF_ZONE_ID     = '<var: 32-hex zone id>'
$env:CF_DDNS_RECORD = '<var: site1.example.com>'
# optional: $env:CF_DDNS_INTERVAL='5'; $env:CF_DDNS_CREATE='1'; $env:CF_DDNS_NTFY_URL='https://ntfy.sh/<topic>'
irm https://raw.githubusercontent.com/mezzanine78/DX-CF-DDNS/main/install.ps1 | iex
exit $LASTEXITCODE
```

If the RMM already exports the variables into the script's environment, the `irm ... | iex` line on its own is enough.

**Technician, interactive:** open an elevated PowerShell, set `CF_ZONE_ID` and `CF_DDNS_RECORD`, leave
`CF_DDNS_TOKEN` empty, and run the `irm` line. You'll be prompted for the token, and what you type is hidden. In a
session that can't prompt, an empty token fails with exit 1.

**Re-runs are idempotent.** Running the installer again updates the script, config and task. Any value you leave out
keeps the value already stored, so a re-run without `CF_DDNS_TOKEN` keeps the existing token. Set `none` to clear
the ntfy values.

## Per-client values

All inputs use the `CF_DDNS_` prefix. The one exception is `CF_ZONE_ID`, which keeps the name from the original guide.

| Variable | Required | Default | Notes |
|---|---|---|---|
| `CF_DDNS_TOKEN` | first install | (prompt if interactive) | **Secure.** Zone > DNS > Edit on this zone only |
| `CF_ZONE_ID` | first install | | 32-hex zone ID (zone Overview page, right side) |
| `CF_DDNS_RECORD` | first install | | One or more FQDNs, separated by `,` or `;`, e.g. `site1.example.com;vpn.example.com` |
| `CF_DDNS_INTERVAL` | no | `5` | Minutes, from 1 to 1440 |
| `CF_DDNS_PROXIED` | no | `false` | `true`/`false`. Applied when a record is created. An existing record's proxied flag only changes if this is set |
| `CF_DDNS_TTL` | no | `1` (auto) | `1` or 60-86400. Ignored by Cloudflare while a record is proxied |
| `CF_DDNS_CREATE` | no | off | `1` creates missing records. Off by default so a typo can't create stray records |
| `CF_DDNS_IPV6` | no | off | `1` also keeps AAAA records on the public IPv6. If there's no IPv6, it logs a WARN and the A records still update |
| `CF_DDNS_NTFY_URL` | no | | `https://<host>/<topic>`. `none` clears it |
| `CF_DDNS_NTFY_TOKEN` | no | | **Secure.** ntfy bearer token. `none` clears it |
| `CF_DDNS_UNINSTALL` | no | | `1` uninstalls |
| `CF_DDNS_NORUNNOW` | no | | `1` skips the first run after install |
| `CF_DDNS_SKIPVERIFY` | no | | `1` skips the token and zone check (for broken egress only) |
| `CF_DDNS_ROOTDIR` | no | `C:\Windows\Scripts\DX` | Root folder override |
| `CF_DDNS_REPOURL` | no | GitHub `main` raw URL | Point this at a commit or tag to pin a release. The pin must match that release |

## Files

| Path (under the root) | ACL | Content |
|---|---|---|
| `Scripts\DX-CF-DDNS.ps1` | SYSTEM + Administrators (SID, protected) | The updater |
| `Config\DX-CF-DDNS.json` | SYSTEM + Administrators (SID, protected) | Zone, records, options, **token** |
| `State\DX-CF-DDNS-state.json` | SYSTEM + Administrators | Last IPs, last check, throttle times |
| `Logs\DX-CF-DDNS.log` (+ `.1`) | inherited from `Logs` | Run log. Rotates at 1 MB, keeping one old file |

If a folder doesn't exist yet, it is created with the protected SID ACL: `S-1-5-18` and `S-1-5-32-544`, both with
full control. A folder that already exists, for example one created by DX-CFTrustedIPs, keeps its ACL as it is. Only
our own files get the protected ACL.

Scheduled task `\DX\DX-CF-DDNS` settings:
- Principal is `S-1-5-18` (SYSTEM), highest privilege.
- Repeats every N minutes, and runs at startup with a 1-minute delay.
- `MultipleInstances IgnoreNew`, so runs never overlap.
- 10-minute execution limit.
- Starts when available, runs on battery.
- Runs `%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File ...`.

## Exit codes

| Code | Installer | Updater (task "Last Run Result") |
|---|---|---|
| 0 | Installed or uninstalled | OK: records current or updated, or no change |
| 1 | Bad or missing input, not Windows, install error | Config missing or invalid |
| 2 | Not elevated | No valid public IP, or providers disagree |
| 3 | Download failed, SHA256 mismatch, or the script doesn't parse | Cloudflare, network or TLS error |
| 4 | Installed but the first run failed (see the log) | Cloudflare 401/403: token invalid or no permission |
| 5 | Token rejected, no DNS access, or wrong zone ID | Record missing and `CF_DDNS_CREATE` is off |

When several records fail, the updater exits with the most serious code.

## Uninstall

```powershell
$env:CF_DDNS_UNINSTALL = '1'; irm https://raw.githubusercontent.com/mezzanine78/DX-CF-DDNS/main/install.ps1 | iex
```

This removes the task and our script, config and state files, then removes any folders left empty. Folders that still
hold DX-CFTrustedIPs files are left alone. The log is kept for audit. Delete it by hand if you don't want it. **DNS
records are not deleted.**

## Logs

`C:\Windows\Scripts\DX\Logs\DX-CF-DDNS.log`. Each line looks like `2026-10-29 14:05:00 [INFO] ...`. Useful entries:

- `public IPv4 203.0.113.10 (2 providers agree)`
- `no change (IPv4 ...)`
- `UPDATED site1.example.com A 198.51.100.7 -> 203.0.113.10`
- `CREATED ...`
- `ERROR ...`

The token never appears in the log: anything that looks like a token or `Bearer` value is masked, Cloudflare error
bodies included.

To run it by hand with full output:

```powershell
& "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass `
  -File C:\Windows\Scripts\DX\Scripts\DX-CF-DDNS.ps1 -Force -Verbose
```

## Troubleshooting

| Symptom | Fix |
|---|---|
| Installer exit 5, "rejected the API token (401)" | The token is wrong, revoked or expired. Create a new one and re-run with `CF_DDNS_TOKEN` set |
| Exit 5, "403 / no DNS permission" | Token is missing Zone > DNS > Edit, or the zone isn't included in its resources |
| Exit 5, "zone not found / wrong zone ID" | `CF_ZONE_ID` belongs to another zone or account. Copy it from the zone's Overview page |
| Updater exit 5, "record does not exist" | Create the A record in the dashboard (any IP), or re-run with `CF_DDNS_CREATE=1` |
| Updater exit 2, "providers disagree" | Usually a multi-WAN or load-balanced uplink, or a proxy. Pin outbound traffic to one WAN. Nothing is changed while this persists |
| Updater exit 2, "no valid public IP" | No internet, outbound HTTPS blocked, or the WAN address is CGNAT (100.64/10). With CGNAT, DDNS can't make the site reachable |
| Exit 3 with TLS / "could not create SSL/TLS secure channel" | The log has a TLS diagnostics line (OS build, .NET release, registry values). Set `SchUseStrongCrypto=1` and `SystemDefaultTlsVersions=1` under `HKLM\SOFTWARE\Microsoft\.NETFramework\v4.0.30319` and `HKLM\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319`. On 2012 R2, install KB3140245 / the ECDHE-GCM updates, then reboot |
| Installer exit 3, "SHA256 mismatch" | The raw file doesn't match the pin. This happens on a cached or partial download, or when `CF_DDNS_REPOURL` points at a different release. Never edit the pin by hand on a client |
| Installer exit 2 | Run elevated, or as SYSTEM from the RMM |
| Record keeps getting "fixed" | Something else, such as a router DDNS client or another tool, is also writing that record. Remove one of them |
| Force an update now | `Start-ScheduledTask -TaskPath '\DX\' -TaskName 'DX-CF-DDNS'` (it updates when due), or run it by hand with `-Force` |

## Security notes

- **Token scope:** one zone, DNS edit only, and never the Global API Key. A leaked token can still edit *every*
  record in that zone. To limit the damage, consider a dedicated DDNS zone (e.g. `ddns.example.com` as its own zone),
  and rotate the token if a machine is compromised. Cloudflare's Manage Account > Audit Logs shows which token
  changed which record.
- **Config ACL:** the config file is protected by SID (SYSTEM and Administrators only). It's created empty and locked
  down before the token is written, so there's never a moment when it can be read through inherited permissions.
- **DPAPI LocalMachine decision: not used.** A blob encrypted with DPAPI LocalMachine can be decrypted by *any*
  process on the same machine, including non-admin ones. So on the box itself it gives no more protection than the
  ACL, which already blocks non-admins. Anyone who is admin or SYSTEM can read either one. DPAPI would only help if
  someone copied the file off the machine, and the token is scoped to one zone and can be revoked. DPAPI would also
  make the config unreadable for a technician checking it, and break restores to other hardware. Keeping it plain
  JSON behind the ACL is the simpler and more transparent choice. A per-user DPAPI scope doesn't fit a SYSTEM task.
- **Secrets in transit:** the token is only sent to `api.cloudflare.com` over HTTPS. The installer clears
  `CF_DDNS_TOKEN` and `CF_DDNS_NTFY_TOKEN` from the process environment when it finishes. Don't put the token in the
  RMM script text; use a secure variable.
- **Supply chain:** the installer runs only a script whose SHA256 matches the pin committed with it. To get an
  immutable release, set `CF_DDNS_REPOURL` to a commit URL
  (`https://raw.githubusercontent.com/mezzanine78/DX-CF-DDNS/<sha>`) and run `install.ps1` from the same commit.
- **Logs:** no secrets are logged, and the log keeps its inherited ACL. Only non-secret data such as IPs and record
  names is written.

## Alternative: server-side DNS updates

Clients running DX-CFTrustedIPs already report their public IP to the collector. If the collector PATCHes
`CLIENTCODE.example.com` with its own token, the Cloudflare token never leaves the server, and a leaked client
token can only report an IP. The trade-off is that updates follow the collector's interval (hourly by default).
DX-CF-DDNS is the per-site option: updates within minutes, with no server dependency.

## Development

```powershell
pwsh -NoProfile -File tools/Invoke-Tests.ps1    # PSScriptAnalyzer (incl. PS 5.1 compatibility) + Pester 5+
pwsh -NoProfile -File tools/Update-Pins.ps1     # after ANY change to src/DX-CF-DDNS.ps1, then commit both files
```

The tests mock `Invoke-RestMethod` (a fake Cloudflare API and ntfy), along with the task and ACL operations, so they
run on Linux and macOS. `.gitattributes` forces LF line endings so the pinned hash is the same on every platform.

## License

MIT (c) 2026 mezzanine78
