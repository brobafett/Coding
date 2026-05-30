<#
.SYNOPSIS
    NetToolkit - composable network diagnostics for Windows PowerShell 5.1 and PowerShell 7+.

.DESCRIPTION
    Two layers:
      * Data functions  - pure, parameterised, emit objects to the pipeline. No prompts,
                          no Write-Host, no Format-Table. Composable and testable:
                              Test-PortConnectivity -ComputerName host -Port 80,443 | Export-Csv ...
                              Invoke-NetworkSweep -Cidr 192.168.1.0/24 -Port 22,445 -OpenOnly
      * Interactive layer - Show-NetToolkitMenu and its Invoke-* wrappers prompt, render,
                          and offer an export. Optional; everything works headless.

    Import-Module .\NetToolkit.psd1 ; then call the functions directly, or
    Show-NetToolkitMenu for the interactive console.
#>

Set-StrictMode -Version 2.0

#region Helper Functions

# Returns $true if the current session is elevated.
function Test-IsAdmin {
    $identity  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Expands a port specification such as "80,443,8000-8010" into a sorted, de-duplicated
# array of valid (1-65535) integers. Invalid tokens are warned about and skipped.
function Expand-PortList {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Spec)

    $ports = [System.Collections.Generic.List[int]]::new()
    foreach ($token in $Spec.Split(',')) {
        $t = $token.Trim()
        if ($t -eq '') { continue }

        if ($t -match '^\s*(\d+)\s*-\s*(\d+)\s*$') {
            $start = [int]$Matches[1]
            $end   = [int]$Matches[2]
            if ($start -gt $end) { $start, $end = $end, $start }
            for ($p = $start; $p -le $end; $p++) { $ports.Add($p) }
        }
        elseif ($t -match '^\d+$') {
            $ports.Add([int]$t)
        }
        else {
            Write-Warning "Ignoring invalid port token: '$t'"
        }
    }

    $ports | Where-Object { $_ -ge 1 -and $_ -le 65535 } | Sort-Object -Unique
}

# Expands an IPv4 CIDR block (e.g. 192.168.1.0/24) into its usable host addresses.
# Network and broadcast addresses are excluded except for /31 and /32. Capped at a
# /16 (65536 addresses) to prevent accidental enormous sweeps.
function Expand-Cidr {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Cidr)

    if ($Cidr -notmatch '^(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})$') {
        throw "Invalid CIDR: '$Cidr'. Expected form like 192.168.1.0/24."
    }
    $ip     = [System.Net.IPAddress]::Parse($Matches[1])
    $prefix = [int]$Matches[2]
    if ($prefix -lt 0 -or $prefix -gt 32) { throw "Invalid prefix length /$prefix." }

    # Convert the dotted address to a 32-bit integer (work in uint64 throughout, using
    # arithmetic rather than shift/-bnot, which don't preserve unsigned types in PowerShell).
    $bytes = $ip.GetAddressBytes(); [array]::Reverse($bytes)
    $ipInt = [uint64][System.BitConverter]::ToUInt32($bytes, 0)

    $blockSize = [uint64][math]::Pow(2, (32 - $prefix))   # addresses in the block
    $mask      = [uint64]4294967296 - $blockSize          # 2^32 - blockSize
    $network   = $ipInt -band $mask
    $broadcast = $network + $blockSize - 1

    $start = if ($prefix -ge 31) { $network }   else { $network + 1 }
    $end   = if ($prefix -ge 31) { $broadcast } else { $broadcast - 1 }

    $count = ($end - $start) + 1
    if ($count -gt 65536) {
        throw "CIDR /$prefix expands to $count hosts; refusing. Use /16 or narrower."
    }

    for ($addr = $start; $addr -le $end; $addr++) {
        $ab = [System.BitConverter]::GetBytes([uint32]$addr); [array]::Reverse($ab)
        [System.Net.IPAddress]::new($ab).ToString()
    }
}

# Tests a single TCP port with an explicit timeout, using a raw TcpClient so we get
# fast, controllable results instead of Test-NetConnection's heavyweight probe.
function Test-TcpPort {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter(Mandatory)][int]$Port,
        [int]$TimeoutMs = 1000
    )

    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $async = $client.BeginConnect($ComputerName, $Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne($TimeoutMs)) {
            return $false   # timed out -> treat as closed/filtered
        }
        $client.EndConnect($async)   # throws if actively refused
        return $true
    }
    catch {
        return $false
    }
    finally {
        $client.Close()
    }
}

#endregion

#region Data Functions (pure - emit objects, no UI)

# Local IP configuration via CIM (the modern replacement for Get-WmiObject).
function Get-LocalNetworkInfo {
    [CmdletBinding()]
    param()

    $adapters = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration `
                    -Filter 'IPEnabled = TRUE' -ErrorAction Stop
    foreach ($adapter in $adapters) {
        [PSCustomObject]@{
            Interface      = $adapter.Description
            IPv4Address    = (@($adapter.IPAddress)           | Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' }) -join ', '
            DefaultGateway = (@($adapter.DefaultIPGateway)     | Where-Object { $_ }) -join ', '
            DNSServers     = (@($adapter.DNSServerSearchOrder) | Where-Object { $_ }) -join ', '
        }
    }
}

# Established TCP connections with owning process names.
function Get-ActiveTcpConnectionInfo {
    [CmdletBinding()]
    param()

    $connections = Get-NetTCPConnection -State Established -ErrorAction Stop
    if (-not $connections) { return }

    # Resolve every PID once, not once-per-connection.
    $processById = @{}
    foreach ($p in Get-Process -ErrorAction SilentlyContinue) {
        $processById[$p.Id] = $p.ProcessName
    }

    foreach ($conn in $connections) {
        [PSCustomObject]@{
            ProcessID     = $conn.OwningProcess
            ProcessName   = if ($processById.ContainsKey([int]$conn.OwningProcess)) { $processById[[int]$conn.OwningProcess] } else { 'N/A' }
            LocalAddress  = $conn.LocalAddress
            LocalPort     = $conn.LocalPort
            RemoteAddress = $conn.RemoteAddress
            RemotePort    = $conn.RemotePort
        }
    }
}

# Port scanner against a single host. Resolves the host once (fail fast on a bad name),
# then emits one result object per port. Progress is on the Progress stream, not stdout.
function Test-PortConnectivity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter(Mandatory)][int[]]$Port,
        [int]$TimeoutMs = 1000
    )

    try {
        [System.Net.Dns]::GetHostAddresses($ComputerName) | Out-Null
    }
    catch {
        Write-Error "Host '$ComputerName' could not be resolved."
        return
    }

    $i = 0
    foreach ($p in $Port) {
        $i++
        Write-Progress -Activity "Scanning $ComputerName" -Status "Port $p" `
            -PercentComplete (($i / $Port.Count) * 100)
        $isOpen = Test-TcpPort -ComputerName $ComputerName -Port $p -TimeoutMs $TimeoutMs
        [PSCustomObject]@{
            Host   = $ComputerName
            Port   = $p
            Status = if ($isOpen) { 'Open' } else { 'Closed' }
        }
    }
    Write-Progress -Activity "Scanning $ComputerName" -Completed
}

# Parallel sweep across many hosts (CIDR or explicit list) and many ports, using a
# runspace pool so it works the same on PowerShell 5.1 and 7+. Emits {Host, Port, Status}.
function Invoke-NetworkSweep {
    [CmdletBinding(DefaultParameterSetName = 'Cidr')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Cidr', Position = 0)]
        [string]$Cidr,

        [Parameter(Mandatory, ParameterSetName = 'Hosts', Position = 0)]
        [string[]]$ComputerName,

        [Parameter(Mandatory)]
        [string]$Port,

        [int]$TimeoutMs = 1000,

        [ValidateRange(1, 512)]
        [int]$ThrottleLimit = 64,

        [switch]$OpenOnly
    )

    # Wrap the whole if/else in @() so a single-element result stays an array. (@() inside
    # the branches isn't enough: a one-element array emitted from an if-branch is unrolled
    # to a scalar on assignment, which then has no .Count under StrictMode.)
    $targets = @(
        if ($PSCmdlet.ParameterSetName -eq 'Cidr') { Expand-Cidr -Cidr $Cidr }
        else { $ComputerName | ForEach-Object { $_.Trim() } | Where-Object { $_ } }
    )

    if ($targets.Count -eq 0) { Write-Warning 'No hosts to scan.'; return }

    $ports = @(Expand-PortList -Spec $Port)
    if ($ports.Count -eq 0) { Write-Warning 'No valid ports to scan.'; return }

    $total = $targets.Count * $ports.Count
    Write-Verbose "Sweeping $($targets.Count) host(s) x $($ports.Count) port(s) = $total checks."

    # Self-contained probe; runspaces don't inherit the module scope, so this stays inline.
    $probe = {
        param($ComputerName, $Port, $TimeoutMs)
        $client = [System.Net.Sockets.TcpClient]::new()
        $open = $false
        try {
            $async = $client.BeginConnect($ComputerName, $Port, $null, $null)
            if ($async.AsyncWaitHandle.WaitOne($TimeoutMs)) {
                try { $client.EndConnect($async); $open = $true } catch { $open = $false }
            }
        }
        catch { $open = $false }
        finally { $client.Close() }

        [PSCustomObject]@{
            Host   = $ComputerName
            Port   = $Port
            Status = if ($open) { 'Open' } else { 'Closed' }
        }
    }

    $pool = [runspacefactory]::CreateRunspacePool(1, $ThrottleLimit)
    $pool.Open()
    try {
        $jobs = [System.Collections.Generic.List[object]]::new()
        foreach ($t in $targets) {
            foreach ($p in $ports) {
                $ps = [powershell]::Create()
                $ps.RunspacePool = $pool
                $null = $ps.AddScript($probe).AddArgument($t).AddArgument($p).AddArgument($TimeoutMs)
                $jobs.Add([PSCustomObject]@{ PS = $ps; Handle = $ps.BeginInvoke() })
            }
        }

        $done = 0
        foreach ($job in $jobs) {
            $result = $job.PS.EndInvoke($job.Handle)
            $job.PS.Dispose()
            $done++
            Write-Progress -Activity 'Network sweep' -Status "$done/$total checks" `
                -PercentComplete (($done / $total) * 100)
            foreach ($r in $result) {
                if (-not $OpenOnly -or $r.Status -eq 'Open') { $r }
            }
        }
        Write-Progress -Activity 'Network sweep' -Completed
    }
    finally {
        $pool.Close()
        $pool.Dispose()
    }
}

# Traceroute. Test-NetConnection's TraceRoute is a string[] of hop addresses, so we
# number them ourselves rather than asking for properties that don't exist.
function Get-TraceRouteHop {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ComputerName)

    $trace = Test-NetConnection -ComputerName $ComputerName -TraceRoute `
                -WarningAction SilentlyContinue -ErrorAction Stop
    if (-not $trace.TraceRoute) {
        Write-Warning "No route information returned (host may be unreachable)."
        return
    }

    $hop = 0
    foreach ($address in $trace.TraceRoute) {
        [PSCustomObject]@{
            Hop     = (++$hop)
            Address = $address      # '0.0.0.0' indicates a hop that did not respond
        }
    }
}

# DNS lookup - thin object-returning wrapper around Resolve-DnsName.
function Resolve-HostNameRecord {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Name)

    Resolve-DnsName -Name $Name -ErrorAction Stop
}

# Flush the DNS resolver cache (requires elevation). Throws if not elevated.
function Clear-DnsResolverCache {
    [CmdletBinding()]
    param()

    if (-not (Test-IsAdmin)) {
        throw "Administrator privileges are required to flush the DNS cache."
    }
    Clear-DnsClientCache -ErrorAction Stop
}

#endregion

#region Presentation Helpers

# Prompts the user to export $Data to the Desktop as text or CSV.
function Export-Results {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Data,
        [Parameter(Mandatory)][string]$BaseFileName
    )

    if (-not $Data) { return }

    $exportChoice = Read-Host "Do you want to export these results? (y/n)"
    if ($exportChoice -ne 'y') { return }

    $formatChoice = Read-Host "Choose export format: [T]ext or [C]SV"
    $desktopPath  = [System.Environment]::GetFolderPath('Desktop')

    # Strip characters that are illegal in file names (e.g. ':' from an IPv6 target).
    $safeBase = $BaseFileName -replace '[\\/:*?"<>|]', '_'
    $fileName = "$safeBase-$(Get-Date -Format 'yyyyMMdd-HHmmss')"

    switch -Wildcard ($formatChoice) {
        't*' {
            $fullPath = Join-Path -Path $desktopPath -ChildPath "$fileName.txt"
            # Out-String -Width prevents Out-File from truncating wide tables with '...'.
            $Data | Format-Table -AutoSize | Out-String -Width 4096 | Out-File -FilePath $fullPath -Encoding UTF8
            Write-Host "Results exported to $fullPath" -ForegroundColor Green
        }
        'c*' {
            # CSV needs objects with properties. PSCustomObject members are NoteProperty;
            # real .NET objects expose Property. Accept either.
            $hasProps = @($Data | Get-Member -MemberType NoteProperty, Property -ErrorAction SilentlyContinue).Count -gt 0
            if ($hasProps) {
                $fullPath = Join-Path -Path $desktopPath -ChildPath "$fileName.csv"
                $Data | Export-Csv -Path $fullPath -NoTypeInformation -Encoding UTF8
                Write-Host "Results exported to $fullPath" -ForegroundColor Green
            }
            else {
                Write-Warning "CSV export is not supported for this data type. Try Text format."
            }
        }
        default {
            Write-Warning "Invalid format choice. No file was exported."
        }
    }
}

# Renders a result set as a table and offers to export it.
function Show-Result {
    [CmdletBinding()]
    param(
        $Data,
        [Parameter(Mandatory)][string]$BaseFileName,
        [string[]]$Property
    )

    if (-not $Data) {
        Write-Warning "No results to display."
        return
    }

    if ($Property) { $Data | Format-Table -Property $Property -AutoSize }
    else           { $Data | Format-Table -AutoSize }

    Export-Results -Data $Data -BaseFileName $BaseFileName
}

#endregion

#region Interactive Layer (prompt -> call data function -> display)

function Invoke-LocalNetworkInfo {
    Write-Host "`n[+] Getting Local Network Information..." -ForegroundColor Cyan
    try {
        $results = @(Get-LocalNetworkInfo)
        if (-not $results) { Write-Warning "No IP-enabled network adapters found."; return }
        Show-Result -Data $results -BaseFileName 'Local-IP-Config'
    }
    catch {
        Write-Error "An error occurred while fetching network information: $_"
    }
}

function Invoke-ActiveTcpConnections {
    Write-Host "`n[+] Getting Active TCP Connections..." -ForegroundColor Cyan
    try {
        $results = @(Get-ActiveTcpConnectionInfo)
        if (-not $results) { Write-Warning "No established TCP connections found."; return }
        Show-Result -Data $results -BaseFileName 'Active-TCP-Connections'
    }
    catch {
        Write-Error "An error occurred while fetching TCP connections: $_"
        Write-Warning "Try running PowerShell as an Administrator for complete results."
    }
}

function Invoke-PortScan {
    Write-Host "`n[+] Testing Port Connectivity..." -ForegroundColor Cyan
    $targetHost = (Read-Host "Enter the target hostname or IP address (e.g., google.com)").Trim()
    $portSpec   = Read-Host "Enter ports to scan (e.g., 80,443,8000-8010)"

    if (-not $targetHost -or -not $portSpec) {
        Write-Warning "Host and port numbers are required."
        return
    }

    $ports = @(Expand-PortList -Spec $portSpec)
    if ($ports.Count -eq 0) { Write-Warning "No valid ports to scan."; return }

    try {
        $results = @(Test-PortConnectivity -ComputerName $targetHost -Port $ports -ErrorAction Stop)
        Show-Result -Data $results -BaseFileName "PortScan-$targetHost"
    }
    catch {
        Write-Host " FAILED ($_)" -ForegroundColor DarkRed
    }
}

function Invoke-NetworkSweepInteractive {
    Write-Host "`n[+] Parallel Network Sweep..." -ForegroundColor Cyan
    $target   = (Read-Host "Enter a CIDR (e.g. 192.168.1.0/24) or comma-separated hosts").Trim()
    $portSpec = Read-Host "Enter ports to scan (e.g., 22,80,443,3389)"

    if (-not $target -or -not $portSpec) {
        Write-Warning "Target and ports are required."
        return
    }

    Write-Host "Sweeping (showing open ports only)..."
    try {
        $results = @(
            if ($target -match '/\d{1,2}$') {
                Invoke-NetworkSweep -Cidr $target -Port $portSpec -OpenOnly
            }
            else {
                Invoke-NetworkSweep -ComputerName ($target.Split(',')) -Port $portSpec -OpenOnly
            }
        )

        if (-not $results) { Write-Warning "No open ports found across the sweep."; return }
        Show-Result -Data $results -BaseFileName "Sweep-$target"
    }
    catch {
        Write-Error "Sweep failed: $_"
    }
}

function Invoke-TraceRoute {
    Write-Host "`n[+] Performing a Traceroute..." -ForegroundColor Cyan
    $targetHost = (Read-Host "Enter the destination hostname or IP address").Trim()

    if (-not $targetHost) { Write-Warning "A target host is required."; return }

    Write-Host "Tracing route to '$targetHost'... (this can take a while)"
    try {
        $results = @(Get-TraceRouteHop -ComputerName $targetHost)
        Show-Result -Data $results -BaseFileName "Traceroute-To-$targetHost"
    }
    catch {
        Write-Error "An error occurred during the traceroute: $_"
    }
}

function Invoke-DnsLookup {
    Write-Host "`n[+] Performing DNS Lookup..." -ForegroundColor Cyan
    $hostname = (Read-Host "Enter the hostname to resolve (e.g., www.google.com)").Trim()

    if (-not $hostname) { Write-Warning "A hostname is required."; return }

    Write-Host "Resolving '$hostname'..."
    try {
        $results = @(Resolve-HostNameRecord -Name $hostname)
        Show-Result -Data $results -BaseFileName "DNS-Lookup-For-$hostname" -Property Name, Type, IPAddress
    }
    catch {
        Write-Error "Could not resolve the hostname: $_"
    }
}

function Invoke-FlushDnsCache {
    Write-Host "`n[+] Flushing DNS Resolver Cache..." -ForegroundColor Cyan
    try {
        Clear-DnsResolverCache
        Write-Host "Successfully flushed the DNS resolver cache." -ForegroundColor Green
    }
    catch {
        Write-Warning $_.Exception.Message
    }
}

#endregion

#region Main Menu

function Show-NetToolkitMenu {
    [CmdletBinding()]
    param()

    while ($true) {
        Write-Host "`n--- PowerShell Network Toolkit ---" -ForegroundColor Yellow
        Write-Host "1: Display Local IP Information"
        Write-Host "2: Show Active TCP Connections (Enhanced Netstat)"
        Write-Host "3: Scan Ports on a Remote Host"
        Write-Host "4: Sweep Ports across a Subnet / Host List (parallel)"
        Write-Host "5: Perform a Traceroute"
        Write-Host "6: Perform a DNS Lookup"
        Write-Host "7: Flush DNS Cache (Requires Admin)"
        Write-Host "Q: Quit"
        Write-Host "--------------------------------" -ForegroundColor Yellow

        $selection = (Read-Host "Please make a selection").Trim()

        switch ($selection) {
            '1' { Invoke-LocalNetworkInfo }
            '2' { Invoke-ActiveTcpConnections }
            '3' { Invoke-PortScan }
            '4' { Invoke-NetworkSweepInteractive }
            '5' { Invoke-TraceRoute }
            '6' { Invoke-DnsLookup }
            '7' { Invoke-FlushDnsCache }
            'Q' {
                Write-Host "Exiting the toolkit. Goodbye!" -ForegroundColor Green
                return
            }
            default {
                Write-Host "Invalid selection. Please try again." -ForegroundColor Red
            }
        }

        if ($selection -ne 'Q') {
            Read-Host "`nPress Enter to return to the menu..." | Out-Null
            Clear-Host
        }
    }
}

#endregion

Export-ModuleMember -Function @(
    'Get-LocalNetworkInfo'
    'Get-ActiveTcpConnectionInfo'
    'Test-PortConnectivity'
    'Invoke-NetworkSweep'
    'Get-TraceRouteHop'
    'Resolve-HostNameRecord'
    'Clear-DnsResolverCache'
    'Expand-PortList'
    'Expand-Cidr'
    'Test-TcpPort'
    'Show-NetToolkitMenu'
)
