<#
.SYNOPSIS
    A multi-function PowerShell script for performing common network diagnostics and queries.

.DESCRIPTION
    This script provides a menu-driven interface for various TCP/IP tasks,
    acting as a consolidated toolkit for network administrators. It combines the
    functionality of several command-line tools like ipconfig, netstat, nslookup,
    and tracert into a single, user-friendly PowerShell script.

    Inspired by concepts from "TCP/IP Network Administration" and "Windows PowerShell Cookbook".

    Features:
    1. Display Local IP Configuration: Shows detailed IP information for all network adapters.
    2. Show Active TCP Connections: Lists active connections and their owning processes.
    3. Port Scanner: Scans a target host for specified open TCP ports.
    4. Traceroute: Performs a traceroute to a remote host to map the network path.
    5. DNS Lookup: Resolves a given hostname to its IP address(es).
    6. Flush DNS Cache: Clears the local DNS resolver cache (Requires Admin).

    Most functions now include an option to export results to a .txt or .csv file on your Desktop.


.NOTES
    Run this script in a PowerShell console. The menu will guide you through the available options.
    Some functions require administrative privileges to run correctly. The script will notify you
    if elevated permissions are needed.
#>

#region Helper Functions

<#
.SYNOPSIS
    Checks if the current PowerShell session is running with Administrator privileges.
.RETURNS
    $true if running as Admin, $false otherwise.
#>
function Test-IsAdmin {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

<#
.SYNOPSIS
    Prompts the user to export data to a file on their desktop.
.PARAMETER Data
    The object or collection of objects to export.
.PARAMETER BaseFileName
    The base name for the output file (without extension).
#>
function Export-Results {
    param(
        [Parameter(Mandatory=$true)]
        $Data,
        [Parameter(Mandatory=$true)]
        [string]$BaseFileName
    )

    $exportChoice = Read-Host "Do you want to export these results? (y/n)"
    if ($exportChoice -ne 'y') {
        return
    }

    $formatChoice = Read-Host "Choose export format: [T]ext or [C]SV"
    $desktopPath = [System.Environment]::GetFolderPath('Desktop')
    $fileName = "$($BaseFileName)-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    $fullPath = ""

    switch -Wildcard ($formatChoice) {
        "t*" {
            $fullPath = Join-Path -Path $desktopPath -ChildPath "$($fileName).txt"
            $Data | Format-Table | Out-File -FilePath $fullPath
            Write-Host "Results exported to $fullPath" -ForegroundColor Green
        }
        "c*" {
            # CSV export requires objects, not formatted text.
            if ($Data | Get-Member | Where-Object { $_.MemberType -eq 'Property' }) {
                $fullPath = Join-Path -Path $desktopPath -ChildPath "$($fileName).csv"
                $Data | Export-Csv -Path $fullPath -NoTypeInformation
                Write-Host "Results exported to $fullPath" -ForegroundColor Green
            } else {
                Write-Warning "CSV export is not supported for this data type. Try Text format."
            }
        }
        default {
            Write-Warning "Invalid format choice. No file was exported."
        }
    }
}


#endregion

#region Main Menu and Core Logic

# Main loop to display the menu and handle user input
function Show-Menu {
    param()

    # Infinite loop to keep the menu active until the user chooses to exit.
    while ($true) {
        Write-Host "`n--- PowerShell Network Toolkit ---" -ForegroundColor Yellow
        Write-Host "1: Display Local IP Information"
        Write-Host "2: Show Active TCP Connections (Enhanced Netstat)"
        Write-Host "3: Scan Ports on a Remote Host"
        Write-Host "4: Perform a Traceroute"
        Write-Host "5: Perform a DNS Lookup"
        Write-Host "6: Flush DNS Cache (Requires Admin)"
        Write-Host "Q: Quit"
        Write-Host "--------------------------------" -ForegroundColor Yellow

        # Prompt the user for their choice.
        $selection = Read-Host "Please make a selection"

        # Use a switch statement to execute the function corresponding to the user's choice.
        switch ($selection) {
            '1' { Get-LocalNetworkInfo }
            '2' { Get-ActiveTCPConnections }
            '3' { Test-PortConnectivity }
            '4' { Trace-RouteToHost }
            '5' { Resolve-DNSNameInteractive }
            '6' { Flush-DnsCache }
            'Q' {
                Write-Host "Exiting the toolkit. Goodbye!" -ForegroundColor Green
                return # Exit the function, which terminates the script.
            }
            default {
                Write-Host "Invalid selection. Please try again." -ForegroundColor Red
            }
        }
        # Pause after a function completes to allow the user to read the output.
        # The export prompt now serves as this pause, so we only need it for non-exporting functions.
        if ($selection -in '3','6') {
            Read-Host "Press Enter to return to the menu..."
        }
        Clear-Host
    }
}

#endregion

#region Feature Functions

<#
.SYNOPSIS
    Displays detailed IP configuration and provides an option to export.
#>
function Get-LocalNetworkInfo {
    Write-Host "`n[+] Getting Local Network Information (WMI Method)..." -ForegroundColor Cyan
    try {
        $adapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled='TRUE'" -ErrorAction Stop
        if (-not $adapters) {
            Write-Warning "No IP-enabled network adapters found."
            return
        }

        # Create custom objects for clean output and exporting.
        $results = foreach ($adapter in $adapters) {
             [PSCustomObject]@{
                Interface       = $adapter.Description
                IPv4Address     = ($adapter.IPAddress | Where-Object { $_ -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$' }) -join ', '
                DefaultGateway  = ($adapter.DefaultIPGateway) -join ', '
                DNSServers      = ($adapter.DNSServerSearchOrder) -join ', '
            }
        }
        
        # Display results on screen and then prompt for export.
        $results | Format-Table -AutoSize
        Export-Results -Data $results -BaseFileName "Local-IP-Config"
    }
    catch {
        Write-Error "An error occurred while fetching network information via WMI: $_"
    }
}

<#
.SYNOPSIS
    Lists active TCP connections and provides an option to export.
#>
function Get-ActiveTCPConnections {
    Write-Host "`n[+] Getting Active TCP Connections..." -ForegroundColor Cyan
    try {
        $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
        if (-not $connections) {
            Write-Warning "No established TCP connections found."
            return
        }

        $results = foreach ($conn in $connections) {
            $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
            [PSCustomObject]@{
                ProcessID      = if ($process) { $process.Id } else { $conn.OwningProcess }
                ProcessName    = if ($process) { $process.ProcessName } else { "N/A" }
                LocalAddress   = $conn.LocalAddress
                LocalPort      = $conn.LocalPort
                RemoteAddress  = $conn.RemoteAddress
                RemotePort     = $conn.RemotePort
            }
        }
        
        $results | Format-Table -AutoSize
        Export-Results -Data $results -BaseFileName "Active-TCP-Connections"
    }
    catch {
        Write-Error "An error occurred while fetching TCP connections: $_"
        Write-Warning "Try running PowerShell as an Administrator for complete results."
    }
}

<#
.SYNOPSIS
    Scans a remote host for open TCP ports. (No export option for this function).
#>
function Test-PortConnectivity {
    Write-Host "`n[+] Testing Port Connectivity..." -ForegroundColor Cyan
    $targetHost = Read-Host "Enter the target hostname or IP address (e.g., google.com)"
    $ports = Read-Host "Enter ports to scan, separated by commas (e.g., 80,443,8080)"

    if (-not $targetHost -or -not $ports) {
        Write-Warning "Host and port numbers are required."
        return
    }

    $portArray = $ports.Split(',') | ForEach-Object { $_.Trim() }
    Write-Host "Scanning '$targetHost'..."

    foreach ($port in $portArray) {
        Write-Host "  - Checking port $port..." -NoNewline
        try {
            $result = Test-NetConnection -ComputerName $targetHost -Port $port -WarningAction SilentlyContinue
            if ($result.TcpTestSucceeded) {
                Write-Host " OPEN" -ForegroundColor Green
            }
            else {
                Write-Host " CLOSED" -ForegroundColor Red
            }
        }
        catch {
            Write-Host " FAILED (Host not found or unreachable)" -ForegroundColor DarkRed
            break
        }
    }
}

<#
.SYNOPSIS
    Performs a traceroute and provides an option to export.
#>
function Trace-RouteToHost {
    Write-Host "`n[+] Performing a Traceroute..." -ForegroundColor Cyan
    $targetHost = Read-Host "Enter the destination hostname or IP address"

    if (-not $targetHost) {
        Write-Warning "A target host is required."
        return
    }

    Write-Host "Tracing route to '$targetHost'..."
    try {
        $trace = Test-NetConnection -ComputerName $targetHost -TraceRoute
        $results = $trace.TraceRoute
        
        $results | Format-Table -Property Hop, RoundTripTime, Address, Status -AutoSize
        Export-Results -Data $results -BaseFileName "Traceroute-To-$($targetHost)"
    }
    catch {
        Write-Error "An error occurred during the traceroute: $_"
    }
}

<#
.SYNOPSIS
    Resolves a DNS hostname and provides an option to export.
#>
function Resolve-DNSNameInteractive {
    Write-Host "`n[+] Performing DNS Lookup..." -ForegroundColor Cyan
    $hostname = Read-Host "Enter the hostname to resolve (e.g., www.google.com)"

    if (-not $hostname) {
        Write-Warning "A hostname is required."
        return
    }

    Write-Host "Resolving '$hostname'..."
    try {
        $results = Resolve-DnsName -Name $hostname -ErrorAction Stop
        
        $results | Format-Table -Property Name, Type, IPAddress -AutoSize
        Export-Results -Data $results -BaseFileName "DNS-Lookup-For-$($hostname)"
    }
    catch {
        Write-Error "Could not resolve the hostname: $_"
    }
}

<#
.SYNOPSIS
    Clears the local client-side DNS resolver cache. (No export option for this function).
#>
function Flush-DnsCache {
    Write-Host "`n[+] Flushing DNS Resolver Cache..." -ForegroundColor Cyan

    if (-not (Test-IsAdmin)) {
        Write-Warning "This action requires Administrator privileges. Please re-run PowerShell as an Administrator."
        return
    }

    try {
        Clear-DnsClientCache -ErrorAction Stop
        Write-Host "Successfully flushed the DNS resolver cache." -ForegroundColor Green
    }
    catch {
        Write-Error "An error occurred while flushing the DNS cache: $_"
    }
}

#endregion

# --- Script Entry Point ---
# Clears the screen and calls the main menu function to start the toolkit.
Clear-Host
Show-Menu
