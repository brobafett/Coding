<#
.SYNOPSIS
    Launcher for the NetToolkit network diagnostics module.

.DESCRIPTION
    Backwards-compatible entry point. Imports the NetToolkit module from this folder
    and starts the interactive menu. All functionality now lives in NetToolkit.psm1
    and can be used headless instead:

        Import-Module '.\NetToolkit.psd1'
        Invoke-NetworkSweep -Cidr 192.168.1.0/24 -Port 22,445,3389 -OpenOnly | Export-Csv sweep.csv
        Get-ActiveTcpConnectionInfo | Where-Object RemotePort -eq 443
#>

Import-Module (Join-Path $PSScriptRoot 'NetToolkit.psd1') -Force
Clear-Host
Show-NetToolkitMenu
