@{
    RootModule        = 'NetToolkit.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'b1d2c3e4-5f6a-7b8c-9d0e-1f2a3b4c5d6e'
    Author            = 'brobafett'
    Description       = 'Composable network diagnostics toolkit: local config, TCP connections, single-host and parallel subnet port scanning, traceroute, DNS lookup, and DNS cache flush.'
    PowerShellVersion = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')

    FunctionsToExport = @(
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
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()

    PrivateData = @{
        PSData = @{
            Tags       = @('Network', 'Diagnostics', 'PortScan', 'DNS', 'Traceroute', 'Windows')
            ProjectUri = 'https://github.com/brobafett/Coding'
        }
    }
}
