#   Description:
# This script blocks telemetry related domains via the hosts file and related
# IPs via Windows Firewall.

Write-Verbose "Disabling telemetry via Group Policies"
Import-PowerShellDataFile -Path "$PSScriptRoot\..\RegFixes\LocalMachine\DisableTelemetry.psd1" | Install-RegistryTweaks -Verbose

Write-Verbose "Adding telemetry ips to firewall"
$ips = @(
    "134.170.30.202"
    "137.116.81.24"
    "157.56.106.189"
    "2.22.61.43"
    "2.22.61.66"
    "204.79.197.200"
    "23.218.212.69"
    "65.39.117.230"
    "65.52.108.33"
    "65.55.108.23"
)

Remove-NetFirewallRule -DisplayName "Block Telemetry IPs" -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName "Block Telemetry IPs" -Direction Outbound -Action Block -RemoteAddress ([string[]]$ips)