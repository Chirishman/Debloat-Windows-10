#   Description:
# This script optimizes Windows updates by disabling automatic download and
# seeding updates to other computers.
#

Import-PowerShellDataFile -Path "$PSScriptRoot\..\RegFixes\LocalMachine\DisableWindowsUpdateSeeding.psd1" | Install-RegistryTweaks -Verbose