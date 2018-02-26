#   Description:
# This script will try to fix many of the privacy settings for the machine.

Write-Verbose "Elevating priviledges for this process"
do {} until (Elevate-Privileges SeTakeOwnershipPrivilege)

Import-PowerShellDataFile -Path "$PSScriptRoot\..\RegFixes\LocalMachine\FixGeneralPrivacySettings.psd1" | Install-RegistryTweaks -Verbose