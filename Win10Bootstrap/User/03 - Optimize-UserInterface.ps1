#   Description
# This script will disable some accessibility features regarding keyboard input.
# Additionaly it will set some visibility/UI elements will be changed.

write-verbose "Elevating priviledges for this process"
do {} until (Elevate-Privileges SeTakeOwnershipPrivilege)

Import-PowerShellDataFile -Path "$PSScriptRoot\..\RegFixes\CurrentUser\UITweaks.psd1" | Install-RegistryTweaks -Verbose