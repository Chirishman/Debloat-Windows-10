#   Description:
# This script will try to fix many of the privacy settings for the user. This
# is work in progress!

write-verbose "Elevating priviledges for this process"
do {} until (Elevate-Privileges SeTakeOwnershipPrivilege)

write-verbose "Defuse Windows search settings"
Set-WindowsSearchSetting -EnableWebResultsSetting $false

Import-PowerShellDataFile -Path "$PSScriptRoot\..\RegFixes\CurrentUser\FixGeneralPrivacySettings.psd1" | Install-RegistryTweaks -Verbose
Import-PowerShellDataFile -Path "$PSScriptRoot\..\RegFixes\LocalMachine\FixGeneralPrivacySettings.psd1" | Install-RegistryTweaks -Verbose

write-verbose "Disable background access of default apps"
foreach ($key in (ls "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications")) {
    sp ("HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\" + $key.PSChildName) "Disabled" 1
}

write-verbose "Denying device access"

foreach ($key in (ls "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global")) {
    if ($key.PSChildName -EQ "LooselyCoupled") {
        continue
    }
	@(
		@(
			"Type",
			"InterfaceClass"
		),
		@(
			"Value",
			"Deny"
		),
		@(
			"InitialAppValue",
			"Unspecified"
		)
	) | %{
		Set-ItemProperty -Path ("HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\" + $key.PSChildName) -Name $_[0] -Value $_[1]
	}
    
    
}

write-verbose "Do not share wifi networks"
$user = New-Object System.Security.Principal.NTAccount($env:UserName)
$sid = $user.Translate([System.Security.Principal.SecurityIdentifier]).value
force-mkdir ("HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\features\" + $sid)
sp ("HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\features\" + $sid) "FeatureStates" 0x33c

