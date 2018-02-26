#   Description:
# This script will try to fix many of the privacy settings for the user. This
# is work in progress!

Write-Verbose "Elevating priviledges for this process"
do {} until (Elevate-Privileges SeTakeOwnershipPrivilege)

Write-Verbose "Defuse Windows search settings"
Set-WindowsSearchSetting -EnableWebResultsSetting $false

Import-PowerShellDataFile -Path "$PSScriptRoot\..\RegFixes\CurrentUser\FixGeneralPrivacySettings.psd1" | Install-RegistryTweaks -Verbose

Write-Verbose "Denying device access"
$Payload = @{
    'Type'=@{
        Val='InterfaceClass'
        Type='String'
    }
    'Value'=@{
        Val='Deny'
        Type='String'
    }
	'InitialAppValue'=@{
        Val='Unspecified'
        Type='String'
    }
}

$SetForAllUsers=@{}

gci "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global" | ?{
	$_.PSChildName -ne 'LooselyCoupled'
} | select @{
	n='path';
	e={
		$_.name -replace 'HKEY_CURRENT_USER','HKCU:'
	}
} | select -ExpandProperty path | %{
	$SetForAllUsers[$_] = $Payload
}

Write-Verbose "Disable background access of default apps"
gci "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" | select @{
	n='path';
	e={
		$_.name -replace 'HKEY_CURRENT_USER','HKCU:'
	}
} | select -ExpandProperty path | %{
	$SetForAllUsers[$_] = @{
		"Disabled" = {
			Val=1
			Type='int'
		}
	}
}

Write-Verbose "Do not share wifi networks"
$SetForAllUsers["$(
		-join(
			"HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\features\",
			(
				(
					New-Object System.Security.Principal.NTAccount($env:UserName)
				).Translate(
					[System.Security.Principal.SecurityIdentifier]
				).value
			)
		)
	)"] = @{
        'FeatureStates'=@{
            Val=828
            Type='int'
        }
    }

$SetForAllUsers | Install-RegistryTweaks -Verbose