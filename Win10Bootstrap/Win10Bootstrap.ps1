Param(
	[ValidateSet('User','Machine','Both')][string]$Selector = 'Both'
)

$VerbosePreference = 'Continue'

function Elevate-Privileges {
    param($Privilege)
    $Definition = @"
    using System;
    using System.Runtime.InteropServices;

    public class AdjPriv {
        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
            internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall, ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr rele);

        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
            internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);

        [DllImport("advapi32.dll", SetLastError = true)]
            internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
            internal struct TokPriv1Luid {
                public int Count;
                public long Luid;
                public int Attr;
            }

        internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
        internal const int TOKEN_QUERY = 0x00000008;
        internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;

        public static bool EnablePrivilege(long processHandle, string privilege) {
            bool retVal;
            TokPriv1Luid tp;
            IntPtr hproc = new IntPtr(processHandle);
            IntPtr htok = IntPtr.Zero;
            retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
            tp.Count = 1;
            tp.Luid = 0;
            tp.Attr = SE_PRIVILEGE_ENABLED;
            retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
            retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
            return retVal;
        }
    }
"@
    $ProcessHandle = (Get-Process -id $pid).Handle
    $type = Add-Type $definition -PassThru
    $type[0]::EnablePrivilege($processHandle, $Privilege)
}

do {} until (Elevate-Privileges SeTakeOwnershipPrivilege)

function Install-RegistryTweaks {
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [Alias('InputObject')]
        [hashtable]$RegistryTweaks
    )
       
    $RegistryTweaks.GetEnumerator() | %{
        $path = $_.Key -split "\\"
        
        if (-not (Test-Path $_.Key)){
            Write-Verbose "Key doesn't exist, beginning to recursively create subkeys"    
            0..($path.length - 1) | %{
                if (-not (Test-Path ($path[0..$_] -join "\"))){
                    Write-Verbose "Creating subkey $($path[$_]) in $($path[0..($_-1)] -join "\")"
                    (get-item ($path[0..($_-2)] -join "\")).OpenSubKey($path[$_-1],$true).CreateSubKey($path[$_])
                }
            }
        }

        Write-Verbose "Opening Target Key $($_.Key)"
        $thisKey = (get-item ($path[0..($path.Length-2)] -join "\")).OpenSubKey($path[$path.Length-1],$true)
        $_.Value.GetEnumerator() | % {
            if (($thisKey.GetValue($_.Key) -eq $_.Value.Val)) {
                Write-Verbose "Value $($_.Key) = $($_.Value.Val) value already set"
            } else {
                Write-Verbose "Writing Value $(($_.Key, $_.Value.Val, [Microsoft.Win32.RegistryValueKind]::($_.Value.Type)) -join ", ")"
                $thisKey.SetValue($_.Key, $_.Value.Val,  [Microsoft.Win32.RegistryValueKind]::($_.Value.Type))
            }
        }

    }
}

if ($Selector -in @('User','Both')){
	#Enable GodMode
	Write-Information "###############################################################################`r`n#       _______  _______  ______     __   __  _______  ______   _______       #`r`n#      |       ||       ||      |   |  |_|  ||       ||      | |       |      #`r`n#      |    ___||   _   ||  _    |  |       ||   _   ||  _    ||    ___|      #`r`n#      |   | __ |  | |  || | |   |  |       ||  | |  || | |   ||   |___       #`r`n#      |   ||  ||  |_|  || |_|   |  |       ||  |_|  || |_|   ||    ___|      #`r`n#      |   |_| ||       ||       |  | ||_|| ||       ||       ||   |___       #`r`n#      |_______||_______||______|   |_|   |_||_______||______| |_______|      #`r`n#                                                                             #`r`n#      God Mode has been enabled, check out the new link on your Desktop      #`r`n#                                                                             #`r`n###############################################################################" -InformationAction Continue
	New-Item -Path ([Environment]::GetFolderPath("Desktop")) -Name 'GodMode.{ED7BA470-8E54-465E-825C-99712043E01C}' -ItemType Directory -ErrorAction SilentlyContinue
		
	Write-Verbose "Defuse Windows search settings"
	Set-WindowsSearchSetting -EnableWebResultsSetting $false
	
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
				Type='dword'
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
				Type='dword'
			}
		}

	@(
		#Basic Privacy Tweaks
		@{
			'HKCU:\Control Panel\International\User Profile'=@{
				'HttpAcceptLanguageOptOut'=@{
					Val=1
					Type='dword'
				}
			}
			'HKCU:\SOFTWARE\Microsoft\Input\TIPC'=@{
				'Enabled'=@{
					Val=0
					Type='dword'
				}
			}
			'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo'=@{
				'Enabled'=@{
					Val=0
					Type='dword'
				}
			}
			'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost'=@{
				'EnableWebContentEvaluation'=@{
					Val=0
					Type='dword'
				}
			}
			'HKCU:\SOFTWARE\Microsoft\Personalization\Settings'=@{
				'AcceptedPrivacyPolicy'=@{
					Val=0
					Type='dword'
				}
			}
			'HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore'=@{
				'HarvestContacts'=@{
					Val=0
					Type='dword'
				}
			}
			'HKCU:\SOFTWARE\Microsoft\InputPersonalization'=@{
				'RestrictImplicitInkCollection'=@{
					Val=1
					Type='dword'
				}
				'RestrictImplicitTextCollection'=@{
					Val=1
					Type='dword'
				}
			}
			'HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main'=@{
				'DoNotTrack'=@{
					Val=1
					Type='dword'
				}
			}
			'HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\User\Default\SearchScopes'=@{
				'ShowSearchSuggestionsGlobal'=@{
					Val=0
					Type='dword'
				}
			}
			'HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\FlipAhead'=@{
				'FPEnabled'=@{
					Val=0
					Type='dword'
				}
			}
			'HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter'=@{
				'EnabledV9'=@{
					Val=0
					Type='dword'
				}
			}
			'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled'=@{
				'Type'=@{
					Val='LooselyCoupled'
					Type='string'
				}
				'Value'=@{
					Val='Deny'
					Type='string'
				}
				'InitialAppValue'=@{
					Val='Unspecified'
					Type='string'
				}
			}
		},
		$SetForAllUsers,
		#Apply UI Tweaks
		@{
			'HKCU:\Control Panel\Accessibility\StickyKeys'=@{
				'Flags'=@{
					Val=506
					Type='dword'
				}
			}
			'HKCU:\Control Panel\Accessibility\Keyboard Response'=@{
				'Flags'=@{
					Val=122
					Type='dword'
				}
			}
			'HKCU:\Control Panel\Accessibility\ToggleKeys'=@{
				'Flags'=@{
					Val=58
					Type='dword'
				}
			}
			'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced'=@{
				'Hidden'=@{
					Val=1
					Type='dword'
				}
				'HideFileExt'=@{
					Val=0
					Type='dword'
				}
				'HideDrivesWithNoMedia'=@{
					Val=0
					Type='dword'
				}
				'LaunchTo'=@{
					Val=1
					Type='dword'
				}
			}
			'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize'=@{
				'AppsUseLightTheme'=@{
					Val=0
					Type='dword'
				}
			}
		},
		#Apply Anti Edge Hijack
		@{
			'HKCU:\SOFTWARE\Classes\AppX4hxtad77fbk3jkkeerkrm0ze94wjf3s9'=@{
				'NoOpenWith'=@{
					Val=''
					Type='String'
				}
				'NoStaticDefaultVerb'=@{
					Val=''
					Type='String'
				}
			}
			'HKCU:\SOFTWARE\Classes\AppXd4nrz8ff68srnhf9t5a8sbjyar1cr723'=@{
				'NoOpenWith'=@{
					Val=''
					Type='String'
				}
				'NoStaticDefaultVerb'=@{
					Val=''
					Type='String'
				}
			}
		}
	) | % { $_ | Install-RegistryTweaks -Verbose }
}

if ($Selector -in @('Machine','Both')){
	#Bootstrap Chocolatey & Basic Software
	$packages = @(
		'notepadplusplus',
		'adobeair',
		'foxitreader',
		'googlechrome',
		'javaruntime',
		'7zip',
		'dotnet4.7.1',
		'powershell'
	)

	Write-Verbose "Setting up Chocolatey software package manager"
	#Get-PackageProvider -Name chocolatey -Force
	iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
	choco feature enable -n=useFipsCompliantChecksums
	choco feature enable -n=allowGlobalConfirmation 

	Write-Verbose "Installing Packages"
	#Install-Package -Name $packages -Force -ProviderName chocolatey
	choco install $packages


	

	Write-Verbose "Adding telemetry ips to firewall"
	[string[]]$ips = @(
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
	New-NetFirewallRule -DisplayName "Block Telemetry IPs" -Direction Outbound -Action Block -RemoteAddress ($ips)

	#Disable Bad Tasks
	$tasks = @(
		"\Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319",
		"\Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 64",
		"\Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 64 Critical",
		"\Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 Critical",
		"\Microsoft\Windows\AppID\SmartScreenSpecific",
		"\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
		"\Microsoft\Windows\Application Experience\ProgramDataUpdater",
		"\Microsoft\Windows\Autochk\Proxy",
		"\Microsoft\Windows\CloudExperienceHost\CreateObjectTask",
		"\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
		"\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask",
		"\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
		"\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector",
		"\Microsoft\Windows\Feedback\Siuf\DmClient",
		"\Microsoft\Windows\Mobile Broadband Accounts\MNO Metadata Parser"
	)

	foreach ($task in $tasks) {
		$parts = $task.split('\')
		$name = $parts[-1]
		$path = $parts[0..($parts.length-2)] -join '\'

		Disable-ScheduledTask -TaskName "$name" -TaskPath "$path" -ErrorAction SilentlyContinue
	}

	#Disable Bad Services
	$services = @(
		"diagnosticshub.standardcollector.service" # Microsoft (R) Diagnostics Hub Standard Collector Service
		"DiagTrack"                                # Diagnostics Tracking Service
		"HomeGroupListener"                        # HomeGroup Listener
		"HomeGroupProvider"                        # HomeGroup Provider
		"lfsvc"                                    # Geolocation Service
		"MapsBroker"                               # Downloaded Maps Manager
		"WMPNetworkSvc"                            # Windows Media Player Network Sharing Service
		"XblAuthManager"                           # Xbox Live Auth Manager
		"XblGameSave"                              # Xbox Live Game Save Service
		"XboxNetApiSvc"                            # Xbox Live Networking Service
	)

	foreach ($service in $services) {
		write-verbose "Trying to disable $service"
		Get-Service -Name $service | Set-Service -StartupType Disabled -ErrorAction SilentlyContinue
	}

	write-verbose "Uninstalling default apps"
	$apps = @(
		# default Windows 10 apps
			"Microsoft.3DBuilder"
			"Microsoft.Appconnector"
			"Microsoft.BingFinance"
			"Microsoft.BingNews"
			"Microsoft.BingSports"
			#"Microsoft.BingWeather"
			"Microsoft.Getstarted"
			"Microsoft.MicrosoftOfficeHub"
			"Microsoft.MicrosoftSolitaireCollection"
			"Microsoft.Office.OneNote"
			#"Microsoft.OneConnect"
			"Microsoft.People"
			"Microsoft.SkypeApp"
			#"Microsoft.WindowsCamera"
			"Microsoft.WindowsMaps"
			"Microsoft.WindowsPhone"
			#"Microsoft.WindowsStore"
			"Microsoft.XboxApp"
			"Microsoft.ZuneMusic"
			"Microsoft.ZuneVideo"
			"microsoft.windowscommunicationsapps"
			"Microsoft.MinecraftUWP"

		# Threshold 2 apps
			"Microsoft.CommsPhone"
			"Microsoft.ConnectivityStore"
			"Microsoft.Messaging"
			"Microsoft.Office.Sway"
			"Microsoft.OneConnect"
			"Microsoft.WindowsFeedbackHub"

		#Redstone apps
			"Microsoft.BingFoodAndDrink"
			"Microsoft.BingTravel"
			"Microsoft.BingHealthAndFitness"
			"Microsoft.WindowsReadingList"

		# non-Microsoft
			"9E2F88E3.Twitter"
			"PandoraMediaInc.29680B314EFC2"
			"Flipboard.Flipboard"
			"ShazamEntertainmentLtd.Shazam"
			"king.com.CandyCrushSaga"
			"king.com.CandyCrushSodaSaga"
			"king.com.*"
			"ClearChannelRadioDigital.iHeartRadio"
			"4DF9E0F8.Netflix"
			"6Wunderkinder.Wunderlist"
			"Drawboard.DrawboardPDF"
			"2FE3CB00.PicsArt-PhotoStudio"
			"D52A8D61.FarmVille2CountryEscape"
			"TuneIn.TuneInRadio"
			"GAMELOFTSA.Asphalt8Airborne"
			"DB6EA5DB.CyberLinkMediaSuiteEssentials"
			"Facebook.Facebook"
			"flaregamesGmbH.RoyalRevolt2"
			"Playtika.CaesarsSlotsFreeCasino"
	)

	foreach ($app in $apps) {
		write-verbose "Trying to remove $app"

		Get-AppxPackage -Name $app -AllUsers | Remove-AppxPackage

		Get-AppXProvisionedPackage -Online |
			where DisplayName -EQ $app |
			Remove-AppxProvisionedPackage -Online
	}

	#Remove annoying redundant UI objects
	$BaseKeys = @(
		'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\',
		'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\'
	)

	$FolderKeys = @(
		#Desktop
			'{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}',
		#Documents
			'{A8CDFF1C-4878-43be-B5FD-F8091C1C60D0}',
			'{d3162b92-9365-467a-956b-92703aca08af}',
		#Downloads
			'{374DE290-123F-4565-9164-39C4925E467B}',
			'{088e3905-0323-4b02-9826-5d99428e115f}',
		#Music
			'{1CF1260C-4DD0-4ebb-811F-33C572699FDE}',
			'{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}',
		#Pictures
			'{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}',
			'{24ad3ad4-a569-4530-98e1-ab02f9417aa8}',
		#Videos
			'{A0953C92-50DC-43bf-BE83-3742FED03C9C}',
			'{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}',
		#3D Objects
			'{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}'
	)

	$BaseKeys | %{
		$ThisKey = $_
		$FolderKeys | %{
			Remove-Item -Path "$(-join($ThisKey,$_))" -ErrorAction SilentlyContinue
		}
	}
	
	#Apply Reg Packs
	@(
		@{
			'HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\features'=@{
				'WiFiSenseCredShared'=@{
					Val=0
					Type='int'
				}
				'WiFiSenseOpen'=@{
					Val=0
					Type='int'
				}
			}
		},
		@{
			'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Cloud Content'=@{
				'DisableWindowsConsumerFeatures'=@{
					Val=1
					Type='int'
				}
			}
		},
		@{
			'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization'=@{
				'DODownloadMode'=@{
					Val=0
					Type='int'
				}
			}
		},
		#Block Telemetry
		@{
			'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'=@{
				'AllowTelemetry'=@{
					Val=0
					Type='int'
				}
			}
		},
		@{
			'HKLM:\SOFTWARE\Classes\AppX4hxtad77fbk3jkkeerkrm0ze94wjf3s9'=@{
				'NoOpenWith'=@{
					Val=''
					Type='String'
				}
				'NoStaticDefaultVerb'=@{
					Val=''
					Type='String'
				}
			}
			'HKLM:\SOFTWARE\Classes\AppXd4nrz8ff68srnhf9t5a8sbjyar1cr723'=@{
				'NoOpenWith'=@{
					Val=''
					Type='String'
				}
				'NoStaticDefaultVerb'=@{
					Val=''
					Type='String'
				}
			}
		},
		@{
			'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize'=@{
				'AppsUseLightTheme'=@{
					Val=0
					Type='int'
				}
			}
		}
	) | % { $_ | Install-RegistryTweaks -Verbose }
	
	$ScheduledJob = @{
		Name = 'ChocoUpdate'
		Trigger = New-JobTrigger -Daily -At 0:0:0 -RandomDelay ([timespan]::new(0,5,0))
		ScheduledJobOption = New-ScheduledJobOption -RunElevated -MultipleInstancePolicy StopExisting -RequireNetwork -WakeToRun
		ScriptBlock = {
			cup all -y
		}
		Credential = Get-Credential -Message "Enter Local Admin Creds"
	}

	#Get-ScheduledJob -Name $ScheduledJob.Name | Set-ScheduledJob @ScheduledJob -RunNow
	Register-ScheduledJob @ScheduledJob -ErrorAction SilentlyContinue
}

$VerbosePreference = 'SilentlyContinue'