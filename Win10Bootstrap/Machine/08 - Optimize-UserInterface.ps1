#   Description
# This script will disable some accessibility features regarding keyboard input.
# Additionaly it will set some visibility/UI elements will be changed.

write-verbose "Elevating priviledges for this process"
do {} until (Elevate-Privileges SeTakeOwnershipPrivilege)

Import-PowerShellDataFile -Path "$PSScriptRoot\..\RegFixes\LocalMachine\UITweaks.psd1" | Install-RegistryTweaks -Verbose

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
		Remove-Item -Path "$(-join($ThisKey,$_))"
	}
}