#   Description:
# This script will use Windows package manager to bootstrap Chocolatey and
# install a list of packages. Script will also install Sysinternals Utilities
# into your default drive's root directory.

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