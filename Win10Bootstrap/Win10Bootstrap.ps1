Param(
	[ValidateSet('User','Machine','Both')][string]$Selector = 'Both'
)

$VerbosePreference = 'Continue'

Import-Module "$PSScriptRoot\Win10BootstrapTools\Win10BootstrapTools.psd1"

<#
$Tools = @( Get-ChildItem -Path "$PSScriptRoot\Win10BootstrapTools\Public\*.ps1" -ErrorAction SilentlyContinue )

$Tools | % {
    Try
    {
        Write-Verbose -Message "Dot Sourcing $($_.fullname)"
        . $_.fullname
    }
    Catch
    {
        Write-Error -Message "Failed to dot source $($_.fullname): $_"
    }
}
#>

if ($Selector -in @('User','Both')){
	@( Get-ChildItem -Path $PSScriptRoot\User\*.ps1 -ErrorAction SilentlyContinue ) | % {
		Try
		{
			Write-Verbose -Message "Executing $($_.fullname)"
			. $_.fullname
		}
		Catch
		{
			Write-Error -Message "Failed to execute step $($_.fullname): $_"
		}
	}
}

if ($Selector -in @('Machine','Both')){
	@( Get-ChildItem -Path $PSScriptRoot\Machine\*.ps1 -ErrorAction SilentlyContinue )| % {
		Try
		{
			Write-Verbose -Message "Executing $($_.fullname)"
			. $_.fullname
		}
		Catch
		{
			Write-Error -Message "Failed to execute step $($_.fullname): $_"
		}
	}
}

$VerbosePreference = 'SilentlyContinue'