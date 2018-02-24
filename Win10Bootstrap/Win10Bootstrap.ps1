$VerbosePreference = 'Continue'

Import-Module "$PSScriptRoot\Win10BootstrapTools\Win10BootstrapTools.psd1"

$Steps  = @( Get-ChildItem -Path $PSScriptRoot\Steps\*.ps1 -ErrorAction SilentlyContinue )

$Steps | % {
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

$VerbosePreference = 'SilentlyContinue'