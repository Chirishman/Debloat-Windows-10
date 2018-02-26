$VerbosePreference = 'Continue'

#Import-Module "$PSScriptRoot\Win10BootstrapTools\Win10BootstrapTools.psd1"

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