# Relaunch the script if not admin
function Invoke-RequireAdmin
{
    Param(
    [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true)]
    [System.Management.Automation.InvocationInfo]
    $MyInvocation)

    if (-not (Test-IsAdmin))
    {
        # Get the script path
        $scriptPath = $MyInvocation.MyCommand.Path
        $scriptPath = Get-UNCFromPath -Path $scriptPath

        # Need to quote the paths in case of spaces
        $scriptPath = '"' + $scriptPath + '"'

        # Build base arguments for powershell.exe
        [string[]]$argList = @('-NoLogo -NoProfile', '-ExecutionPolicy Bypass', '-File', $scriptPath)

        # Add 
        $argList += $MyInvocation.BoundParameters.GetEnumerator() | Foreach {"-$($_.Key)", "$($_.Value)"}
        $argList += $MyInvocation.UnboundArguments

        try
        {    
            $process = Start-Process PowerShell.exe -PassThru -Verb Runas -Wait -WorkingDirectory $pwd -ArgumentList $argList
            exit $process.ExitCode
        }
        catch {}

        # Generic failure code
        exit 1 
    }
}