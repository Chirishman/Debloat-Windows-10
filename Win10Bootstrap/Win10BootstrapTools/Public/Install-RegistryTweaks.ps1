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