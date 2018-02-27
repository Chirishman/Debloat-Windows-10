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