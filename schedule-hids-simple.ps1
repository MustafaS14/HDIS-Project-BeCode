# Simple PowerShell script to schedule HIDS tasks (run as current user)
# PowerShell -ExecutionPolicy Bypass -File schedule-hids-simple.ps1

$ProjectPath = "C:\Users\musta\Desktop\HIDS_project"
$BashPath = "bash.exe"
# bash's `cd` cannot parse a Windows-style backslash path; translate it to the WSL /mnt/c equivalent for use inside bash -c.
$WslProjectPath = "/mnt/c/" + ($ProjectPath.Substring(3) -replace '\\', '/')

# Task 1: Hourly HIDS scan, ELK shipping, and email report.
$Task1Name = "HIDS-Hourly-Scan"
$Task1Trigger = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Hours 1) -RepetitionDuration (New-TimeSpan -Days 3650) -At (Get-Date) -Once
$Task1Cmd = "cd $WslProjectPath; . ./email_config.env; bash HIDS.sh --ship-elk"
$Task1Action = New-ScheduledTaskAction `
  -Execute $BashPath `
  -Argument "-c `"$Task1Cmd`"" `
  -WorkingDirectory $ProjectPath

$Task1Settings = New-ScheduledTaskSettingsSet `
  -AllowStartIfOnBatteries `
  -DontStopIfGoingOnBatteries `
  -RunOnlyIfNetworkAvailable

try {
  Register-ScheduledTask -TaskName $Task1Name -Action $Task1Action -Trigger $Task1Trigger -Settings $Task1Settings -Force | Out-Null
  Write-Host "✓ Task 'HIDS-Hourly-Scan' created" -ForegroundColor Green
} catch {
  Write-Host "✗ Failed: $_" -ForegroundColor Red
}

# Task 2: Instant alerts (runs a real scan every minute so alerts fire immediately on detection).
$Task2Name = "HIDS-Instant-Alerts"
$Task2Trigger = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Minutes 1) -RepetitionDuration (New-TimeSpan -Days 3650) -At (Get-Date) -Once
$Task2Cmd = "cd $WslProjectPath; . ./email_config.env; bash HIDS.sh --instant-check"
$Task2Action = New-ScheduledTaskAction `
  -Execute $BashPath `
  -Argument "-c `"$Task2Cmd`"" `
  -WorkingDirectory $ProjectPath

$Task2Settings = New-ScheduledTaskSettingsSet `
  -AllowStartIfOnBatteries `
  -DontStopIfGoingOnBatteries `
  -RunOnlyIfNetworkAvailable

try {
  Register-ScheduledTask -TaskName $Task2Name -Action $Task2Action -Trigger $Task2Trigger -Settings $Task2Settings -Force | Out-Null
  Write-Host "✓ Task 'HIDS-Instant-Alerts' created" -ForegroundColor Green
} catch {
  Write-Host "✗ Failed: $_" -ForegroundColor Red
}

Write-Host ""
Write-Host "Setup complete! Tasks are now scheduled." -ForegroundColor Cyan
Write-Host ""
Write-Host "Verify with: Get-ScheduledTask | Where-Object {`$_.TaskName -like '*HIDS*'}" -ForegroundColor Yellow
