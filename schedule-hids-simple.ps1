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

Write-Host ""
Write-Host "Setup complete! Hourly scan is now scheduled." -ForegroundColor Cyan
Write-Host ""
Write-Host "Verify with: Get-ScheduledTask | Where-Object {`$_.TaskName -like '*HIDS*'}" -ForegroundColor Yellow
