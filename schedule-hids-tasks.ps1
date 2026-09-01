# PowerShell script to schedule HIDS hourly scans and email reports on Windows
# Run as Administrator: powershell -ExecutionPolicy Bypass -File schedule-hids-tasks.ps1

# Define variables
$ProjectPath = "C:\Users\musta\Desktop\HIDS_project"
$BashPath = "bash.exe"
# bash's `cd` cannot parse a Windows-style backslash path; translate it to the WSL /mnt/c equivalent for use inside bash -c.
$WslProjectPath = "/mnt/c/" + ($ProjectPath.Substring(3) -replace '\\', '/')
$EnvVars = ". ./email_config.env;"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "HIDS Task Scheduler Setup" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-not $isAdmin) {
  Write-Host "WARNING: Run as Administrator for full functionality" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Creating Task 1: HIDS Hourly Scan and ELK Ship..." -ForegroundColor Green

# Task 1: Hourly HIDS scan and ELK shipping (with hourly email report)
$Task1Name = "HIDS-Hourly-Scan"
$Task1Trigger = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Hours 1) -RepetitionDuration (New-TimeSpan -Days 3650) -At (Get-Date) -Once
$Task1Action = New-ScheduledTaskAction `
  -Execute $BashPath `
  -Argument "-c `"cd $WslProjectPath && $EnvVars bash HIDS.sh --ship-elk`"" `
  -WorkingDirectory $ProjectPath

$Task1Settings = New-ScheduledTaskSettingsSet `
  -AllowStartIfOnBatteries `
  -DontStopIfGoingOnBatteries `
  -RunOnlyIfNetworkAvailable `
  -StartWhenAvailable

$Task1Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

try {
  Register-ScheduledTask `
    -TaskName $Task1Name `
    -Action $Task1Action `
    -Trigger $Task1Trigger `
    -Settings $Task1Settings `
    -Principal $Task1Principal `
    -Force | Out-Null
  Write-Host "Task '$Task1Name' created successfully" -ForegroundColor Green
  Write-Host "  Runs: Every 1 hour" -ForegroundColor Green
  Write-Host "  Action: HIDS scan + ELK ship + hourly email report" -ForegroundColor Green
} catch {
  Write-Host "Failed to create $Task1Name : $_" -ForegroundColor Red
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Setup Complete!" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Summary:" -ForegroundColor Yellow
Write-Host "  1. HIDS-Hourly-Scan     - Runs every 1 hour" -ForegroundColor White
Write-Host ""
Write-Host "To verify tasks:" -ForegroundColor Yellow
Write-Host "  Get-ScheduledTask | Where-Object {`$_.TaskName -like '*HIDS*'}" -ForegroundColor Cyan
