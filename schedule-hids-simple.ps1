# Simple PowerShell script to schedule HIDS tasks (run as current user)
# PowerShell -ExecutionPolicy Bypass -File schedule-hids-simple.ps1

$ProjectPath = "C:\Users\musta\Desktop\HIDS_project"
$BashPath = "bash.exe"

# Task 1: Hourly HIDS scan and ELK shipping
$Task1Name = "HIDS-Hourly-Scan"
$Task1Trigger = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Hours 1) -RepetitionDuration (New-TimeSpan -Days 3650) -At (Get-Date) -Once
$Task1Cmd = "cd $ProjectPath; export EMAIL_TO='mustafasyed82@gmail.com' SMTP_USER='mustafasyed82@gmail.com' SMTP_PASS='sklg fhwo zyzl xdzp' SMTP_SERVER='smtp.gmail.com:587' ELASTIC_URL='https://my-elasticsearch-project-d17947.es.europe-west1.gcp.elastic.cloud:443' ELASTIC_API_KEY='RDRQV1I2QUJzVDlOMmpMU3NIbkE6dkZKaEd2TmRSSjkwVUdhaUtJVkxlQQ=='; bash HIDS.sh --ship-elk; bash send_email_report.sh --hourly"
$Task1Action = New-ScheduledTaskAction `
  -Execute $BashPath `
  -Argument "-c '$Task1Cmd'" `
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

# Task 2: Instant alerts (runs a real scan every minute so alerts fire immediately on detection)
$Task2Name = "HIDS-Instant-Alerts"
$Task2Trigger = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Minutes 1) -RepetitionDuration (New-TimeSpan -Days 3650) -At (Get-Date) -Once
$Task2Cmd = "cd $ProjectPath; export EMAIL_TO='mustafasyed82@gmail.com' SMTP_USER='mustafasyed82@gmail.com' SMTP_PASS='sklg fhwo zyzl xdzp' SMTP_SERVER='smtp.gmail.com:587'; bash HIDS.sh --instant-check"
$Task2Action = New-ScheduledTaskAction `
  -Execute $BashPath `
  -Argument "-c '$Task2Cmd'" `
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
