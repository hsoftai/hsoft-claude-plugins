<#
  sandbox-dlp-setup.ps1 — installs the Windows kernel-DLP stack for secrets-guard:
    1. WinFsp (signed file-system driver, https://winfsp.dev)
    2. sandbox-dlp.exe (our user-mode provider service)
    3. a per-user logon Scheduled Task that runs `sandbox-dlp serve`

  Run elevated (the secrets-guard trigger launches it via Start-Process -Verb RunAs).
  This is a SCAFFOLD — fill the TODOs and code-sign before distributing. The production
  path should ship a signed MSI instead of a downloaded .ps1; this script documents the
  exact steps an MSI would perform.

  Idempotent: re-running upgrades the binary and re-registers the task.
#>

[CmdletBinding()]
param(
  # Base URL the assets are fetched from (mirror for air-gapped installs).
  [string]$AssetBase = "https://github.com/hsoftai/hsoft-claude-plugins/releases/latest/download",
  # Where sandbox-dlp.exe is installed.
  [string]$InstallDir = (Join-Path $env:LOCALAPPDATA "secrets-guard\sandbox-dlp")
)

$ErrorActionPreference = "Stop"

function Step($m) { Write-Host "[sandbox-dlp] $m" }

# --- 1. WinFsp ---------------------------------------------------------------------
# Detect WinFsp via its install registry key / the well-known DLL.
$winfspDll = Join-Path ${env:ProgramFiles(x86)} "WinFsp\bin\winfsp-x64.dll"
if (-not (Test-Path $winfspDll)) {
  Step "WinFsp not found — installing"
  # TODO: pin a specific WinFsp version + verify its signature/hash.
  $winfspMsi = Join-Path $env:TEMP "winfsp.msi"
  Invoke-WebRequest -Uri "https://github.com/winfsp/winfsp/releases/latest/download/winfsp-x64.msi" -OutFile $winfspMsi
  Start-Process msiexec.exe -ArgumentList "/i `"$winfspMsi`" /qn" -Wait
} else {
  Step "WinFsp already installed"
}

# --- 2. sandbox-dlp.exe ------------------------------------------------------------
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
$exe = Join-Path $InstallDir "sandbox-dlp.exe"
Step "Installing sandbox-dlp.exe to $exe"
# TODO: fetch the signed, WinFsp-enabled build (go build -tags sandboxdlp ./cmd/sandbox-dlp)
#       and VERIFY its Authenticode signature before writing it.
Invoke-WebRequest -Uri "$AssetBase/sandbox-dlp-windows-amd64.exe" -OutFile $exe

# --- 3. per-user logon task -------------------------------------------------------
# A per-user Scheduled Task at logon avoids needing a system service; the provider runs
# as the user (least privilege) and only its owner can reach its named pipe.
$taskName = "secrets-guard sandbox-dlp"
Step "Registering logon task '$taskName'"
$action  = New-ScheduledTaskAction -Execute $exe -Argument "serve"
$trigger = New-ScheduledTaskTrigger -AtLogOn
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Force | Out-Null

# Start it now so the user need not log out/in.
Step "Starting the service"
Start-ScheduledTask -TaskName $taskName

Step "Done. Verify with: secrets-guard dlp-status"
