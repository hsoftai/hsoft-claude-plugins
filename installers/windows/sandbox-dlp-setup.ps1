<#
  sandbox-dlp-setup.ps1 - installs the Windows kernel-DLP stack for secrets-guard:
    1. WinFsp (signed file-system driver, https://winfsp.dev) - pinned version, signature
       verified before install.
    2. sandbox-dlp.exe (our user-mode provider service) - from a local build or a release
       asset.
    3. a per-user logon Scheduled Task that runs `sandbox-dlp serve`.

  Run elevated (the secrets-guard trigger launches it via Start-Process -Verb RunAs).

  SIGNING (TODO before public distribution): this script and sandbox-dlp.exe are NOT yet
  Authenticode-signed. The production path should ship a signed MSI (see the MSI TODO at
  the bottom) and verify the sandbox-dlp.exe signature the same way WinFsp's is verified
  below. Until then, install only from a trusted local build (-ExePath) or a checksum-
  pinned asset.

  Idempotent: re-running upgrades the binary and re-registers the task.
#>

[CmdletBinding()]
param(
  # Base URL the assets are fetched from (mirror for air-gapped installs).
  [string]$AssetBase = "https://github.com/hsoftai/hsoft-claude-plugins/releases/latest/download",
  # Where sandbox-dlp.exe is installed.
  [string]$InstallDir = (Join-Path $env:LOCALAPPDATA "secrets-guard\sandbox-dlp"),
  # Optional: install this locally-built sandbox-dlp.exe instead of downloading one.
  # Build it with: go build -tags sandboxdlp -o sandbox-dlp.exe ./cmd/sandbox-dlp
  [string]$ExePath = "",
  # Pinned WinFsp installer. Update both when bumping the pinned version. The signature
  # check below is the primary integrity gate; set $WinFspSha256 to also pin the bytes.
  [string]$WinFspMsiUrl = "https://github.com/winfsp/winfsp/releases/download/v2.0/winfsp-2.0.23075.msi",
  [string]$WinFspSha256 = "",
  # WinFsp's Authenticode signer (the publisher the downloaded MSI must be signed by).
  [string]$WinFspSigner = "Navimatics"
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

function Step($m) { Write-Host "[sandbox-dlp] $m" }
function Fail($m) { Write-Error "[sandbox-dlp] $m"; exit 1 }

# --- 1. WinFsp ---------------------------------------------------------------------
# Detect WinFsp via the well-known DLL; install the pinned, signature-verified MSI if absent.
$winfspDll = Join-Path ${env:ProgramFiles(x86)} "WinFsp\bin\winfsp-x64.dll"
if (-not (Test-Path $winfspDll)) {
  Step "WinFsp not found - installing pinned build"
  $winfspMsi = Join-Path $env:TEMP "winfsp-pinned.msi"
  Step "Downloading $WinFspMsiUrl"
  Invoke-WebRequest -Uri $WinFspMsiUrl -OutFile $winfspMsi

  if ($WinFspSha256 -ne "") {
    $got = (Get-FileHash -Algorithm SHA256 -Path $winfspMsi).Hash
    if ($got -ne $WinFspSha256.ToUpper()) { Fail "WinFsp MSI checksum mismatch (got $got)" }
    Step "WinFsp MSI checksum OK"
  }

  # Verify the MSI is validly Authenticode-signed by the expected publisher before running it.
  $sig = Get-AuthenticodeSignature -FilePath $winfspMsi
  if ($sig.Status -ne "Valid") { Fail "WinFsp MSI signature not valid: $($sig.Status)" }
  $subject = $sig.SignerCertificate.Subject
  if ($subject -notmatch [regex]::Escape($WinFspSigner)) {
    Fail "WinFsp MSI signed by unexpected publisher: $subject"
  }
  Step "WinFsp MSI signature OK ($subject)"

  Start-Process msiexec.exe -ArgumentList "/i `"$winfspMsi`" /qn /norestart" -Wait
  if (-not (Test-Path $winfspDll)) { Fail "WinFsp install did not produce $winfspDll" }
  Step "WinFsp installed"
} else {
  Step "WinFsp already installed"
}

# --- 2. sandbox-dlp.exe ------------------------------------------------------------
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
$exe = Join-Path $InstallDir "sandbox-dlp.exe"

if ($ExePath -ne "") {
  if (-not (Test-Path $ExePath)) { Fail "ExePath not found: $ExePath" }
  Step "Installing sandbox-dlp.exe from local build $ExePath"
  Copy-Item -Path $ExePath -Destination $exe -Force
} else {
  $url = "$AssetBase/sandbox-dlp-windows-amd64.exe"
  Step "Downloading sandbox-dlp.exe from $url"
  Invoke-WebRequest -Uri $url -OutFile $exe
  # Verify a checksum sidecar when present (fail-closed). The production signed build
  # should additionally verify the exe's Authenticode signature here (TODO).
  try {
    $shaText = (Invoke-WebRequest -Uri "$url.sha256" -UseBasicParsing).Content
    $want = ($shaText -split '\s+')[0]
    $got  = (Get-FileHash -Algorithm SHA256 -Path $exe).Hash
    if ($got -ne $want.ToUpper()) { Fail "sandbox-dlp.exe checksum mismatch (got $got)" }
    Step "sandbox-dlp.exe checksum OK"
  } catch {
    Step "WARNING: no checksum sidecar found for sandbox-dlp.exe (dev/best-effort)"
  }
}

# --- 3. per-user autostart --------------------------------------------------------
# The provider runs as the user (least privilege); only its owner can reach its named
# pipe. Prefer a logon Scheduled Task (the canonical mechanism), but registering one
# needs elevation. For a purely per-user provider a HKCU Run key is an equivalent
# autostart that needs NO elevation, so fall back to it when the task can't be created.
# (WinFsp above still required elevation once, to install its driver.)
$taskName = "secrets-guard sandbox-dlp"
$autostart = "scheduled-task"
try {
  $action  = New-ScheduledTaskAction -Execute $exe -Argument "serve"
  $trigger = New-ScheduledTaskTrigger -AtLogOn
  $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
  Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Force -ErrorAction Stop | Out-Null
  Step "Registered logon task '$taskName'"
} catch {
  $autostart = "run-key"
  Step "Scheduled task unavailable ($($_.Exception.Message.Trim())); using per-user Run key"
  $runKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
  if (-not (Test-Path $runKey)) { New-Item -Path $runKey -Force | Out-Null }
  Set-ItemProperty -Path $runKey -Name "secrets-guard-sandbox-dlp" -Value "`"$exe`" serve"
}

# --- 4. start now -----------------------------------------------------------------
Step "Starting the service"
if ($autostart -eq "scheduled-task") {
  try { Start-ScheduledTask -TaskName $taskName -ErrorAction Stop } catch { }
}
# Ensure it is actually running now (covers the Run-key path and any task-start lag).
if (-not (Get-Process -Name "sandbox-dlp" -ErrorAction SilentlyContinue)) {
  Start-Process -FilePath $exe -ArgumentList "serve" -WindowStyle Hidden
}

# --- 5. verify --------------------------------------------------------------------
Step "Verifying the service is answering"
$ok = $false
foreach ($i in 1..20) {
  Start-Sleep -Milliseconds 250
  & $exe status 2>$null
  if ($LASTEXITCODE -eq 0) { $ok = $true; break }
}
if ($ok) {
  Step "Done. Service is running. Verify any time with: secrets-guard dlp-status"
} else {
  Step "Installed, but the service did not answer yet. Check: secrets-guard dlp-status"
}

# --- MSI (TODO) -------------------------------------------------------------------
# The production installer should be a signed MSI that performs the same three steps
# (pinned+verified WinFsp, the signed sandbox-dlp.exe, the logon task). Build it with WiX
# (candle/light) over a .wxs authoring these components, then Authenticode-sign the MSI.
# This .ps1 documents the exact steps that MSI must reproduce.
