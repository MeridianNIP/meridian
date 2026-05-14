#Requires -RunAsAdministrator
#Requires -Version 5.1
<#
  Meridian Hyper-V VM bootstrap.

  One-shot setup: downloads the current Debian 13 netinst ISO (SHA-256 verified),
  creates a Gen 2 VM on the WSL-Bridge vSwitch, attaches the ISO, disables
  Secure Boot, and opens vmconnect so you can click through the Debian installer.

  Run from an elevated Windows PowerShell. Defaults match answers.local.env.
#>

param(
  [string] $VMName       = "meridian-vm",
  [string] $VMRoot       = "C:\VMs",
  [int]    $MemoryGB     = 4,
  [int]    $CPUCount     = 2,
  [int]    $DiskGB       = 40,
  [string] $Switch       = "WSL-Bridge",
  [int]    $DebianMajor  = 13,
  [string] $IsoUrlBase   = "https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/",
  [string] $IsoPath      = "",
  [switch] $Force,
  # Unattended mode: skip the Debian netinst ISO download and use the
  # caller-supplied preseed-injected ISO instead. Built by
  # scripts/repack-preseed-iso.sh. With this set, the VM autoboots the
  # installer with all answers preseeded — no vmconnect click-through.
  [switch] $Unattended
)

$ErrorActionPreference = "Stop"

function Info($m) { Write-Host "[INFO] $m" -ForegroundColor Cyan }
function Ok($m)   { Write-Host "[ OK ] $m" -ForegroundColor Green }
function Warn($m) { Write-Host "[WARN] $m" -ForegroundColor Yellow }

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
Info "Preflight checks"

# Hyper-V module present? (The feature may be installed but the module disabled.)
if (-not (Get-Module -ListAvailable -Name Hyper-V)) {
  throw "Hyper-V PowerShell module not available. Enable 'Hyper-V Module for Windows PowerShell' optional feature."
}
Import-Module Hyper-V -ErrorAction Stop

# vSwitch present?
$sw = Get-VMSwitch -Name $Switch -ErrorAction SilentlyContinue
if (-not $sw) {
  throw "vSwitch '$Switch' not found. Run Get-VMSwitch to list available switches."
}
Ok "vSwitch '$Switch' present ($($sw.SwitchType))"

# Existing VM collision
$existingVm = Get-VM -Name $VMName -ErrorAction SilentlyContinue
if ($existingVm) {
  if (-not $Force) {
    throw "VM '$VMName' already exists. Re-run with -Force to replace, or pick a different -VMName."
  }
  Warn "Removing existing VM '$VMName' (-Force was set)"
  if ($existingVm.State -ne 'Off') { Stop-VM -Name $VMName -TurnOff -Force }
  Remove-VM -Name $VMName -Force
}

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
$vmDir    = Join-Path $VMRoot $VMName
$vhdxPath = Join-Path $vmDir  "$VMName.vhdx"
$isoDir   = Join-Path $VMRoot "ISOs"
New-Item -Path $vmDir -ItemType Directory -Force | Out-Null
New-Item -Path $isoDir -ItemType Directory -Force | Out-Null

# If a stale VHDX from a previous failed run is lying around, clear it.
if (Test-Path $vhdxPath) {
  if (-not $Force) {
    throw "VHDX already exists at $vhdxPath. Re-run with -Force to overwrite."
  }
  Warn "Removing existing VHDX $vhdxPath"
  Remove-Item $vhdxPath -Force
}

# ---------------------------------------------------------------------------
# Download + verify the Debian netinst ISO
# ---------------------------------------------------------------------------
if ($Unattended -and -not $IsoPath) {
  throw "-Unattended requires -IsoPath pointing at a preseed-injected ISO (build it with WSL: scripts/repack-preseed-iso.sh)"
}

if (-not $IsoPath) {
  Info "Resolving current Debian $DebianMajor netinst ISO at $IsoUrlBase"
  $listing = Invoke-WebRequest -Uri $IsoUrlBase -UseBasicParsing
  $pattern = "^debian-$DebianMajor\.[\d.]+-amd64-netinst\.iso$"
  $isoName = ($listing.Links |
              Where-Object { $_.href -match $pattern } |
              Select-Object -First 1).href
  if (-not $isoName) {
    throw "No ISO matching $pattern in $IsoUrlBase (has Debian $DebianMajor been superseded?)"
  }
  $IsoPath = Join-Path $isoDir $isoName
  Ok "Target ISO: $isoName"

  if (-not (Test-Path $IsoPath)) {
    Info "Downloading $isoName (this is ~630 MB, uses BITS for resume support)"
    try {
      Start-BitsTransfer -Source ($IsoUrlBase + $isoName) -Destination $IsoPath -ErrorAction Stop
    } catch {
      Warn "BITS transfer failed ($_); falling back to Invoke-WebRequest"
      Invoke-WebRequest -Uri ($IsoUrlBase + $isoName) -OutFile $IsoPath -UseBasicParsing
    }
    Ok "ISO downloaded to $IsoPath"
  } else {
    Info "ISO already present at $IsoPath -- skipping download"
  }

  # Verify SHA-256 against the mirror's SHA256SUMS file.
  Info "Verifying SHA-256"
  $sumsFile = Join-Path $isoDir "SHA256SUMS.$DebianMajor"
  Invoke-WebRequest -Uri ($IsoUrlBase + "SHA256SUMS") -OutFile $sumsFile -UseBasicParsing
  $expectedLine = (Get-Content $sumsFile | Where-Object { $_ -match "\s$([regex]::Escape($isoName))\s*$" }) |
                  Select-Object -First 1
  if (-not $expectedLine) {
    throw "$isoName not listed in SHA256SUMS -- refusing to proceed without a checksum to match."
  }
  $expected = ($expectedLine -split '\s+')[0].ToLower()
  $actual   = (Get-FileHash -Algorithm SHA256 -Path $IsoPath).Hash.ToLower()
  if ($expected -ne $actual) {
    Remove-Item $IsoPath -Force
    throw "SHA-256 mismatch. expected=$expected actual=$actual. ISO deleted -- rerun to redownload."
  }
  Ok "SHA-256 verified"
} else {
  if (-not (Test-Path $IsoPath)) {
    throw "ISO path supplied but not found: $IsoPath"
  }
  Ok "Using caller-supplied ISO: $IsoPath"
}

# ---------------------------------------------------------------------------
# Create the VHDX and the VM
# ---------------------------------------------------------------------------
Info "Creating $DiskGB GB dynamic VHDX at $vhdxPath"
New-VHD -Path $vhdxPath -SizeBytes ($DiskGB * 1GB) -Dynamic | Out-Null

Info "Creating Gen 2 VM '$VMName' - ${MemoryGB} GB RAM - $CPUCount vCPU - switch=$Switch"
New-VM -Name $VMName `
       -Generation 2 `
       -MemoryStartupBytes ($MemoryGB * 1GB) `
       -VHDPath $vhdxPath `
       -SwitchName $Switch `
       -Path $vmDir | Out-Null

# Fixed RAM (dynamic memory interacts badly with Debian's slow memory ballooning
# during install). CPU count set separately -- New-VM doesn't take it directly.
Set-VMMemory    -VMName $VMName -DynamicMemoryEnabled $false
Set-VMProcessor -VMName $VMName -Count $CPUCount
Set-VM          -VMName $VMName `
                -AutomaticStartAction Nothing `
                -AutomaticStopAction Shutdown `
                -CheckpointType Disabled

# Mount the ISO as a DVD drive and set boot order (DVD first for installer).
Add-VMDvdDrive -VMName $VMName -Path $IsoPath
$dvd = Get-VMDvdDrive      -VMName $VMName
$hd  = Get-VMHardDiskDrive -VMName $VMName

# Secure Boot off: Debian's shim isn't signed by the MS UEFI CA template
# that Hyper-V applies by default. Turning it off avoids the "Boot failed,
# no bootable device" dead-end that otherwise trips every Debian install here.
Set-VMFirmware -VMName $VMName -EnableSecureBoot Off
Set-VMFirmware -VMName $VMName -BootOrder $dvd, $hd

Ok "VM '$VMName' created"

# ---------------------------------------------------------------------------
# Start + open console
# ---------------------------------------------------------------------------
Info "Starting VM and opening vmconnect..."
Start-VM -Name $VMName
Start-Process vmconnect.exe -ArgumentList "localhost", $VMName

Write-Host ""
if ($Unattended) {
  Ok "Done. Unattended Debian install is booting in the vmconnect window."
  Write-Host ""
  Write-Host "Hands-off path:" -ForegroundColor Cyan
  Write-Host "  - The preseed ISO autoboots the installer with all answers."
  Write-Host "  - Expect ~10 minutes to first SSH-able boot. No interaction needed."
  Write-Host "  - Watch progress in the vmconnect window if you're curious; close it any time."
  Write-Host "  - The 'admin' user is created with password 'meridiannip'."
  Write-Host "  - If you set MERIDIAN_AUTHORIZED_KEY before building the ISO,"
  Write-Host "    that key is also authorized; otherwise password-only login."
  Write-Host ""
  Write-Host "Next (once the VM reboots out of the installer):" -ForegroundColor Cyan
  Write-Host "  ssh admin@<vm-dhcp-ip>    # password: meridiannip (or your key)"
  Write-Host "  rsync -az ./meridian/ admin@<vm-dhcp-ip>:~/meridian/"
  Write-Host "  ssh admin@<vm-dhcp-ip>"
  Write-Host "    sudo rm -rf /opt/meridian; sudo mv ~/meridian /opt/meridian"
  Write-Host "    sudo chown -R root:root /opt/meridian; sudo chmod 0755 /opt/meridian"
  Write-Host "    sudo /opt/meridian/install.sh --unattended --config /opt/meridian/answers.local.env"
  Write-Host ""
  Write-Host "(copy answers.example.env to answers.local.env and edit before running install.sh)"
} else {
  Ok "Done. Debian installer is booting in the vmconnect window."
  Write-Host ""
  Write-Host "Click-through cheat sheet:" -ForegroundColor Cyan
  Write-Host "  - Choose: Graphical Install (or regular Install)"
  Write-Host "  - Hostname:     meridiannip"
  Write-Host "  - Domain:       meridian.local"
  Write-Host "  - Root pw:      (your choice)"
  Write-Host "  - User account: admin  (sudo-capable; install.sh detects via SUDO_USER)"
  Write-Host "  - Partition:    Guided - use entire disk  ->  All files in one partition"
  Write-Host "  - Mirror:       accept defaults"
  Write-Host "  - Tasks:        UNSELECT 'Debian desktop environment'"
  Write-Host "                  SELECT   'SSH server' and 'standard system utilities'"
  Write-Host "  - After reboot, log in and note the DHCP address it picked up."
  Write-Host ""
  Write-Host "Next (once Debian is up):" -ForegroundColor Cyan
  Write-Host "  rsync -az ./meridian/ admin@<vm-dhcp-ip>:~/meridian/"
  Write-Host "  ssh admin@<vm-dhcp-ip>"
  Write-Host "    sudo rm -rf /opt/meridian; sudo mv ~/meridian /opt/meridian"
  Write-Host "    sudo chown -R root:root /opt/meridian; sudo chmod 0755 /opt/meridian"
  Write-Host "    sudo /opt/meridian/install.sh --unattended --config /opt/meridian/answers.local.env"
  Write-Host ""
  Write-Host "Add to your hosts file / LAN DNS:"
  Write-Host "  192.168.50.240   meridiannip.meridian.local"
}
