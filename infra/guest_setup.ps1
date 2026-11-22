# Guest setup for win11-detect (runs inside the VM as analyst with full admin token).
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$dl = 'C:\lab\setup'
New-Item -ItemType Directory -Force -Path 'C:\lab', 'C:\lab\sandbox', $dl | Out-Null
function Step($m) { Write-Output "=== $m" }

# --- 1. Python 3.11 at C:\Python311 + PyYAML -------------------------------
Step 'Python 3.11'
if (-not (Test-Path 'C:\Python311\python.exe')) {
    $py = "$dl\python-3.11.9-amd64.exe"
    Invoke-WebRequest 'https://www.python.org/ftp/python/3.11.9/python-3.11.9-amd64.exe' -OutFile $py
    $p = Start-Process $py -Wait -PassThru -ArgumentList '/quiet', 'InstallAllUsers=1', 'TargetDir=C:\Python311', 'PrependPath=1', 'Include_test=0', 'Include_launcher=1'
    if ($p.ExitCode -ne 0) { throw "python installer exit $($p.ExitCode)" }
}
& 'C:\Python311\python.exe' -m pip install --quiet --upgrade pip pyyaml
& 'C:\Python311\python.exe' -c "import sys, yaml; print(sys.version.split()[0], 'pyyaml', yaml.__version__)"

# --- 2. Sysmon + sysmon-modular config --------------------------------------
Step 'Sysmon'
$sys = "$dl\Sysmon"
Invoke-WebRequest 'https://download.sysinternals.com/files/Sysmon.zip' -OutFile "$dl\Sysmon.zip"
Expand-Archive "$dl\Sysmon.zip" -DestinationPath $sys -Force
Invoke-WebRequest 'https://github.com/olafhartong/sysmon-modular/releases/latest/download/sysmonconfig.xml' -OutFile "$dl\sysmonconfig.xml"
# Sysmon writes its banner to stderr; run it via Start-Process and judge by exit code.
if (Get-Service Sysmon64 -ErrorAction SilentlyContinue) {
    $sa = @('-accepteula', '-c', "$dl\sysmonconfig.xml")
} else {
    $sa = @('-accepteula', '-i', "$dl\sysmonconfig.xml")
}
$p = Start-Process "$sys\Sysmon64.exe" -ArgumentList $sa -Wait -PassThru -NoNewWindow `
        -RedirectStandardOutput "$dl\sysmon_out.txt" -RedirectStandardError "$dl\sysmon_err.txt"
Get-Content "$dl\sysmon_out.txt", "$dl\sysmon_err.txt" | Where-Object { $_ -match 'install|config|error|start|valid' }
if ($p.ExitCode -ne 0) { throw "Sysmon exit $($p.ExitCode)" }
Get-Service Sysmon64 | Format-Table -AutoSize Name, Status, StartType | Out-String

# --- 3. Invoke-AtomicRedTeam (AllUsers so -NoProfile sessions find it) + atomics
Step 'Invoke-AtomicRedTeam'
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope AllUsers | Out-Null
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
Install-Module -Name invoke-atomicredteam, powershell-yaml -Scope AllUsers -Force
Import-Module invoke-atomicredteam
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicsfolder.ps1' -UseBasicParsing)
Install-AtomicsFolder -Force -InstallPath 'C:\AtomicRedTeam'
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope LocalMachine -Force

Step 'DONE'
