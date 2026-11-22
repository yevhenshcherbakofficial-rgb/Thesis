# resources.ps1 - per-process resource sampler (runs inside the Windows guest).
# Started by lab.py (outside the scenario's process tree) for the length of a
# run. Every $IntervalMs it appends one CSV row per process:
#   ts_utc, pid, start_utc, cpu_s, ws_mb, private_mb, threads, handles, name
# Sysmon has no CPU/memory telemetry; features.py joins these rows to Sysmon
# processes by (pid, start time) to build the resource-metric feature group.
param([string]$Out = 'C:\lab\resources.csv', [int]$Seconds = 120, [int]$IntervalMs = 1000)
$ErrorActionPreference = 'SilentlyContinue'
'ts_utc,pid,start_utc,cpu_s,ws_mb,private_mb,threads,handles,name' | Out-File $Out -Encoding ascii
$end = (Get-Date).AddSeconds($Seconds)
while ((Get-Date) -lt $end) {
    $ts = (Get-Date).ToUniversalTime().ToString('o')
    $rows = foreach ($p in Get-Process) {
        if ($p.StartTime) {
            '{0},{1},{2},{3},{4},{5},{6},{7},{8}' -f $ts, $p.Id,
                $p.StartTime.ToUniversalTime().ToString('o'),
                [math]::Round([double]$p.CPU, 3),
                [math]::Round($p.WorkingSet64 / 1MB, 2),
                [math]::Round($p.PrivateMemorySize64 / 1MB, 2),
                $p.Threads.Count, $p.HandleCount, ($p.ProcessName -replace ',', '_')
        }
    }
    $rows | Out-File $Out -Append -Encoding ascii
    Start-Sleep -Milliseconds $IntervalMs
}
