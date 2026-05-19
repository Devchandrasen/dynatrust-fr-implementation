param(
    [string]$MaliciousRatio = "0.20",
    [int]$Nodes = 36,
    [int]$Rounds = 12,
    [int]$Heads = 4
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir
$ns3Root = if ($env:NS3_ROOT) { $env:NS3_ROOT } else { Join-Path $repoRoot "ns3-local\ns-3.47" }
function ConvertTo-MsysPath {
    param([string]$Path)
    $resolved = (Resolve-Path -LiteralPath $Path).Path
    $drive = $resolved.Substring(0, 1).ToLowerInvariant()
    $pathWithoutDrive = $resolved.Substring(2) -replace "\\", "/"
    return "/$drive$pathWithoutDrive"
}
$bash = "C:\msys64\usr\bin\bash.exe"
$exe = Join-Path $ns3Root "build\scratch\ns3.47-dynatrust-fr-smoke-optimized.exe"

if (-not (Test-Path $bash)) {
    throw "MSYS2 bash was not found at $bash"
}

if (-not (Test-Path $exe)) {
    throw "DynaTrust-FR NS-3 executable was not found. Run the NS-3 build first."
}

$env:MSYSTEM = "MINGW64"
$env:CHERE_INVOKING = "1"

$msysNs3Root = ConvertTo-MsysPath $ns3Root
$command = "export PATH='$msysNs3Root/build/lib':/mingw64/bin:/usr/bin:`$PATH; '$msysNs3Root/build/scratch/ns3.47-dynatrust-fr-smoke-optimized.exe' --maliciousRatio=$MaliciousRatio --nodes=$Nodes --rounds=$Rounds --heads=$Heads"

& $bash -lc $command
