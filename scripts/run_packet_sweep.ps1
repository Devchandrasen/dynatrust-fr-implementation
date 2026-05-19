param(
    [int]$Nodes = 36,
    [int]$Rounds = 12,
    [int]$Heads = 4,
    [string[]]$Ratios = @("0.10", "0.20", "0.30", "0.40"),
    [int[]]$Seeds = @(19, 23, 29),
    [string[]]$Policies = @(
        "dynatrust",
        "dynatrust-no-filter",
        "dynatrust-no-diversity",
        "dynatrust-no-fairness",
        "dynatrust-no-robust",
        "trust",
        "robust-reputation",
        "quarantine-only",
        "oracle",
        "energy",
        "heed",
        "trust-leach",
        "leach"
    ),
    [string]$ResultSet = "",
    [double]$TrustPoisoningStrength = 0.35,
    [string]$Mobility = "static",
    [string]$AttackMode = "fixed",
    [double]$BenignReportLossProbability = 0.0,
    [double]$BenignAggregateLossProbability = 0.0,
    [double]$BenignCorruptProbability = 0.0,
    [double]$BenignEvidenceErrorProbability = 0.0,
    [double]$MobilitySpeed = 1.0,
    [double]$RecommendationTrimFraction = 0.20,
    [double]$RecommendationClipRadius = 0.20,
    [double]$RecommendationResidualScale = 0.0,
    [int]$OnOffPeriod = 4,
    [int]$StrategicWarmupRounds = 3,
    [double]$StrategicTrustThreshold = 0.58,
    [double]$TrustUpdateStep = 0.28,
    [double]$FilterTrustThreshold = 0.45,
    [double]$HeadTrustThreshold = 0.38,
    [double]$DynatrustTrustWeight = 0.58,
    [double]$DynatrustEnergyWeight = 0.24,
    [double]$DynatrustFairnessWeight = 0.10,
    [double]$DynatrustCentralityWeight = 0.05,
    [double]$DynatrustDiversityWeight = 0.04,
    [double]$InitialEnergyJ = 1.0,
    [double]$SensorReportCostJ = 0.0010,
    [double]$HeadReceiveCostJ = 0.0004,
    [double]$AggregateTxCostJ = 0.0025,
    [double]$ClusterHeadRoundCostJ = 0.0015,
    [double]$TrustUpdateCostJ = 0.0001,
    [double]$TxCurrentA = 0.020,
    [double]$RxCurrentA = 0.012,
    [double]$IdleCurrentA = 0.001
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
$exe = Join-Path $ns3Root "build\scratch\ns3.47-dynatrust-fr-packet-optimized.exe"
if ([string]::IsNullOrWhiteSpace($ResultSet)) {
    $ResultSet = "packet_n$Nodes-r$Rounds-s$($Seeds.Count)"
}
$resultsRoot = Join-Path $repoRoot "results"
$results = Join-Path $resultsRoot $ResultSet

if (-not (Test-Path $bash)) {
    throw "MSYS2 bash was not found at $bash"
}

if (-not (Test-Path $exe)) {
    throw "Packet-level NS-3 executable was not found. Build dynatrust-fr-packet first."
}

$msysNs3Root = ConvertTo-MsysPath $ns3Root

New-Item -ItemType Directory -Force -Path $results | Out-Null

$env:MSYSTEM = "MINGW64"
$env:CHERE_INVOKING = "1"

foreach ($policy in $Policies) {
    foreach ($ratio in $Ratios) {
        foreach ($seed in $Seeds) {
            $outFile = Join-Path $results "packet-$policy-ratio-$ratio-seed-$seed.csv"
            $command = "export PATH='$msysNs3Root/build/lib':/mingw64/bin:/usr/bin:`$PATH; '$msysNs3Root/build/scratch/ns3.47-dynatrust-fr-packet-optimized.exe' --policy=$policy --maliciousRatio=$ratio --nodes=$Nodes --rounds=$Rounds --heads=$Heads --seed=$seed --trustPoisoningStrength=$TrustPoisoningStrength --mobility=$Mobility --attackMode=$AttackMode --benignReportLossProbability=$BenignReportLossProbability --benignAggregateLossProbability=$BenignAggregateLossProbability --benignCorruptProbability=$BenignCorruptProbability --benignEvidenceErrorProbability=$BenignEvidenceErrorProbability --mobilitySpeed=$MobilitySpeed --recommendationTrimFraction=$RecommendationTrimFraction --recommendationClipRadius=$RecommendationClipRadius --recommendationResidualScale=$RecommendationResidualScale --onOffPeriod=$OnOffPeriod --strategicWarmupRounds=$StrategicWarmupRounds --strategicTrustThreshold=$StrategicTrustThreshold --trustUpdateStep=$TrustUpdateStep --filterTrustThreshold=$FilterTrustThreshold --headTrustThreshold=$HeadTrustThreshold --dynatrustTrustWeight=$DynatrustTrustWeight --dynatrustEnergyWeight=$DynatrustEnergyWeight --dynatrustFairnessWeight=$DynatrustFairnessWeight --dynatrustCentralityWeight=$DynatrustCentralityWeight --dynatrustDiversityWeight=$DynatrustDiversityWeight --initialEnergyJ=$InitialEnergyJ --sensorReportCostJ=$SensorReportCostJ --headReceiveCostJ=$HeadReceiveCostJ --aggregateTxCostJ=$AggregateTxCostJ --clusterHeadRoundCostJ=$ClusterHeadRoundCostJ --trustUpdateCostJ=$TrustUpdateCostJ --txCurrentA=$TxCurrentA --rxCurrentA=$RxCurrentA --idleCurrentA=$IdleCurrentA"
            & $bash -lc $command | Set-Content -Path $outFile -Encoding ASCII
            $lineCount = (Get-Content $outFile | Measure-Object -Line).Lines
            if ($lineCount -ne ($Rounds + 1)) {
                throw "Unexpected row count in $outFile"
            }
        }
    }
}

$runRows = @()
function Get-FirstRoundAtOrBelow {
    param([object[]]$Rows, [int]$Threshold, [int]$FallbackRound)
    foreach ($row in $Rows) {
        if ([int]$row.alive_nodes -le $Threshold) {
            return [int]$row.round
        }
    }
    return $FallbackRound
}

foreach ($file in Get-ChildItem $results -Filter "packet-*.csv") {
    $rows = Import-Csv $file.FullName
    $steady = $rows | Where-Object { [int]$_.round -ge [Math]::Min(3, $Rounds - 1) }
    $first = $rows[0]
    $fndRound = Get-FirstRoundAtOrBelow $rows ($Nodes - 1) $Rounds
    $hndRound = Get-FirstRoundAtOrBelow $rows ([Math]::Floor($Nodes / 2)) $Rounds
    $lndRound = Get-FirstRoundAtOrBelow $rows 0 $Rounds
    $runRows += [PSCustomObject]@{
        policy = $first.policy
        malicious_ratio = [double]$first.malicious_ratio
        attack_mode = if ($first.PSObject.Properties.Name -contains "attack_mode") { $first.attack_mode } else { $AttackMode }
        seed = ([regex]::Match($file.BaseName, "seed-(\d+)").Groups[1].Value)
        rounds = $rows.Count
        mean_pdr = (($steady | Measure-Object -Property pdr -Average).Average)
        mean_clean_pdr = (($steady | Measure-Object -Property clean_pdr -Average).Average)
        mean_aggregate_delivery = (($steady | Measure-Object -Property aggregate_delivery -Average).Average)
        compromised_head_selections = (($rows | Measure-Object -Property compromised_heads -Sum).Sum)
        corrupted_reports = (($rows | Measure-Object -Property corrupted_reports -Sum).Sum)
        quarantined_reports = (($rows | Measure-Object -Property quarantined_reports -Sum).Sum)
        quarantined_honest_reports = if ($rows[0].PSObject.Properties.Name -contains "quarantined_honest_reports") { (($rows | Measure-Object -Property quarantined_honest_reports -Sum).Sum) } else { "" }
        quarantined_malicious_reports = if ($rows[0].PSObject.Properties.Name -contains "quarantined_malicious_reports") { (($rows | Measure-Object -Property quarantined_malicious_reports -Sum).Sum) } else { "" }
        final_mean_trust = [double]$rows[-1].mean_trust
        final_mean_energy = [double]$rows[-1].mean_energy
        mean_energy_jain = (($steady | Measure-Object -Property energy_jain -Average).Average)
        mean_ch_jain = (($steady | Measure-Object -Property ch_jain -Average).Average)
        first_node_death_round = $fndRound
        half_node_death_round = $hndRound
        last_node_death_round = $lndRound
        final_alive_nodes = [int]$rows[-1].alive_nodes
    }
}

$runRows |
    Sort-Object policy, malicious_ratio, seed |
    Export-Csv (Join-Path $results "packet_summary_by_run.csv") -NoTypeInformation -Encoding ASCII

function Get-Mean {
    param([object[]]$Items, [string]$Property)
    return (($Items | Measure-Object -Property $Property -Average).Average)
}

function Get-Ci95 {
    param([object[]]$Items, [string]$Property)
    $values = @($Items | ForEach-Object { [double]$_.$Property })
    if ($values.Count -lt 2) {
        return 0.0
    }
    $mean = ($values | Measure-Object -Average).Average
    $sumSq = 0.0
    foreach ($value in $values) {
        $sumSq += [Math]::Pow($value - $mean, 2)
    }
    $sd = [Math]::Sqrt($sumSq / ($values.Count - 1))
    return 1.96 * $sd / [Math]::Sqrt($values.Count)
}

$groupRows = foreach ($g in ($runRows | Group-Object policy, malicious_ratio, attack_mode)) {
    $items = $g.Group
    [PSCustomObject]@{
        policy = $items[0].policy
        malicious_ratio = $items[0].malicious_ratio
        attack_mode = $items[0].attack_mode
        runs = $items.Count
        mean_pdr = "{0:N4}" -f (Get-Mean $items "mean_pdr")
        ci95_pdr = "{0:N4}" -f (Get-Ci95 $items "mean_pdr")
        mean_clean_pdr = "{0:N4}" -f (Get-Mean $items "mean_clean_pdr")
        ci95_clean_pdr = "{0:N4}" -f (Get-Ci95 $items "mean_clean_pdr")
        mean_aggregate_delivery = "{0:N4}" -f (Get-Mean $items "mean_aggregate_delivery")
        avg_compromised_head_selections = "{0:N2}" -f (Get-Mean $items "compromised_head_selections")
        avg_corrupted_reports = "{0:N2}" -f (Get-Mean $items "corrupted_reports")
        avg_quarantined_reports = "{0:N2}" -f (Get-Mean $items "quarantined_reports")
        avg_quarantined_honest_reports = if ("$($items[0].quarantined_honest_reports)" -ne "") { "{0:N2}" -f (Get-Mean $items "quarantined_honest_reports") } else { "" }
        avg_quarantined_malicious_reports = if ("$($items[0].quarantined_malicious_reports)" -ne "") { "{0:N2}" -f (Get-Mean $items "quarantined_malicious_reports") } else { "" }
        final_mean_trust = "{0:N4}" -f (Get-Mean $items "final_mean_trust")
        final_mean_energy = "{0:N4}" -f (Get-Mean $items "final_mean_energy")
        mean_energy_jain = "{0:N4}" -f (Get-Mean $items "mean_energy_jain")
        mean_ch_jain = "{0:N4}" -f (Get-Mean $items "mean_ch_jain")
        avg_fnd_round = "{0:N2}" -f (Get-Mean $items "first_node_death_round")
        avg_hnd_round = "{0:N2}" -f (Get-Mean $items "half_node_death_round")
        avg_lnd_round = "{0:N2}" -f (Get-Mean $items "last_node_death_round")
        avg_final_alive_nodes = "{0:N2}" -f (Get-Mean $items "final_alive_nodes")
    }
}

$groupRows |
    Sort-Object attack_mode, malicious_ratio, policy |
    Export-Csv (Join-Path $results "packet_summary_by_policy_ratio.csv") -NoTypeInformation -Encoding ASCII

$groupRows | Sort-Object attack_mode, malicious_ratio, policy | Format-Table -AutoSize
