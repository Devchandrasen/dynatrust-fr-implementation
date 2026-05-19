param(
    [int]$Nodes = 36,
    [int]$Rounds = 12,
    [int]$Heads = 4,
    [int[]]$Seeds = (1..30),
    [string]$Mobility = "static",
    [string]$AttackMode = "fixed",
    [string]$ResultSet = "packet_parameter_sensitivity_n36_s30"
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir
$resultsRoot = Join-Path $repoRoot "results"
$root = Join-Path $resultsRoot $ResultSet
New-Item -ItemType Directory -Force -Path $root | Out-Null

$configs = @(
    @{ name = "Default"; trustStep = 0.28; filter = 0.45; head = 0.38; trustWeight = 0.58; energyWeight = 0.24 },
    @{ name = "RhoLow"; trustStep = 0.20; filter = 0.45; head = 0.38; trustWeight = 0.58; energyWeight = 0.24 },
    @{ name = "RhoHigh"; trustStep = 0.36; filter = 0.45; head = 0.38; trustWeight = 0.58; energyWeight = 0.24 },
    @{ name = "FilterLow"; trustStep = 0.28; filter = 0.40; head = 0.38; trustWeight = 0.58; energyWeight = 0.24 },
    @{ name = "FilterHigh"; trustStep = 0.28; filter = 0.50; head = 0.38; trustWeight = 0.58; energyWeight = 0.24 },
    @{ name = "HeadLow"; trustStep = 0.28; filter = 0.45; head = 0.34; trustWeight = 0.58; energyWeight = 0.24 },
    @{ name = "HeadHigh"; trustStep = 0.28; filter = 0.45; head = 0.42; trustWeight = 0.58; energyWeight = 0.24 },
    @{ name = "TrustWeightLow"; trustStep = 0.28; filter = 0.45; head = 0.38; trustWeight = 0.50; energyWeight = 0.32 },
    @{ name = "TrustWeightHigh"; trustStep = 0.28; filter = 0.45; head = 0.38; trustWeight = 0.66; energyWeight = 0.16 }
)

$summaryRows = @()
foreach ($cfg in $configs) {
    $child = "${ResultSet}_$($cfg.name)"
    & "$scriptDir\run_packet_sweep.ps1" `
        -Nodes $Nodes `
        -Rounds $Rounds `
        -Heads $Heads `
        -Ratios @("0.40") `
        -Seeds $Seeds `
        -Policies @("dynatrust") `
        -ResultSet $child `
        -TrustPoisoningStrength 1.20 `
        -Mobility $Mobility `
        -AttackMode $AttackMode `
        -TrustUpdateStep $cfg.trustStep `
        -FilterTrustThreshold $cfg.filter `
        -HeadTrustThreshold $cfg.head `
        -DynatrustTrustWeight $cfg.trustWeight `
        -DynatrustEnergyWeight $cfg.energyWeight | Out-Host

    $row = Import-Csv (Join-Path $resultsRoot "$child\packet_summary_by_policy_ratio.csv") | Select-Object -First 1
    $summaryRows += [PSCustomObject]@{
        variant = $cfg.name
        trust_update_step = $cfg.trustStep
        filter_threshold = $cfg.filter
        head_threshold = $cfg.head
        trust_weight = $cfg.trustWeight
        energy_weight = $cfg.energyWeight
        mean_clean_pdr = $row.mean_clean_pdr
        ci95_clean_pdr = $row.ci95_clean_pdr
        compromised_heads = $row.avg_compromised_head_selections
        corrupted_reports = $row.avg_corrupted_reports
        quarantined_reports = $row.avg_quarantined_reports
        quarantined_honest_reports = $row.avg_quarantined_honest_reports
        quarantined_malicious_reports = $row.avg_quarantined_malicious_reports
        ch_jain = $row.mean_ch_jain
    }
}

$summaryRows | Export-Csv (Join-Path $root "parameter_sensitivity_summary.csv") -NoTypeInformation -Encoding ASCII
$summaryRows | Format-Table -AutoSize
