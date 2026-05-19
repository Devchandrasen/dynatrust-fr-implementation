param(
    [int[]]$Seeds = (1..30),
    [string]$ResultSet = "packet_wide_sensitivity_n36_s30"
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir
$resultsRoot = Join-Path $repoRoot "results"
$root = Join-Path $resultsRoot $ResultSet
New-Item -ItemType Directory -Force -Path $root | Out-Null

$rows = @()

foreach ($poison in @(0.40, 0.80, 1.20, 1.60)) {
    $child = "${ResultSet}_poison_$($poison.ToString('0.00'))"
    & "$scriptDir\run_packet_sweep.ps1" `
        -Nodes 36 `
        -Rounds 12 `
        -Heads 4 `
        -Ratios @("0.40") `
        -Seeds $Seeds `
        -Policies @("dynatrust", "dynatrust-no-robust", "trust") `
        -ResultSet $child `
        -TrustPoisoningStrength $poison `
        -Mobility "static" `
        -AttackMode "fixed" | Out-Host
    foreach ($r in Import-Csv (Join-Path $resultsRoot "$child\packet_summary_by_policy_ratio.csv")) {
        $rows += [PSCustomObject]@{
            scenario = "poisoning_strength"
            setting = $poison.ToString("0.00")
            policy = $r.policy
            clean_pdr = $r.mean_clean_pdr
            ci95 = $r.ci95_clean_pdr
            compromised_heads = $r.avg_compromised_head_selections
            corrupted_reports = $r.avg_corrupted_reports
            honest_quarantine = $r.avg_quarantined_honest_reports
            malicious_quarantine = $r.avg_quarantined_malicious_reports
        }
    }
}

foreach ($speed in @(1.0, 3.0, 5.0)) {
    $child = "${ResultSet}_speed_$($speed.ToString('0.0'))"
    & "$scriptDir\run_packet_sweep.ps1" `
        -Nodes 36 `
        -Rounds 12 `
        -Heads 4 `
        -Ratios @("0.40") `
        -Seeds $Seeds `
        -Policies @("dynatrust", "heed", "leach") `
        -ResultSet $child `
        -TrustPoisoningStrength 1.20 `
        -Mobility "random-walk" `
        -MobilitySpeed $speed `
        -AttackMode "fixed" | Out-Host
    foreach ($r in Import-Csv (Join-Path $resultsRoot "$child\packet_summary_by_policy_ratio.csv")) {
        $rows += [PSCustomObject]@{
            scenario = "mobility_speed"
            setting = $speed.ToString("0.0")
            policy = $r.policy
            clean_pdr = $r.mean_clean_pdr
            ci95 = $r.ci95_clean_pdr
            compromised_heads = $r.avg_compromised_head_selections
            corrupted_reports = $r.avg_corrupted_reports
            honest_quarantine = $r.avg_quarantined_honest_reports
            malicious_quarantine = $r.avg_quarantined_malicious_reports
        }
    }
}

$child = "${ResultSet}_ratio_0.50"
& "$scriptDir\run_packet_sweep.ps1" `
    -Nodes 36 `
    -Rounds 12 `
    -Heads 4 `
    -Ratios @("0.50") `
    -Seeds $Seeds `
    -Policies @("dynatrust", "oracle", "robust-reputation", "trust-leach", "heed", "leach") `
    -ResultSet $child `
    -TrustPoisoningStrength 1.20 `
    -Mobility "static" `
    -AttackMode "fixed" | Out-Host
foreach ($r in Import-Csv (Join-Path $resultsRoot "$child\packet_summary_by_policy_ratio.csv")) {
    $rows += [PSCustomObject]@{
        scenario = "malicious_ratio"
        setting = "0.50"
        policy = $r.policy
        clean_pdr = $r.mean_clean_pdr
        ci95 = $r.ci95_clean_pdr
        compromised_heads = $r.avg_compromised_head_selections
        corrupted_reports = $r.avg_corrupted_reports
        honest_quarantine = $r.avg_quarantined_honest_reports
        malicious_quarantine = $r.avg_quarantined_malicious_reports
    }
}

$rows | Export-Csv (Join-Path $root "wide_sensitivity_summary.csv") -NoTypeInformation -Encoding ASCII
$rows | Format-Table -AutoSize
