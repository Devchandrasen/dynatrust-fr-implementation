param(
    [int[]]$Seeds = (1..30),
    [string]$ResultSet = "packet_alpha_delta_n36_s30",
    [double[]]$AlphaValues = @(0.10, 0.20, 0.30),
    [double[]]$DeltaValues = @(0.10, 0.20, 0.30)
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir
$root = Join-Path $repoRoot "results"
$summaryRows = @()

foreach ($alpha in $AlphaValues) {
    foreach ($delta in $DeltaValues) {
        $tag = "a{0:N2}_d{1:N2}" -f $alpha, $delta
        $tag = $tag -replace "\.", "p"
        $scenario = "${ResultSet}_${tag}"
        & "$scriptDir\run_packet_sweep.ps1" `
            -Nodes 36 `
            -Rounds 12 `
            -Heads 4 `
            -Ratios @("0.40") `
            -Seeds $Seeds `
            -Policies @("dynatrust") `
            -ResultSet $scenario `
            -TrustPoisoningStrength 1.20 `
            -Mobility "static" `
            -AttackMode "fixed" `
            -RecommendationTrimFraction $alpha `
            -RecommendationClipRadius $delta `
            -RecommendationResidualScale 1.0

        $policySummary = Import-Csv (Join-Path $root "$scenario\packet_summary_by_policy_ratio.csv") |
            Select-Object -First 1
        $summaryRows += [PSCustomObject]@{
            alpha = "{0:N2}" -f $alpha
            delta = "{0:N2}" -f $delta
            clean_pdr = $policySummary.mean_clean_pdr
            ci95_clean_pdr = $policySummary.ci95_clean_pdr
            compromised_heads = $policySummary.avg_compromised_head_selections
            corrupted_reports = $policySummary.avg_corrupted_reports
            honest_quarantine = $policySummary.avg_quarantined_honest_reports
            malicious_quarantine = $policySummary.avg_quarantined_malicious_reports
        }
    }
}

$outDir = Join-Path $root $ResultSet
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$summaryRows |
    Sort-Object alpha, delta |
    Export-Csv (Join-Path $outDir "alpha_delta_summary.csv") -NoTypeInformation -Encoding ASCII
$summaryRows | Format-Table -AutoSize
