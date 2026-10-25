# Experiment guide

`experiments/catalog.json` lists the six collections and runtime version. Each collection includes its source snapshot, C++ checks, manifest and results.

```text
experiments/<collection>/
  manifest.json
  source/                  C++ implementation and headers
  tests/                   Component checks
  fixtures/                Calibration inputs, where needed
  results/<phase>/
    raw/<scenario>/        Round-level CSVs compressed with gzip
    metrics/<scenario>/    Settings, arguments, metrics and checksums
    summary.csv            Recorded grouped metrics
```

The core source retains its `ns3/v2a/` layout so the original include paths remain valid. Calibration includes 650 primary/control/long missions and 120 separate keep-all controls. Core also contains `fusion_stress.csv` with 7,200 local trials. Development and tuning runs are outside this collection.

## Inspect metrics

```bash
python3 scripts/summarize_results.py --study core --output runs/core-summary.csv
python3 scripts/summarize_results.py --study calibration --output runs/calibration-summary.csv
```

The tool groups per-run metrics by phase, scenario and variant, exporting means and sample standard deviations across seeds. It does not combine separate cohorts or add significance claims.

Read a compressed CSV directly:

```python
import csv
import gzip

with gzip.open("path/to/case.csv.gz", "rt", newline="") as stream:
    rows = list(csv.DictReader(stream))
```

## Replay selection

```bash
python3 scripts/run_study.py --list
python3 scripts/run_study.py \
  --study rolling --phase primary --limit 1 \
  --ns3-root /absolute/path/to/ns-3.47 \
  --output runs/rolling-check
```

Add `--seed`, `--scenario` or `--variant` to narrow the selection. Omit `--limit` to run all matching cases. Arguments come from the recorded execution, including settings that differ from a mode's defaults.

Calibration replays copy the selected fixture into the new output directory and pass a relative filename to the simulator.

## Integrity

The verifier checks source checksums, decompressed CSV checksums, case counts, round numbering and stored counter totals. It checks that accepted corrupted reports do not exceed received corrupted reports.

Metrics distinguish delivery from nonmalicious sources, clean content from all sources, and reception regardless of quality. Keep their denominators separate when comparing configurations.

Use a new directory under `runs/` for fresh outputs. Included results remain fixed for later comparisons.
