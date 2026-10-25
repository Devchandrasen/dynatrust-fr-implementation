# Calibration collection

770 recorded missions across 259,000 rounds.

The [manifest](manifest.json) lists exact cases, source checksums and result paths.

| Phase | Missions |
| --- | ---: |
| primary | 270 |
| controls | 340 |
| long | 40 |
| keep-all | 120 |

## Replay one case

Run from the project root with a built ns-3.47 runtime:

```bash
python3 scripts/run_study.py --study calibration --phase primary --limit 1 \
  --ns3-root /absolute/path/to/ns-3.47 --output runs/calibration-check
```

[Setup guide](../../docs/getting-started.md) · [Experiment guide](../../docs/experiments.md)
