# References collection

760 recorded missions across 284,000 rounds.

The [manifest](manifest.json) lists exact cases, source checksums and result paths.

| Phase | Missions |
| --- | ---: |
| primary | 270 |
| controls | 200 |
| gate-ablation | 60 |
| reference-count | 60 |
| reference-failures | 90 |
| long | 60 |
| energy | 20 |

## Replay one case

Run from the project root with a built ns-3.47 runtime:

```bash
python3 scripts/run_study.py --study references --phase primary --limit 1 \
  --ns3-root /absolute/path/to/ns-3.47 --output runs/references-check
```

[Setup guide](../../docs/getting-started.md) · [Experiment guide](../../docs/experiments.md)
