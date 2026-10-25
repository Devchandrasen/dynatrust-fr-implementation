# Sequential collection

810 recorded missions across 285,000 rounds.

The [manifest](manifest.json) lists exact cases, source checksums and result paths.

| Phase | Missions |
| --- | ---: |
| primary | 180 |
| controls | 300 |
| kernels | 150 |
| fairness | 60 |
| scale | 60 |
| long | 60 |

## Replay one case

Run from the project root with a built ns-3.47 runtime:

```bash
python3 scripts/run_study.py --study sequential --phase primary --limit 1 \
  --ns3-root /absolute/path/to/ns-3.47 --output runs/sequential-check
```

[Setup guide](../../docs/getting-started.md) · [Experiment guide](../../docs/experiments.md)
