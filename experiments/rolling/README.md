# Rolling collection

870 recorded missions across 338,000 rounds.

The [manifest](manifest.json) lists exact cases, source checksums and result paths.

| Phase | Missions |
| --- | ---: |
| primary | 270 |
| controls | 270 |
| energy | 90 |
| kernels | 150 |
| long | 20 |
| loss-ablation | 30 |
| scale | 40 |

## Replay one case

Run from the project root with a built ns-3.47 runtime:

```bash
python3 scripts/run_study.py --study rolling --phase primary --limit 1 \
  --ns3-root /absolute/path/to/ns-3.47 --output runs/rolling-check
```

[Setup guide](../../docs/getting-started.md) · [Experiment guide](../../docs/experiments.md)
