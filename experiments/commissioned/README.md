# Commissioned collection

600 recorded missions across 222,000 rounds.

The [manifest](manifest.json) lists exact cases, source checksums and result paths.

| Phase | Missions |
| --- | ---: |
| primary | 180 |
| controls | 180 |
| honest-bias | 120 |
| scale | 60 |
| long | 60 |

## Replay one case

Run from the project root with a built ns-3.47 runtime:

```bash
python3 scripts/run_study.py --study commissioned --phase primary --limit 1 \
  --ns3-root /absolute/path/to/ns-3.47 --output runs/commissioned-check
```

[Setup guide](../../docs/getting-started.md) · [Experiment guide](../../docs/experiments.md)
