# Core collection

1,510 recorded missions across 467,000 rounds.

The [manifest](manifest.json) lists exact cases, source checksums and result paths.

| Phase | Missions |
| --- | ---: |
| final-study | 1,510 |

## Replay one case

Run from the project root with a built ns-3.47 runtime:

```bash
python3 scripts/run_study.py --study core --phase final-study --limit 1 \
  --ns3-root /absolute/path/to/ns-3.47 --output runs/core-check
```

[Setup guide](../../docs/getting-started.md) · [Experiment guide](../../docs/experiments.md)
