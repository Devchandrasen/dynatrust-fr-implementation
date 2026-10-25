# Contributing

Keep changes focused on the simulator, experiment tools or documentation. Include the command and configuration used to check a behavior change.

Before opening a pull request:

```bash
python3 -m compileall -q scripts
python3 scripts/run_unit_tests.py
python3 scripts/verify_results.py
```

For transport or controller changes, build against ns-3.47 and replay an affected case into a new output directory. Describe differences in the resulting counters.

Keep recorded datasets fixed. Add new configurations as separate collections with source checksums and exact arguments. Avoid committing runtime builds, local logs, device credentials or generated output folders.
