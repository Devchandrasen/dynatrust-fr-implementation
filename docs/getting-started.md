# Getting started

Data tools need Python 3.10 or newer and the standard library. Component checks need a C++17 compiler. Packet simulations need Linux or WSL, C++20, OpenSSL 3 and ns-3.47.

## Build ns-3

Use the recorded runtime commit:

```bash
git clone https://gitlab.com/nsnam/ns-3-dev.git ns-3.47
cd ns-3.47
git checkout e2c9e30c6ebdfd534aa7e30f6324b5674d138b9f
python3 ns3 configure --build-profile=optimized \
  --enable-modules=core,network,internet,internet-apps,mobility,lr-wpan,sixlowpan,spectrum,propagation,antenna \
  --disable-examples --disable-tests
python3 ns3 build -j 4
```

The replay tool reads the version and library profile from this build and links the selected source snapshot to its libraries.

## Check a collection

From the project root:

```bash
python3 scripts/verify_results.py
python3 scripts/run_unit_tests.py --study calibration
```

## Replay recorded cases

```bash
python3 scripts/run_study.py \
  --study core --scenario core --variant dynatrust --limit 1 \
  --ns3-root /absolute/path/to/ns-3.47 \
  --output runs/core-check
```

Use `--phase`, `--scenario`, `--variant` and `--seed` to narrow the selection. Without filters, the tool selects the entire collection. Use `--limit` for a small installation check.

The output directory must be new. Generated CSVs, calibration fixtures and the replay report go there; build products go under `build/`. A replay compares every CSV field with the stored data and returns a nonzero status on a difference.

Runtime, compiler and operating-system differences can affect exact replay. The report retains the selected arguments and differences for inspection.

## Windows

Run packet commands inside WSL. A Windows path such as `C:\work\ns-3.47` becomes `/mnt/c/work/ns-3.47`. The Python data verifier also runs directly on Windows.

Simulator file arguments use local filenames to avoid command-line parsing problems when a checkout path contains spaces.

The older Python plotting examples use the packages in `requirements.txt`; the main replay and verification tools use the standard library.
