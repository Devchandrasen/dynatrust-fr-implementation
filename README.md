# DynaTrust-FR Implementation

This repository contains the packet-level implementation and helper scripts for DynaTrust-FR, a robust trust fusion and packet filtering method for cluster-head selection in mobile IoT sensor networks.

The code has two parts:

- `ns3/scratch/`: ns-3 scratch programs for packet-level simulation and LR-WPAN validation.
- `scripts/`: PowerShell runners for packet sweeps, sensitivity tests, and smoke checks.
- `python/dynatrust_fr/`: lightweight Python simulator used for quick algorithm checks.

## Requirements

- ns-3.47
- MSYS2 with MinGW64 on Windows, or a compatible ns-3 build environment
- Python 3.10 or newer for the Python simulator

The PowerShell scripts expect the ns-3 root through `NS3_ROOT`. If it is not set, they look for `ns3-local/ns-3.47` inside the repository.

## ns-3 Setup

Copy the scratch programs into an ns-3.47 checkout:

```powershell
Copy-Item .\ns3\scratch\*.cc $env:NS3_ROOT\scratch\ -Force
```

Build the scratch targets from the ns-3 root:

```powershell
cd $env:NS3_ROOT
.\ns3 configure --enable-examples --enable-tests
.\ns3 build dynatrust-fr-packet
.\ns3 build dynatrust-fr-smoke
.\ns3 build dynatrust-lr-wpan-validation
```

## Run Packet Experiments

From the repository root:

```powershell
$env:NS3_ROOT = "C:\path\to\ns-3.47"
.\scripts\run_packet_sweep.ps1 -Seeds @(1,2,3) -Ratios @("0.10","0.20","0.30","0.40")
```

Results are written under `results/<result-set>/` as per-run CSV files and aggregate summaries.

Useful runners:

```powershell
.\scripts\run_smoke.ps1
.\scripts\run_parameter_sensitivity.ps1
.\scripts\run_alpha_delta_sensitivity.ps1
.\scripts\run_wide_sensitivity.ps1
```

## Python Simulator

The Python simulator is independent of ns-3 and uses only the standard library:

```powershell
python .\python\dynatrust_fr\run_experiment.py
python .\python\dynatrust_fr\run_stress_experiments.py
```

## Repository Scope

This repository contains implementation code, execution scripts, and reproducibility helpers only.
