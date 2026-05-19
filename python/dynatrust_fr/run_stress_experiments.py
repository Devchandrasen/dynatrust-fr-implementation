from __future__ import annotations

import csv
import json
from dataclasses import replace
from pathlib import Path

from run_experiment import load_best_weights, make_seeds, write_csv, aggregate
from simulator import SimulationConfig, WSNSimulator, summarize_metrics


ROOT = Path(__file__).resolve().parent
OUT = ROOT / "results_v3_stress"


def run_malicious_ratio_sweep() -> list[dict]:
    protocols = ["leach", "trust", "hybrid", "dynatrust"]
    ratios = [0.05, 0.10, 0.20, 0.30]
    seeds = make_seeds(10)
    best = load_best_weights()
    rows = []
    base = SimulationConfig(
        node_count=100,
        rounds=300,
        initial_energy=0.12,
        cluster_head_ratio=0.08,
        attack_type="mixed",
        bursty_traffic=True,
        drift_round=50,
    )
    for ratio in ratios:
        for protocol in protocols:
            for seed in seeds:
                cfg = replace(
                    base,
                    malicious_ratio=ratio,
                    protocol=protocol,
                    seed=seed,
                    **(best if protocol == "dynatrust" else {}),
                )
                sim = WSNSimulator(cfg)
                rows.append({
                    "sweep": "malicious_ratio",
                    "malicious_ratio": ratio,
                    "node_count": cfg.node_count,
                    "protocol": protocol,
                    "attack": "mixed",
                    "seed": seed,
                    **summarize_metrics(sim.run()),
                })
    return rows


def run_scalability_sweep() -> list[dict]:
    protocols = ["leach", "trust", "hybrid", "dynatrust"]
    node_counts = [100, 200, 500]
    seeds = make_seeds(6)
    best = load_best_weights()
    rows = []
    for node_count in node_counts:
        initial_energy = 0.12 if node_count <= 200 else 0.15
        base = SimulationConfig(
            node_count=node_count,
            rounds=260,
            initial_energy=initial_energy,
            malicious_ratio=0.10,
            cluster_head_ratio=0.08,
            attack_type="mixed",
            bursty_traffic=True,
            drift_round=50,
        )
        for protocol in protocols:
            for seed in seeds:
                cfg = replace(
                    base,
                    protocol=protocol,
                    seed=seed,
                    **(best if protocol == "dynatrust" else {}),
                )
                sim = WSNSimulator(cfg)
                rows.append({
                    "sweep": "scalability",
                    "malicious_ratio": cfg.malicious_ratio,
                    "node_count": node_count,
                    "protocol": protocol,
                    "attack": "mixed",
                    "seed": seed,
                    **summarize_metrics(sim.run()),
                })
    return rows


def aggregate_stress(rows: list[dict]) -> list[dict]:
    groups: dict[tuple, list[dict]] = {}
    for row in rows:
        key = (row["sweep"], row["malicious_ratio"], row["node_count"], row["attack"], row["protocol"])
        groups.setdefault(key, []).append(row)

    out = []
    for (sweep, ratio, node_count, attack, protocol), group in sorted(groups.items()):
        summary = aggregate(group)[0]
        out.append({
            "sweep": sweep,
            "malicious_ratio": ratio,
            "node_count": node_count,
            "attack": attack,
            **summary,
        })
    return out


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    rows = run_malicious_ratio_sweep() + run_scalability_sweep()
    write_csv(OUT / "stress_summary.csv", rows)
    (OUT / "stress_summary.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
    agg = aggregate_stress(rows)
    write_csv(OUT / "stress_aggregate.csv", agg)
    print(f"Wrote {OUT / 'stress_summary.csv'}")
    print(f"Wrote {OUT / 'stress_aggregate.csv'}")
    for row in agg:
        if row["protocol"] == "dynatrust":
            print(
                f"{row['sweep']} ratio={row['malicious_ratio']} nodes={row['node_count']} "
                f"PDR={row['mean_overall_pdr']:.3f} FND={fmt(row['mean_first_node_dead'])}"
            )


def fmt(value: float | None) -> str:
    return "NA" if value is None else f"{value:.1f}"


if __name__ == "__main__":
    main()
