from __future__ import annotations

import csv
import json
from dataclasses import replace
from pathlib import Path
from random import Random

from simulator import SimulationConfig, WSNSimulator, summarize_metrics


ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
OUT = RESULTS / "weight_tuning.csv"
BEST = RESULTS / "best_weights.json"


def normalized(values: list[float]) -> tuple[float, ...]:
    total = sum(values)
    return tuple(value / total for value in values)


def sample_candidate(rng: Random) -> dict:
    dyn_base = normalized([
        rng.uniform(0.22, 0.40),  # energy
        rng.uniform(0.14, 0.28),  # trust
        rng.uniform(0.10, 0.24),  # low risk
        rng.uniform(0.04, 0.12),  # centrality
        rng.uniform(0.03, 0.10),  # sink proximity
        rng.uniform(0.04, 0.12),  # low load
        rng.uniform(0.08, 0.22),  # fairness
    ])
    route = normalized([
        rng.uniform(0.16, 0.30),  # energy
        rng.uniform(0.14, 0.28),  # trust
        rng.uniform(0.12, 0.26),  # low risk
        rng.uniform(0.10, 0.22),  # link quality
        rng.uniform(0.05, 0.16),  # route memory
        rng.uniform(0.04, 0.12),  # member distance
        rng.uniform(0.03, 0.10),  # sink distance
        rng.uniform(0.04, 0.12),  # load balance
    ])
    drift = (
        rng.uniform(-0.08, 0.02),
        rng.uniform(0.04, 0.16),
        rng.uniform(0.04, 0.16),
        rng.uniform(0.02, 0.10),
    )
    return {
        "dynatrust_weights": dyn_base,
        "dynatrust_drift_gains": drift,
        "route_weights": route,
        "survival_threshold": rng.uniform(0.45, 0.70),
    }


def evaluate(candidate: dict, seeds: list[int], attacks: list[str]) -> dict:
    rows = []
    base = SimulationConfig(
        node_count=100,
        rounds=260,
        initial_energy=0.12,
        malicious_ratio=0.10,
        cluster_head_ratio=0.08,
        protocol="dynatrust",
        bursty_traffic=True,
        drift_round=50,
        **candidate,
    )
    for attack in attacks:
        for seed in seeds:
            cfg = replace(base, attack_type=attack, seed=seed)
            sim = WSNSimulator(cfg)
            summary = summarize_metrics(sim.run())
            rows.append(summary)

    pdr = avg(rows, "overall_pdr")
    first = avg(rows, "first_node_dead") / base.rounds
    half = avg(rows, "half_nodes_dead") / base.rounds
    mean_alive = avg(rows, "mean_alive_nodes") / base.node_count
    final_alive = avg(rows, "final_alive_nodes") / base.node_count
    malicious_heads = avg(rows, "mean_malicious_heads")
    isolated_malicious = avg(rows, "final_isolated_malicious_nodes")
    score = (
        0.36 * pdr
        + 0.20 * first
        + 0.12 * half
        + 0.16 * mean_alive
        + 0.06 * final_alive
        + 0.06 * min(1.0, isolated_malicious / 4.0)
        - 0.04 * min(1.0, malicious_heads)
    )
    return {
        "score": score,
        "pdr": pdr,
        "first_node_dead_norm": first,
        "half_nodes_dead_norm": half,
        "mean_alive_norm": mean_alive,
        "final_alive_norm": final_alive,
        "malicious_heads": malicious_heads,
        "isolated_malicious": isolated_malicious,
        **candidate,
    }


def avg(rows: list[dict], key: str) -> float:
    vals = [row.get(key) for row in rows if row.get(key) is not None]
    return sum(float(value) for value in vals) / len(vals) if vals else 0.0


def main() -> None:
    RESULTS.mkdir(parents=True, exist_ok=True)
    rng = Random(20260514)
    seeds = [7, 19]
    attacks = ["blackhole", "selective", "mixed"]
    candidates = [
        {
            "dynatrust_weights": SimulationConfig.dynatrust_weights,
            "dynatrust_drift_gains": SimulationConfig.dynatrust_drift_gains,
            "route_weights": SimulationConfig.route_weights,
            "survival_threshold": SimulationConfig.survival_threshold,
        }
    ]
    candidates.extend(sample_candidate(rng) for _ in range(8))

    results = []
    for idx, candidate in enumerate(candidates):
        result = evaluate(candidate, seeds, attacks)
        result["candidate"] = idx
        results.append(result)
        print(
            f"candidate={idx:02d} score={result['score']:.4f} "
            f"pdr={result['pdr']:.4f} first={result['first_node_dead_norm']:.3f} "
            f"mean_alive={result['mean_alive_norm']:.3f}",
            flush=True,
        )

    results.sort(key=lambda row: row["score"], reverse=True)
    write_csv(OUT, results)
    best = results[0]
    BEST.write_text(json.dumps(best, indent=2), encoding="utf-8")
    print()
    print(f"Best candidate: {best['candidate']} score={best['score']:.4f}")
    print(f"Wrote {OUT}")
    print(f"Wrote {BEST}")


def write_csv(path: Path, rows: list[dict]) -> None:
    fieldnames = [
        "candidate",
        "score",
        "pdr",
        "first_node_dead_norm",
        "half_nodes_dead_norm",
        "mean_alive_norm",
        "final_alive_norm",
        "malicious_heads",
        "isolated_malicious",
        "dynatrust_weights",
        "dynatrust_drift_gains",
        "route_weights",
        "survival_threshold",
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


if __name__ == "__main__":
    main()
