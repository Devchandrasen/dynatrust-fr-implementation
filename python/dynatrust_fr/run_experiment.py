from __future__ import annotations

import csv
import json
import argparse
from dataclasses import replace
from pathlib import Path

from simulator import SimulationConfig, WSNSimulator, summarize_metrics


ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
BEST_WEIGHTS = RESULTS / "best_weights.json"


def run_suite(
    results_dir: Path = RESULTS,
    seed_count: int = 3,
    rounds: int = 300,
    node_count: int = 100,
) -> list[dict]:
    results_dir.mkdir(parents=True, exist_ok=True)
    protocols = ["leach", "energy", "trust", "hybrid", "dynatrust"]
    attacks = ["none", "blackhole", "selective", "sinkhole", "mixed"]
    seeds = make_seeds(seed_count)
    best_weights = load_best_weights()

    rows: list[dict] = []
    explanations: list[dict] = []
    topologies: dict[str, list[dict]] = {}

    base = SimulationConfig(
        node_count=node_count,
        rounds=rounds,
        initial_energy=0.12,
        malicious_ratio=0.10,
        cluster_head_ratio=0.08,
        bursty_traffic=True,
        drift_round=50,
    )

    for attack in attacks:
        for protocol in protocols:
            for seed in seeds:
                malicious_ratio = 0.0 if attack == "none" else base.malicious_ratio
                cfg = replace(
                    base,
                    attack_type=attack,
                    protocol=protocol,
                    seed=seed,
                    malicious_ratio=malicious_ratio,
                    **(best_weights if protocol == "dynatrust" else {}),
                )
                sim = WSNSimulator(cfg)
                topology_key = f"{attack}_{seed}"
                if protocol == protocols[0]:
                    topologies[topology_key] = sim.topology_snapshot()
                metrics = sim.run()
                summary = summarize_metrics(metrics)
                row = {
                    "protocol": protocol,
                    "attack": attack,
                    "seed": seed,
                    **summary,
                }
                rows.append(row)
                if protocol == "dynatrust":
                    explanations.extend({
                        "attack": attack,
                        "seed": seed,
                        **item,
                    } for item in sim.explanations[:60])

    write_csv(results_dir / "summary.csv", rows)
    (results_dir / "summary.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
    (results_dir / "explanations.json").write_text(json.dumps(explanations, indent=2), encoding="utf-8")
    (results_dir / "topologies.json").write_text(json.dumps(topologies, indent=2), encoding="utf-8")
    return rows


def write_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fieldnames = list(rows[0].keys())
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def aggregate(rows: list[dict]) -> list[dict]:
    groups: dict[tuple[str, str], list[dict]] = {}
    for row in rows:
        groups.setdefault((row["attack"], row["protocol"]), []).append(row)

    aggregate_rows: list[dict] = []
    for (attack, protocol), group in sorted(groups.items()):
        aggregate_rows.append({
            "attack": attack,
            "protocol": protocol,
            "mean_overall_pdr": avg(group, "overall_pdr"),
            "mean_alive_nodes": avg(group, "mean_alive_nodes"),
            "mean_final_alive_nodes": avg(group, "final_alive_nodes"),
            "mean_final_avg_energy": avg(group, "final_avg_energy"),
            "mean_first_node_dead": avg_optional(group, "first_node_dead"),
            "mean_half_nodes_dead": avg_optional(group, "half_nodes_dead"),
            "mean_malicious_heads": avg(group, "mean_malicious_heads"),
            "mean_final_isolated_nodes": avg(group, "final_isolated_nodes"),
            "mean_final_isolated_malicious_nodes": avg(group, "final_isolated_malicious_nodes"),
            "mean_final_avg_trust": avg(group, "final_avg_trust"),
        })
    return aggregate_rows


def load_best_weights() -> dict:
    if not BEST_WEIGHTS.exists():
        return {}
    data = json.loads(BEST_WEIGHTS.read_text(encoding="utf-8"))
    return {
        "dynatrust_weights": tuple(data["dynatrust_weights"]),
        "dynatrust_drift_gains": tuple(data["dynatrust_drift_gains"]),
        "route_weights": tuple(data["route_weights"]),
        "survival_threshold": float(data["survival_threshold"]),
    }


def make_seeds(seed_count: int) -> list[int]:
    base = [7, 19, 31, 43, 59, 71, 83, 97, 109, 127]
    seeds = base[:]
    value = 149
    while len(seeds) < seed_count:
        seeds.append(value)
        value += 18
    return seeds[:seed_count]


def avg(rows: list[dict], key: str) -> float:
    values = [float(row[key]) for row in rows if row.get(key) is not None]
    return sum(values) / len(values) if values else 0.0


def avg_optional(rows: list[dict], key: str) -> float | None:
    values = [float(row[key]) for row in rows if row.get(key) is not None]
    return sum(values) / len(values) if values else None


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seeds", type=int, default=3)
    parser.add_argument("--rounds", type=int, default=300)
    parser.add_argument("--nodes", type=int, default=100)
    parser.add_argument("--out", type=Path, default=RESULTS)
    args = parser.parse_args()

    rows = run_suite(
        results_dir=args.out,
        seed_count=args.seeds,
        rounds=args.rounds,
        node_count=args.nodes,
    )
    aggregate_rows = aggregate(rows)
    write_csv(args.out / "aggregate.csv", aggregate_rows)
    print("Wrote:")
    print(f"- {args.out / 'summary.csv'}")
    print(f"- {args.out / 'aggregate.csv'}")
    print(f"- {args.out / 'summary.json'}")
    print(f"- {args.out / 'explanations.json'}")
    print(f"- {args.out / 'topologies.json'}")
    print()
    print("Aggregate results:")
    for row in aggregate_rows:
        print(
            f"{row['attack']:10s} {row['protocol']:10s} "
            f"PDR={row['mean_overall_pdr']:.3f} "
            f"mean_alive={row['mean_alive_nodes']:.1f} "
            f"alive={row['mean_final_alive_nodes']:.1f} "
            f"energy={row['mean_final_avg_energy']:.4f} "
            f"FND={format_metric(row['mean_first_node_dead'])} "
            f"HND={format_metric(row['mean_half_nodes_dead'])} "
            f"mal_heads={row['mean_malicious_heads']:.2f} "
            f"iso={row['mean_final_isolated_nodes']:.1f}"
        )


def format_metric(value: float | None) -> str:
    return "NA" if value is None else f"{value:.1f}"


if __name__ == "__main__":
    main()
