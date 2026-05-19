from __future__ import annotations

from dataclasses import dataclass, field
from math import hypot, sqrt
from random import Random
from statistics import mean
from typing import Iterable


PACKET_BITS = 4000
E_ELEC = 50e-9
E_FS = 10e-12
E_MP = 0.0013e-12
E_DA = 5e-9
D0 = sqrt(E_FS / E_MP)


@dataclass
class Node:
    node_id: int
    x: float
    y: float
    energy: float
    initial_energy: float
    malicious: bool = False
    attack_type: str = "none"
    trust: float = 0.85
    risk: float = 0.10
    queue_load: float = 0.0
    head_count: int = 0
    expected_forward: int = 0
    successful_forward: int = 0
    recent_delivery: list[float] = field(default_factory=list)
    recent_energy: list[float] = field(default_factory=list)
    isolated: bool = False

    @property
    def alive(self) -> bool:
        return self.energy > 0

    @property
    def energy_ratio(self) -> float:
        if self.initial_energy <= 0:
            return 0.0
        return clamp(self.energy / self.initial_energy)


@dataclass
class SimulationConfig:
    node_count: int = 100
    field_size: float = 100.0
    sink_x: float = 50.0
    sink_y: float = 125.0
    initial_energy: float = 0.5
    heterogeneity: float = 0.15
    cluster_head_ratio: float = 0.08
    malicious_ratio: float = 0.10
    attack_type: str = "mixed"
    rounds: int = 120
    seed: int = 7
    protocol: str = "dynatrust"
    bursty_traffic: bool = True
    drift_round: int = 50
    dynatrust_weights: tuple[float, float, float, float, float, float, float] = (
        0.31, 0.18, 0.13, 0.08, 0.06, 0.06, 0.14
    )
    dynatrust_drift_gains: tuple[float, float, float, float] = (-0.06, 0.12, 0.10, 0.04)
    route_weights: tuple[float, float, float, float, float, float, float, float] = (
        0.22, 0.20, 0.18, 0.14, 0.10, 0.06, 0.05, 0.05
    )
    survival_threshold: float = 0.55


@dataclass
class RoundMetrics:
    round_id: int
    alive_nodes: int
    delivered_packets: int
    generated_packets: int
    packet_delivery_ratio: float
    avg_energy: float
    first_node_dead: int | None
    half_nodes_dead: int | None
    malicious_heads: int
    isolated_nodes: int
    isolated_malicious_nodes: int
    drift_level: float
    avg_trust: float


class WSNSimulator:
    def __init__(self, config: SimulationConfig):
        self.config = config
        self.rng = Random(config.seed)
        self.nodes = self._make_nodes()
        self.metrics: list[RoundMetrics] = []
        self.explanations: list[dict] = []
        self.route_trust: dict[tuple[int, int], float] = {}
        self.first_node_dead: int | None = None
        self.half_nodes_dead: int | None = None

    def _make_nodes(self) -> list[Node]:
        nodes: list[Node] = []
        malicious_ids = set(self.rng.sample(
            range(self.config.node_count),
            int(self.config.node_count * self.config.malicious_ratio),
        ))
        for node_id in range(self.config.node_count):
            initial_energy = self.config.initial_energy * self.rng.uniform(
                1.0 - self.config.heterogeneity,
                1.0 + self.config.heterogeneity,
            )
            attack_type = "none"
            if node_id in malicious_ids:
                attack_type = self._choose_attack_type()
            nodes.append(Node(
                node_id=node_id,
                x=self.rng.uniform(0, self.config.field_size),
                y=self.rng.uniform(0, self.config.field_size),
                energy=initial_energy,
                initial_energy=initial_energy,
                malicious=node_id in malicious_ids,
                attack_type=attack_type,
            ))
        return nodes

    def _choose_attack_type(self) -> str:
        if self.config.attack_type != "mixed":
            return self.config.attack_type
        return self.rng.choice(["blackhole", "selective", "sinkhole"])

    def run(self) -> list[RoundMetrics]:
        for round_id in range(self.config.rounds):
            alive = [node for node in self.nodes if node.alive and not node.isolated]
            if not alive:
                break

            self._update_load(round_id)
            drift_level = self._network_drift_level(round_id)
            heads = self._select_cluster_heads(round_id, alive, drift_level)
            assignments = self._assign_members(alive, heads)
            delivered, generated, malicious_heads = self._communicate(round_id, heads, assignments)
            self._update_lifecycle_markers(round_id)

            alive_nodes = sum(1 for node in self.nodes if node.alive)
            avg_energy = mean([node.energy for node in self.nodes])
            avg_trust = mean([node.trust for node in self.nodes if node.alive] or [0.0])
            pdr = delivered / generated if generated else 0.0
            self.metrics.append(RoundMetrics(
                round_id=round_id,
                alive_nodes=alive_nodes,
                delivered_packets=delivered,
                generated_packets=generated,
                packet_delivery_ratio=pdr,
                avg_energy=avg_energy,
                first_node_dead=self.first_node_dead,
                half_nodes_dead=self.half_nodes_dead,
                malicious_heads=malicious_heads,
                isolated_nodes=sum(1 for node in self.nodes if node.isolated),
                isolated_malicious_nodes=sum(1 for node in self.nodes if node.isolated and node.malicious),
                drift_level=drift_level,
                avg_trust=avg_trust,
            ))

        return self.metrics

    def _update_load(self, round_id: int) -> None:
        for node in self.nodes:
            if not node.alive:
                node.queue_load = 0.0
                continue
            base = self.rng.uniform(0.1, 0.45)
            if self.config.bursty_traffic and round_id >= self.config.drift_round:
                burst = self.rng.uniform(0.2, 0.65)
                node.queue_load = clamp(base + burst)
            else:
                node.queue_load = base

    def _network_drift_level(self, round_id: int) -> float:
        if not self.metrics:
            return 0.0
        recent = self.metrics[-5:]
        pdr_now = mean([m.packet_delivery_ratio for m in recent])
        energy_now = mean([m.avg_energy for m in recent])
        pdr_change = abs(pdr_now - self.metrics[-1].packet_delivery_ratio)
        initial_avg = mean([node.initial_energy for node in self.nodes])
        energy_drop = clamp((initial_avg - energy_now) / max(initial_avg, 1e-9))
        traffic_shift = 0.35 if self.config.bursty_traffic and round_id >= self.config.drift_round else 0.0
        return clamp(0.45 * pdr_change + 0.35 * energy_drop + traffic_shift)

    def _select_cluster_heads(self, round_id: int, alive: list[Node], drift_level: float) -> list[Node]:
        head_count = max(1, int(len(alive) * self.config.cluster_head_ratio))
        protocol = self.config.protocol.lower()

        if protocol == "leach":
            candidates = alive[:]
            self.rng.shuffle(candidates)
            heads = candidates[:head_count]
        elif protocol == "energy":
            heads = sorted(alive, key=self._energy_score, reverse=True)[:head_count]
        elif protocol == "trust":
            heads = sorted(alive, key=lambda node: node.trust, reverse=True)[:head_count]
        elif protocol == "hybrid":
            heads = sorted(alive, key=lambda node: self._hybrid_score(node, alive), reverse=True)[:head_count]
        elif protocol == "dynatrust":
            scored = [(self._dynatrust_score(node, alive, drift_level), node) for node in alive]
            heads = [node for _, node in sorted(scored, key=lambda pair: pair[0], reverse=True)[:head_count]]
            self._record_explanations(round_id, heads, alive, drift_level)
        else:
            raise ValueError(f"Unknown protocol: {self.config.protocol}")

        for head in heads:
            head.head_count += 1
        return heads

    def _energy_score(self, node: Node) -> float:
        sink_distance = distance_to_sink(node, self.config)
        proximity = 1.0 - clamp(sink_distance / (self.config.field_size * 1.8))
        return 0.75 * node.energy_ratio + 0.25 * proximity

    def _hybrid_score(self, node: Node, alive: list[Node]) -> float:
        sink_distance = distance_to_sink(node, self.config)
        proximity = 1.0 - clamp(sink_distance / (self.config.field_size * 1.8))
        centrality = self._centrality(node, alive)
        fairness = 1.0 / (1.0 + node.head_count)
        return clamp(
            0.34 * node.energy_ratio
            + 0.28 * node.trust
            + 0.16 * (1.0 - node.risk)
            + 0.10 * proximity
            + 0.06 * centrality
            + 0.06 * fairness
        )

    def _dynatrust_score(self, node: Node, alive: list[Node], drift_level: float) -> float:
        energy = node.energy_ratio
        trust = node.trust
        risk = 1.0 - node.risk
        centrality = self._centrality(node, alive)
        sink_proximity = 1.0 - clamp(distance_to_sink(node, self.config) / (self.config.field_size * 1.8))
        load = 1.0 - node.queue_load
        fairness = 1.0 / (1.0 + node.head_count)

        base_energy, base_trust, base_risk, centrality_w, sink_w, load_w, base_fairness = self.config.dynatrust_weights
        drift_energy, drift_trust, drift_risk, drift_fairness = self.config.dynatrust_drift_gains
        alive_ratio = len(alive) / max(1, self.config.node_count)
        survival_pressure = clamp((self.config.survival_threshold - alive_ratio) / max(self.config.survival_threshold, 1e-9))
        trust_weight = base_trust + drift_trust * drift_level
        risk_weight = base_risk + drift_risk * drift_level
        energy_weight = base_energy + drift_energy * drift_level + 0.10 * survival_pressure
        fairness_weight = base_fairness + drift_fairness * drift_level + 0.10 * survival_pressure
        load_weight = load_w + 0.05 * survival_pressure
        score = (
            energy_weight * energy
            + trust_weight * trust
            + risk_weight * risk
            + centrality_w * centrality
            + sink_w * sink_proximity
            + load_weight * load
            + fairness_weight * fairness
        )
        return clamp(score)

    def _centrality(self, node: Node, alive: list[Node]) -> float:
        if len(alive) <= 1:
            return 1.0
        sample = alive if len(alive) <= 25 else self.rng.sample(alive, 25)
        avg_distance = mean([distance(node, other) for other in sample if other.node_id != node.node_id] or [0.0])
        return 1.0 - clamp(avg_distance / (self.config.field_size * 1.414))

    def _record_explanations(self, round_id: int, heads: list[Node], alive: list[Node], drift_level: float) -> None:
        for head in heads[:5]:
            factors = {
                "energy": head.energy_ratio,
                "trust": head.trust,
                "low_risk": 1.0 - head.risk,
                "centrality": self._centrality(head, alive),
                "sink_proximity": 1.0 - clamp(distance_to_sink(head, self.config) / (self.config.field_size * 1.8)),
                "low_load": 1.0 - head.queue_load,
                "fairness": 1.0 / (1.0 + head.head_count),
            }
            top = sorted(factors.items(), key=lambda item: item[1], reverse=True)[:3]
            self.explanations.append({
                "round": round_id,
                "node": head.node_id,
                "malicious": head.malicious,
                "attack_type": head.attack_type,
                "drift_level": round(drift_level, 4),
                "score": round(self._dynatrust_score(head, alive, drift_level), 4),
                "top_reasons": [{"factor": key, "value": round(value, 4)} for key, value in top],
            })

    def _assign_members(self, alive: list[Node], heads: list[Node]) -> dict[int, list[Node]]:
        assignments = {head.node_id: [] for head in heads}
        for node in alive:
            if node.node_id in assignments:
                continue
            if self.config.protocol.lower() == "dynatrust":
                chosen = max(
                    heads,
                    key=lambda head: self._route_score(node, head, len(assignments[head.node_id]), len(alive), len(heads)),
                )
            else:
                chosen = min(heads, key=lambda head: distance(node, head))
            assignments[chosen.node_id].append(node)
        return assignments

    def _route_score(self, member: Node, head: Node, assigned_count: int, alive_count: int, head_count: int) -> float:
        expected_cluster_size = max(1.0, alive_count / max(1, head_count))
        link_quality = self._link_quality_value(member, head)
        route_memory = self.route_trust.get((member.node_id, head.node_id), 0.78)
        member_cost = 1.0 - clamp(distance(member, head) / (self.config.field_size * 1.414))
        sink_cost = 1.0 - clamp(distance_to_sink(head, self.config) / (self.config.field_size * 1.8))
        load_balance = 1.0 - clamp(assigned_count / expected_cluster_size)
        energy_w, trust_w, risk_w, link_w, route_memory_w, member_w, sink_w, load_w = self.config.route_weights
        return clamp(
            energy_w * head.energy_ratio
            + trust_w * head.trust
            + risk_w * (1.0 - head.risk)
            + link_w * link_quality
            + route_memory_w * route_memory
            + member_w * member_cost
            + sink_w * sink_cost
            + load_w * load_balance
        )

    def _communicate(self, round_id: int, heads: list[Node], assignments: dict[int, list[Node]]) -> tuple[int, int, int]:
        delivered = 0
        generated = 0
        malicious_heads = sum(1 for head in heads if head.malicious)
        head_by_id = {head.node_id: head for head in heads}

        for head_id, members in assignments.items():
            head = head_by_id[head_id]
            member_link_successes = 0
            expected_link_quality = 0.0

            for member in members:
                if not member.alive:
                    continue
                generated += 1
                self._tx(member, distance(member, head))
                self._rx(head)
                expected_link_quality += self._link_quality_value(member, head)
                link_success = self._link_success(member, head)
                self._update_route_trust(member, head, link_success)
                if link_success:
                    member_link_successes += 1

            head_forwarded = False
            if head.alive:
                generated += 1
                self._aggregate(head, max(1, member_link_successes))
                self._tx(head, distance_to_sink(head, self.config))
                head_forwarded = self._head_forwards(head)
                if head_forwarded:
                    delivered += member_link_successes + 1

            if members:
                member_count = len(members)
                member_link_ratio = member_link_successes / member_count
                expected_quality = expected_link_quality / member_count
            else:
                member_link_ratio = 1.0
                expected_quality = 1.0
            self._update_head_trust(head, member_link_ratio, expected_quality, head_forwarded, round_id)

        for node in self.nodes:
            if node.alive:
                node.recent_energy.append(node.energy)
                node.recent_energy = node.recent_energy[-8:]

        return delivered, generated, malicious_heads

    def _link_success(self, member: Node, head: Node) -> bool:
        return self.rng.random() < self._link_quality_value(member, head)

    def _link_quality_value(self, member: Node, head: Node) -> float:
        d = distance(member, head)
        quality = clamp(1.0 - (d / (self.config.field_size * 1.6)) ** 2)
        return max(0.72, quality)

    def _update_route_trust(self, member: Node, head: Node, success: bool) -> None:
        key = (member.node_id, head.node_id)
        current = self.route_trust.get(key, 0.78)
        observation = 1.0 if success else 0.0
        self.route_trust[key] = clamp(0.82 * current + 0.18 * observation)

    def _head_forwards(self, head: Node) -> bool:
        if not head.malicious:
            return True
        if head.attack_type == "blackhole":
            return False
        if head.attack_type == "selective":
            return self.rng.random() > 0.55
        if head.attack_type == "sinkhole":
            return self.rng.random() > 0.35
        return True

    def _update_head_trust(
        self,
        head: Node,
        member_link_ratio: float,
        expected_link_quality: float,
        head_forwarded: bool,
        round_id: int,
    ) -> None:
        head.expected_forward += 1
        head.successful_forward += 1 if head_forwarded else 0
        observed_delivery = member_link_ratio if head_forwarded else 0.0
        head.recent_delivery.append(observed_delivery)
        head.recent_delivery = head.recent_delivery[-8:]

        forwarding = head.successful_forward / max(1, head.expected_forward)
        recent = mean(head.recent_delivery)
        energy_consistency = self._energy_consistency(head)
        channel_shortfall = clamp(expected_link_quality - member_link_ratio)
        link_health = 1.0 - channel_shortfall
        forwarding_penalty = 0.0 if head_forwarded else 1.0
        anomaly = clamp(0.78 * forwarding_penalty + 0.22 * channel_shortfall)
        if head.attack_type == "sinkhole":
            anomaly = clamp(anomaly + 0.10)

        head.trust = clamp(
            0.40 * forwarding
            + 0.24 * recent
            + 0.20 * energy_consistency
            + 0.16 * link_health
            - 0.26 * forwarding_penalty
            - 0.06 * channel_shortfall
        )
        head.risk = clamp(0.58 * head.risk + 0.34 * anomaly + 0.08 * channel_shortfall)
        if (
            self.config.protocol == "dynatrust"
            and head.expected_forward >= 3
            and head.trust < 0.45
            and head.risk > 0.62
        ):
            head.isolated = True

    def _energy_consistency(self, node: Node) -> float:
        if len(node.recent_energy) < 2:
            return 0.9
        drops = [a - b for a, b in zip(node.recent_energy, node.recent_energy[1:])]
        avg_drop = mean([max(0.0, drop) for drop in drops])
        expected_drop = node.initial_energy * 0.015
        return 1.0 - clamp(avg_drop / max(expected_drop, 1e-9))

    def _tx(self, node: Node, d: float, bits: int = PACKET_BITS) -> None:
        if not node.alive:
            return
        amp = E_FS * d * d if d < D0 else E_MP * d ** 4
        node.energy = max(0.0, node.energy - bits * (E_ELEC + amp))

    def _rx(self, node: Node, bits: int = PACKET_BITS) -> None:
        if node.alive:
            node.energy = max(0.0, node.energy - bits * E_ELEC)

    def _aggregate(self, node: Node, packet_count: int, bits: int = PACKET_BITS) -> None:
        if node.alive:
            node.energy = max(0.0, node.energy - packet_count * bits * E_DA)

    def _update_lifecycle_markers(self, round_id: int) -> None:
        dead = sum(1 for node in self.nodes if not node.alive)
        if self.first_node_dead is None and dead > 0:
            self.first_node_dead = round_id
        if self.half_nodes_dead is None and dead >= self.config.node_count / 2:
            self.half_nodes_dead = round_id

    def topology_snapshot(self) -> list[dict]:
        return [
            {
                "node_id": node.node_id,
                "x": round(node.x, 6),
                "y": round(node.y, 6),
                "initial_energy": round(node.initial_energy, 8),
                "malicious": node.malicious,
                "attack_type": node.attack_type,
            }
            for node in self.nodes
        ]


def distance(a: Node, b: Node) -> float:
    return hypot(a.x - b.x, a.y - b.y)


def distance_to_sink(node: Node, config: SimulationConfig) -> float:
    return hypot(node.x - config.sink_x, node.y - config.sink_y)


def clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


def summarize_metrics(metrics: Iterable[RoundMetrics]) -> dict[str, float | int | None]:
    rows = list(metrics)
    if not rows:
        return {}
    generated = sum(row.generated_packets for row in rows)
    delivered = sum(row.delivered_packets for row in rows)
    return {
        "rounds_completed": len(rows),
        "overall_pdr": delivered / generated if generated else 0.0,
        "mean_pdr": mean(row.packet_delivery_ratio for row in rows),
        "mean_alive_nodes": mean(row.alive_nodes for row in rows),
        "final_alive_nodes": rows[-1].alive_nodes,
        "final_avg_energy": rows[-1].avg_energy,
        "first_node_dead": next((row.first_node_dead for row in rows if row.first_node_dead is not None), None),
        "half_nodes_dead": next((row.half_nodes_dead for row in rows if row.half_nodes_dead is not None), None),
        "mean_malicious_heads": mean(row.malicious_heads for row in rows),
        "final_isolated_nodes": rows[-1].isolated_nodes,
        "final_isolated_malicious_nodes": rows[-1].isolated_malicious_nodes,
        "mean_drift_level": mean(row.drift_level for row in rows),
        "final_avg_trust": rows[-1].avg_trust,
    }
