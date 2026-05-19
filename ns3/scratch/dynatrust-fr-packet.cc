#include "ns3/core-module.h"
#include "ns3/energy-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/network-module.h"
#include "ns3/wifi-module.h"

#include <algorithm>
#include <cmath>
#include <iomanip>
#include <iostream>
#include <numeric>
#include <random>
#include <sstream>
#include <string>
#include <vector>

using namespace ns3;
using namespace ns3::energy;

namespace
{
constexpr uint16_t CH_PORT = 9100;
constexpr uint16_t SINK_PORT = 9200;
constexpr uint32_t MSG_SENSOR_REPORT = 1;
constexpr uint32_t MSG_AGGREGATE = 2;
} // namespace

class DynaTrustPacketHeader : public Header
{
  public:
    DynaTrustPacketHeader() = default;

    static TypeId GetTypeId()
    {
        static TypeId tid = TypeId("ns3::DynaTrustPacketHeader")
                                .SetParent<Header>()
                                .AddConstructor<DynaTrustPacketHeader>();
        return tid;
    }

    TypeId GetInstanceTypeId() const override
    {
        return GetTypeId();
    }

    void Set(uint32_t type, uint32_t round, uint32_t origin, uint32_t reports, uint32_t corrupted)
    {
        m_type = type;
        m_round = round;
        m_origin = origin;
        m_reports = reports;
        m_corrupted = corrupted;
    }

    uint32_t GetType() const
    {
        return m_type;
    }

    uint32_t GetRound() const
    {
        return m_round;
    }

    uint32_t GetOrigin() const
    {
        return m_origin;
    }

    uint32_t GetReports() const
    {
        return m_reports;
    }

    uint32_t GetCorrupted() const
    {
        return m_corrupted;
    }

    uint32_t GetSerializedSize() const override
    {
        return 20;
    }

    void Serialize(Buffer::Iterator start) const override
    {
        start.WriteHtonU32(m_type);
        start.WriteHtonU32(m_round);
        start.WriteHtonU32(m_origin);
        start.WriteHtonU32(m_reports);
        start.WriteHtonU32(m_corrupted);
    }

    uint32_t Deserialize(Buffer::Iterator start) override
    {
        m_type = start.ReadNtohU32();
        m_round = start.ReadNtohU32();
        m_origin = start.ReadNtohU32();
        m_reports = start.ReadNtohU32();
        m_corrupted = start.ReadNtohU32();
        return GetSerializedSize();
    }

    void Print(std::ostream& os) const override
    {
        os << "type=" << m_type << " round=" << m_round << " origin=" << m_origin
           << " reports=" << m_reports << " corrupted=" << m_corrupted;
    }

  private:
    uint32_t m_type{0};
    uint32_t m_round{0};
    uint32_t m_origin{0};
    uint32_t m_reports{0};
    uint32_t m_corrupted{0};
};

NS_OBJECT_ENSURE_REGISTERED(DynaTrustPacketHeader);

struct NodeState
{
    bool malicious{false};
    double trust{0.55};
    double virtualEnergyJ{1.0};
    uint32_t selectedAsHead{0};
    Ptr<BasicEnergySource> energy;
};

struct HeadBuffer
{
    uint32_t reports{0};
    uint32_t corrupted{0};
};

struct RoundStats
{
    uint32_t generatedReports{0};
    uint32_t receivedAtHeads{0};
    uint32_t quarantinedReports{0};
    uint32_t quarantinedHonestReports{0};
    uint32_t quarantinedMaliciousReports{0};
    uint32_t expectedAggregates{0};
    uint32_t sinkAggregates{0};
    uint32_t deliveredReports{0};
    uint32_t corruptedReports{0};
    uint32_t compromisedHeads{0};
    double meanTrust{0.0};
    double meanEnergy{0.0};
    double energyJain{0.0};
    double chJain{0.0};
    uint32_t aliveNodes{0};
};

struct ExperimentContext
{
    uint32_t nodes{36};
    uint32_t rounds{12};
    uint32_t headsPerRound{4};
    uint32_t seed{19};
    double maliciousRatio{0.2};
    double initialEnergyJ{1.0};
    double roundDuration{1.0};
    double maliciousDropProbability{0.65};
    double maliciousCorruptProbability{0.70};
    double trustPoisoningStrength{0.35};
    double benignReportLossProbability{0.0};
    double benignAggregateLossProbability{0.0};
    double benignCorruptProbability{0.0};
    double benignEvidenceErrorProbability{0.0};
    double mobilitySpeed{1.0};
    double recommendationTrimFraction{0.20};
    double recommendationClipRadius{0.20};
    double recommendationResidualScale{0.0};
    double trustUpdateStep{0.28};
    double filterTrustThreshold{0.45};
    double headTrustThreshold{0.38};
    double dynatrustTrustWeight{0.58};
    double dynatrustEnergyWeight{0.24};
    double dynatrustFairnessWeight{0.10};
    double dynatrustCentralityWeight{0.05};
    double dynatrustDiversityWeight{0.04};
    double sensorReportCostJ{0.0010};
    double headReceiveCostJ{0.0004};
    double aggregateTxCostJ{0.0025};
    double clusterHeadRoundCostJ{0.0015};
    double trustUpdateCostJ{0.0001};
    double txCurrentA{0.020};
    double rxCurrentA{0.012};
    double idleCurrentA{0.001};
    std::string policy{"dynatrust"};
    std::string mobilityMode{"static"};
    std::string attackMode{"fixed"};
    uint32_t onOffPeriod{4};
    uint32_t strategicWarmupRounds{3};
    double strategicTrustThreshold{0.58};

    NodeContainer sensors;
    NodeContainer allNodes;
    Ipv4InterfaceContainer interfaces;
    std::vector<Ptr<Socket>> sockets;
    std::vector<NodeState> state;
    std::vector<RoundStats> stats;
    std::vector<HeadBuffer> headBuffers;
    std::vector<uint32_t> currentHeads;
    std::vector<bool> isHead;
    Ptr<UniformRandomVariable> rng;
};

static double
Clamp(double value, double low, double high)
{
    return std::max(low, std::min(value, high));
}

static bool TrustAwarePolicy(const std::string& policy);
static bool RobustAggregationPolicy(const std::string& policy);

static bool
MaliciousActionActive(const ExperimentContext* ctx, uint32_t nodeId, uint32_t round, bool asHead)
{
    if (!ctx->state[nodeId].malicious)
    {
        return false;
    }
    if (ctx->attackMode == "on-off")
    {
        const uint32_t period = std::max<uint32_t>(2, ctx->onOffPeriod);
        return (round % period) >= (period / 2);
    }
    if (ctx->attackMode == "strategic")
    {
        if (round < ctx->strategicWarmupRounds)
        {
            return false;
        }
        const bool trustAware = TrustAwarePolicy(ctx->policy);
        return asHead && (!trustAware || ctx->state[nodeId].trust >= ctx->strategicTrustThreshold);
    }
    return true;
}

static double
RecommendationAttackFactor(const ExperimentContext* ctx, uint32_t round)
{
    if (ctx->attackMode == "on-off")
    {
        const uint32_t period = std::max<uint32_t>(2, ctx->onOffPeriod);
        return (round % period) >= (period / 2) ? 1.0 : 0.0;
    }
    if (ctx->attackMode == "strategic")
    {
        return round >= ctx->strategicWarmupRounds ? 0.75 : 0.0;
    }
    return 1.0;
}

static double
DirectBehaviorEvidence(const ExperimentContext* ctx, uint32_t nodeId, uint32_t round)
{
    if (!ctx->state[nodeId].malicious)
    {
        if (ctx->benignEvidenceErrorProbability > 0.0 &&
            ctx->rng->GetValue() < ctx->benignEvidenceErrorProbability)
        {
            return 0.18;
        }
        return 0.92;
    }
    if (ctx->attackMode == "strategic")
    {
        return MaliciousActionActive(ctx, nodeId, round, ctx->isHead[nodeId]) ? 0.05 : 0.84;
    }
    return MaliciousActionActive(ctx, nodeId, round, ctx->isHead[nodeId]) ? 0.18 : 0.84;
}

static bool
TrustAwarePolicy(const std::string& policy)
{
    return policy == "dynatrust" || policy == "trust" || policy == "dynatrust-no-filter" ||
           policy == "dynatrust-no-diversity" || policy == "dynatrust-no-fairness" ||
           policy == "dynatrust-no-robust" || policy == "trust-leach" ||
           policy == "robust-reputation" || policy == "quarantine-only";
}

static bool
RobustAggregationPolicy(const std::string& policy)
{
    return policy == "dynatrust" || policy == "dynatrust-no-filter" ||
           policy == "dynatrust-no-diversity" || policy == "dynatrust-no-fairness" ||
           policy == "robust-reputation";
}

static double
RobustRecommendationBias(const ExperimentContext* ctx, uint32_t round)
{
    const double alpha = Clamp(ctx->recommendationTrimFraction, 0.0, 0.45);
    const double theta = Clamp(ctx->maliciousRatio * RecommendationAttackFactor(ctx, round), 0.0, 0.90);
    const double retainedAdversarialMass =
        std::max(0.0, theta - alpha) / std::max(1.0e-9, 1.0 - (2.0 * alpha));
    return ctx->recommendationResidualScale * ctx->trustPoisoningStrength *
           ctx->recommendationClipRadius *
           Clamp(retainedAdversarialMass, 0.0, 1.0);
}

static double
EnergyFraction(const ExperimentContext* ctx, uint32_t nodeId)
{
    double remaining = ctx->state[nodeId].virtualEnergyJ;
    if (!ctx->state[nodeId].energy)
    {
        return Clamp(remaining / ctx->initialEnergyJ, 0.0, 1.0);
    }
    remaining = std::min(remaining, ctx->state[nodeId].energy->GetRemainingEnergy());
    return Clamp(remaining / ctx->initialEnergyJ, 0.0, 1.0);
}

static void
ConsumeEnergy(ExperimentContext* ctx, uint32_t nodeId, double joules)
{
    if (nodeId >= ctx->nodes)
    {
        return;
    }
    ctx->state[nodeId].virtualEnergyJ = Clamp(ctx->state[nodeId].virtualEnergyJ - joules,
                                              0.0,
                                              ctx->initialEnergyJ);
}

static std::string
JoinHeads(const std::vector<uint32_t>& heads)
{
    std::ostringstream out;
    for (size_t i = 0; i < heads.size(); ++i)
    {
        if (i > 0)
        {
            out << "|";
        }
        out << heads[i];
    }
    return out.str();
}

static uint32_t
NearestHead(const ExperimentContext* ctx, uint32_t nodeId)
{
    Ptr<MobilityModel> nodeMobility = ctx->sensors.Get(nodeId)->GetObject<MobilityModel>();
    double bestDistance = std::numeric_limits<double>::max();
    uint32_t bestHead = ctx->currentHeads.front();

    for (uint32_t head : ctx->currentHeads)
    {
        Ptr<MobilityModel> headMobility = ctx->sensors.Get(head)->GetObject<MobilityModel>();
        const double distance = nodeMobility->GetDistanceFrom(headMobility);
        if (distance < bestDistance)
        {
            bestDistance = distance;
            bestHead = head;
        }
    }
    return bestHead;
}

static double
MaxSensorDistance(const ExperimentContext* ctx)
{
    double maxDistance = 1.0;
    for (uint32_t i = 0; i < ctx->nodes; ++i)
    {
        Ptr<MobilityModel> lhs = ctx->sensors.Get(i)->GetObject<MobilityModel>();
        for (uint32_t j = i + 1; j < ctx->nodes; ++j)
        {
            Ptr<MobilityModel> rhs = ctx->sensors.Get(j)->GetObject<MobilityModel>();
            maxDistance = std::max(maxDistance, lhs->GetDistanceFrom(rhs));
        }
    }
    return maxDistance;
}

static double
CentralityScore(const ExperimentContext* ctx, uint32_t nodeId, double maxDistance)
{
    Ptr<MobilityModel> nodeMobility = ctx->sensors.Get(nodeId)->GetObject<MobilityModel>();
    double distanceSum = 0.0;
    for (uint32_t other = 0; other < ctx->nodes; ++other)
    {
        Ptr<MobilityModel> otherMobility = ctx->sensors.Get(other)->GetObject<MobilityModel>();
        distanceSum += nodeMobility->GetDistanceFrom(otherMobility);
    }
    const double meanDistance = distanceSum / ctx->nodes;
    return Clamp(1.0 - (meanDistance / maxDistance), 0.0, 1.0);
}

static double
DiversityScore(const ExperimentContext* ctx,
               uint32_t nodeId,
               const std::vector<uint32_t>& selectedHeads,
               double maxDistance)
{
    if (selectedHeads.empty())
    {
        return 1.0;
    }

    Ptr<MobilityModel> nodeMobility = ctx->sensors.Get(nodeId)->GetObject<MobilityModel>();
    double minDistance = maxDistance;
    for (uint32_t head : selectedHeads)
    {
        Ptr<MobilityModel> headMobility = ctx->sensors.Get(head)->GetObject<MobilityModel>();
        minDistance = std::min(minDistance, nodeMobility->GetDistanceFrom(headMobility));
    }
    return Clamp(minDistance / maxDistance, 0.0, 1.0);
}

static bool
UsesTrust(const std::string& policy)
{
    return TrustAwarePolicy(policy);
}

static bool
UsesFiltering(const std::string& policy)
{
    return policy == "dynatrust" || policy == "trust" || policy == "dynatrust-no-diversity" ||
           policy == "dynatrust-no-fairness" || policy == "dynatrust-no-robust" ||
           policy == "quarantine-only" || policy == "oracle";
}

static bool
UsesFairness(const std::string& policy)
{
    return policy == "dynatrust" || policy == "dynatrust-no-filter" ||
           policy == "dynatrust-no-diversity" || policy == "dynatrust-no-robust" ||
           policy == "leach" || policy == "heed" || policy == "trust-leach" ||
           policy == "robust-reputation" || policy == "quarantine-only" || policy == "oracle";
}

static bool
UsesDiversity(const std::string& policy)
{
    return policy == "dynatrust" || policy == "dynatrust-no-filter" ||
           policy == "dynatrust-no-fairness" || policy == "dynatrust-no-robust";
}

static bool
UsesCentrality(const std::string& policy)
{
    return policy == "dynatrust" || policy == "dynatrust-no-filter" ||
           policy == "dynatrust-no-diversity" || policy == "dynatrust-no-fairness" ||
           policy == "dynatrust-no-robust" || policy == "heed" ||
           policy == "robust-reputation" || policy == "oracle";
}

static std::vector<uint32_t>
SelectClusterHeads(ExperimentContext* ctx)
{
    std::vector<std::pair<double, uint32_t>> scored;
    scored.reserve(ctx->nodes);
    const double maxDistance = MaxSensorDistance(ctx);

    for (uint32_t nodeId = 0; nodeId < ctx->nodes; ++nodeId)
    {
        const auto& node = ctx->state[nodeId];
        const double fairness = 1.0 / (1.0 + node.selectedAsHead);
        const double energy = EnergyFraction(ctx, nodeId);
        const double centrality = CentralityScore(ctx, nodeId, maxDistance);
        double score = energy + 0.02 * ctx->rng->GetValue();
        if (ctx->policy == "leach")
        {
            score = energy + (UsesFairness(ctx->policy) ? 0.20 * fairness : 0.0) +
                    0.03 * ctx->rng->GetValue();
        }
        else if (ctx->policy == "energy")
        {
            score = energy + 0.01 * ctx->rng->GetValue();
        }
        else if (ctx->policy == "trust")
        {
            score = (0.75 * node.trust) + (0.25 * energy);
        }
        else if (ctx->policy == "heed")
        {
            score = (0.62 * energy) + (0.24 * centrality) + (0.10 * fairness) +
                    (0.04 * ctx->rng->GetValue());
        }
        else if (ctx->policy == "trust-leach")
        {
            score = (0.54 * node.trust) + (0.30 * energy) + (0.12 * fairness) +
                    (0.04 * ctx->rng->GetValue());
        }
        else if (ctx->policy == "robust-reputation")
        {
            score = (0.70 * node.trust) + (0.20 * energy) + (0.07 * fairness) +
                    (0.03 * centrality);
        }
        else if (ctx->policy == "quarantine-only")
        {
            score = energy + (0.20 * fairness) + (0.03 * ctx->rng->GetValue());
        }
        else if (ctx->policy == "oracle")
        {
            score = (0.64 * energy) + (0.24 * centrality) + (0.10 * fairness) +
                    (0.02 * ctx->rng->GetValue());
        }
        else
        {
            score = (ctx->dynatrustTrustWeight * node.trust) +
                    (ctx->dynatrustEnergyWeight * energy) +
                    (UsesFairness(ctx->policy) ? ctx->dynatrustFairnessWeight * fairness : 0.0) +
                    (UsesCentrality(ctx->policy) ? ctx->dynatrustCentralityWeight * centrality : 0.0) +
                    (0.03 * ctx->rng->GetValue());
        }
        scored.push_back({score, nodeId});
    }

    std::sort(scored.begin(), scored.end(), [](const auto& lhs, const auto& rhs) {
        if (lhs.first == rhs.first)
        {
            return lhs.second < rhs.second;
        }
        return lhs.first > rhs.first;
    });

    std::vector<uint32_t> heads;
    if (UsesDiversity(ctx->policy))
    {
        std::vector<bool> chosen(ctx->nodes, false);
        while (heads.size() < ctx->headsPerRound)
        {
            double bestScore = -1.0;
            uint32_t bestNode = ctx->nodes;
            for (const auto& [baseScore, nodeId] : scored)
            {
                if (chosen[nodeId] || EnergyFraction(ctx, nodeId) < 0.08 ||
                    (ctx->policy == "oracle" && ctx->state[nodeId].malicious) ||
                    (UsesTrust(ctx->policy) && ctx->state[nodeId].trust < ctx->headTrustThreshold))
                {
                    continue;
                }
                const double score =
                    baseScore +
                    (ctx->dynatrustDiversityWeight * DiversityScore(ctx, nodeId, heads, maxDistance));
                if (score > bestScore)
                {
                    bestScore = score;
                    bestNode = nodeId;
                }
            }
            if (bestNode == ctx->nodes)
            {
                break;
            }
            chosen[bestNode] = true;
            heads.push_back(bestNode);
        }
    }
    else
    {
        for (const auto& [score, nodeId] : scored)
        {
            if (EnergyFraction(ctx, nodeId) < 0.08)
            {
                continue;
            }
            if (ctx->policy == "oracle" && ctx->state[nodeId].malicious)
            {
                continue;
            }
            if (UsesTrust(ctx->policy) && ctx->state[nodeId].trust < ctx->headTrustThreshold)
            {
                continue;
            }
            heads.push_back(nodeId);
            if (heads.size() == ctx->headsPerRound)
            {
                break;
            }
        }
    }

    if (heads.empty())
    {
        heads.push_back(scored.front().second);
    }
    return heads;
}

static void ReceiveAtClusterHead(ExperimentContext* ctx, uint32_t headId, Ptr<Socket> socket)
{
    Address from;
    while (Ptr<Packet> packet = socket->RecvFrom(from))
    {
        DynaTrustPacketHeader header;
        packet->RemoveHeader(header);
        if (header.GetType() != MSG_SENSOR_REPORT || header.GetRound() >= ctx->rounds)
        {
            continue;
        }
        if (!ctx->isHead[headId])
        {
            continue;
        }
        ConsumeEnergy(ctx, headId, ctx->headReceiveCostJ * header.GetReports());
        if (ctx->policy == "oracle" && ctx->state[header.GetOrigin()].malicious)
        {
            ctx->stats[header.GetRound()].quarantinedReports += header.GetReports();
            ctx->stats[header.GetRound()].quarantinedMaliciousReports += header.GetReports();
            continue;
        }
        if (UsesFiltering(ctx->policy) &&
            ctx->state[header.GetOrigin()].trust < ctx->filterTrustThreshold)
        {
            ctx->stats[header.GetRound()].quarantinedReports += header.GetReports();
            if (ctx->state[header.GetOrigin()].malicious)
            {
                ctx->stats[header.GetRound()].quarantinedMaliciousReports += header.GetReports();
            }
            else
            {
                ctx->stats[header.GetRound()].quarantinedHonestReports += header.GetReports();
            }
            continue;
        }
        ctx->headBuffers[headId].reports += header.GetReports();
        ctx->headBuffers[headId].corrupted += header.GetCorrupted();
        ctx->stats[header.GetRound()].receivedAtHeads += header.GetReports();
    }
}

static void ReceiveAtSink(ExperimentContext* ctx, Ptr<Socket> socket)
{
    Address from;
    while (Ptr<Packet> packet = socket->RecvFrom(from))
    {
        DynaTrustPacketHeader header;
        packet->RemoveHeader(header);
        if (header.GetType() != MSG_AGGREGATE || header.GetRound() >= ctx->rounds)
        {
            continue;
        }
        auto& stats = ctx->stats[header.GetRound()];
        stats.sinkAggregates += 1;
        stats.deliveredReports += header.GetReports();
        stats.corruptedReports += header.GetCorrupted();
    }
}

static void SendPacket(ExperimentContext* ctx,
                       uint32_t senderId,
                       Ipv4Address destination,
                       uint16_t port,
                       const DynaTrustPacketHeader& header,
                       uint32_t payloadBytes)
{
    Ptr<Packet> packet = Create<Packet>(payloadBytes);
    packet->AddHeader(header);
    ctx->sockets[senderId]->SendTo(packet, 0, InetSocketAddress(destination, port));
}

static void SendSensorReport(ExperimentContext* ctx, uint32_t nodeId, uint32_t round)
{
    if (ctx->currentHeads.empty() || EnergyFraction(ctx, nodeId) < 0.03)
    {
        return;
    }

    const uint32_t head = NearestHead(ctx, nodeId);
    if (ctx->rng->GetValue() < ctx->benignReportLossProbability)
    {
        ConsumeEnergy(ctx, nodeId, ctx->sensorReportCostJ);
        ctx->stats[round].generatedReports += 1;
        return;
    }
    const uint32_t corrupted = MaliciousActionActive(ctx, nodeId, round, false) ? 1 : 0;
    DynaTrustPacketHeader header;
    header.Set(MSG_SENSOR_REPORT, round, nodeId, 1, corrupted);
    SendPacket(ctx, nodeId, ctx->interfaces.GetAddress(head), CH_PORT, header, 64);
    ConsumeEnergy(ctx, nodeId, ctx->sensorReportCostJ);
    ctx->stats[round].generatedReports += 1;
}

static void TransmitAggregate(ExperimentContext* ctx, uint32_t round, uint32_t head)
{
    const uint32_t sinkId = ctx->nodes;
    const Ipv4Address sinkAddress = ctx->interfaces.GetAddress(sinkId);

    auto& buffer = ctx->headBuffers[head];
    if (buffer.reports == 0)
    {
        return;
    }

    ctx->stats[round].expectedAggregates += 1;
    if (EnergyFraction(ctx, head) < 0.03)
    {
        return;
    }
    bool drop = false;
    uint32_t corrupted = buffer.corrupted;
    if (buffer.reports > 0 && ctx->rng->GetValue() < ctx->benignCorruptProbability)
    {
        corrupted = std::min<uint32_t>(buffer.reports, corrupted + 1);
    }
    if (MaliciousActionActive(ctx, head, round, true))
    {
        drop = ctx->rng->GetValue() < ctx->maliciousDropProbability;
        if (!drop && ctx->rng->GetValue() < ctx->maliciousCorruptProbability)
        {
            corrupted = buffer.reports;
        }
    }

    if (drop)
    {
        return;
    }
    if (ctx->rng->GetValue() < ctx->benignAggregateLossProbability)
    {
        ConsumeEnergy(ctx, head, ctx->aggregateTxCostJ);
        return;
    }

    DynaTrustPacketHeader header;
    header.Set(MSG_AGGREGATE, round, head, buffer.reports, corrupted);
    SendPacket(ctx, head, sinkAddress, SINK_PORT, header, 96);
    ConsumeEnergy(ctx, head, ctx->aggregateTxCostJ);
}

static void SendAggregates(ExperimentContext* ctx, uint32_t round)
{
    uint32_t slot = 0;
    for (uint32_t head : ctx->currentHeads)
    {
        Simulator::Schedule(MilliSeconds(25 * slot), &TransmitAggregate, ctx, round, head);
        ++slot;
    }
}

static void UpdateTrust(ExperimentContext* ctx, uint32_t round)
{
    if (!UsesTrust(ctx->policy))
    {
        return;
    }

    for (uint32_t nodeId = 0; nodeId < ctx->nodes; ++nodeId)
    {
        ConsumeEnergy(ctx, nodeId, ctx->trustUpdateCostJ);
        double behaviorEvidence = DirectBehaviorEvidence(ctx, nodeId, round);
        if (ctx->policy == "trust" || ctx->policy == "dynatrust-no-robust" ||
            ctx->policy == "quarantine-only")
        {
            // Naive trust aggregation accepts poisoned recommendations: malicious recommenders
            // bad-mouth honest nodes and ballot-stuff malicious nodes. DynaTrust-FR's robust
            // aggregation keeps the direct behavior evidence dominant.
            const double poisoning =
                ctx->trustPoisoningStrength * ctx->maliciousRatio * RecommendationAttackFactor(ctx, round);
            behaviorEvidence =
                ctx->state[nodeId].malicious ? Clamp(behaviorEvidence + poisoning, 0.0, 1.0)
                                             : Clamp(behaviorEvidence - poisoning, 0.0, 1.0);
        }
        else if (RobustAggregationPolicy(ctx->policy))
        {
            const double residualBias = RobustRecommendationBias(ctx, round);
            behaviorEvidence =
                ctx->state[nodeId].malicious ? Clamp(behaviorEvidence + residualBias, 0.0, 1.0)
                                             : Clamp(behaviorEvidence - residualBias, 0.0, 1.0);
        }
        const double headPenalty = ctx->isHead[nodeId] && MaliciousActionActive(ctx, nodeId, round, true)
                                       ? 0.05
                                       : behaviorEvidence;
        const double evidence = ctx->isHead[nodeId] ? headPenalty : behaviorEvidence;
        ctx->state[nodeId].trust = Clamp(((1.0 - ctx->trustUpdateStep) * ctx->state[nodeId].trust) +
                                             (ctx->trustUpdateStep * evidence),
                                         0.0,
                                         1.0);
    }
}

static void EndRound(ExperimentContext* ctx, uint32_t round)
{
    auto& stats = ctx->stats[round];
    double energySum = 0.0;
    double energySq = 0.0;
    double headCountSum = 0.0;
    double headCountSq = 0.0;
    for (uint32_t nodeId = 0; nodeId < ctx->nodes; ++nodeId)
    {
        const double energyFraction = EnergyFraction(ctx, nodeId);
        stats.meanTrust += ctx->state[nodeId].trust;
        stats.meanEnergy += energyFraction;
        energySum += energyFraction;
        energySq += energyFraction * energyFraction;

        const double headCount = static_cast<double>(ctx->state[nodeId].selectedAsHead);
        headCountSum += headCount;
        headCountSq += headCount * headCount;

        if (energyFraction > 0.05)
        {
            ++stats.aliveNodes;
        }
    }
    stats.meanTrust /= ctx->nodes;
    stats.meanEnergy /= ctx->nodes;
    stats.energyJain = energySq > 0.0 ? (energySum * energySum) / (ctx->nodes * energySq) : 0.0;
    stats.chJain =
        headCountSq > 0.0 ? (headCountSum * headCountSum) / (ctx->nodes * headCountSq) : 0.0;

    const double pdr = stats.generatedReports == 0
                           ? 0.0
                           : static_cast<double>(stats.deliveredReports) / stats.generatedReports;
    const double cleanPdr =
        stats.generatedReports == 0
            ? 0.0
            : static_cast<double>(stats.deliveredReports - stats.corruptedReports) /
                  stats.generatedReports;
    const double aggregateDelivery =
        stats.expectedAggregates == 0
            ? 0.0
            : static_cast<double>(stats.sinkAggregates) / stats.expectedAggregates;

    std::cout << ctx->policy << "," << round << "," << std::fixed << std::setprecision(2)
              << ctx->maliciousRatio << "," << ctx->attackMode << ",\""
              << JoinHeads(ctx->currentHeads) << "\","
              << stats.compromisedHeads << "," << stats.generatedReports << ","
              << stats.receivedAtHeads << "," << stats.quarantinedReports << ","
              << stats.quarantinedHonestReports << "," << stats.quarantinedMaliciousReports << ","
              << stats.expectedAggregates << "," << stats.sinkAggregates << ","
              << stats.deliveredReports << "," << stats.corruptedReports << ","
              << std::setprecision(4) << pdr << "," << cleanPdr << "," << aggregateDelivery
              << "," << stats.meanTrust << "," << stats.meanEnergy << "," << stats.aliveNodes
              << "," << stats.energyJain << "," << stats.chJain << "\n";

    UpdateTrust(ctx, round);
}

static void StartRound(ExperimentContext* ctx, uint32_t round)
{
    ctx->headBuffers.assign(ctx->nodes, HeadBuffer{});
    ctx->isHead.assign(ctx->nodes, false);
    ctx->currentHeads = SelectClusterHeads(ctx);

    auto& stats = ctx->stats[round];
    for (uint32_t head : ctx->currentHeads)
    {
        ctx->isHead[head] = true;
        ctx->state[head].selectedAsHead += 1;
        if (ctx->state[head].malicious)
        {
            ++stats.compromisedHeads;
        }
        ConsumeEnergy(ctx, head, ctx->clusterHeadRoundCostJ + ctx->sensorReportCostJ);
        ctx->headBuffers[head].reports += 1;
        ctx->headBuffers[head].corrupted += MaliciousActionActive(ctx, head, round, true) ? 1 : 0;
        stats.generatedReports += 1;
        stats.receivedAtHeads += 1;
    }

    const double base = 0.0;
    for (uint32_t nodeId = 0; nodeId < ctx->nodes; ++nodeId)
    {
        if (ctx->isHead[nodeId])
        {
            continue;
        }
        const double jitter = ctx->rng->GetValue(0.02, 0.45);
        Simulator::Schedule(Seconds(base + jitter), &SendSensorReport, ctx, nodeId, round);
    }

    Simulator::Schedule(Seconds(base + 0.70 * ctx->roundDuration), &SendAggregates, ctx, round);
    Simulator::Schedule(Seconds(base + 0.92 * ctx->roundDuration), &EndRound, ctx, round);

    if (round + 1 < ctx->rounds)
    {
        Simulator::Schedule(Seconds(ctx->roundDuration), &StartRound, ctx, round + 1);
    }
}

static void InstallTopology(ExperimentContext* ctx)
{
    ctx->sensors.Create(ctx->nodes);
    ctx->allNodes.Add(ctx->sensors);
    ctx->allNodes.Create(1);

    const std::string phyMode = "DsssRate1Mbps";
    Config::SetDefault("ns3::WifiRemoteStationManager::NonUnicastMode", StringValue(phyMode));

    WifiHelper wifi;
    wifi.SetStandard(WIFI_STANDARD_80211b);
    wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager",
                                 "DataMode",
                                 StringValue(phyMode),
                                 "ControlMode",
                                 StringValue(phyMode));

    YansWifiPhyHelper wifiPhy;
    wifiPhy.Set("RxGain", DoubleValue(-10));

    YansWifiChannelHelper wifiChannel;
    wifiChannel.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");
    wifiChannel.AddPropagationLoss("ns3::FriisPropagationLossModel");
    wifiPhy.SetChannel(wifiChannel.Create());

    WifiMacHelper wifiMac;
    wifiMac.SetType("ns3::AdhocWifiMac");
    NetDeviceContainer devices = wifi.Install(wifiPhy, wifiMac, ctx->allNodes);

    MobilityHelper sensorMobility;
    sensorMobility.SetPositionAllocator("ns3::GridPositionAllocator",
                                        "MinX",
                                        DoubleValue(0.0),
                                        "MinY",
                                        DoubleValue(0.0),
                                        "DeltaX",
                                        DoubleValue(8.0),
                                        "DeltaY",
                                        DoubleValue(8.0),
                                        "GridWidth",
                                        UintegerValue(10),
                                        "LayoutType",
                                        StringValue("RowFirst"));
    if (ctx->mobilityMode == "random-walk")
    {
        sensorMobility.SetMobilityModel("ns3::RandomWalk2dMobilityModel",
                                        "Mode",
                                        StringValue("Time"),
                                         "Time",
                                         StringValue("1s"),
                                         "Speed",
                                         StringValue("ns3::ConstantRandomVariable[Constant=" +
                                                     std::to_string(ctx->mobilitySpeed) + "]"),
                                        "Bounds",
                                        StringValue("0|120|0|120"));
    }
    else
    {
        sensorMobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    }
    sensorMobility.Install(ctx->sensors);

    NodeContainer sinkNode;
    sinkNode.Add(ctx->allNodes.Get(ctx->nodes));
    Ptr<ListPositionAllocator> sinkPosition = CreateObject<ListPositionAllocator>();
    sinkPosition->Add(Vector(40.0, 40.0, 0.0));
    MobilityHelper sinkMobility;
    sinkMobility.SetPositionAllocator(sinkPosition);
    sinkMobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    sinkMobility.Install(sinkNode);

    BasicEnergySourceHelper energySource;
    energySource.Set("BasicEnergySourceInitialEnergyJ", DoubleValue(ctx->initialEnergyJ));
    EnergySourceContainer sources = energySource.Install(ctx->allNodes);

    WifiRadioEnergyModelHelper radioEnergy;
    radioEnergy.Set("TxCurrentA", DoubleValue(ctx->txCurrentA));
    radioEnergy.Set("RxCurrentA", DoubleValue(ctx->rxCurrentA));
    radioEnergy.Set("IdleCurrentA", DoubleValue(ctx->idleCurrentA));
    radioEnergy.Install(devices, sources);

    InternetStackHelper internet;
    internet.Install(ctx->allNodes);

    Ipv4AddressHelper address;
    address.SetBase("10.42.0.0", "255.255.0.0");
    ctx->interfaces = address.Assign(devices);

    ctx->state.resize(ctx->nodes);
    for (uint32_t nodeId = 0; nodeId < ctx->nodes; ++nodeId)
    {
        ctx->state[nodeId].virtualEnergyJ = ctx->initialEnergyJ;
        ctx->state[nodeId].energy = DynamicCast<BasicEnergySource>(sources.Get(nodeId));
    }
}

static void MarkMaliciousNodes(ExperimentContext* ctx)
{
    std::vector<uint32_t> ids(ctx->nodes);
    std::iota(ids.begin(), ids.end(), 0);
    std::mt19937 generator(ctx->seed);
    std::shuffle(ids.begin(), ids.end(), generator);

    const uint32_t maliciousCount =
        std::min(ctx->nodes, static_cast<uint32_t>(std::round(ctx->nodes * ctx->maliciousRatio)));
    for (uint32_t i = 0; i < maliciousCount; ++i)
    {
        ctx->state[ids[i]].malicious = true;
    }
}

static void InstallSockets(ExperimentContext* ctx)
{
    TypeId udpFactory = TypeId::LookupByName("ns3::UdpSocketFactory");
    ctx->sockets.resize(ctx->nodes);

    for (uint32_t nodeId = 0; nodeId < ctx->nodes; ++nodeId)
    {
        ctx->sockets[nodeId] = Socket::CreateSocket(ctx->sensors.Get(nodeId), udpFactory);
        ctx->sockets[nodeId]->Bind(InetSocketAddress(Ipv4Address::GetAny(), CH_PORT));
        ctx->sockets[nodeId]->SetRecvCallback(MakeBoundCallback(&ReceiveAtClusterHead, ctx, nodeId));
    }

    Ptr<Node> sink = ctx->allNodes.Get(ctx->nodes);
    Ptr<Socket> sinkSocket = Socket::CreateSocket(sink, udpFactory);
    sinkSocket->Bind(InetSocketAddress(Ipv4Address::GetAny(), SINK_PORT));
    sinkSocket->SetRecvCallback(MakeBoundCallback(&ReceiveAtSink, ctx));
}

int
main(int argc, char* argv[])
{
    ExperimentContext ctx;

    CommandLine cmd(__FILE__);
    cmd.AddValue("policy", "Cluster-head policy: dynatrust or leach", ctx.policy);
    cmd.AddValue("mobility", "Mobility mode: static or random-walk", ctx.mobilityMode);
    cmd.AddValue("nodes", "Number of sensor nodes", ctx.nodes);
    cmd.AddValue("rounds", "Number of clustering rounds", ctx.rounds);
    cmd.AddValue("heads", "Cluster heads per round", ctx.headsPerRound);
    cmd.AddValue("seed", "Deterministic scenario seed", ctx.seed);
    cmd.AddValue("maliciousRatio", "Fraction of malicious sensor nodes", ctx.maliciousRatio);
    cmd.AddValue("dropProbability", "Malicious cluster-head drop probability", ctx.maliciousDropProbability);
    cmd.AddValue("corruptProbability",
                 "Malicious cluster-head corruption probability",
                 ctx.maliciousCorruptProbability);
    cmd.AddValue("trustPoisoningStrength",
                 "Strength of poisoned recommendations in naive trust policies",
                 ctx.trustPoisoningStrength);
    cmd.AddValue("benignReportLossProbability",
                 "Probability that an otherwise benign source report is lost before the cluster head",
                 ctx.benignReportLossProbability);
    cmd.AddValue("benignAggregateLossProbability",
                 "Probability that an otherwise benign aggregate is lost before the sink",
                 ctx.benignAggregateLossProbability);
    cmd.AddValue("benignCorruptProbability",
                 "Probability that benign channel noise corrupts one accepted report in an aggregate",
                 ctx.benignCorruptProbability);
    cmd.AddValue("benignEvidenceErrorProbability",
                 "Probability that benign conditions create a low direct evidence sample",
                 ctx.benignEvidenceErrorProbability);
    cmd.AddValue("mobilitySpeed", "Random-walk mobility speed in meters per second", ctx.mobilitySpeed);
    cmd.AddValue("recommendationTrimFraction",
                 "Symmetric trimmed fraction for robust recommendation aggregation",
                 ctx.recommendationTrimFraction);
    cmd.AddValue("recommendationClipRadius",
                 "Per-round clipping radius for robust recommendation aggregation",
                 ctx.recommendationClipRadius);
    cmd.AddValue("recommendationResidualScale",
                 "Scale for retained adversarial recommendation residual in robust policies",
                 ctx.recommendationResidualScale);
    cmd.AddValue("attackMode", "Malicious behavior mode: fixed, on-off, or strategic", ctx.attackMode);
    cmd.AddValue("onOffPeriod", "Rounds per on-off attacker cycle", ctx.onOffPeriod);
    cmd.AddValue("strategicWarmupRounds",
                 "Warmup rounds before strategic attackers begin misbehaving as heads",
                 ctx.strategicWarmupRounds);
    cmd.AddValue("strategicTrustThreshold",
                 "Trust threshold above which strategic malicious heads attack",
                 ctx.strategicTrustThreshold);
    cmd.AddValue("trustUpdateStep", "Trust recursion step size", ctx.trustUpdateStep);
    cmd.AddValue("filterTrustThreshold", "Packet filter trust threshold", ctx.filterTrustThreshold);
    cmd.AddValue("headTrustThreshold", "Head eligibility trust threshold", ctx.headTrustThreshold);
    cmd.AddValue("dynatrustTrustWeight", "DynaTrust score weight for trust", ctx.dynatrustTrustWeight);
    cmd.AddValue("dynatrustEnergyWeight", "DynaTrust score weight for residual energy", ctx.dynatrustEnergyWeight);
    cmd.AddValue("dynatrustFairnessWeight", "DynaTrust score weight for fairness", ctx.dynatrustFairnessWeight);
    cmd.AddValue("dynatrustCentralityWeight",
                 "DynaTrust score weight for mobility centrality",
                 ctx.dynatrustCentralityWeight);
    cmd.AddValue("dynatrustDiversityWeight",
                 "DynaTrust score weight for spatial diversity",
                 ctx.dynatrustDiversityWeight);
    cmd.AddValue("initialEnergyJ", "Initial per-node battery energy in joules", ctx.initialEnergyJ);
    cmd.AddValue("sensorReportCostJ", "Virtual energy cost of one sensor report", ctx.sensorReportCostJ);
    cmd.AddValue("headReceiveCostJ", "Virtual energy cost for a cluster head to receive one report", ctx.headReceiveCostJ);
    cmd.AddValue("aggregateTxCostJ", "Virtual energy cost for one cluster-head aggregate transmission", ctx.aggregateTxCostJ);
    cmd.AddValue("clusterHeadRoundCostJ", "Virtual energy cost paid by a selected cluster head each round", ctx.clusterHeadRoundCostJ);
    cmd.AddValue("trustUpdateCostJ", "Virtual energy cost of one local trust update", ctx.trustUpdateCostJ);
    cmd.AddValue("txCurrentA", "Wi-Fi radio transmit current", ctx.txCurrentA);
    cmd.AddValue("rxCurrentA", "Wi-Fi radio receive current", ctx.rxCurrentA);
    cmd.AddValue("idleCurrentA", "Wi-Fi radio idle current", ctx.idleCurrentA);
    cmd.Parse(argc, argv);

    RngSeedManager::SetSeed(ctx.seed);
    RngSeedManager::SetRun(1);
    ctx.rng = CreateObject<UniformRandomVariable>();
    ctx.rng->SetStream(23);
    ctx.stats.resize(ctx.rounds);

    InstallTopology(&ctx);
    MarkMaliciousNodes(&ctx);
    InstallSockets(&ctx);

    std::cout << "policy,round,malicious_ratio,attack_mode,cluster_heads,compromised_heads,generated_reports,"
                 "received_at_heads,quarantined_reports,quarantined_honest_reports,"
                 "quarantined_malicious_reports,expected_aggregates,sink_aggregates,"
                 "delivered_reports,corrupted_reports,pdr,clean_pdr,aggregate_delivery,mean_trust,"
                 "mean_energy,alive_nodes,energy_jain,ch_jain\n";

    Simulator::Schedule(Seconds(0.0), &StartRound, &ctx, 0);
    Simulator::Stop(Seconds(ctx.roundDuration * ctx.rounds + 1.0));
    Simulator::Run();
    Simulator::Destroy();

    return 0;
}
