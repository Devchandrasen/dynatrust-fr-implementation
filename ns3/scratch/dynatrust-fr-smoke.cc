#include "ns3/core-module.h"
#include "ns3/mobility-module.h"
#include "ns3/network-module.h"

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <numeric>
#include <sstream>
#include <vector>

using namespace ns3;

struct SensorState
{
    uint32_t id{};
    bool malicious{};
    double trust{0.55};
    double energyJ{1.0};
    uint32_t selectedAsHead{0};
};

static double
Clamp(double value, double lo, double hi)
{
    return std::max(lo, std::min(value, hi));
}

static std::string
JoinHeads(const std::vector<uint32_t>& heads)
{
    std::ostringstream out;
    for (size_t i = 0; i < heads.size(); ++i)
    {
        if (i)
        {
            out << "|";
        }
        out << heads[i];
    }
    return out.str();
}

static void
RunRound(std::vector<SensorState>* sensors,
         Ptr<UniformRandomVariable> rng,
         uint32_t round,
         uint32_t totalRounds,
         uint32_t headsPerRound)
{
    for (auto& sensor : *sensors)
    {
        const double attackNoise = sensor.malicious ? rng->GetValue(0.45, 0.90) : rng->GetValue(0.00, 0.18);
        const double honestEvidence = 1.0 - attackNoise;
        sensor.trust = Clamp((0.78 * sensor.trust) + (0.22 * honestEvidence), 0.0, 1.0);
        sensor.energyJ = Clamp(sensor.energyJ - rng->GetValue(0.002, 0.006), 0.0, 1.0);
    }

    std::vector<uint32_t> order(sensors->size());
    std::iota(order.begin(), order.end(), 0);
    std::sort(order.begin(), order.end(), [&](uint32_t a, uint32_t b) {
        const auto& lhs = sensors->at(a);
        const auto& rhs = sensors->at(b);
        const double lhsFairness = 1.0 / (1.0 + lhs.selectedAsHead);
        const double rhsFairness = 1.0 / (1.0 + rhs.selectedAsHead);
        const double lhsScore = (0.60 * lhs.trust) + (0.25 * lhs.energyJ) + (0.15 * lhsFairness);
        const double rhsScore = (0.60 * rhs.trust) + (0.25 * rhs.energyJ) + (0.15 * rhsFairness);
        if (lhsScore == rhsScore)
        {
            return lhs.id < rhs.id;
        }
        return lhsScore > rhsScore;
    });

    std::vector<uint32_t> heads;
    for (const auto candidate : order)
    {
        const auto& sensor = sensors->at(candidate);
        if (sensor.trust >= 0.52 && sensor.energyJ >= 0.15)
        {
            heads.push_back(candidate);
            if (heads.size() == headsPerRound)
            {
                break;
            }
        }
    }

    uint32_t compromisedHeads = 0;
    for (const auto headId : heads)
    {
        auto& head = sensors->at(headId);
        ++head.selectedAsHead;
        head.energyJ = Clamp(head.energyJ - rng->GetValue(0.010, 0.018), 0.0, 1.0);
        if (head.malicious)
        {
            ++compromisedHeads;
        }
    }

    const double avgTrust =
        std::accumulate(sensors->begin(), sensors->end(), 0.0, [](double sum, const SensorState& s) {
            return sum + s.trust;
        }) /
        sensors->size();
    const double avgEnergy =
        std::accumulate(sensors->begin(), sensors->end(), 0.0, [](double sum, const SensorState& s) {
            return sum + s.energyJ;
        }) /
        sensors->size();
    const double pdr = Clamp(0.94 + (0.05 * avgTrust) - (0.12 * compromisedHeads), 0.0, 1.0);

    std::cout << round << "," << JoinHeads(heads) << "," << compromisedHeads << "," << std::fixed
              << std::setprecision(4) << avgTrust << "," << avgEnergy << "," << pdr << "\n";

    if (round + 1 < totalRounds)
    {
        Simulator::Schedule(Seconds(1.0),
                            &RunRound,
                            sensors,
                            rng,
                            round + 1,
                            totalRounds,
                            headsPerRound);
    }
}

int
main(int argc, char* argv[])
{
    uint32_t nodes = 36;
    uint32_t rounds = 12;
    uint32_t heads = 4;
    double maliciousRatio = 0.20;

    CommandLine cmd(__FILE__);
    cmd.AddValue("nodes", "Number of sensor nodes", nodes);
    cmd.AddValue("rounds", "Number of trust-update rounds", rounds);
    cmd.AddValue("heads", "Cluster heads per round", heads);
    cmd.AddValue("maliciousRatio", "Fraction of malicious nodes", maliciousRatio);
    cmd.Parse(argc, argv);

    NodeContainer sensorNodes;
    sensorNodes.Create(nodes);

    MobilityHelper mobility;
    mobility.SetPositionAllocator("ns3::GridPositionAllocator",
                                  "MinX",
                                  DoubleValue(0.0),
                                  "MinY",
                                  DoubleValue(0.0),
                                  "DeltaX",
                                  DoubleValue(12.0),
                                  "DeltaY",
                                  DoubleValue(12.0),
                                  "GridWidth",
                                  UintegerValue(6),
                                  "LayoutType",
                                  StringValue("RowFirst"));
    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobility.Install(sensorNodes);

    Ptr<UniformRandomVariable> rng = CreateObject<UniformRandomVariable>();
    rng->SetStream(19);

    std::vector<SensorState> sensors(nodes);
    for (uint32_t i = 0; i < nodes; ++i)
    {
        sensors[i].id = i;
        sensors[i].malicious = (static_cast<double>(i) / nodes) < maliciousRatio;
        sensors[i].trust = sensors[i].malicious ? 0.44 : 0.62;
        sensors[i].energyJ = rng->GetValue(0.82, 1.0);
    }

    std::cout << "round,cluster_heads,compromised_heads,avg_trust,avg_energy,pdr\n";
    Simulator::Schedule(Seconds(0.0), &RunRound, &sensors, rng, 0, rounds, heads);
    Simulator::Stop(Seconds(rounds + 1));
    Simulator::Run();
    Simulator::Destroy();

    return 0;
}
