#include "ns3/core-module.h"
#include "ns3/internet-apps-module.h"
#include "ns3/internet-module.h"
#include "ns3/lr-wpan-module.h"
#include "ns3/mobility-module.h"
#include "ns3/sixlowpan-module.h"

#include <iomanip>
#include <iostream>

using namespace ns3;

namespace
{
uint32_t g_nodes = 2;
double g_distance = 20.0;
uint32_t g_packetSize = 32;

void
Report(const Ping::PingReport& report)
{
    std::cout << "stack,nodes,distance_m,packet_size,transmitted,received,loss_pct,rtt_avg_ms\n";
    std::cout << "lr-wpan-6lowpan," << g_nodes << "," << std::fixed << std::setprecision(1)
              << g_distance << "," << g_packetSize << "," << report.m_transmitted << ","
              << report.m_received << "," << report.m_loss << "," << std::setprecision(4)
              << report.m_rttAvg << "\n";
}
} // namespace

int
main(int argc, char** argv)
{
    uint32_t count = 10;
    uint32_t seed = 19;

    CommandLine cmd(__FILE__);
    cmd.AddValue("distance", "Distance between LR-WPAN nodes in meters", g_distance);
    cmd.AddValue("packetSize", "ICMPv6 ping payload size", g_packetSize);
    cmd.AddValue("count", "Number of ICMPv6 echo requests", count);
    cmd.AddValue("seed", "Deterministic seed", seed);
    cmd.Parse(argc, argv);

    RngSeedManager::SetSeed(seed);
    RngSeedManager::SetRun(1);

    NodeContainer nodes;
    nodes.Create(g_nodes);

    Ptr<ListPositionAllocator> positions = CreateObject<ListPositionAllocator>();
    positions->Add(Vector(0.0, 0.0, 0.0));
    positions->Add(Vector(g_distance, 0.0, 0.0));
    MobilityHelper mobility;
    mobility.SetPositionAllocator(positions);
    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobility.Install(nodes);

    LrWpanHelper lrWpanHelper;
    lrWpanHelper.SetPropagationDelayModel("ns3::ConstantSpeedPropagationDelayModel");
    lrWpanHelper.AddPropagationLossModel("ns3::LogDistancePropagationLossModel");
    NetDeviceContainer lrwpanDevices = lrWpanHelper.Install(nodes);
    lrWpanHelper.CreateAssociatedPan(lrwpanDevices, 1);

    InternetStackHelper internetv6;
    internetv6.Install(nodes);

    SixLowPanHelper sixlowpan;
    NetDeviceContainer sixlowpanDevices = sixlowpan.Install(lrwpanDevices);

    Ipv6AddressHelper ipv6;
    ipv6.SetBase(Ipv6Address("2001:2::"), Ipv6Prefix(64));
    Ipv6InterfaceContainer interfaces = ipv6.Assign(sixlowpanDevices);

    PingHelper ping(interfaces.GetAddress(1, 1));
    ping.SetAttribute("Count", UintegerValue(count));
    ping.SetAttribute("Interval", TimeValue(Seconds(1.0)));
    ping.SetAttribute("Size", UintegerValue(g_packetSize));
    ping.SetAttribute("VerboseMode", EnumValue(Ping::SILENT));
    ApplicationContainer apps = ping.Install(nodes.Get(0));
    apps.Get(0)->TraceConnectWithoutContext("Report", MakeCallback(&Report));
    apps.Start(Seconds(2.0));
    apps.Stop(Seconds(2.0 + count + 2.0));

    Simulator::Stop(Seconds(2.0 + count + 3.0));
    Simulator::Run();
    Simulator::Destroy();

    return 0;
}
