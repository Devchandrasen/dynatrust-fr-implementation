#include "trust-v2.h"
#include "temporal-evidence.h"
#include "calibration-coverage.h"
#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/lr-wpan-module.h"
#include "ns3/sixlowpan-module.h"
#include "ns3/mobility-module.h"
#include <dlfcn.h>
#include <array>
#include <fstream>
#include <iomanip>
#include <map>
#include <numeric>
#include <random>
#include <set>
#include <string>
#include <tuple>

using namespace ns3;
using namespace ns3::lrwpan;
using Bytes=std::vector<uint8_t>;
namespace {
constexpr uint16_t PORT=9122;
enum Message:uint8_t{CONTROL=1,REPORT=2,AGGREGATE=3,RECOMMENDATION=4,PROBE=5};
void Put(Bytes& b,uint64_t x,unsigned n){for(int i=n-1;i>=0;--i)b.push_back((x>>(8*i))&255);}
uint64_t Get(const Bytes& b,size_t& at,unsigned n){if(at+n>b.size())throw std::runtime_error("short packet");uint64_t x=0;while(n--)x=(x<<8)|b[at++];return x;}
struct Crypto {
    void* lib=dlopen("libcrypto.so.3",RTLD_NOW);
    using Md=const void*(*)();
    using Hm=unsigned char*(*)(const void*,const void*,int,const unsigned char*,size_t,unsigned char*,unsigned int*);
    Md sha;Hm hmac;
    Crypto(){if(!lib)throw std::runtime_error("OpenSSL 3 runtime is required");sha=reinterpret_cast<Md>(dlsym(lib,"EVP_sha256"));hmac=reinterpret_cast<Hm>(dlsym(lib,"HMAC"));if(!sha||!hmac)throw std::runtime_error("OpenSSL HMAC unavailable");}
    uint64_t Tag(const Bytes& b,const std::string& key) const {
        unsigned char out[32];unsigned len=0;
        if(!hmac(sha(),key.data(),key.size(),b.data(),b.size(),out,&len)||len!=32)throw std::runtime_error("HMAC failed");
        uint64_t x=0;for(unsigned i=0;i<8;++i)x=(x<<8)|out[i];return x;
    }
} crypto;
struct Sample{uint16_t source;uint32_t sequence;int32_t value;uint64_t tag;};
void PackSample(Bytes& b,const Sample& s){Put(b,s.source,2);Put(b,s.sequence,4);Put(b,static_cast<uint32_t>(s.value),4);Put(b,s.tag,8);}
Sample UnpackSample(const Bytes& b,size_t& at){Sample s;s.source=Get(b,at,2);s.sequence=Get(b,at,4);s.value=static_cast<int32_t>(Get(b,at,4));s.tag=Get(b,at,8);return s;}
struct Frame{uint8_t type;uint32_t round;uint16_t sender,dest,count;Bytes body;};
struct Config {
    unsigned nodes=36,heads=4,rounds=300,seed=1,warmup=30,period=20,recs=8;
    double ratio=.4,speed=1,roundSeconds=10,initialEnergy=500,noise=1,loss=0;
    double shift=18,drop=.65,tamper=.70,plausibility=6,weightTrust=.58,weightEnergy=.24,weightPath=.35;
    std::string policy="dynatrust",attack="fixed",output="rounds.csv",trace="";
    bool central=false,outage=false,roleMemory=true,probeIsolation=false;
    unsigned referenceMin=3;
    bool ambiguityGuard=false,temporal=false,calibrated=false,coverage=false;
    unsigned calibrationRounds=60,calibrationMinimum=40;
    double referenceStep=3,physicalStep=0;
    double temporalLambda=.04,temporalMargin=.45,temporalZ=2.5,benignBias=0;
    unsigned temporalMinimum=20;
    dynatrust::Parameters trust;
} cfg;
struct Truth {bool generated=false,bad=false;int32_t original=0;Sample sent{};};
struct NodeView {
    int controlRound=-1;std::vector<unsigned> heads;std::vector<bool> admit,quarantine;
    std::map<unsigned,std::pair<double,unsigned>> local;std::map<unsigned,Vector> headPositions;
    int previousHead=-1;bool previousParticipated=false;
};
struct Radio {double joules=0,last=0,current=.000001;};
struct Stats {
    unsigned generated=0,honestGenerated=0,delivered=0,honestClean=0,contentClean=0,badDelivered=0;
    unsigned filtered=0,honestFiltered=0,maliciousFiltered=0,probes=0,probeGood=0;
    unsigned compromisedHeads=0,activeHeads=0,aggregates=0,validAggregates=0;
    unsigned txFrames=0,txBytes=0,appDataBytes=0,appControlBytes=0;
    unsigned honestTrimmed=0,badRetained=0,retained=0,recommendations=0;
    unsigned falsePositive=0,falseNegative=0,detectedGood=0,detectedBad=0,accepted=0,acceptedHonestClean=0,acceptedContentClean=0,acceptedBad=0;
    unsigned ambiguous=0,temporalRejected=0,temporalHonestRejected=0,temporalBadRejected=0;
    double latency=0,coverageUtility=0,scoreUtility=0;
};
struct World {
    std::unique_ptr<LrWpanHelper> lr;NodeContainer nodes;Ipv6InterfaceContainer ip;std::vector<Ptr<Socket>> sockets;
    std::vector<temporal::History> history;
    std::vector<calibration::Baseline> calibration;
    bool anchorAvailable=false;double anchor=0;
    std::vector<dynatrust::State> state;std::vector<NodeView> views;std::vector<Radio> radio;
    std::vector<bool> malicious; // Attack generation / offline scoring only.
    std::vector<Truth> truth;std::vector<double> physical,advertisedEnergy;std::vector<Vector> advertisedPosition;
    std::vector<std::vector<Sample>> buffer;std::vector<unsigned> headCount,currentHeads;
    std::vector<std::vector<std::pair<unsigned,double>>> recs;
    std::vector<Sample> received,probeSamples;std::vector<bool> arrived,goodPath,lastAck;
    std::set<unsigned> delivered;Stats stats;unsigned round=0;bool started=false;
    Ptr<UniformRandomVariable> rng;std::ofstream output,trace;
} w;

std::string SourceKey(unsigned id){return "v2-simulation-source|"+std::to_string(cfg.seed)+"|"+std::to_string(id);}
std::string LinkKey(unsigned s,unsigned d){return "v2-simulation-link|"+std::to_string(cfg.seed)+"|"+std::to_string(std::min(s,d))+"|"+std::to_string(std::max(s,d));}
uint64_t SampleTag(const Sample& s){Bytes b;Put(b,s.source,2);Put(b,s.sequence,4);Put(b,static_cast<uint32_t>(s.value),4);return crypto.Tag(b,SourceKey(s.source));}
bool Valid(const Sample& s){return s.source<cfg.nodes && s.sequence==w.round && s.tag==SampleTag(s);}
Bytes Encode(const Frame& f){Bytes b;Put(b,f.type,1);Put(b,f.round,4);Put(b,f.sender,2);Put(b,f.dest,2);Put(b,f.count,2);b.insert(b.end(),f.body.begin(),f.body.end());Put(b,crypto.Tag(b,LinkKey(f.sender,f.dest)),8);return b;}
Frame Decode(const Bytes& b){
    if(b.size()<19)throw std::runtime_error("short frame");size_t at=0;Frame f;
    f.type=Get(b,at,1);f.round=Get(b,at,4);f.sender=Get(b,at,2);f.dest=Get(b,at,2);f.count=Get(b,at,2);
    f.body=Bytes(b.begin()+11,b.end()-8);Bytes authenticated(b.begin(),b.end()-8);at=b.size()-8;
    if(Get(b,at,8)!=crypto.Tag(authenticated,LinkKey(f.sender,f.dest)))throw std::runtime_error("bad link MAC");return f;
}
double ScenarioUniform(unsigned id,unsigned t,unsigned kind){
    uint64_t x=(uint64_t(cfg.seed)<<32)^(uint64_t(t)*0x9e3779b97f4a7c15ULL)^(id*7919+kind*104729);x=(x^(x>>30))*0xbf58476d1ce4e5b9ULL;x=(x^(x>>27))*0x94d049bb133111ebULL;x^=x>>31;return (x>>11)*0x1.0p-53;
}
bool Attack(unsigned id,unsigned t,bool head){
    if(!w.malicious[id]||cfg.attack=="none")return false;
    if(cfg.attack=="delayed")return t>=cfg.warmup;
    if(cfg.attack=="sleeper")return t>=cfg.warmup && head;
    if(cfg.attack=="on-off")return t>=cfg.warmup && (t-cfg.warmup)%cfg.period>=cfg.period/2;
    return true;
}
std::string Phase(){if(cfg.ratio==0||cfg.attack=="none")return "benign";if(cfg.attack=="fixed")return "attack";if(w.round<cfg.warmup)return "warmup";if(cfg.attack=="sleeper"||cfg.attack=="delayed")return "attack";return (w.round-cfg.warmup)%cfg.period>=cfg.period/2?"attack":"benign-recovery";}
double Current(PhyEnumeration s){if(s==IEEE_802_15_4_PHY_BUSY_TX||s==IEEE_802_15_4_PHY_TX_ON)return .020;if(s==IEEE_802_15_4_PHY_RX_ON||s==IEEE_802_15_4_PHY_BUSY_RX)return .012;return .000001;}
void Account(unsigned id){auto& r=w.radio[id];const double now=Simulator::Now().GetSeconds();r.joules+=3*r.current*(now-r.last);r.last=now;}
void StateChanged(unsigned id,PhyEnumeration old,PhyEnumeration next){Account(id);w.radio[id].current=Current(next);}
void Tx(unsigned id,Ptr<const Packet> packet){if(w.started){++w.stats.txFrames;w.stats.txBytes+=packet->GetSize();}}
double Energy(unsigned id){Account(id);return std::max(0.0,1-w.radio[id].joules/cfg.initialEnergy);}
bool Alive(unsigned id){return Energy(id)>0;}
void Send(const Frame& f){
    if(f.sender<cfg.nodes && !Alive(f.sender))return;
    if(cfg.outage && w.round>=80 && w.round<100 && f.sender<cfg.nodes && f.sender%5==0)return;
    if(f.type==REPORT && ScenarioUniform(f.sender,w.round,1)<cfg.loss)return;
    const auto data=Encode(f);
    if(f.type==CONTROL||f.type==RECOMMENDATION||f.type==PROBE)w.stats.appControlBytes+=data.size();else w.stats.appDataBytes+=data.size();
    w.sockets[f.sender]->SendTo(Create<Packet>(data.data(),data.size()),0,Inet6SocketAddress(w.ip.GetAddress(f.dest,1),PORT));
}
bool UsesTrust(){return cfg.policy!="leach-style" && cfg.policy!="heed-style" && cfg.policy!="energy" && cfg.policy!="oracle";}
bool Filtering(){return cfg.policy=="dynatrust"||cfg.policy=="isolated-reference"||cfg.policy=="no-role-memory"||cfg.policy=="no-reference-weight"||cfg.policy=="no-probe-isolation"||cfg.policy=="legacy"||cfg.policy=="no-robust"||cfg.policy=="no-fairness"||cfg.policy=="no-diversity"||cfg.policy=="quarantine-only"||cfg.policy=="oracle";}
bool RoleMemory(){return cfg.roleMemory && UsesTrust() && cfg.policy!="legacy" && cfg.policy!="no-role-memory" && cfg.policy!="robust-reputation" && cfg.policy!="trust-leach-style" && cfg.policy!="quarantine-only";}
bool IsolateProbes(){return (cfg.probeIsolation||cfg.policy=="isolated-reference") && cfg.policy!="legacy";}
double ReportedDistance(unsigned a,unsigned b){return CalculateDistance(w.advertisedPosition[a],w.advertisedPosition[b]);}
double Distance(unsigned a,unsigned b){return w.nodes.Get(a)->GetObject<MobilityModel>()->GetDistanceFrom(w.nodes.Get(b)->GetObject<MobilityModel>());}
std::vector<unsigned> Select(){
    std::vector<unsigned> selected;double maxDist=1;std::vector<double> base(cfg.nodes),energy(cfg.nodes);
    for(unsigned a=0;a<cfg.nodes;++a)for(unsigned b=0;b<a;++b)maxDist=std::max(maxDist,ReportedDistance(a,b));
    for(unsigned i=0;i<cfg.nodes;++i){
        energy[i]=w.advertisedEnergy[i];double d=0;for(unsigned j=0;j<cfg.nodes;++j)d+=ReportedDistance(i,j);
        const double central=1-d/cfg.nodes/maxDist,fair=1.0/(1+w.headCount[i]),tie=.001*w.rng->GetValue();
        if(cfg.policy=="leach-style"||cfg.policy=="energy"||cfg.policy=="quarantine-only")base[i]=energy[i]+.1*fair+.05*w.rng->GetValue();
        else if(cfg.policy=="heed-style"||cfg.policy=="oracle")base[i]=.7*energy[i]+.2*central+.1*fair+tie;
        else if(cfg.policy=="trust-leach-style")base[i]=.6*w.state[i].trust+.3*energy[i]+.1*fair+tie;
        else base[i]=cfg.weightTrust*w.state[i].trust+cfg.weightEnergy*energy[i]+(cfg.policy=="no-fairness"?0:.10*fair)+.05*central+(RoleMemory()?cfg.weightPath*w.state[i].headPath:0)+tie;
    }
    std::vector<unsigned> coverageHeads;
    std::vector<std::vector<double>> benefit;
    {
        // All coefficients and the eligibility set are frozen for this round.
        // The theorem concerns this observable surrogate, not the hidden P1.
        std::vector<bool> eligible(cfg.nodes);benefit.assign(cfg.nodes,std::vector<double>(cfg.nodes));
        for(unsigned j=0;j<cfg.nodes;++j)eligible[j]=energy[j]>.01 && (!UsesTrust()||dynatrust::Eligible(w.state[j],cfg.trust));
        for(unsigned i=0;i<cfg.nodes;++i)for(unsigned j=0;j<cfg.nodes;++j){
            const bool admitted=!Filtering()||dynatrust::Admit(w.state[i],cfg.trust);
            benefit[i][j]=admitted?w.state[i].trust*std::max(0.0,base[j])*(.25+.75*(1-ReportedDistance(i,j)/maxDist)):0;
        }
        coverageHeads=coverage::Greedy(benefit,eligible,cfg.heads);
    }
    while(selected.size()<cfg.heads){
        int best=-1;double score=-1;
        for(unsigned i=0;i<cfg.nodes;++i){
            if(energy[i]<=.01||std::find(selected.begin(),selected.end(),i)!=selected.end())continue;
            if(UsesTrust()&&cfg.policy!="quarantine-only"&&!dynatrust::Eligible(w.state[i],cfg.trust))continue;
            if(cfg.policy=="oracle"&&w.malicious[i])continue; // Explicit labeled oracle baseline only.
            double div=1;for(auto j:selected)div=std::min(div,ReportedDistance(i,j)/maxDist);
            const double s=base[i]+((cfg.policy=="no-diversity"||cfg.policy=="leach-style"||cfg.policy=="heed-style")?0:.04*div);
            if(s>score){score=s;best=i;}
        }
        if(best<0)break;selected.push_back(best);
    }
    w.stats.coverageUtility=coverage::Utility(benefit,coverageHeads);w.stats.scoreUtility=coverage::Utility(benefit,selected);
    return cfg.coverage?coverageHeads:selected; // No eligibility bypass.
}
bool ControllerAdmit(unsigned i){if(cfg.policy=="oracle")return !w.malicious[i];return !Filtering()||dynatrust::Admit(w.state[i],cfg.trust);}
void Control(unsigned id){
    Frame f{CONTROL,w.round,static_cast<uint16_t>(cfg.nodes),static_cast<uint16_t>(id),static_cast<uint16_t>(w.currentHeads.size()),{}};
    for(auto head:w.currentHeads){Put(f.body,head,2);Put(f.body,std::lround(w.advertisedPosition[head].x*100),2);Put(f.body,std::lround(w.advertisedPosition[head].y*100),2);}
    for(unsigned kind=0;kind<2;++kind)for(unsigned byte=0;byte<(cfg.nodes+7)/8;++byte){unsigned bits=0;for(unsigned bit=0;bit<8;++bit){unsigned i=byte*8+bit;if(i<cfg.nodes && (kind?w.state[i].status!=0:ControllerAdmit(i)))bits|=1<<bit;}Put(f.body,bits,1);}
    Put(f.body,w.lastAck[id],1);Send(f);
}
void Receive(unsigned id,Ptr<Socket> socket){
    Address address;
    while(auto packet=socket->RecvFrom(address)){
        Bytes data(packet->GetSize());packet->CopyData(data.data(),data.size());
        try{
            auto f=Decode(data);if(f.round!=w.round||f.dest!=id||f.sender>cfg.nodes)continue;
            size_t at=0;
            if(f.type==CONTROL && id<cfg.nodes && f.sender==cfg.nodes){
                auto& v=w.views[id];v.controlRound=w.round;v.heads.clear();for(unsigned k=0;k<f.count;++k){auto head=Get(f.body,at,2);v.heads.push_back(head);double x=Get(f.body,at,2)/100.0;double y=Get(f.body,at,2)/100.0;v.headPositions[head]=Vector(x,y,0);}
                for(auto* bits:{&v.admit,&v.quarantine}){bits->assign(cfg.nodes,false);for(unsigned byte=0;byte<(cfg.nodes+7)/8;++byte){auto value=Get(f.body,at,1);for(unsigned bit=0;bit<8;++bit)if(byte*8+bit<cfg.nodes)(*bits)[byte*8+bit]=(value>>bit)&1;}}
                const bool ack=Get(f.body,at,1);if(v.previousParticipated && v.previousHead>=0)v.local[v.previousHead]={ack?.9:.2,w.round};
            }else if(f.type==REPORT && id<cfg.nodes && f.count==1){
                auto s=UnpackSample(f.body,at);auto& v=w.views[id];if(s.source>=cfg.nodes||s.sequence!=w.round||v.controlRound!=static_cast<int>(w.round)||std::find(v.heads.begin(),v.heads.end(),id)==v.heads.end())continue;
                const double difference=std::abs(s.value/1000.0-w.physical[id]);v.local[s.source]={difference<=cfg.plausibility?.9:.1,w.round};
                const bool attack=Attack(id,w.round,true);
                if((v.admit[s.source]||attack))w.buffer[id].push_back(s);
                else {++w.stats.filtered;if(w.malicious[s.source])++w.stats.maliciousFiltered;else ++w.stats.honestFiltered;}
            }else if(f.type==AGGREGATE && id==cfg.nodes && f.sender<cfg.nodes){
                if(std::find(w.currentHeads.begin(),w.currentHeads.end(),f.sender)==w.currentHeads.end())continue;
                ++w.stats.aggregates;w.arrived[f.sender]=true;const int64_t declared=static_cast<int64_t>(Get(f.body,at,8));int64_t sum=0;bool good=true;
                std::vector<Sample> samples;for(unsigned k=0;k<f.count;++k){auto s=UnpackSample(f.body,at);sum+=s.value;good=good&&Valid(s);samples.push_back(s);}
                good=good&&(sum==declared);w.goodPath[f.sender]=good;if(good)++w.stats.validAggregates;
                for(const auto& s:samples)if(s.source<cfg.nodes && s.sequence==w.round && w.delivered.insert(s.source).second){
                    w.received.push_back(s);++w.stats.delivered;
                    // Scoring ledger only: these labels do not enter dynatrust::Evidence.
                    const auto& truth=w.truth[s.source];const bool clean=truth.generated && s.value==truth.original && Valid(s);
                    if(clean){++w.stats.contentClean;if(!w.malicious[s.source])++w.stats.honestClean;}else ++w.stats.badDelivered;
                    w.stats.latency+=Simulator::Now().GetSeconds()-(2+w.round*cfg.roundSeconds);
                }
            }else if(f.type==PROBE && id==cfg.nodes && f.sender<cfg.nodes && f.count==1){
                auto s=UnpackSample(f.body,at);if(s.source==f.sender && Valid(s))w.probeSamples.push_back(s);
            }else if(f.type==RECOMMENDATION && id==cfg.nodes && f.sender<cfg.nodes && !w.state[f.sender].status){
                w.advertisedEnergy[f.sender]=Get(f.body,at,2)/65535.0;double x=Get(f.body,at,2)/100.0;double y=Get(f.body,at,2)/100.0;w.advertisedPosition[f.sender]=Vector(x,y,0);
                for(unsigned k=0;k<f.count;++k){unsigned target=Get(f.body,at,2);double score=Get(f.body,at,1)/255.0;Get(f.body,at,1);if(target<cfg.nodes && target!=f.sender)w.recs[target].push_back({f.sender,score});}
            }
        }catch(const std::exception&){continue;}
    }
}
void Generate(){
    w.truth.assign(cfg.nodes,{});w.physical.resize(cfg.nodes);
    // Sensor variation is deterministic by seed/round/node, independent of policy RNG calls.
    for(unsigned i=0;i<cfg.nodes;++i){
        const double u=std::fmod(std::sin((cfg.seed+1)*31.31+(w.round+1)*17.71+(i+1)*23.13)*43758.5453,1.0);
        const double value=45+3*std::sin(w.round/30.0)+cfg.noise*(2*std::abs(u)-1)+(i%5==0?cfg.benignBias:0)+(w.round>=cfg.warmup?cfg.physicalStep:0);
        w.physical[i]=value;if(!Alive(i))continue;
        auto& t=w.truth[i];t.generated=true;t.original=std::lround(value*1000);
        t.sent={static_cast<uint16_t>(i),w.round,t.original,0};
        const bool isHead=std::find(w.currentHeads.begin(),w.currentHeads.end(),i)!=w.currentHeads.end();
        if(Attack(i,w.round,isHead) && cfg.attack!="sleeper")t.sent.value+=std::lround(cfg.shift*1000);
        t.sent.tag=SampleTag(t.sent);t.bad=t.sent.value!=t.original;
        ++w.stats.generated;if(!w.malicious[i])++w.stats.honestGenerated;
    }
}
void Report(unsigned id){
    if(!w.truth[id].generated)return;auto& v=w.views[id];v.previousParticipated=false;
    if(v.controlRound!=static_cast<int>(w.round))return;
    if(v.quarantine[id]&&Filtering()){
        ++w.stats.filtered;if(w.malicious[id])++w.stats.maliciousFiltered;else ++w.stats.honestFiltered;
        if(dynatrust::ProbeDue(w.state[id],w.round,cfg.trust)){
            Frame f{PROBE,w.round,static_cast<uint16_t>(id),static_cast<uint16_t>(cfg.nodes),1,{}};PackSample(f.body,w.truth[id].sent);++w.stats.probes;Send(f);
        }
        return;
    }
    if(v.heads.empty())return;
    auto own=w.nodes.Get(id)->GetObject<MobilityModel>()->GetPosition();unsigned head=v.heads.front();for(auto h:v.heads)if(CalculateDistance(own,v.headPositions[h])<CalculateDistance(own,v.headPositions[head]))head=h;
    v.previousHead=head;v.previousParticipated=v.admit[id];
    if(head==id){if(v.admit[id]||Attack(id,w.round,true))w.buffer[id].push_back(w.truth[id].sent);return;}
    Frame f{REPORT,w.round,static_cast<uint16_t>(id),static_cast<uint16_t>(head),1,{}};PackSample(f.body,w.truth[id].sent);Send(f);
}
void Aggregate(unsigned id){
    if(!Alive(id))return;auto samples=w.buffer[id];if(samples.empty())return;
    if(Attack(id,w.round,true)){
        if(ScenarioUniform(id,w.round,2)<cfg.drop)return;
        if(ScenarioUniform(id,w.round,3)<cfg.tamper)for(auto& s:samples)s.value+=7000; // Invalidates source authentication, not the head's link MAC.
    }
    Frame f{AGGREGATE,w.round,static_cast<uint16_t>(id),static_cast<uint16_t>(cfg.nodes),static_cast<uint16_t>(samples.size()),{}};
    int64_t sum=0;for(auto s:samples)sum+=s.value;Put(f.body,static_cast<uint64_t>(sum),8);for(auto s:samples)PackSample(f.body,s);Send(f);
}
void Recommendations(unsigned id){
    if(!Alive(id)||w.views[id].controlRound!=static_cast<int>(w.round)||w.views[id].quarantine[id])return;
    std::vector<std::pair<unsigned,double>> values;
    if(Attack(id,w.round,false)|| (w.malicious[id]&&cfg.attack=="sleeper"&&w.round>=cfg.warmup)){
        std::vector<std::pair<double,unsigned>> near;for(unsigned i=0;i<cfg.nodes;++i)if(i!=id)near.push_back({Distance(id,i),i});std::sort(near.begin(),near.end());
        for(unsigned j=0;j<std::min<unsigned>(cfg.recs,near.size());++j){unsigned i=near[j].second;values.push_back({i,w.malicious[i]?(cfg.central?.70:1.0):(cfg.central?.50:0.0)});}
    }else for(auto [target,observation]:w.views[id].local)if(w.round-observation.second<=10 && values.size()<cfg.recs)values.push_back({target,observation.first});
    Frame f{RECOMMENDATION,w.round,static_cast<uint16_t>(id),static_cast<uint16_t>(cfg.nodes),static_cast<uint16_t>(values.size()),{}};
    Put(f.body,std::lround(Energy(id)*65535),2);auto position=w.nodes.Get(id)->GetObject<MobilityModel>()->GetPosition();Put(f.body,std::lround(position.x*100),2);Put(f.body,std::lround(position.y*100),2);
    for(auto [target,score]:values){Put(f.body,target,2);Put(f.body,std::lround(score*255),1);Put(f.body,1,1);}Send(f);
}
double Median(std::vector<double> a){if(a.empty())return 45;std::sort(a.begin(),a.end());return (a[(a.size()-1)/2]+a[a.size()/2])/2;}
void AuditTrim(unsigned i){
    std::vector<std::tuple<double,unsigned>> a;for(auto [sender,x]:w.recs[i])a.push_back({cfg.trust.robust?std::clamp(x,std::max(0.0,w.state[i].trust-cfg.trust.delta),std::min(1.0,w.state[i].trust+cfg.trust.delta)):x,sender});
    std::stable_sort(a.begin(),a.end());unsigned k=cfg.trust.robust?std::floor(a.size()*cfg.trust.alpha):0;
    for(unsigned j=0;j<a.size();++j){bool retained=j>=k&&j<a.size()-k;bool bad=w.malicious[std::get<1>(a[j])];if(retained){++w.stats.retained;if(bad)++w.stats.badRetained;}else if(!bad)++w.stats.honestTrimmed;}
    w.stats.recommendations+=a.size();
}
void Finish(){
    // The semantic reference is formed before any state update. Recovery probes
    // use the same pre-update head reliability as regular observations.
    const bool learning=cfg.calibrated && w.round<cfg.calibrationRounds;
    const bool calibrated=cfg.calibrated && !learning;
    auto corrected=[&](const Sample& s){return s.value/1000.0-(calibrated?w.calibration[s.source].Mean():0);};
    auto usable=[&](const Sample& s){return Valid(s)&&(!calibrated||w.calibration[s.source].count>=cfg.calibrationMinimum);};
    std::vector<std::pair<double,double>> values;
    const bool weighted=RoleMemory() && cfg.policy!="no-reference-weight";
    for(auto s:w.received)if(usable(s))values.push_back({corrected(s),weighted?std::max(.05,w.state[s.source].headPath):1.0});
    std::vector<std::pair<double,double>> probes;for(auto s:w.probeSamples)if(usable(s))probes.push_back({corrected(s),weighted?std::max(.05,w.state[s.source].headPath):1.0});
    const auto reference=dynatrust::Reference(values,probes,IsolateProbes(),cfg.policy=="legacy"?0:cfg.referenceMin);
    std::vector<std::pair<double,double>> referenceValues=values;
    if(!IsolateProbes())referenceValues.insert(referenceValues.end(),probes.begin(),probes.end());
    const bool ambiguous=cfg.ambiguityGuard && temporal::Ambiguous(referenceValues,cfg.plausibility);
    w.stats.ambiguous=ambiguous;
    bool referenceAvailable=reference.available && !ambiguous;double median=reference.median;
    if(calibrated){
        const auto anchored=calibration::Anchor(referenceValues,w.anchorAvailable,w.anchor,cfg.referenceStep,cfg.plausibility,cfg.referenceMin);
        referenceAvailable=anchored.available;median=anchored.value;
    }
    if(referenceAvailable){w.anchorAvailable=true;w.anchor=median;}
    if(learning && referenceAvailable){
        auto learn=[&](const Sample& s){if(Valid(s))w.calibration[s.source].Observe(s.value/1000.0-median);};
        for(const auto& s:w.received)learn(s);for(const auto& s:w.probeSamples)learn(s);
    }
    temporal::Contrast contrast;
    if(cfg.temporal && !learning && referenceAvailable){
        auto update=[&](const Sample& s){if(usable(s)&&(!calibrated||std::abs(corrected(s)-median)<=cfg.plausibility))w.history[s.source].Observe(corrected(s)-median,w.round,cfg.temporalLambda);};
        for(const auto& s:w.received)update(s);for(const auto& s:w.probeSamples)update(s);
        std::vector<temporal::Peer> peers;
        for(unsigned i=0;i<cfg.nodes;++i)if(w.history[i].count>=cfg.temporalMinimum && w.round-w.history[i].last<=20)
            peers.push_back({w.history[i].Mean(),w.history[i].SE(),weighted?std::max(.05,w.state[i].headPath):1.0});
        contrast=temporal::PeerContrast(peers);
    }
    std::vector<dynatrust::Evidence> evidence(cfg.nodes);w.lastAck.assign(cfg.nodes,false);
    auto observe=[&](const Sample& s,bool probe){
        if(!usable(s))return;
        if(!referenceAvailable && s.value>=0 && s.value<=100000)return; // Unknown semantics: no fabricated observation or acceptance.
        bool good=referenceAvailable && s.value>=0 && s.value<=100000 && std::abs(corrected(s)-median)<=cfg.plausibility;
        const bool temporalBad=good && cfg.temporal && !learning && contrast.available && w.history[s.source].count>=cfg.temporalMinimum &&
            temporal::Reject(w.history[s.source],contrast,cfg.temporalMargin,cfg.temporalZ);
        if(temporalBad)good=false;
        auto& e=evidence[s.source];e.hasDirect=true;e.direct=good?1:0;if(probe){e.probe=true;e.probeGood=good;if(good)++w.stats.probeGood;}else w.lastAck[s.source]=good;
        const bool trueBad=s.value!=w.truth[s.source].original;
        if(temporalBad){++w.stats.temporalRejected;if(trueBad)++w.stats.temporalBadRejected;else if(!w.malicious[s.source])++w.stats.temporalHonestRejected;}
        if(!probe&&good){++w.stats.accepted;if(trueBad)++w.stats.acceptedBad;else{++w.stats.acceptedContentClean;if(!w.malicious[s.source])++w.stats.acceptedHonestClean;}}
        if(good){if(trueBad)++w.stats.falseNegative;else ++w.stats.detectedGood;}else{if(trueBad)++w.stats.detectedBad;else ++w.stats.falsePositive;}
    };
    for(auto s:w.received)observe(s,false);for(auto s:w.probeSamples)observe(s,true);
    for(auto head:w.currentHeads){evidence[head].hasPath=true;evidence[head].path=w.arrived[head]&&w.goodPath[head]?1:0;
        if(!w.arrived[head]||!w.goodPath[head]){evidence[head].hasDirect=true;evidence[head].direct=0;}}
    for(unsigned i=0;i<cfg.nodes;++i){
        evidence[i].energy=w.advertisedEnergy[i];for(auto [sender,x]:w.recs[i])evidence[i].recommendations.push_back(x);
        AuditTrim(i);if(UsesTrust())dynatrust::Update(w.state[i],evidence[i],w.round,cfg.trust);
    }
    unsigned alive=0,qh=0,qm=0,probation=0;double energy=0,trustH=0,trustM=0;unsigned nh=0,nm=0;
    for(unsigned i=0;i<cfg.nodes;++i){const bool living=Alive(i);energy+=w.radio[i].joules;if(living)++alive;if(w.state[i].status){if(w.malicious[i])++qm;else ++qh;}if(w.state[i].status==2)++probation;if(w.malicious[i]){trustM+=w.state[i].trust;++nm;}else{trustH+=w.state[i].trust;++nh;}}
    const auto& s=w.stats;auto ratio=[](double a,double b){return b?a/b:0;};
    double honestHeadSum=0,honestHeadSquares=0;for(unsigned i=0;i<cfg.nodes;++i)if(!w.malicious[i]){honestHeadSum+=w.headCount[i];honestHeadSquares+=double(w.headCount[i])*w.headCount[i];}
    double headSum=0,headSquares=0,pathH=0,pathM=0;for(unsigned i=0;i<cfg.nodes;++i){headSum+=w.headCount[i];headSquares+=double(w.headCount[i])*w.headCount[i];if(w.malicious[i])pathM+=w.state[i].headPath;else pathH+=w.state[i].headPath;}
    w.output<<w.round<<','<<Phase()<<','<<s.generated<<','<<s.honestGenerated<<','<<s.delivered<<','<<s.honestClean<<','<<s.contentClean<<','<<s.badDelivered<<','
      <<s.filtered<<','<<s.honestFiltered<<','<<s.maliciousFiltered<<','<<s.probes<<','<<s.probeGood<<','<<w.currentHeads.size()<<','<<s.compromisedHeads<<','<<s.activeHeads<<','
      <<s.aggregates<<','<<s.validAggregates<<','<<s.txFrames<<','<<s.txBytes<<','<<s.appDataBytes<<','<<s.appControlBytes<<','<<alive<<','<<energy<<','<<qh<<','<<qm<<','<<probation<<','
      <<ratio(trustH,nh)<<','<<ratio(trustM,nm)<<','<<s.latency<<','<<s.honestTrimmed<<','<<s.badRetained<<','<<s.retained<<','<<s.recommendations<<','<<s.falsePositive<<','<<s.falseNegative<<','<<s.detectedGood<<','<<s.detectedBad<<','<<s.accepted<<','<<s.acceptedHonestClean<<','<<s.acceptedContentClean<<','<<s.acceptedBad<<','<<(values.size()+(IsolateProbes()?0:probes.size()))<<','<<referenceAvailable<<','<<ratio(headSum*headSum,cfg.nodes*headSquares)<<','<<ratio(pathH,nh)<<','<<ratio(pathM,nm)<<','<<ratio(honestHeadSum*honestHeadSum,nh*honestHeadSquares)<<','<<s.ambiguous<<','<<s.temporalRejected<<','<<s.temporalHonestRejected<<','<<s.temporalBadRejected<<','<<s.coverageUtility<<','<<s.scoreUtility<<'\n';
    if(w.trace)for(unsigned i=0;i<cfg.nodes;++i)w.trace<<w.round<<','<<i<<','<<static_cast<bool>(w.malicious[i])<<','<<w.truth[i].generated<<','<<w.truth[i].original<<','<<w.truth[i].sent.value<<','<<w.delivered.count(i)<<','<<static_cast<bool>(w.lastAck[i])<<','<<w.state[i].trust<<','<<w.state[i].status<<','<<(std::find(w.currentHeads.begin(),w.currentHeads.end(),i)!=w.currentHeads.end())<<','<<w.state[i].headPath<<'\n';
}
void Start(unsigned round){
    w.round=round;w.started=true;w.stats={};w.received.clear();w.probeSamples.clear();w.delivered.clear();
    w.buffer.assign(cfg.nodes,{});w.recs.assign(cfg.nodes,{});w.arrived.assign(cfg.nodes,false);w.goodPath.assign(cfg.nodes,false);
    w.currentHeads=Select();for(auto h:w.currentHeads){++w.headCount[h];if(w.malicious[h])++w.stats.compromisedHeads;if(Attack(h,round,true))++w.stats.activeHeads;}
    Generate();
    for(unsigned i=0;i<cfg.nodes;++i){Simulator::Schedule(Seconds(.02*i),&Control,i);Simulator::Schedule(Seconds(2.5+.012*i),&Report,i);Simulator::Schedule(Seconds(7+.012*i),&Recommendations,i);}
    for(unsigned k=0;k<w.currentHeads.size();++k)Simulator::Schedule(Seconds(4.5+.20*k),&Aggregate,w.currentHeads[k]);
    Simulator::Schedule(Seconds(cfg.roundSeconds-.2),&Finish);
    if(round+1<cfg.rounds)Simulator::Schedule(Seconds(cfg.roundSeconds),&Start,round+1);
}
void Setup(){
    RngSeedManager::SetSeed(20261015);RngSeedManager::SetRun(cfg.seed);
    w.rng=CreateObject<UniformRandomVariable>();w.rng->SetStream(1000);
    w.nodes.Create(cfg.nodes+1);w.history.resize(cfg.nodes);w.calibration.resize(cfg.nodes);w.state.resize(cfg.nodes);w.views.resize(cfg.nodes);w.headCount.assign(cfg.nodes,0);w.lastAck.assign(cfg.nodes,false);w.radio.resize(cfg.nodes+1);w.advertisedEnergy.assign(cfg.nodes,1);w.advertisedPosition.resize(cfg.nodes);
    w.malicious.assign(cfg.nodes,false);std::vector<unsigned> ids(cfg.nodes);std::iota(ids.begin(),ids.end(),0);
    std::mt19937 attackRng(cfg.seed);std::shuffle(ids.begin(),ids.end(),attackRng);for(unsigned j=0;j<std::lround(cfg.ratio*cfg.nodes);++j)w.malicious[ids[j]]=true;
    MobilityHelper mobility;auto positions=CreateObject<ListPositionAllocator>();unsigned width=std::ceil(std::sqrt(cfg.nodes));
    NodeContainer sensors;for(unsigned i=0;i<cfg.nodes;++i){sensors.Add(w.nodes.Get(i));w.advertisedPosition[i]=Vector(8+(i%width)*6,8+(i/width)*6,0);positions->Add(w.advertisedPosition[i]);}
    mobility.SetPositionAllocator(positions);
    if(cfg.speed>0)mobility.SetMobilityModel("ns3::RandomWalk2dMobilityModel","Bounds",RectangleValue(Rectangle(0,80,0,80)),"Speed",StringValue("ns3::ConstantRandomVariable[Constant="+std::to_string(cfg.speed)+"]"),"Time",TimeValue(Seconds(1)));
    else mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobility.Install(sensors);mobility.AssignStreams(sensors,2000);
    NodeContainer sink;sink.Add(w.nodes.Get(cfg.nodes));MobilityHelper sinkMobility;sinkMobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");sinkMobility.Install(sink);sink.Get(0)->GetObject<MobilityModel>()->SetPosition(Vector(32,32,0));
    w.lr=std::make_unique<LrWpanHelper>();auto& lr=*w.lr;lr.SetPropagationDelayModel("ns3::ConstantSpeedPropagationDelayModel");lr.AddPropagationLossModel("ns3::LogDistancePropagationLossModel","Exponent",DoubleValue(2.7));
    auto devices=lr.Install(w.nodes);lr.CreateAssociatedPan(devices,1);
    for(unsigned i=0;i<devices.GetN();++i){auto dev=DynamicCast<LrWpanNetDevice>(devices.Get(i));dev->GetPhy()->TraceConnectWithoutContext("TrxStateValue",MakeBoundCallback(&StateChanged,i));dev->GetPhy()->TraceConnectWithoutContext("PhyTxBegin",MakeBoundCallback(&Tx,i));}
    InternetStackHelper internet;internet.Install(w.nodes);SixLowPanHelper six;auto low=six.Install(devices);
    Ipv6AddressHelper address;address.SetBase(Ipv6Address("2001:2::"),Ipv6Prefix(64));w.ip=address.Assign(low);
    w.sockets.resize(cfg.nodes+1);for(unsigned i=0;i<=cfg.nodes;++i){w.sockets[i]=Socket::CreateSocket(w.nodes.Get(i),UdpSocketFactory::GetTypeId());w.sockets[i]->Bind(Inet6SocketAddress(Ipv6Address::GetAny(),PORT));w.sockets[i]->SetRecvCallback(MakeBoundCallback(&Receive,i));}
    Simulator::Schedule(Seconds(2),&Start,0);Simulator::Stop(Seconds(2+cfg.rounds*cfg.roundSeconds));
}
} // namespace
int main(int argc,char** argv){
    CommandLine cmd(__FILE__);cmd.AddValue("nodes","Sensor count",cfg.nodes);cmd.AddValue("heads","Maximum eligible heads",cfg.heads);cmd.AddValue("rounds","Mission rounds",cfg.rounds);cmd.AddValue("seed","Paired scenario seed",cfg.seed);
    cmd.AddValue("ratio","Compromised identity fraction (attack/scoring only)",cfg.ratio);cmd.AddValue("speed","Sensor random-walk speed m/s",cfg.speed);cmd.AddValue("policy","Policy",cfg.policy);cmd.AddValue("attack","none/fixed/sleeper/on-off",cfg.attack);
    cmd.AddValue("output","Round CSV",cfg.output);cmd.AddValue("trace","Optional report trace CSV",cfg.trace);cmd.AddValue("alpha","Trimming fraction per tail",cfg.trust.alpha);cmd.AddValue("delta","Clip radius",cfg.trust.delta);
    cmd.AddValue("etaB","Direct evidence fusion weight",cfg.trust.etaB);cmd.AddValue("etaR","Recommendation fusion weight",cfg.trust.etaR);cmd.AddValue("etaG","Path fusion weight",cfg.trust.etaG);cmd.AddValue("etaE","Energy fusion weight",cfg.trust.etaE);
    cmd.AddValue("noise","Sensor heterogeneity half-width",cfg.noise);cmd.AddValue("loss","Additional report erasure probability",cfg.loss);cmd.AddValue("shift","False scalar reading shift",cfg.shift);cmd.AddValue("central","Central-value collusive recommendations",cfg.central);cmd.AddValue("outage","Benign outage in rounds 80-99 for every fifth node",cfg.outage);
    cmd.AddValue("roleMemory","Separate and preserve head-role evidence",cfg.roleMemory);cmd.AddValue("probeIsolation","Exclude probes and ineligible sources from semantic reference",cfg.probeIsolation);cmd.AddValue("weightPath","Head-role path score coefficient",cfg.weightPath);cmd.AddValue("betaPath","Head-exposure smoothing",cfg.trust.betaPath);cmd.AddValue("referenceMin","Minimum eligible regular reference observations",cfg.referenceMin);
    cmd.AddValue("calibrated","Use received attack-free commissioning observations and bounded reference changes",cfg.calibrated);
    cmd.AddValue("coverage","Select heads by frozen marginal coverage utility",cfg.coverage);
    cmd.AddValue("calibrationRounds","Declared commissioning duration",cfg.calibrationRounds);
    cmd.AddValue("calibrationMinimum","Required received commissioning samples per source",cfg.calibrationMinimum);
    cmd.AddValue("referenceStep","Maximum common-reference movement per round",cfg.referenceStep);
    cmd.AddValue("warmup","Attack onset round",cfg.warmup);
    cmd.AddValue("period","On-off period",cfg.period);
    cmd.AddValue("physicalStep","Legitimate common-process step after warmup (assumption stress)",cfg.physicalStep);
    cmd.AddValue("ambiguityGuard","Defer semantic verdict for near-balanced separated clusters",cfg.ambiguityGuard);
    cmd.AddValue("temporal","Use observable temporal peer contrast",cfg.temporal);
    cmd.AddValue("temporalLambda","Exponential history gain",cfg.temporalLambda);
    cmd.AddValue("temporalMargin","Minimum persistent residual effect",cfg.temporalMargin);
    cmd.AddValue("temporalZ","Operational uncertainty multiplier, not a calibrated p-value",cfg.temporalZ);
    cmd.AddValue("temporalMinimum","Minimum received records per history",cfg.temporalMinimum);
    cmd.AddValue("benignBias","Legitimate persistent offset on every fifth sensor",cfg.benignBias);
    cmd.AddValue("headDrop","Head drop attack probability",cfg.drop);
    cmd.AddValue("headTamper","Head alteration probability",cfg.tamper);
    cmd.AddValue("initialEnergy","Per-sensor energy J",cfg.initialEnergy);cmd.AddValue("rho","Trust update step",cfg.trust.rho);cmd.AddValue("filter","Admission threshold",cfg.trust.filter);cmd.AddValue("headThreshold","Head eligibility threshold",cfg.trust.head);cmd.AddValue("quarantineThreshold","Quarantine threshold",cfg.trust.quarantine);cmd.AddValue("hold","Minimum quarantine rounds",cfg.trust.hold);cmd.AddValue("successes","Consecutive successful probes for release",cfg.trust.successes);cmd.AddValue("probePeriod","Rounds between probes",cfg.trust.probePeriod);cmd.Parse(argc,argv);
    try{
        cfg.trust.roleMemory=RoleMemory();cfg.trust.robust=cfg.policy!="no-robust"&&cfg.policy!="quarantine-only";cfg.trust.quarantineEnabled=Filtering()&&UsesTrust();cfg.trust.Validate();
        if(cfg.temporalLambda<=0||cfg.temporalLambda>1||cfg.temporalMinimum<2||cfg.temporalMargin<0)throw std::invalid_argument("invalid temporal parameters");
        if(cfg.nodes<2||cfg.nodes>100||cfg.heads>10||cfg.ratio<0||cfg.ratio>.9)throw std::invalid_argument("unsupported scenario");
        if(crypto.Tag(Bytes{'H','i',' ','T','h','e','r','e'},std::string(20,'\x0b'))!=0xb0344c61d8db3853ULL)throw std::runtime_error("RFC 4231 HMAC test failed");
        w.output.open(cfg.output);if(!w.output)throw std::runtime_error("cannot open output");w.output<<std::setprecision(10);
        w.output<<"round,phase,generated,honest_generated,delivered,honest_clean,content_clean,bad_delivered,filtered,honest_filtered,malicious_filtered,probes,good_probes,heads,compromised_heads,active_attack_heads,aggregates,valid_aggregates,tx_frames,tx_bytes,app_data_bytes,app_control_bytes,alive,cumulative_radio_energy_j,honest_quarantine,malicious_quarantine,probation,mean_honest_trust,mean_malicious_trust,latency_sum_s,honest_trimmed,bad_retained,retained,recommendations,false_positive,false_negative,detected_good,detected_bad,accepted,accepted_honest_clean,accepted_content_clean,accepted_bad,reference_count,reference_available,head_jain,mean_honest_path,mean_malicious_path,honest_head_jain,ambiguous_round,temporal_rejected,temporal_honest_rejected,temporal_bad_rejected,coverage_utility,score_utility\n";
        if(!cfg.trace.empty()){w.trace.open(cfg.trace);w.trace<<"round,source,malicious,generated,physical_value,source_value,delivered,acknowledged_good,trust,state,head,path\n";}
        Setup();Simulator::Run();Simulator::Destroy();return 0;
    }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
}
