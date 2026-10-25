#include "trust-v2.h"
#include "temporal-evidence.h"
#include "calibration-coverage.h"
#include "published-kernels.h"
#include "trusted-reference.h"
#include "certified-evidence.h"
#include <sstream>
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
enum Message:uint8_t{CONTROL=1,REPORT=2,AGGREGATE=3,RECOMMENDATION=4,PROBE=5,AUDIT=6,REFERENCE=7};
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
    bool batteryCutoff=false;double energySpread=0;
    unsigned referenceMin=3;
    bool ambiguityGuard=false,temporal=false,calibrated=false,coverage=false;
    unsigned calibrationRounds=60,calibrationMinimum=40;
    double referenceStep=3,physicalStep=0;
    double temporalLambda=.04,temporalMargin=.45,temporalZ=2.5,benignBias=0;
    unsigned temporalMinimum=20;
    bool sequential=false,commonRecovery=false,adaptiveReference=false;
    bool probationAudit=false;unsigned auditGuard=0;double auditMeanBound=.75;
    bool probationData=false;double probationLower=.25,probationUpper=.75;
    bool rollingRecovery=false;unsigned recoveryAge=3,alarmRelease=0;double releaseMargin=.3;
    double cusumK=.5,cusumH=8,varianceFloor=.5,fairBonus=0,fairPathPower=0;
    unsigned references=0,referenceCompromised=0,referenceTampered=0;
    bool referenceAssist=false,evidenceFirst=false,referenceOutage=false,referenceOff=false;
    double referenceNoise=.5,referenceBias=.25,referenceBound=.751,referenceLoss=0;
    double referenceDelay=0,referenceShift=18,referenceCommonBias=0,physicalDrift=0;
    bool certifiedCalibration=false,directVeto=false;
    std::string calibrationFile="";double certifiedNoiseBound=1,certificateMaxBound=.051;
    dynatrust::Parameters trust;
} cfg;
struct Truth {bool generated=false,bad=false;int32_t original=0;Sample sent{};};
struct NodeView {
    int controlRound=-1;std::vector<unsigned> heads;std::vector<bool> admit,quarantine;
    std::map<unsigned,std::pair<double,unsigned>> local;std::map<unsigned,Vector> headPositions;
    int previousHead=-1;bool previousParticipated=false;
};
struct Radio {double joules=0,last=0,current=.000001;bool dead=false;};
struct Stats {
    unsigned generated=0,honestGenerated=0,delivered=0,honestClean=0,contentClean=0,badDelivered=0;
    unsigned filtered=0,honestFiltered=0,maliciousFiltered=0,probes=0,probeGood=0;
    unsigned compromisedHeads=0,activeHeads=0,aggregates=0,validAggregates=0;
    unsigned txFrames=0,txBytes=0,appDataBytes=0,appControlBytes=0;
    unsigned honestTrimmed=0,badRetained=0,retained=0,recommendations=0;
    unsigned falsePositive=0,falseNegative=0,detectedGood=0,detectedBad=0,accepted=0,acceptedHonestClean=0,acceptedContentClean=0,acceptedBad=0;
    unsigned ambiguous=0,temporalRejected=0,temporalHonestRejected=0,temporalBadRejected=0;
    unsigned auditAccepted=0,auditBad=0;
    unsigned referenceSent=0,referenceReceived=0,referenceStale=0,referenceAvailable=0,referenceWitnesses=0,recommendationGated=0;
    unsigned referenceBytes=0,referenceRejected=0,directVetoes=0;
    double latency=0,coverageUtility=0,scoreUtility=0;
};
struct World {
    std::vector<Ptr<LrWpanNetDevice>> devices;
    std::unique_ptr<LrWpanHelper> lr;NodeContainer nodes;Ipv6InterfaceContainer ip;std::vector<Ipv6Address> addresses;std::vector<Ptr<Socket>> sockets;
    std::vector<certified::Offset> certificates;
    std::vector<temporal::History> history;
    std::vector<calibration::Baseline> calibration;
    std::vector<sequential::Cusum> cusum;
    std::vector<published::Window> publishedWindow;
    sequential::CommonEvent commonEvent;
    recovery::RollingReference rollingReference;
    std::vector<recovery::AlarmRelease> alarmRelease;
    std::vector<recovery::RecentBand> auditHistory;
    bool anchorAvailable=false;double anchor=0;
    std::map<unsigned,independent::Observation> referenceReceived;
    std::vector<dynatrust::State> state;std::vector<NodeView> views;std::vector<Radio> radio;
    std::vector<bool> malicious; // Attack generation / offline scoring only.
    std::vector<Truth> truth;std::vector<double> physical,advertisedEnergy;std::vector<Vector> advertisedPosition;
    std::vector<std::vector<Sample>> buffer;std::vector<unsigned> headCount,currentHeads;
    std::vector<std::vector<std::pair<unsigned,double>>> recs;
    std::vector<Sample> received,probeSamples,auditSamples;std::vector<bool> arrived,goodPath,lastAck;
    std::set<unsigned> delivered;Stats stats;unsigned round=0;bool started=false;
    Ptr<UniformRandomVariable> rng;std::ofstream output,trace;
} w;

unsigned TotalNodes(){return cfg.nodes+1+cfg.references;}
bool BatteryNode(unsigned id){return id!=cfg.nodes;}
std::string SourceKey(unsigned id){return "v2-simulation-source|"+std::to_string(cfg.seed)+"|"+std::to_string(id);}
std::string LinkKey(unsigned s,unsigned d){return "v2-simulation-link|"+std::to_string(cfg.seed)+"|"+std::to_string(std::min(s,d))+"|"+std::to_string(std::max(s,d));}
uint64_t SampleTag(const Sample& s){Bytes b;Put(b,s.source,2);Put(b,s.sequence,4);Put(b,static_cast<uint32_t>(s.value),4);return crypto.Tag(b,SourceKey(s.source));}
// Calibration records contain independent predeployment observations only.
// Runtime authentication does not read sensor truth or compromise allocation.
void LoadCertificates(){
    w.certificates.assign(cfg.nodes,{});if(!cfg.certifiedCalibration)return;
    std::ifstream f(cfg.calibrationFile);if(!f)throw std::runtime_error("cannot open calibration records");
    std::vector<bool> seen(cfg.nodes,false);std::string line;
    while(std::getline(f,line)){
      try{
        std::istringstream in(line);std::vector<std::string> fields;std::string part;
        while(std::getline(in,part,','))fields.push_back(part);
        if(fields.size()!=5)continue;
        unsigned id=std::stoul(fields[0]),epoch=std::stoul(fields[1]);
        if(id>=cfg.nodes)continue;
        if(seen[id]){w.certificates[id]={};continue;}seen[id]=true;
        int32_t offset=std::stol(fields[2]);unsigned bound=std::stoul(fields[3]);
        uint64_t tag=std::stoull(fields[4],nullptr,16);
        Bytes body;Put(body,id,2);Put(body,epoch,4);Put(body,static_cast<uint32_t>(offset),4);Put(body,bound,4);
        if(epoch!=1||bound>1000*cfg.certificateMaxBound+.01||
           tag!=crypto.Tag(body,"v2-simulation-calibration-authority|"+std::to_string(cfg.seed)))continue;
        w.certificates[id]={true,offset/1000.0,bound/1000.0};
      }catch(const std::exception&){continue;}
    }
}
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
    if(cfg.attack=="delayed"||cfg.attack=="signflip")return t>=cfg.warmup;
    if(cfg.attack=="sleeper")return t>=cfg.warmup && head;
    if(cfg.attack=="on-off")return t>=cfg.warmup && (t-cfg.warmup)%cfg.period>=cfg.period/2;
    return true;
}
std::string Phase(){if(cfg.ratio==0||cfg.attack=="none")return "benign";if(cfg.attack=="fixed")return "attack";if(w.round<cfg.warmup)return "warmup";if(cfg.attack=="sleeper"||cfg.attack=="delayed"||cfg.attack=="signflip")return "attack";return (w.round-cfg.warmup)%cfg.period>=cfg.period/2?"attack":"benign-recovery";}
double Current(PhyEnumeration s){if(s==IEEE_802_15_4_PHY_BUSY_TX||s==IEEE_802_15_4_PHY_TX_ON)return .020;if(s==IEEE_802_15_4_PHY_RX_ON||s==IEEE_802_15_4_PHY_BUSY_RX)return .012;return .000001;}
double Budget(unsigned id){return cfg.initialEnergy*(1-cfg.energySpread+2*cfg.energySpread*ScenarioUniform(id,0,77));}
void Account(unsigned id){auto& r=w.radio[id];const double now=Simulator::Now().GetSeconds();if(!r.dead)r.joules+=3*r.current*(now-r.last);if(cfg.batteryCutoff&&BatteryNode(id))r.joules=std::min(Budget(id),r.joules);r.last=now;}
void Cutoff(unsigned id){
    // Round-boundary budget cutoff: collection has ended, avoiding mid-frame radio interruption.
    auto& r=w.radio[id];if(r.dead)return;Account(id);if(r.joules<Budget(id))return;
    r.dead=true;r.joules=Budget(id);r.current=0;
    auto device=w.devices[id];device->GetMac()->SetRxOnWhenIdle(false);
    device->GetPhy()->PlmeSetTRXStateRequest(IEEE_802_15_4_PHY_FORCE_TRX_OFF);
    auto ipv6=w.nodes.Get(id)->GetObject<Ipv6>();for(unsigned j=1;j<ipv6->GetNInterfaces();++j)ipv6->SetDown(j);
}
void StateChanged(unsigned id,PhyEnumeration old,PhyEnumeration next){Account(id);w.radio[id].current=w.radio[id].dead?0:Current(next);}
void Tx(unsigned id,Ptr<const Packet> packet){if(w.radio[id].dead)throw std::runtime_error("TX after battery cutoff");if(w.started){++w.stats.txFrames;w.stats.txBytes+=packet->GetSize();}}
double Energy(unsigned id){Account(id);return std::max(0.0,1-w.radio[id].joules/Budget(id));}
bool Alive(unsigned id){return Energy(id)>0;}
void Send(const Frame& f){
    if(BatteryNode(f.sender) && !Alive(f.sender))return;
    if(cfg.outage && w.round>=80 && w.round<100 && f.sender<cfg.nodes && f.sender%5==0)return;
    if(f.type==REPORT && ScenarioUniform(f.sender,w.round,1)<cfg.loss)return;
    if(f.type==REFERENCE){
        if((cfg.referenceOutage&&w.round>=cfg.warmup&&w.round<cfg.warmup+20)||
           (cfg.referenceOff&&w.round>=cfg.warmup)||ScenarioUniform(f.sender,w.round,91)<cfg.referenceLoss)return;
    }
    const auto data=Encode(f);
    if(f.type==CONTROL||f.type==RECOMMENDATION||f.type==PROBE||f.type==AUDIT||f.type==REFERENCE)w.stats.appControlBytes+=data.size();else w.stats.appDataBytes+=data.size();
    if(f.type==REFERENCE){++w.stats.referenceSent;w.stats.referenceBytes+=data.size();}
    w.sockets[f.sender]->SendTo(Create<Packet>(data.data(),data.size()),0,Inet6SocketAddress(w.addresses[f.dest],PORT));
}
bool Published(){return cfg.policy=="gtms-kernel"||cfg.policy=="edtm-com-kernel"||cfg.policy=="ltmhl-kernel"||cfg.policy=="ldts-direct-kernel";}
bool UsesTrust(){return cfg.policy!="leach-style" && cfg.policy!="heed-style" && cfg.policy!="energy" && cfg.policy!="oracle";}
bool Filtering(){return Published()||cfg.policy=="dynatrust"||cfg.policy=="isolated-reference"||cfg.policy=="no-role-memory"||cfg.policy=="no-reference-weight"||cfg.policy=="no-probe-isolation"||cfg.policy=="legacy"||cfg.policy=="no-robust"||cfg.policy=="no-fairness"||cfg.policy=="no-diversity"||cfg.policy=="quarantine-only"||cfg.policy=="oracle";}
bool RoleMemory(){return !Published() && cfg.roleMemory && UsesTrust() && cfg.policy!="legacy" && cfg.policy!="no-role-memory" && cfg.policy!="robust-reputation" && cfg.policy!="trust-leach-style" && cfg.policy!="quarantine-only";}
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
        for(unsigned j=0;j<cfg.nodes;++j)eligible[j]=(!cfg.certifiedCalibration||w.certificates[j].valid) && energy[j]>.01 && (!UsesTrust()||(Published()&&w.round<5)||dynatrust::Eligible(w.state[j],cfg.trust));
        for(unsigned i=0;i<cfg.nodes;++i)for(unsigned j=0;j<cfg.nodes;++j){
            const bool admitted=(!cfg.certifiedCalibration||w.certificates[i].valid)&&(!Filtering()||dynatrust::Admit(w.state[i],cfg.trust));
            benefit[i][j]=admitted?w.state[i].trust*std::max(0.0,base[j])*(.25+.75*(1-ReportedDistance(i,j)/maxDist)):0;
        }
        std::vector<double> bonus(cfg.nodes,0);double average=0;unsigned candidates=0;
        for(unsigned j=0;j<cfg.nodes;++j)if(eligible[j]){average+=w.headCount[j];++candidates;}
        if(candidates)average/=candidates;
        for(unsigned j=0;j<cfg.nodes;++j)bonus[j]=cfg.fairBonus*std::max(0.0,average-w.headCount[j])*std::pow(std::max(.05,w.state[j].headPath),cfg.fairPathPower);
        coverageHeads=coverage::Greedy(benefit,eligible,cfg.heads,bonus);
    }
    while(selected.size()<cfg.heads){
        int best=-1;double score=-1;
        for(unsigned i=0;i<cfg.nodes;++i){
            if(cfg.certifiedCalibration&&!w.certificates[i].valid)continue;
            if(energy[i]<=.01||std::find(selected.begin(),selected.end(),i)!=selected.end())continue;
            if(UsesTrust()&&!(Published()&&w.round<5)&&cfg.policy!="quarantine-only"&&!dynatrust::Eligible(w.state[i],cfg.trust))continue;
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
bool ControllerAdmit(unsigned i){if(cfg.certifiedCalibration&&!w.certificates[i].valid)return false;if(cfg.policy=="oracle")return !w.malicious[i];return !Filtering()||dynatrust::Admit(w.state[i],cfg.trust);}
void Control(unsigned id){
    Frame f{CONTROL,w.round,static_cast<uint16_t>(cfg.nodes),static_cast<uint16_t>(id),static_cast<uint16_t>(w.currentHeads.size()),{}};
    for(auto head:w.currentHeads){Put(f.body,head,2);Put(f.body,std::lround(w.advertisedPosition[head].x*100),2);Put(f.body,std::lround(w.advertisedPosition[head].y*100),2);}
    for(unsigned kind=0;kind<2;++kind)for(unsigned byte=0;byte<(cfg.nodes+7)/8;++byte){unsigned bits=0;for(unsigned bit=0;bit<8;++bit){unsigned i=byte*8+bit;if(i<cfg.nodes && (kind?w.state[i].status!=0:ControllerAdmit(i)))bits|=1<<bit;}Put(f.body,bits,1);}
    Put(f.body,w.lastAck[id],1);Send(f);
}
void Receive(unsigned id,Ptr<Socket> socket){
    Address address;
    while(auto packet=socket->RecvFrom(address)){
        if(BatteryNode(id)&&w.radio[id].dead)continue;
        Bytes data(packet->GetSize());packet->CopyData(data.data(),data.size());
        try{
            auto f=Decode(data);
            if(f.type==REFERENCE&&id==cfg.nodes&&f.sender>cfg.nodes&&f.sender<TotalNodes()&&f.round!=w.round)++w.stats.referenceStale;
            if(f.round!=w.round||f.dest!=id||f.sender>=TotalNodes())continue;
            size_t at=0;
            if(f.type==REFERENCE&&id==cfg.nodes&&f.sender>cfg.nodes&&f.count==1){
                auto sample=UnpackSample(f.body,at);
                if(at==f.body.size()&&sample.source==f.sender&&sample.sequence==w.round&&sample.tag==SampleTag(sample)){
                    w.referenceReceived[f.sender-cfg.nodes-1]={sample.value/1000.0,w.round};++w.stats.referenceReceived;
                }else ++w.stats.referenceRejected;
            }else if(f.type==CONTROL && id<cfg.nodes && f.sender==cfg.nodes){
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
            }else if((f.type==PROBE||f.type==AUDIT) && id==cfg.nodes && f.sender<cfg.nodes && f.count==1){
                auto s=UnpackSample(f.body,at);if(s.source==f.sender && Valid(s)){
                    if(f.type==AUDIT)w.auditSamples.push_back(s);else w.probeSamples.push_back(s);
                    if(cfg.probationData&&w.delivered.insert(s.source).second){
                        ++w.stats.delivered;
                        const bool clean=w.truth[s.source].generated&&s.value==w.truth[s.source].original;
                        if(clean){++w.stats.contentClean;if(!w.malicious[s.source])++w.stats.honestClean;}else ++w.stats.badDelivered;
                        w.stats.latency+=Simulator::Now().GetSeconds()-(2+w.round*cfg.roundSeconds);
                    }
                }
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
        const double value=45+3*std::sin(w.round/30.0)+cfg.noise*(2*std::abs(u)-1)+(i%5==0?cfg.benignBias:0)+(w.round>=cfg.warmup?cfg.physicalStep+cfg.physicalDrift*(w.round-cfg.warmup):0);
        w.physical[i]=value;if(!Alive(i))continue;
        auto& t=w.truth[i];t.generated=true;t.original=std::lround(value*1000);
        t.sent={static_cast<uint16_t>(i),w.round,t.original,0};
        const bool isHead=std::find(w.currentHeads.begin(),w.currentHeads.end(),i)!=w.currentHeads.end();
        if(Attack(i,w.round,isHead) && cfg.attack!="sleeper")t.sent.value+=std::lround(cfg.shift*1000)*(cfg.attack=="signflip"&&((w.round-cfg.warmup)/(cfg.period/2))%2?-1:1);
        t.sent.tag=SampleTag(t.sent);t.bad=t.sent.value!=t.original;
        ++w.stats.generated;if(!w.malicious[i])++w.stats.honestGenerated;
    }
}
// Independent measurement generation, never called by the controller. The
// shared latent field drives each physical sensor; only its signed noisy packet
// is visible to the sink. It is not the ordinary sensors' truth/scoring ledger.
void ReferenceReport(unsigned reference){
    const unsigned id=cfg.nodes+1+reference;
    if(!Alive(id))return;
    const double field=45+3*std::sin(w.round/30.0)+(w.round>=cfg.warmup?cfg.physicalStep+cfg.physicalDrift*(w.round-cfg.warmup):0);
    double measured=field+cfg.referenceNoise*(2*ScenarioUniform(id,w.round,92)-1)
        +cfg.referenceBias*(2*ScenarioUniform(id,0,93)-1)+cfg.referenceCommonBias;
    if(reference<cfg.referenceCompromised)measured+=cfg.referenceShift;
    Sample sample{static_cast<uint16_t>(id),w.round,static_cast<int32_t>(std::lround(1000*measured)),0};
    sample.tag=SampleTag(sample);
    if(reference<cfg.referenceTampered)sample.tag^=1;
    Frame f{REFERENCE,w.round,static_cast<uint16_t>(id),static_cast<uint16_t>(cfg.nodes),1,{}};
    PackSample(f.body,sample);
    if(cfg.referenceDelay>0)Simulator::Schedule(Seconds(cfg.referenceDelay),&Send,f);else Send(f);
}
void Report(unsigned id){
    if(!w.truth[id].generated)return;auto& v=w.views[id];v.previousParticipated=false;
    if(v.controlRound!=static_cast<int>(w.round))return;
    if(v.quarantine[id]&&Filtering()){
        ++w.stats.filtered;if(w.malicious[id])++w.stats.maliciousFiltered;else ++w.stats.honestFiltered;
        if(dynatrust::ProbeDue(w.state[id],w.round,cfg.trust)||cfg.probationAudit){
            Frame f{static_cast<uint8_t>(dynatrust::ProbeDue(w.state[id],w.round,cfg.trust)?PROBE:AUDIT),w.round,static_cast<uint16_t>(id),static_cast<uint16_t>(cfg.nodes),1,{}};PackSample(f.body,w.truth[id].sent);++w.stats.probes;Send(f);
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
    const bool learning=cfg.calibrated && !cfg.certifiedCalibration && w.round<cfg.calibrationRounds;
    const bool calibrated=cfg.calibrated && !learning;
    auto corrected=[&](const Sample& s){if(cfg.certifiedCalibration)return s.value/1000.0-w.certificates[s.source].value;return s.value/1000.0-((calibrated&&(!cfg.referenceAssist||w.calibration[s.source].count>=cfg.calibrationMinimum))?w.calibration[s.source].Mean():0);};
    auto usable=[&](const Sample& s){if(cfg.certifiedCalibration)return Valid(s)&&w.certificates[s.source].valid;return Valid(s)&&(cfg.referenceAssist||!calibrated||w.calibration[s.source].count>=cfg.calibrationMinimum);};
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
    if(calibrated&&!cfg.referenceAssist){
        double referenceStep=cfg.referenceStep;
        std::vector<std::pair<double,double>> sigmas;
        for(unsigned i=0;i<cfg.nodes;++i)if(w.calibration[i].count>=cfg.calibrationMinimum)
            sigmas.push_back({std::max(cfg.varianceFloor,w.calibration[i].SD()),1});
        const double sigma=sigmas.empty()?cfg.varianceFloor:temporal::WeightedMedian(sigmas);
        if(cfg.adaptiveReference)referenceStep+=3*sigma/std::sqrt(std::max(1.0,double(referenceValues.size())));
        const auto anchored=calibration::Anchor(referenceValues,w.anchorAvailable,w.anchor,referenceStep,cfg.plausibility,cfg.referenceMin);
        referenceAvailable=anchored.available;median=anchored.value;
        if(cfg.rollingRecovery){
            std::map<unsigned,double> unique;
            for(auto s:w.received)if(usable(s))unique[s.source]=corrected(s);
            if(!IsolateProbes())for(auto s:w.probeSamples)if(usable(s))unique[s.source]=corrected(s);
            const auto rolling=w.rollingReference.Observe(unique,cfg.nodes,w.round,cfg.recoveryAge,std::max(2.0,3*sigma),referenceStep);
            if(!referenceAvailable&&rolling.available){referenceAvailable=true;median=rolling.value;}
        }
        if(cfg.commonRecovery&&!referenceAvailable){
            std::map<unsigned,double> unique;
            for(auto s:w.received)if(usable(s))unique[s.source]=corrected(s);
            if(!IsolateProbes())for(auto s:w.probeSamples)if(usable(s))unique[s.source]=corrected(s);
            std::vector<double> observations;for(auto [id,x]:unique)observations.push_back(x);
            const auto event=w.commonEvent.Observe(observations,cfg.nodes,w.round,std::max(2.0,3*sigma),referenceStep);
            if(event.available){referenceAvailable=true;median=event.value;}
        }else w.commonEvent.Reset();
    }
    if(cfg.referenceAssist){
        const auto independent=independent::Reference(w.referenceReceived,cfg.references,w.round,cfg.referenceBound);
        referenceAvailable=independent.available;median=independent.value;
        w.stats.referenceAvailable=independent.available;w.stats.referenceWitnesses=independent.witnesses;
    }
    if(referenceAvailable){w.anchorAvailable=true;w.anchor=median;}
    if(learning && referenceAvailable){
        auto learn=[&](const Sample& s){if(Valid(s)&&(!cfg.referenceAssist||std::abs(s.value/1000.0-median)<=cfg.plausibility+2*cfg.referenceBound))w.calibration[s.source].Observe(s.value/1000.0-median);};
        for(const auto& s:w.received)learn(s);for(const auto& s:w.probeSamples)learn(s);
    }
    temporal::Contrast contrast;
    if(cfg.temporal && !learning && referenceAvailable){
        auto update=[&](const Sample& s){if(usable(s)&&(!calibrated||std::abs(corrected(s)-median)<=cfg.plausibility))w.history[s.source].Observe(corrected(s)-median,w.round,cfg.temporalLambda);};
        for(const auto& s:w.received)update(s);for(const auto& s:w.probeSamples)update(s);
        std::vector<temporal::Peer> peers;
        for(unsigned i=0;i<cfg.nodes;++i)if(w.history[i].count>=cfg.temporalMinimum && w.round-w.history[i].last<=20)
            peers.push_back({w.history[i].Mean(),w.history[i].SE(),weighted?std::max(.05,w.state[i].headPath):1.0});
        contrast=cfg.referenceAssist?temporal::Contrast{true,0,0}:temporal::PeerContrast(peers);
    }
    std::vector<dynatrust::Evidence> evidence(cfg.nodes);w.lastAck.assign(cfg.nodes,false);
    auto observe=[&](const Sample& s,bool probe){
        if(!usable(s))return;
        if(!referenceAvailable && s.value>=0 && s.value<=100000)return; // Unknown semantics: no fabricated observation or acceptance.
        const double tolerance=cfg.certifiedCalibration?certified::Tolerance(w.certificates[s.source],cfg.certifiedNoiseBound,cfg.referenceBound):cfg.plausibility+(cfg.referenceAssist?2*cfg.referenceBound:0);
        bool good=referenceAvailable && s.value>=0 && s.value<=100000 && std::abs(corrected(s)-median)<=tolerance;
        bool sequentialBad=false,probationAccept=false;
        if(good&&cfg.sequential&&calibrated&&contrast.available){
            const double sigma=std::max(cfg.varianceFloor,w.calibration[s.source].SD());
            const double z=(corrected(s)-median-contrast.center)/sigma;
            const bool recentGood=!cfg.auditGuard||w.auditHistory[s.source].Observe(z,w.round,cfg.auditGuard,cfg.auditMeanBound);
            w.cusum[s.source].Observe(z,cfg.cusumK,cfg.cusumH);
            if(cfg.alarmRelease&&w.alarmRelease[s.source].Observe(w.cusum[s.source].Reject(cfg.cusumH),z,w.round,cfg.alarmRelease,cfg.releaseMargin)){
                w.cusum[s.source]={};w.history[s.source]={};
                w.history[s.source].Observe(corrected(s)-median,w.round,cfg.temporalLambda);
            }
            sequentialBad=w.cusum[s.source].Reject(cfg.cusumH);
            if(probe&&cfg.probationData&&sequentialBad&&recentGood){
                const auto& c=w.cusum[s.source];
                probationAccept=(c.positive>cfg.cusumH&&c.negative<=cfg.cusumH&&z>=-cfg.probationUpper&&z<=-cfg.probationLower)||
                    (c.negative>cfg.cusumH&&c.positive<=cfg.cusumH&&z>=cfg.probationLower&&z<=cfg.probationUpper);
            }
        }
        const bool temporalBad=sequentialBad || (good && cfg.temporal && !learning && contrast.available && w.history[s.source].count>=cfg.temporalMinimum &&
            temporal::Reject(w.history[s.source],contrast,cfg.temporalMargin,cfg.temporalZ));
        if(temporalBad)good=false;
        auto& e=evidence[s.source];e.hasDirect=true;e.direct=good?1:0;if(probe){e.probe=true;e.probeGood=good;if(good)++w.stats.probeGood;}else w.lastAck[s.source]=good;
        const bool trueBad=s.value!=w.truth[s.source].original;
        if(temporalBad){++w.stats.temporalRejected;if(trueBad)++w.stats.temporalBadRejected;else if(!w.malicious[s.source])++w.stats.temporalHonestRejected;}
        if((!probe&&good)||(probe&&cfg.probationData&&probationAccept)){if(probe){++w.stats.auditAccepted;if(trueBad)++w.stats.auditBad;}++w.stats.accepted;if(trueBad)++w.stats.acceptedBad;else{++w.stats.acceptedContentClean;if(!w.malicious[s.source])++w.stats.acceptedHonestClean;}}
        if(good){if(trueBad)++w.stats.falseNegative;else ++w.stats.detectedGood;}else{if(trueBad)++w.stats.detectedBad;else ++w.stats.falsePositive;}
    };
    for(auto s:w.received)observe(s,false);for(auto s:w.probeSamples)observe(s,true);
    // Additional audit records cannot change the reference, histories, CUSUM,
    // recommendations or trust. Only their tightly gated content is counted.
    if(cfg.probationAudit&&referenceAvailable&&calibrated&&contrast.available)
      for(auto sample:w.auditSamples)if(usable(sample)&&sample.value>=0&&sample.value<=100000&&std::abs(corrected(sample)-median)<=cfg.plausibility){
        const auto& c=w.cusum[sample.source];
        const double z=(corrected(sample)-median-contrast.center)/std::max(cfg.varianceFloor,w.calibration[sample.source].SD());
        const bool recentGood=!cfg.auditGuard||w.auditHistory[sample.source].Observe(z,w.round,cfg.auditGuard,cfg.auditMeanBound);
        const bool accepted=recentGood&&((c.positive>cfg.cusumH&&c.negative<=cfg.cusumH&&z>=-cfg.probationUpper&&z<=-cfg.probationLower)||
            (c.negative>cfg.cusumH&&c.positive<=cfg.cusumH&&z>=cfg.probationLower&&z<=cfg.probationUpper));
        if(accepted){++w.stats.accepted;++w.stats.auditAccepted;if(sample.value!=w.truth[sample.source].original){++w.stats.acceptedBad;++w.stats.auditBad;}
          else{++w.stats.acceptedContentClean;if(!w.malicious[sample.source])++w.stats.acceptedHonestClean;}}
      }

    for(auto head:w.currentHeads){evidence[head].hasPath=true;evidence[head].path=w.arrived[head]&&w.goodPath[head]?1:0;
        if(!w.arrived[head]||!w.goodPath[head]){evidence[head].hasDirect=true;evidence[head].direct=0;}}
    for(unsigned i=0;i<cfg.nodes;++i){
        evidence[i].energy=w.advertisedEnergy[i];for(auto [sender,x]:w.recs[i])evidence[i].recommendations.push_back(x);
        AuditTrim(i);
        if(Published()){
            auto& state=w.state[i];const auto& e=evidence[i];
            bool observed=e.hasDirect||e.hasPath;
            // GTMS interaction assurance includes received data quality. EDTM
            // communication component counts reception/path, not semantic truth.
            bool success=cfg.policy=="edtm-com-kernel"?(e.hasPath?e.path>.5:e.hasDirect):(e.hasDirect?e.direct>.5:e.path>.5);
            if(observed)w.publishedWindow[i].observations.push_back({w.round,success});
            auto [good,bad]=w.publishedWindow[i].Counts(w.round,60);
            const double target=cfg.policy=="gtms-kernel"?published::Gtms(good,bad):
                cfg.policy=="edtm-com-kernel"?published::EdtmCommunication(good,bad):
                cfg.policy=="ldts-direct-kernel"?published::LdtsDirect(good,bad):
                observed?published::LtmhlPenalty(state.trust,success):state.trust;
            // Shared wrapper state machine is held fixed to isolate the kernel.
            // Recommendations and DynaTrust smoothing do not alter target trust.
            state.trust=target;dynatrust::Transition(state,e,w.round,cfg.trust);
        }else if(UsesTrust()){
            auto parameters=cfg.trust;
            if(cfg.referenceAssist&&cfg.evidenceFirst&&((evidence[i].hasDirect&&evidence[i].direct<.5)||w.state[i].direct<.5)){
                parameters.etaB+=parameters.etaR;parameters.etaR=0;++w.stats.recommendationGated;
            }
            dynatrust::Update(w.state[i],evidence[i],w.round,parameters);
            if(cfg.directVeto&&certified::Veto(w.state[i],evidence[i],w.round)){++w.stats.directVetoes;if(!w.state[i].status)throw std::logic_error("direct veto bypassed");}
        }
    }
    unsigned alive=0,qh=0,qm=0,probation=0;double energy=0,trustH=0,trustM=0;unsigned nh=0,nm=0;
    for(unsigned i=0;i<cfg.nodes;++i){const bool living=Alive(i);energy+=w.radio[i].joules;if(living)++alive;if(w.state[i].status){if(w.malicious[i])++qm;else ++qh;}if(w.state[i].status==2)++probation;if(w.malicious[i]){trustM+=w.state[i].trust;++nm;}else{trustH+=w.state[i].trust;++nh;}}
    const auto& s=w.stats;auto ratio=[](double a,double b){return b?a/b:0;};
    double honestHeadSum=0,honestHeadSquares=0;for(unsigned i=0;i<cfg.nodes;++i)if(!w.malicious[i]){honestHeadSum+=w.headCount[i];honestHeadSquares+=double(w.headCount[i])*w.headCount[i];}
    double headSum=0,headSquares=0,pathH=0,pathM=0;for(unsigned i=0;i<cfg.nodes;++i){headSum+=w.headCount[i];headSquares+=double(w.headCount[i])*w.headCount[i];if(w.malicious[i])pathM+=w.state[i].headPath;else pathH+=w.state[i].headPath;}
    w.output<<w.round<<','<<Phase()<<','<<s.generated<<','<<s.honestGenerated<<','<<s.delivered<<','<<s.honestClean<<','<<s.contentClean<<','<<s.badDelivered<<','
      <<s.filtered<<','<<s.honestFiltered<<','<<s.maliciousFiltered<<','<<s.probes<<','<<s.probeGood<<','<<w.currentHeads.size()<<','<<s.compromisedHeads<<','<<s.activeHeads<<','
      <<s.aggregates<<','<<s.validAggregates<<','<<s.txFrames<<','<<s.txBytes<<','<<s.appDataBytes<<','<<s.appControlBytes<<','<<alive<<','<<energy<<','<<qh<<','<<qm<<','<<probation<<','
      <<ratio(trustH,nh)<<','<<ratio(trustM,nm)<<','<<s.latency<<','<<s.honestTrimmed<<','<<s.badRetained<<','<<s.retained<<','<<s.recommendations<<','<<s.falsePositive<<','<<s.falseNegative<<','<<s.detectedGood<<','<<s.detectedBad<<','<<s.accepted<<','<<s.acceptedHonestClean<<','<<s.acceptedContentClean<<','<<s.acceptedBad<<','<<(values.size()+(IsolateProbes()?0:probes.size()))<<','<<referenceAvailable<<','<<ratio(headSum*headSum,cfg.nodes*headSquares)<<','<<ratio(pathH,nh)<<','<<ratio(pathM,nm)<<','<<ratio(honestHeadSum*honestHeadSum,nh*honestHeadSquares)<<','<<s.ambiguous<<','<<s.temporalRejected<<','<<s.temporalHonestRejected<<','<<s.temporalBadRejected<<','<<s.coverageUtility<<','<<s.scoreUtility<<','<<s.auditAccepted<<','<<s.auditBad;
    double referenceEnergy=0;unsigned referenceAlive=0;
    for(unsigned id=cfg.nodes+1;id<TotalNodes();++id){if(Alive(id))++referenceAlive;referenceEnergy+=w.radio[id].joules;}
    w.output<<','<<s.referenceSent<<','<<s.referenceReceived<<','<<s.referenceStale<<','<<s.referenceAvailable<<','<<s.referenceWitnesses
      <<','<<s.referenceBytes<<','<<referenceEnergy<<','<<referenceAlive<<','<<s.recommendationGated<<','<<energy+referenceEnergy<<','<<s.referenceRejected<<','<<s.directVetoes<<','<<std::count_if(w.certificates.begin(),w.certificates.end(),[](auto x){return x.valid;})<<'\n';
    if(w.trace)for(unsigned i=0;i<cfg.nodes;++i)w.trace<<w.round<<','<<i<<','<<static_cast<bool>(w.malicious[i])<<','<<w.truth[i].generated<<','<<w.truth[i].original<<','<<w.truth[i].sent.value<<','<<w.delivered.count(i)<<','<<static_cast<bool>(w.lastAck[i])<<','<<w.state[i].trust<<','<<w.state[i].status<<','<<(std::find(w.currentHeads.begin(),w.currentHeads.end(),i)!=w.currentHeads.end())<<','<<w.state[i].headPath<<'\n';
}
void Start(unsigned round){
    w.round=round;w.started=true;w.stats={};w.received.clear();w.probeSamples.clear();w.auditSamples.clear();w.referenceReceived.clear();w.delivered.clear();
    w.buffer.assign(cfg.nodes,{});w.recs.assign(cfg.nodes,{});w.arrived.assign(cfg.nodes,false);w.goodPath.assign(cfg.nodes,false);
    if(cfg.batteryCutoff)for(unsigned i=0;i<TotalNodes();++i)if(BatteryNode(i))Cutoff(i);
    w.currentHeads=Select();for(auto h:w.currentHeads){++w.headCount[h];if(w.malicious[h])++w.stats.compromisedHeads;if(Attack(h,round,true))++w.stats.activeHeads;}
    Generate();
    for(unsigned r=0;r<cfg.references;++r)Simulator::Schedule(Seconds(1+.04*r),&ReferenceReport,r);
    for(unsigned i=0;i<cfg.nodes;++i){Simulator::Schedule(Seconds(.02*i),&Control,i);Simulator::Schedule(Seconds(2.5+.012*i),&Report,i);Simulator::Schedule(Seconds(7+.012*i),&Recommendations,i);}
    for(unsigned k=0;k<w.currentHeads.size();++k)Simulator::Schedule(Seconds(4.5+.20*k),&Aggregate,w.currentHeads[k]);
    Simulator::Schedule(Seconds(cfg.roundSeconds-.2),&Finish);
    if(round+1<cfg.rounds)Simulator::Schedule(Seconds(cfg.roundSeconds),&Start,round+1);
}
void Setup(){
    RngSeedManager::SetSeed(20261015);RngSeedManager::SetRun(cfg.seed);
    w.rng=CreateObject<UniformRandomVariable>();w.rng->SetStream(1000);
    w.nodes.Create(TotalNodes());w.history.resize(cfg.nodes);w.calibration.resize(cfg.nodes);w.cusum.resize(cfg.nodes);w.alarmRelease.resize(cfg.nodes);w.auditHistory.resize(cfg.nodes);w.publishedWindow.resize(cfg.nodes);w.state.resize(cfg.nodes);w.views.resize(cfg.nodes);w.headCount.assign(cfg.nodes,0);w.lastAck.assign(cfg.nodes,false);w.radio.resize(TotalNodes());w.advertisedEnergy.assign(cfg.nodes,1);w.advertisedPosition.resize(cfg.nodes);
    LoadCertificates();
    w.malicious.assign(cfg.nodes,false);std::vector<unsigned> ids(cfg.nodes);std::iota(ids.begin(),ids.end(),0);
    std::mt19937 attackRng(cfg.seed);std::shuffle(ids.begin(),ids.end(),attackRng);for(unsigned j=0;j<std::lround(cfg.ratio*cfg.nodes);++j)w.malicious[ids[j]]=true;
    MobilityHelper mobility;auto positions=CreateObject<ListPositionAllocator>();unsigned width=std::ceil(std::sqrt(cfg.nodes));
    NodeContainer sensors;for(unsigned i=0;i<cfg.nodes;++i){sensors.Add(w.nodes.Get(i));w.advertisedPosition[i]=Vector(8+(i%width)*6,8+(i/width)*6,0);positions->Add(w.advertisedPosition[i]);}
    mobility.SetPositionAllocator(positions);
    if(cfg.speed>0)mobility.SetMobilityModel("ns3::RandomWalk2dMobilityModel","Bounds",RectangleValue(Rectangle(0,80,0,80)),"Speed",StringValue("ns3::ConstantRandomVariable[Constant="+std::to_string(cfg.speed)+"]"),"Time",TimeValue(Seconds(1)));
    else mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobility.Install(sensors);mobility.AssignStreams(sensors,2000);
    NodeContainer sink;sink.Add(w.nodes.Get(cfg.nodes));MobilityHelper sinkMobility;sinkMobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");sinkMobility.Install(sink);sink.Get(0)->GetObject<MobilityModel>()->SetPosition(Vector(32,32,0));
    if(cfg.references){
        NodeContainer refs;for(unsigned r=0;r<cfg.references;++r)refs.Add(w.nodes.Get(cfg.nodes+1+r));
        MobilityHelper refMobility;refMobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");refMobility.Install(refs);
        for(unsigned r=0;r<cfg.references;++r)refs.Get(r)->GetObject<MobilityModel>()->SetPosition(Vector(25+3*r,30,0));
    }
    w.lr=std::make_unique<LrWpanHelper>();auto& lr=*w.lr;lr.SetPropagationDelayModel("ns3::ConstantSpeedPropagationDelayModel");lr.AddPropagationLossModel("ns3::LogDistancePropagationLossModel","Exponent",DoubleValue(2.7));
    auto devices=lr.Install(w.nodes);lr.CreateAssociatedPan(devices,1);
    for(unsigned i=0;i<devices.GetN();++i){auto dev=DynamicCast<LrWpanNetDevice>(devices.Get(i));w.devices.push_back(dev);dev->GetPhy()->TraceConnectWithoutContext("TrxStateValue",MakeBoundCallback(&StateChanged,i));dev->GetPhy()->TraceConnectWithoutContext("PhyTxBegin",MakeBoundCallback(&Tx,i));}
    InternetStackHelper internet;internet.Install(w.nodes);SixLowPanHelper six;auto low=six.Install(devices);
    Ipv6AddressHelper address;address.SetBase(Ipv6Address("2001:2::"),Ipv6Prefix(64));w.ip=address.Assign(low);for(unsigned i=0;i<TotalNodes();++i)w.addresses.push_back(w.ip.GetAddress(i,1));
    w.sockets.resize(TotalNodes());for(unsigned i=0;i<TotalNodes();++i){w.sockets[i]=Socket::CreateSocket(w.nodes.Get(i),UdpSocketFactory::GetTypeId());w.sockets[i]->Bind(Inet6SocketAddress(Ipv6Address::GetAny(),PORT));w.sockets[i]->SetRecvCallback(MakeBoundCallback(&Receive,i));}
    Simulator::Schedule(Seconds(2),&Start,0);Simulator::Stop(Seconds(2+cfg.rounds*cfg.roundSeconds));
}
} // namespace
int main(int argc,char** argv){
    CommandLine cmd(__FILE__);
    cmd.AddValue("references","Provisioned independent reference radios",cfg.references);
    cmd.AddValue("referenceAssist","Use received independent reference as exclusive semantic reference",cfg.referenceAssist);
    cmd.AddValue("evidenceFirst","Gate recommendations after independently observed direct failure",cfg.evidenceFirst);
    cmd.AddValue("referenceCompromised","Compromised references (generation only)",cfg.referenceCompromised);
    cmd.AddValue("referenceTampered","Reference source tags altered in transit (generation only)",cfg.referenceTampered);
    cmd.AddValue("referenceNoise","Independent bounded reference measurement noise",cfg.referenceNoise);
    cmd.AddValue("referenceBias","Independent bounded persistent reference bias",cfg.referenceBias);
    cmd.AddValue("referenceBound","Declared absolute good-reference measurement error bound",cfg.referenceBound);
    cmd.AddValue("certifiedCalibration","Use independent predeployment signed offsets",cfg.certifiedCalibration);
    cmd.AddValue("calibrationFile","Authenticated calibration CSV",cfg.calibrationFile);
    cmd.AddValue("directVeto","Verified negative evidence immediately quarantines",cfg.directVeto);
    cmd.AddValue("certifiedNoiseBound","Declared online sensor noise bound",cfg.certifiedNoiseBound);
    cmd.AddValue("referenceLoss","Reference-frame erasure probability",cfg.referenceLoss);
    cmd.AddValue("referenceDelay","Reference transmission delay in seconds",cfg.referenceDelay);
    cmd.AddValue("referenceOutage","Reference outage during first20 post-warmup rounds",cfg.referenceOutage);
    cmd.AddValue("referenceOff","All reference frames lost after warmup",cfg.referenceOff);
    cmd.AddValue("referenceShift","Compromised reference measurement offset",cfg.referenceShift);
    cmd.AddValue("referenceCommonBias","Unmodelled shared reference bias (failure stress)",cfg.referenceCommonBias);
    cmd.AddValue("physicalDrift","Common field drift per round after warmup",cfg.physicalDrift);cmd.AddValue("nodes","Sensor count",cfg.nodes);cmd.AddValue("heads","Maximum eligible heads",cfg.heads);cmd.AddValue("rounds","Mission rounds",cfg.rounds);cmd.AddValue("seed","Paired scenario seed",cfg.seed);
    cmd.AddValue("ratio","Compromised identity fraction (attack/scoring only)",cfg.ratio);cmd.AddValue("speed","Sensor random-walk speed m/s",cfg.speed);cmd.AddValue("policy","Policy",cfg.policy);cmd.AddValue("attack","none/fixed/sleeper/on-off",cfg.attack);
    cmd.AddValue("output","Round CSV",cfg.output);cmd.AddValue("trace","Optional report trace CSV",cfg.trace);cmd.AddValue("alpha","Trimming fraction per tail",cfg.trust.alpha);cmd.AddValue("delta","Clip radius",cfg.trust.delta);
    cmd.AddValue("etaB","Direct evidence fusion weight",cfg.trust.etaB);cmd.AddValue("etaR","Recommendation fusion weight",cfg.trust.etaR);cmd.AddValue("etaG","Path fusion weight",cfg.trust.etaG);cmd.AddValue("etaE","Energy fusion weight",cfg.trust.etaE);
    cmd.AddValue("noise","Sensor heterogeneity half-width",cfg.noise);cmd.AddValue("loss","Additional report erasure probability",cfg.loss);cmd.AddValue("shift","False scalar reading shift",cfg.shift);cmd.AddValue("central","Central-value collusive recommendations",cfg.central);cmd.AddValue("outage","Benign outage in rounds 80-99 for every fifth node",cfg.outage);
    cmd.AddValue("roleMemory","Separate and preserve head-role evidence",cfg.roleMemory);cmd.AddValue("probeIsolation","Exclude probes and ineligible sources from semantic reference",cfg.probeIsolation);cmd.AddValue("weightPath","Head-role path score coefficient",cfg.weightPath);cmd.AddValue("betaPath","Head-exposure smoothing",cfg.trust.betaPath);cmd.AddValue("referenceMin","Minimum eligible regular reference observations",cfg.referenceMin);
    cmd.AddValue("batteryCutoff","Enforce round-boundary radio budget shutdown",cfg.batteryCutoff);
    cmd.AddValue("energySpread","Fractional per-device budget spread, fixed exogenous stream",cfg.energySpread);
    cmd.AddValue("auditGuard","Recent standardized residual count for audit gate;zero disables",cfg.auditGuard);
    cmd.AddValue("auditMeanBound","Absolute recent-mean audit gate bound",cfg.auditMeanBound);
    cmd.AddValue("probationAudit","Extra read-only audit samples between recovery probes",cfg.probationAudit);
    cmd.AddValue("probationData","Count strictly gated authenticated probation samples as data",cfg.probationData);
    cmd.AddValue("probationLower","Opposite-sign standardized probation band lower magnitude",cfg.probationLower);
    cmd.AddValue("probationUpper","Opposite-sign standardized probation band upper magnitude",cfg.probationUpper);
    cmd.AddValue("rollingRecovery","Latest-per-identity bounded-age registered-majority recovery",cfg.rollingRecovery);
    cmd.AddValue("recoveryAge","Maximum rolling observation age in rounds",cfg.recoveryAge);
    cmd.AddValue("alarmRelease","Recent samples needed to clear alarm; zero disables",cfg.alarmRelease);
    cmd.AddValue("releaseMargin","Absolute standardized recent-mean release margin",cfg.releaseMargin);
    cmd.AddValue("sequential","Enable variance-normalized two-sided CUSUM",cfg.sequential);
    cmd.AddValue("commonRecovery","Enable two-round registered-identity supermajority re-anchor",cfg.commonRecovery);
    cmd.AddValue("adaptiveReference","Scale continuity allowance by commissioning uncertainty",cfg.adaptiveReference);
    cmd.AddValue("cusumK","CUSUM allowance in commissioning SD units",cfg.cusumK);
    cmd.AddValue("cusumH","CUSUM decision limit; cap is twice this value",cfg.cusumH);
    cmd.AddValue("varianceFloor","Commissioning SD floor in sensor units",cfg.varianceFloor);
    cmd.AddValue("fairPathPower","Attenuate fair deficit by observed head reliability power",cfg.fairPathPower);
    cmd.AddValue("fairBonus","Nonnegative modular head-count deficit weight",cfg.fairBonus);
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
        if(cfg.certifiedCalibration&&(!cfg.referenceAssist||!cfg.calibrated||!cfg.temporal||cfg.calibrationFile.empty()))throw std::invalid_argument("certified mode needs references, temporal checks and calibration file");
        cfg.trust.roleMemory=RoleMemory();cfg.trust.robust=cfg.policy!="no-robust"&&cfg.policy!="quarantine-only";cfg.trust.quarantineEnabled=Filtering()&&UsesTrust();cfg.trust.Validate();
        if(cfg.references>5||cfg.referenceCompromised>cfg.references||cfg.referenceTampered>cfg.references||cfg.referenceLoss<0||cfg.referenceLoss>1||cfg.referenceDelay<0||cfg.referenceBound<=0||cfg.referenceNoise<0||cfg.referenceBias<0||cfg.referenceAssist&&!cfg.references)throw std::invalid_argument("invalid independent-reference configuration");
        if(cfg.initialEnergy<=0||cfg.energySpread<0||cfg.energySpread>=1)throw std::invalid_argument("invalid battery budget");
        if(cfg.cusumH<=0||cfg.cusumK<0||cfg.varianceFloor<=0||cfg.fairBonus<0||cfg.fairPathPower<0)throw std::invalid_argument("invalid sequential parameters");
        if(cfg.temporalLambda<=0||cfg.temporalLambda>1||cfg.temporalMinimum<2||cfg.temporalMargin<0)throw std::invalid_argument("invalid temporal parameters");
        if(cfg.nodes<2||cfg.nodes>100||cfg.heads>10||cfg.ratio<0||cfg.ratio>.9)throw std::invalid_argument("unsupported scenario");
        if(crypto.Tag(Bytes{'H','i',' ','T','h','e','r','e'},std::string(20,'\x0b'))!=0xb0344c61d8db3853ULL)throw std::runtime_error("RFC 4231 HMAC test failed");
        w.output.open(cfg.output);if(!w.output)throw std::runtime_error("cannot open output");w.output<<std::setprecision(10);
        w.output<<"round,phase,generated,honest_generated,delivered,honest_clean,content_clean,bad_delivered,filtered,honest_filtered,malicious_filtered,probes,good_probes,heads,compromised_heads,active_attack_heads,aggregates,valid_aggregates,tx_frames,tx_bytes,app_data_bytes,app_control_bytes,alive,cumulative_radio_energy_j,honest_quarantine,malicious_quarantine,probation,mean_honest_trust,mean_malicious_trust,latency_sum_s,honest_trimmed,bad_retained,retained,recommendations,false_positive,false_negative,detected_good,detected_bad,accepted,accepted_honest_clean,accepted_content_clean,accepted_bad,reference_count,reference_available,head_jain,mean_honest_path,mean_malicious_path,honest_head_jain,ambiguous_round,temporal_rejected,temporal_honest_rejected,temporal_bad_rejected,coverage_utility,score_utility,audit_accepted,audit_bad,reference_sent,reference_received,reference_stale,independent_reference_available,reference_witnesses,reference_bytes,cumulative_reference_radio_energy_j,reference_alive,recommendation_gated,cumulative_total_sensor_radio_energy_j,reference_rejected,direct_vetoes,calibration_valid\n";
        if(!cfg.trace.empty()){w.trace.open(cfg.trace);w.trace<<"round,source,malicious,generated,physical_value,source_value,delivered,acknowledged_good,trust,state,head,path\n";}
        Setup();Simulator::Run();Simulator::Destroy();return 0;
    }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
}
