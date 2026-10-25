#pragma once
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <stdexcept>
#include <vector>
#include <utility>

// This controller interface deliberately has no malicious-state or attack-label field.
namespace dynatrust {
struct Parameters {
    double rho=.28, beta=.50, alpha=.20, delta=.20;
    double etaB=.50, etaR=.20, etaG=.25, etaE=.05;
    double filter=.50, head=.60, quarantine=.40, release=.65;
    unsigned hold=3, probePeriod=2, successes=3;
    double betaPath=.50;
    bool robust=true, quarantineEnabled=true, roleMemory=true;
    void Validate() const {
        if(rho<=0 || rho>1 || beta<0 || beta>=1 || alpha<0 || alpha>=.5 || delta<0 ||
           etaB<0 || etaR<0 || etaG<0 || etaE<0 || betaPath<0 || betaPath>=1 ||
           std::abs(etaB+etaR+etaG+etaE-1)>1e-9 || probePeriod==0 || successes==0)
            throw std::invalid_argument("Invalid trust parameters");
    }
};
struct Evidence {
    bool hasDirect=false, hasPath=false, probe=false, probeGood=false;
    double direct=.7, path=.7, energy=1;
    std::vector<double> recommendations;
};
struct State {
    double trust=.70, direct=.70, path=.70, headPath=1.0;
    unsigned status=0, entered=0, success=0; // 0 active, 1 quarantine, 2 probation
};
inline double Clamp(double x){return std::clamp(x,0.0,1.0);}
struct ReferenceResult {bool available=false;double median=0;};
inline ReferenceResult Reference(std::vector<std::pair<double,double>> regular,const std::vector<std::pair<double,double>>& probes,bool isolated,unsigned minimum=3){
    if(!isolated)regular.insert(regular.end(),probes.begin(),probes.end());
    if(regular.size()<minimum)return {};
    if(regular.empty())return {true,45}; // Exact mixed-reference comparator behavior.
    std::sort(regular.begin(),regular.end());double total=0;
    for(auto [value,weight]:regular)total+=weight;
    if(total<=0)return {};
    double cumulative=0;
    for(unsigned j=0;j<regular.size();++j){
        cumulative+=regular[j].second;
        if(std::abs(cumulative-total/2)<1e-10 && j+1<regular.size())return {true,(regular[j].first+regular[j+1].first)/2};
        if(cumulative>total/2)return {true,regular[j].first};
    }
    return {true,regular.back().first};
}
inline double Fusion(std::vector<double> values,double prior,const Parameters& p) {
    if(values.empty()) return prior;
    if(p.robust){
        for(auto& x:values)x=std::clamp(Clamp(x),std::max(0.0,prior-p.delta),std::min(1.0,prior+p.delta));
        std::sort(values.begin(),values.end());
    }
    const unsigned trim=p.robust?static_cast<unsigned>(std::floor(p.alpha*values.size())):0;
    double sum=0;
    for(unsigned i=trim;i<values.size()-trim;++i)sum+=Clamp(values[i]);
    return sum/(values.size()-2*trim);
}
inline bool ProbeDue(const State& s,unsigned round,const Parameters& p){
    return s.status && round>s.entered && (round-s.entered)%p.probePeriod==0;
}
inline void Update(State& s,const Evidence& e,unsigned round,const Parameters& p){
    if(e.hasDirect)s.direct=p.beta*s.direct+(1-p.beta)*Clamp(e.direct);
    // Only an observed head exposure changes head-path reliability. An ordinary
    // source report cannot erase a failed head exposure.
    if(p.roleMemory && e.hasPath)s.headPath=p.betaPath*s.headPath+(1-p.betaPath)*Clamp(e.path);
    s.path=e.hasPath?Clamp(e.path):s.direct;
    const double rec=Fusion(e.recommendations,s.trust,p);
    s.trust=Clamp((1-p.rho)*s.trust+p.rho*(p.etaB*s.direct+p.etaR*rec+p.etaG*s.path+p.etaE*Clamp(e.energy)));
    if(!p.quarantineEnabled){s.status=0;return;}
    if(!s.status && s.trust<p.quarantine){s.status=1;s.entered=round;s.success=0;}
    else if(s.status){
        if(round-s.entered>=p.hold)s.status=2;
        if(e.probe)s.success=e.probeGood?s.success+1:0;
        if(s.status==2 && s.success>=p.successes && s.trust>=p.release){s.status=0;s.success=0;}
    }
}
inline bool Admit(const State& s,const Parameters& p){return s.status==0 && s.trust>=p.filter;}
inline bool Eligible(const State& s,const Parameters& p){return s.status==0 && s.trust>=p.head;}
} // namespace dynatrust
