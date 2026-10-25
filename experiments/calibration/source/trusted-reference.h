#pragma once
#include <algorithm>
#include <cmath>
#include <map>
#include <vector>

// This interface has no scenario, true value, attack state or sensor labels.
namespace independent {
struct Observation {double value=0;unsigned round=0;};
struct Estimate {bool available=false;double value=0;unsigned witnesses=0;};
inline Estimate Reference(const std::map<unsigned,Observation>& received,
    unsigned provisioned,unsigned round,double errorBound){
    if(!provisioned||errorBound<0)return {};
    const unsigned quorum=provisioned/2+1;
    std::vector<double> values;
    for(auto [id,s]:received)
        if(id<provisioned&&s.round==round&&std::isfinite(s.value)&&s.value>=0&&s.value<=100)
            values.push_back(s.value);
    if(values.size()<quorum)return {};
    std::sort(values.begin(),values.end());
    bool found=false;double lower=0,upper=0;
    for(unsigned i=0;i+quorum<=values.size();++i){
        const double lo=values[i+quorum-1]-errorBound,hi=values[i]+errorBound;
        if(lo>hi)continue;
        if(!found){lower=lo;upper=hi;found=true;}
        else if(lo>upper+1e-12)return {}; // Distinct feasible regions: abstain.
        else upper=std::max(upper,hi);
    }
    if(!found)return {};
    const double center=(lower+upper)/2;
    unsigned witnesses=0;for(double v:values)if(std::abs(v-center)<=errorBound+1e-12)++witnesses;
    // Every feasible point is supported by a fixed provisioned quorum. With
    // fewer than quorum faulty identities it is within 2*errorBound of truth.
    // Require the chosen center itself to retain quorum support.
    return witnesses>=quorum?Estimate{true,center,witnesses}:Estimate{};
}
}
