#pragma once
#include "trust-v2.h"
namespace certified {
struct Offset { bool valid=false; double value=0,bound=0; };
// Only observable negative evidence drives this invariant. No recommendation
// list, identity class or latent physical value is inspected.
inline bool Veto(dynatrust::State& s,const dynatrust::Evidence& e,unsigned round) {
    if(!e.hasDirect || e.direct>=.5)return false;
    if(!s.status){s.status=1;s.entered=round;}
    s.success=0;
    return true;
}
inline double Tolerance(const Offset& offset,double onlineNoise,double referenceBound){
    return onlineNoise+offset.bound+2*referenceBound;
}
}
