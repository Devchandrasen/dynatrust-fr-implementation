#include "../source/trusted-reference.h"
#include <cassert>
#include <iostream>
using independent::Observation;
int main(){
    using M=std::map<unsigned,Observation>;
    assert(!independent::Reference({},3,8,.75).available);
    assert(!independent::Reference(M{{0,{45,8}}},3,8,.75).available);
    assert(!independent::Reference(M{{0,{45,7}},{1,{45,7}},{2,{45,7}}},3,8,.75).available);
    assert(!independent::Reference(M{{0,{45,8}},{1,{63,8}}},3,8,.75).available);
    auto e=independent::Reference(M{{0,{45.2,8}},{1,{44.8,8}},{2,{63,8}}},3,8,.75);
    assert(e.available&&std::abs(e.value-45)<1e-9&&e.witnesses==2);
    // Extra identities cannot manufacture a provisioned quorum.
    assert(!independent::Reference(M{{0,{45,8}},{3,{45,8}},{4,{45,8}}},3,8,.75).available);
    assert(!independent::Reference(M{{0,{45,8}},{1,{47,8}},{2,{49,8}}},3,8,1).available);
    auto compromised=independent::Reference(M{{0,{63,8}},{1,{63.1,8}},{2,{45,8}}},3,8,.75);
    assert(compromised.available&&compromised.value>62); // Premise failure is visible.
    // Exhaust bounded honest inputs and arbitrary corrupt values; availability
    // may fall, but an available estimate respects the declared 2b bound.
    unsigned checked=0;
    for(double a=44.25;a<=45.75;a+=.25)for(double b=44.25;b<=45.75;b+=.25)
      for(double z=0;z<=100;z+=.25){
        auto x=independent::Reference(M{{0,{a,8}},{1,{b,8}},{2,{z,8}}},3,8,.75);
        if(x.available)assert(std::abs(x.value-45)<=1.500001);
        ++checked;
      }
    std::cout<<"Trusted-reference quorum/freshness/ambiguity/bounded-error tests passed: "<<checked<<" cases\n";
}
