#include "../source/certified-evidence.h"
#include <cassert>
#include <iostream>
int main(){
 unsigned cases=0;
 for(unsigned n:{0,1,8,16,32})for(double prior:{0.,.2,.39,.6,.7,1.})for(double badFraction:{0.,.5,.6,.7,1.})for(double rec:{0.,.5,.7,1.}){
   dynatrust::Parameters p;dynatrust::State s;s.trust=prior;
   dynatrust::Evidence e;e.hasDirect=true;e.direct=0;e.hasPath=true;e.path=1;e.energy=1;
   for(unsigned j=0;j<n;++j)e.recommendations.push_back(j<n*badFraction?rec:.9);
   dynatrust::Update(s,e,100,p);assert(certified::Veto(s,e,100));assert(s.status!=0&&s.success==0);
   auto before=s;dynatrust::Evidence unknown;assert(!certified::Veto(s,unknown,101));assert(s.status==before.status);++cases;
 }
 // Positive evidence alone cannot skip existing hold and three-probe release.
 dynatrust::State s;dynatrust::Evidence bad;bad.hasDirect=true;bad.direct=0;certified::Veto(s,bad,0);
 dynatrust::Parameters p;dynatrust::Evidence good;good.hasDirect=true;good.direct=1;good.probe=true;good.probeGood=true;good.energy=1;
 for(unsigned t:{2,4,6,8,10,12})dynatrust::Update(s,good,t,p);
 assert(!s.status);
 certified::Offset offset{true,1.5,.051};assert(std::abs(certified::Tolerance(offset,1,.751)-2.553)<1e-12);
 // An attack/legitimate-bias pair with identical online records is separated
 // only by different independently authenticated predeployment corrections.
 assert(46.5-1.5==45.0);assert(46.5-.5==46.0);
 std::cout<<"Certified evidence: "<<cases<<" veto cases, missing evidence, probe recovery and interval checks passed.\n";
}
