#include "../ns3/v2a/trust-v2.h"
#include <cassert>
#include <iostream>
int main(){
 using namespace dynatrust;
 Parameters p;p.Validate();
 assert(std::abs(Fusion({0,0,.6,.6,.6,.6,1,1},.6,p)-.6)<1e-12);
 assert(Fusion({},.7,p)==.7);
 p.alpha=.2;p.delta=.5;
 assert(std::abs(Fusion({0,.4,.5,.6,1},.5,p)-.5)<1e-12);
 State s; Evidence bad;bad.hasDirect=true;bad.direct=0;bad.hasPath=true;bad.path=0;bad.energy=1;
 for(unsigned t=0;t<15;++t)Update(s,bad,t,p);
 assert(s.status!=0 && !Admit(s,p) && !Eligible(s,p));
 unsigned entry=s.entered;assert(ProbeDue(s,entry+2,p));assert(!ProbeDue(s,entry+1,p));
 Evidence good;good.hasDirect=true;good.direct=1;good.energy=1;good.probe=true;good.probeGood=true;
 for(unsigned t=15;t<50;++t)Update(s,good,t,p);
 assert(s.status==0 && Admit(s,p));
 State a,b; Evidence same;same.hasDirect=true;same.direct=.8;same.recommendations={.6,.9,.8};
 for(unsigned t=0;t<20;++t){Update(a,same,t,p);Update(b,same,t,p);}
 assert(a.trust==b.trust); // no external hidden label can alter this interface
 p.alpha=.5;bool rejected=false;try{p.Validate();}catch(...){rejected=true;}assert(rejected);
 std::cout<<"controller tests passed\n";
}
