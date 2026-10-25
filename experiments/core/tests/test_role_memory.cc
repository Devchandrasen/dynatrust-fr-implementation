#include "../ns3/v2a/trust-v2.h"
#include <cassert>
#include <cmath>
#include <iostream>
int main(){
 using namespace dynatrust; Parameters p; p.Validate(); State s;
 Evidence failure; failure.hasPath=true; failure.path=0;
 Update(s,failure,0,p); assert(std::abs(s.headPath-.50)<1e-12);
 Evidence member; member.hasDirect=true; member.direct=1;
 for(unsigned t=1;t<30;++t)Update(s,member,t,p);
 assert(std::abs(s.headPath-.50)<1e-12); assert(s.direct>.99);
 Evidence success; success.hasPath=true; success.path=1;
 Update(s,success,30,p); assert(std::abs(s.headPath-.75)<1e-12);
 State recovery; Evidence bad;bad.hasDirect=true;bad.direct=0;bad.hasPath=true;bad.path=0;
 for(unsigned t=0;t<20;++t)Update(recovery,bad,t,p);
 assert(recovery.status); member.probe=true;member.probeGood=true;
 for(unsigned t=20;t<90;++t)Update(recovery,member,t,p);
 assert(recovery.status==0 && Admit(recovery,p));
 assert(recovery.headPath<.001); // Source recovery never manufactures a successful head exposure.
 auto a=Reference({{44,1},{45,1},{46,1}},{{0,1},{100,1},{100,1},{100,1}},true);
 auto b=Reference({{44,1},{45,1},{46,1}},{{45,1},{45,1},{45,1}},true);
 assert(a.available && a.median==45 && a.median==b.median);
 assert(!Reference({{45,1},{46,1}},{{45,1},{45,1},{45,1}},true).available);
 assert(Reference({{44,1},{45,1},{62,1},{63,1}},{},true).median==53.5);
 assert(Reference({{44,1},{45,1},{62,.5},{63,1}},{},true).median==45);
 assert(Reference({{44,1},{45,1},{46,1},{47,1}},{},false).median==45.5);
 p.betaPath=1;bool invalid=false;try{p.Validate();}catch(...){invalid=true;}assert(invalid);
 std::cout<<"Head-role persistence, exposure update and source recovery tests passed\n";
}
