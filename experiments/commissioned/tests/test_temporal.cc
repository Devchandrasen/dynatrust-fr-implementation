#include "../source/temporal-evidence.h"
#include "../source/trust-v2.h"
#include <cassert>
#include <iostream>
int main(){
 using namespace temporal;
 assert(Ambiguous({{44,1},{45,1},{62,1},{63,1}},6));
 assert(!Ambiguous({{44,1},{45,1},{62,.1},{63,.1}},6));
 assert(!Ambiguous({{44,1},{45,1},{46,1},{47,1}},6));
 assert(!PeerContrast({{0,.1,1},{1,.1,1}}).available);
 std::vector<History> h(36);
 for(unsigned t=0;t<400;++t)for(unsigned i=0;i<36;++i)
     h[i].Observe((i<14?1:0)+.4*std::sin((i+1)*12.13+(t+1)*7.19),t,.04);
 std::vector<Peer> peers;for(auto& state:h)peers.push_back({state.Mean(),state.SE(),1});
 auto contrast=PeerContrast(peers);
 for(unsigned i=0;i<36;++i)assert(Reject(h[i],contrast,.45,2.5)==(i<14));
 const double effective=h[0].EffectiveN();assert(effective>48 && effective<50);
 // Genuine persistent sensor bias has the same observational signature. The
 // candidate deliberately cannot claim to distinguish the two without extra data.
 History legitimateBias;for(unsigned t=0;t<400;++t)legitimateBias.Observe(1,t,.04);
 assert(Reject(legitimateBias,contrast,.45,2.5));
 // Original controller functions remain unchanged.
 dynatrust::Parameters p;p.Validate();dynatrust::State state;
 dynatrust::Evidence failed;failed.hasPath=true;failed.path=0;
 dynatrust::Update(state,failed,0,p);assert(std::abs(state.headPath-.5)<1e-12);
 std::cout<<"Ambiguity, temporal effect, honest controls, known bias limitation and head-memory tests passed\n";
}
